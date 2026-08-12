use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::Path,
    sync::{
        Barrier,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use super::super::{
    HostLayout, LifecycleSession, PhaseTracker, STRESS_INSTALL_DIRECTORY, STRESS_PACKAGE_ID,
    STRESS_PUBLISHED_FILE, StressPackage, UninstallProbeEvent, UninstallTerminal, consume_install,
    consume_uninstall, directory_entry_names, exact_keys, inspect_stress_fixture, message_kind,
    object_string, parse_uninstall_event, path_absent, request_stress_install, strict_result,
    unicode_path, validate_install_action_against_inspect, value_object, verify_regular_bytes,
};
use super::{
    CrashOperation, consume_expected_install_error, read_bounded_journal_prefix,
    read_stress_receipt, receipt_path, require_ready_prepare,
    require_recovered_transaction_absence, require_recovery_cleanup, require_regular_hash,
    stress_file_table, validate_install_base_identity, validate_stress_receipt, verify_exact_tree,
};
use crate::runner::{is_link_or_reparse, sha256_hex, staging::sha256_file};

const CLEANUP_BLOCKER: &str = "probe.cleanup-blocker";
const CLEANUP_BLOCKER_BYTES: &[u8] = b"packaged post-cutover restart probe\n";
const CLEANUP_BLOCKER_WAIT: Duration = Duration::from_secs(30);
const CLEANUP_BLOCKER_RETRY: Duration = Duration::from_millis(2);
const PRECOMMIT_TRIGGER_WAIT: Duration = Duration::from_secs(30);

pub(crate) fn probe_uninstall_precommit_crash_recovery(
    backend: &Path,
    base: StressPackage<'_>,
    barrier: StressPackage<'_>,
    host: HostLayout,
    probe_root: &Path,
) -> Result<(), String> {
    for path in [backend, base.package, base.source_payload, barrier.package] {
        if !path.is_absolute() {
            return Err("uninstall recovery inputs must be absolute paths".into());
        }
    }
    super::require_empty_probe_root(probe_root)?;
    let base_package = unicode_path(base.package, "uninstall recovery payload")?;
    let barrier_package = unicode_path(barrier.package, "uninstall recovery barrier")?;
    let install_base = probe_root.join("install");
    let state_root = probe_root.join("state");
    let install_base_text = unicode_path(&install_base, "uninstall recovery install root")?;
    let state_root_text = unicode_path(&state_root, "uninstall recovery state root")?;

    let base_inspect = LifecycleSession::start(backend)?.run(|session| {
        let inspect = inspect_stress_fixture(
            session,
            base_package,
            host,
            "uninstall_base_inspect",
            base.expected.files,
            base.expected.bytes,
        )?;
        if inspect.package_version != "1.0.0" {
            return Err("uninstall recovery base fixture has an unexpected version".into());
        }
        request_stress_install(
            session,
            "uninstall_base_install",
            base_package,
            &install_base,
            &state_root,
            &inspect,
        )?;
        let installed = consume_install(session, "uninstall_base_install")?;
        validate_install_action_against_inspect(&inspect, &installed, "install")?;
        Ok(inspect)
    })?;
    verify_exact_tree(
        base.source_payload,
        &install_base.join(STRESS_INSTALL_DIRECTORY),
    )?;
    let base_receipt = read_stress_receipt(&state_root)?;
    validate_stress_receipt(
        &base_receipt,
        "1.0.0",
        base.source_payload,
        base.expected.executable,
    )?;
    let base_receipt_hash = sha256_hex(sha256_file(&receipt_path(&state_root))?);
    require_recovered_transaction_absence(&install_base, &state_root)?;

    LifecycleSession::start(backend)?.run_crashed(
        "uninstall_precommit",
        CrashOperation::Uninstall,
        |session| {
            request_uninstall(
                session,
                "uninstall_precommit",
                install_base_text,
                state_root_text,
            )?;
            wait_for_first_uninstall_backup(session, &install_base, &state_root)
        },
    )?;
    let post_crash_journal = require_pending_uninstall(
        &install_base,
        &state_root,
        base.source_payload,
        base.expected.executable,
        &base_receipt,
        &base_receipt_hash,
    )?;

    LifecycleSession::start(backend)?.run(|session| {
        let inspect = inspect_stress_fixture(
            session,
            base_package,
            host,
            "uninstall_recovery_inspect",
            base.expected.files,
            base.expected.bytes,
        )?;
        if inspect != base_inspect {
            return Err("fresh backend inspected a different uninstall recovery payload".into());
        }
        super::require_recovery_prepare(
            session,
            base_package,
            install_base_text,
            state_root_text,
            &inspect.fingerprint,
        )?;
        let after_prepare = require_pending_uninstall(
            &install_base,
            &state_root,
            base.source_payload,
            base.expected.executable,
            &base_receipt,
            &base_receipt_hash,
        )?;
        if after_prepare != post_crash_journal {
            return Err("read-only prepare changed pending uninstall state".into());
        }
        let barrier_inspect = inspect_stress_fixture(
            session,
            barrier_package,
            host,
            "uninstall_barrier_inspect",
            barrier.expected.files,
            barrier.expected.bytes,
        )?;
        if barrier_inspect.package_version != "0.9.0"
            || barrier_inspect.package_id != base_inspect.package_id
            || barrier_inspect.install_directory != base_inspect.install_directory
        {
            return Err("uninstall recovery barrier identity is invalid".into());
        }
        request_stress_install(
            session,
            "uninstall_recovery_barrier",
            barrier_package,
            &install_base,
            &state_root,
            &barrier_inspect,
        )?;
        consume_expected_install_error(session, "uninstall_recovery_barrier", "downgrade_denied")?;
        require_ready_prepare(
            session,
            base_package,
            install_base_text,
            state_root_text,
            &inspect.fingerprint,
            "repair",
            "1.0.0",
        )
    })?;
    verify_exact_tree(
        base.source_payload,
        &install_base.join(STRESS_INSTALL_DIRECTORY),
    )?;
    if read_stress_receipt(&state_root)? != base_receipt
        || sha256_hex(sha256_file(&receipt_path(&state_root))?) != base_receipt_hash
    {
        return Err("uninstall rollback did not restore exact R1/H1".into());
    }
    require_recovered_transaction_absence(&install_base, &state_root)?;
    probe_post_cutover_restart(
        backend,
        base,
        host,
        &install_base,
        &state_root,
        &base_receipt,
        &base_receipt_hash,
    )
}

fn probe_post_cutover_restart(
    backend: &Path,
    base: StressPackage<'_>,
    host: HostLayout,
    install_base: &Path,
    state_root: &Path,
    base_receipt: &[u8],
    base_receipt_hash: &str,
) -> Result<(), String> {
    let base_package = unicode_path(base.package, "post-cutover uninstall payload")?;
    let install_base_text = unicode_path(install_base, "post-cutover uninstall install root")?;
    let state_root_text = unicode_path(state_root, "post-cutover uninstall state root")?;

    let transaction = state_root.join("transactions").join(STRESS_PACKAGE_ID);
    let blocker = transaction.join(CLEANUP_BLOCKER);
    let removed = LifecycleSession::start(backend)?.run(|session| {
        uninstall_with_cleanup_blocker(
            session,
            "uninstall_post_cutover",
            install_base_text,
            state_root_text,
            &blocker,
        )
    })?;
    if removed.package_id != STRESS_PACKAGE_ID
        || removed.removed_files != base.expected.files
        || removed.missing_files != 0
        || removed.preserved_modified_files != 0
    {
        return Err("post-cutover uninstall result was inconsistent".into());
    }
    let committed_journal = require_committed_uninstall(
        install_base,
        state_root,
        base.source_payload,
        base.expected.executable,
        base_receipt,
        base_receipt_hash,
    )?;

    LifecycleSession::start(backend)?.run(|session| {
        let inspect = inspect_stress_fixture(
            session,
            base_package,
            host,
            "uninstall_post_cutover_recovery_inspect",
            base.expected.files,
            base.expected.bytes,
        )?;
        super::require_recovery_prepare(
            session,
            base_package,
            install_base_text,
            state_root_text,
            &inspect.fingerprint,
        )
    })?;
    let after_prepare = require_committed_uninstall(
        install_base,
        state_root,
        base.source_payload,
        base.expected.executable,
        base_receipt,
        base_receipt_hash,
    )?;
    if after_prepare != committed_journal {
        return Err("read-only prepare changed committed uninstall state".into());
    }

    fs::remove_file(&blocker)
        .map_err(|error| format!("could not remove post-cutover cleanup blocker: {error}"))?;
    if !path_absent(&blocker, "post-cutover cleanup blocker")? {
        return Err("post-cutover cleanup blocker remained after removal".into());
    }
    LifecycleSession::start(backend)?.run(|session| {
        request_uninstall(
            session,
            "uninstall_post_cutover_recovery",
            install_base_text,
            state_root_text,
        )?;
        consume_recovered_not_installed(session, "uninstall_post_cutover_recovery")
    })?;
    require_recovery_cleanup(install_base, state_root)
}

fn request_uninstall(
    session: &mut LifecycleSession,
    request_id: &str,
    install_base: &str,
    state_root: &str,
) -> Result<(), String> {
    session.request(
        request_id,
        "uninstall",
        json!({
            "packageId": STRESS_PACKAGE_ID,
            "installBase": install_base,
            "stateRoot": state_root,
        }),
    )
}

fn wait_for_first_uninstall_backup(
    session: &mut LifecycleSession,
    install_base: &Path,
    state_root: &Path,
) -> Result<(), String> {
    let live = install_base
        .join(STRESS_INSTALL_DIRECTORY)
        .join(STRESS_PUBLISHED_FILE);
    let backup = install_base
        .join(format!(".luxury-tx-{STRESS_PACKAGE_ID}"))
        .join("removed")
        .join(STRESS_PUBLISHED_FILE);
    let journal = state_root
        .join("transactions")
        .join(STRESS_PACKAGE_ID)
        .join("journal.jsonl");
    let deadline = Instant::now() + PRECOMMIT_TRIGGER_WAIT;
    loop {
        let live_missing = !regular_file_present(&live, "pre-commit uninstall anchor")?;
        let backup_ready = regular_file_present(&backup, "pre-commit uninstall backup")?;
        let journal_ready = regular_file_present(&journal, "pre-commit uninstall journal")?;
        if live_missing && backup_ready && journal_ready {
            return Ok(());
        }
        if let Some(status) = session
            .child
            .try_wait()
            .map_err(|error| format!("could not inspect pre-commit backend: {error}"))?
        {
            return Err(format!(
                "packaged backend exited before the pre-commit uninstall trigger with {status}"
            ));
        }
        if Instant::now() >= deadline {
            return Err("pre-commit uninstall trigger timed out".into());
        }
        thread::yield_now();
    }
}

fn regular_file_present(path: &Path, label: &str) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Ok(metadata) if metadata.is_file() && !is_link_or_reparse(&metadata) => Ok(true),
        Ok(_) => Err(format!("{label} changed type")),
        Err(error) => Err(format!("could not inspect {label}: {error}")),
    }
}

fn uninstall_with_cleanup_blocker(
    session: &mut LifecycleSession,
    request_id: &str,
    install_base: &str,
    state_root: &str,
    blocker: &Path,
) -> Result<UninstallTerminal, String> {
    let cancelled = AtomicBool::new(false);
    let ready = Barrier::new(2);
    thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            ready.wait();
            create_cleanup_blocker(blocker, &cancelled)
        });
        ready.wait();
        let operation = request_uninstall(session, request_id, install_base, state_root)
            .and_then(|_| consume_uninstall(session, request_id));
        cancelled.store(true, Ordering::Release);
        let watched = watcher
            .join()
            .map_err(|_| "post-cutover cleanup blocker watcher panicked".to_owned())
            .and_then(|result| result);
        match (operation, watched) {
            (Ok(terminal), Ok(())) => Ok(terminal),
            (Err(operation), Ok(())) => Err(operation),
            (Ok(_), Err(watcher)) => Err(watcher),
            (Err(operation), Err(watcher)) => Err(format!("{operation}; {watcher}")),
        }
    })
}

fn create_cleanup_blocker(path: &Path, cancelled: &AtomicBool) -> Result<(), String> {
    let deadline = Instant::now() + CLEANUP_BLOCKER_WAIT;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(
                "post-cutover cleanup blocker watcher was cancelled before creation".into(),
            );
        }
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut file) => {
                return file
                    .write_all(CLEANUP_BLOCKER_BYTES)
                    .and_then(|_| file.sync_all())
                    .map_err(|error| {
                        format!("could not sync post-cutover cleanup blocker: {error}")
                    });
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if Instant::now() >= deadline {
                    return Err("post-cutover cleanup blocker transaction wait timed out".into());
                }
                thread::sleep(CLEANUP_BLOCKER_RETRY);
            }
            Err(error) => {
                return Err(format!(
                    "could not create post-cutover cleanup blocker: {error}"
                ));
            }
        }
    }
}

fn consume_recovered_not_installed(
    session: &mut LifecycleSession,
    request_id: &str,
) -> Result<(), String> {
    const PHASES: &[&str] = &["recovering", "loadingReceipt", "completed"];
    let mut phases = PhaseTracker::default();
    loop {
        let message = session.next_required("post-cutover recovery")?;
        match message_kind(&message, request_id)? {
            "event" => match parse_uninstall_event(&message, request_id)? {
                UninstallProbeEvent::Phase(phase) => {
                    phases.observe(&phase, PHASES, "post-cutover recovery")?;
                }
                UninstallProbeEvent::Progress(_) => {
                    return Err("post-cutover recovery emitted uninstall progress".into());
                }
            },
            "result" => {
                phases.finish(PHASES, "post-cutover recovery")?;
                return validate_not_installed_result(&message, request_id);
            }
            "error" => return Err("post-cutover recovery returned an error".into()),
            _ => unreachable!("message kind is validated"),
        }
    }
}

fn validate_not_installed_result(message: &Value, request_id: &str) -> Result<(), String> {
    let result = strict_result(message, request_id, "post-cutover recovery")?;
    let fields = value_object(result, "post-cutover recovery result")?;
    exact_keys(
        fields,
        &["status", "packageId"],
        "post-cutover recovery result",
    )?;
    if object_string(fields, "status", "post-cutover recovery status")? != "notInstalled"
        || object_string(fields, "packageId", "post-cutover recovery package id")?
            != STRESS_PACKAGE_ID
    {
        return Err("post-cutover recovery did not return exact notInstalled state".into());
    }
    Ok(())
}

fn require_pending_uninstall(
    install_base: &Path,
    state_root: &Path,
    source_payload: &Path,
    expected_published_executable: bool,
    receipt: &[u8],
    receipt_hash: &str,
) -> Result<Vec<u8>, String> {
    if read_stress_receipt(state_root)? != receipt {
        return Err("pending uninstall changed its live ownership receipt".into());
    }
    let transaction = state_root.join("transactions").join(STRESS_PACKAGE_ID);
    if directory_entry_names(&transaction, "pending uninstall transaction")? != ["journal.jsonl"] {
        return Err("pending uninstall state has unexpected entries".into());
    }
    for path in [
        transaction.join("receipt.deleted"),
        transaction.join("receipt.pending"),
        transaction.join("receipt.previous"),
        transaction.join("journal.done"),
    ] {
        if !path_absent(&path, "pre-commit uninstall state")? {
            return Err("pending uninstall crossed its receipt commit point".into());
        }
    }
    let installed_anchor = install_base
        .join(STRESS_INSTALL_DIRECTORY)
        .join(STRESS_PUBLISHED_FILE);
    if !path_absent(&installed_anchor, "pre-commit uninstall anchor")? {
        return Err("uninstall progress did not move its anchor file".into());
    }
    let expected_files = stress_file_table(source_payload, expected_published_executable)?;
    let (anchor_size, anchor_hash, anchor_executable) =
        expected_files
            .get(STRESS_PUBLISHED_FILE)
            .ok_or_else(|| "stress file table has no uninstall anchor".to_owned())?;
    let backup = install_base
        .join(format!(".luxury-tx-{STRESS_PACKAGE_ID}"))
        .join("removed")
        .join(STRESS_PUBLISHED_FILE);
    let expected_hash = sha256_file(&source_payload.join(STRESS_PUBLISHED_FILE))?;
    if sha256_hex(expected_hash) != *anchor_hash {
        return Err("stress file table anchor hash changed".into());
    }
    require_regular_hash(
        &backup,
        *anchor_size,
        expected_hash,
        *anchor_executable,
        "pending uninstall anchor backup",
    )?;
    let journal = read_bounded_journal_prefix(&transaction.join("journal.jsonl"))?;
    validate_uninstall_journal(&journal, &expected_files, receipt_hash, false)?;
    Ok(journal)
}

fn require_committed_uninstall(
    install_base: &Path,
    state_root: &Path,
    source_payload: &Path,
    expected_published_executable: bool,
    receipt: &[u8],
    receipt_hash: &str,
) -> Result<Vec<u8>, String> {
    let transaction = state_root.join("transactions").join(STRESS_PACKAGE_ID);
    if directory_entry_names(&transaction, "committed uninstall transaction")?
        != ["journal.jsonl", CLEANUP_BLOCKER, "receipt.deleted"]
    {
        return Err("committed uninstall state has unexpected entries".into());
    }
    let live_receipt = receipt_path(state_root);
    if !path_absent(&live_receipt, "committed uninstall live receipt")? {
        return Err("committed uninstall retained its live receipt".into());
    }
    for path in [
        transaction.join("receipt.pending"),
        transaction.join("receipt.previous"),
        transaction.join("journal.done"),
    ] {
        if !path_absent(&path, "committed uninstall state")? {
            return Err("committed uninstall retained pre-cutover state".into());
        }
    }
    let tombstone = transaction.join("receipt.deleted");
    verify_regular_bytes(&tombstone, receipt, "committed uninstall receipt tombstone")?;
    if sha256_hex(sha256_file(&tombstone)?) != receipt_hash {
        return Err("committed uninstall tombstone did not match exact R1/H1".into());
    }
    let blocker = transaction.join(CLEANUP_BLOCKER);
    verify_regular_bytes(
        &blocker,
        CLEANUP_BLOCKER_BYTES,
        "post-cutover cleanup blocker",
    )?;

    let destination_transaction = install_base.join(format!(".luxury-tx-{STRESS_PACKAGE_ID}"));
    if directory_entry_names(
        &destination_transaction,
        "committed uninstall destination transaction",
    )? != ["removed"]
    {
        return Err("committed uninstall destination state has unexpected entries".into());
    }
    verify_exact_tree(source_payload, &destination_transaction.join("removed"))?;
    if !path_absent(
        &install_base.join(STRESS_INSTALL_DIRECTORY),
        "committed uninstall install tree",
    )? {
        return Err("committed uninstall left its owned install tree".into());
    }

    let journal_path = transaction.join("journal.jsonl");
    let journal = fs::read(&journal_path)
        .map_err(|error| format!("could not read committed uninstall journal: {error}"))?;
    let complete = read_bounded_journal_prefix(&journal_path)?;
    if journal != complete {
        return Err("committed uninstall journal has a torn trailing record".into());
    }
    let expected_files = stress_file_table(source_payload, expected_published_executable)?;
    validate_uninstall_journal(&journal, &expected_files, receipt_hash, true)?;
    Ok(journal)
}

fn validate_uninstall_journal(
    prefix: &[u8],
    expected_files: &super::StressFileTable,
    receipt_hash: &str,
    expect_committing: bool,
) -> Result<(), String> {
    let lines = prefix
        .strip_suffix(b"\n")
        .ok_or_else(|| "uninstall journal prefix is not terminated".to_owned())?
        .split(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    let mut restored = BTreeSet::new();
    let mut committing = false;
    for (index, line) in lines.iter().enumerate() {
        if line.is_empty() {
            return Err("uninstall journal contains an empty record".into());
        }
        let record: Value = serde_json::from_slice(line)
            .map_err(|_| "uninstall journal contains invalid JSON".to_owned())?;
        let fields = value_object(&record, "uninstall journal record")?;
        let kind = object_string(fields, "kind", "uninstall journal kind")?;
        if index == 0 {
            exact_keys(
                fields,
                &[
                    "kind",
                    "format_version",
                    "operation",
                    "package_id",
                    "directory",
                    "install_base",
                    "scope",
                    "previous_receipt_sha256",
                ],
                "uninstall journal header",
            )?;
            if kind != "header"
                || fields.get("format_version").and_then(Value::as_u64) != Some(4)
                || fields.get("operation").and_then(Value::as_str) != Some("uninstall")
                || fields.get("package_id").and_then(Value::as_str) != Some(STRESS_PACKAGE_ID)
                || fields.get("directory").and_then(Value::as_str) != Some(STRESS_INSTALL_DIRECTORY)
                || fields.get("scope").and_then(Value::as_str) != Some("user")
                || fields
                    .get("previous_receipt_sha256")
                    .and_then(Value::as_str)
                    != Some(receipt_hash)
            {
                return Err("uninstall journal has an invalid receipt-bound header".into());
            }
            validate_install_base_identity(
                fields
                    .get("install_base")
                    .ok_or_else(|| "uninstall journal header has no install base".to_owned())?,
            )?;
            continue;
        }
        if kind == "committing" {
            exact_keys(fields, &["kind"], "uninstall commit record")?;
            if !expect_committing || committing || index + 1 != lines.len() {
                return Err("uninstall journal has an invalid receipt commit point".into());
            }
            committing = true;
            continue;
        }
        if kind != "restore_file" {
            return Err("uninstall journal contains an invalid record".into());
        }
        exact_keys(
            fields,
            &["kind", "path", "sha256", "executable"],
            "uninstall restore record",
        )?;
        let path = object_string(fields, "path", "uninstall restore path")?;
        let hash = object_string(fields, "sha256", "uninstall restore hash")?;
        let executable = fields
            .get("executable")
            .and_then(Value::as_bool)
            .ok_or_else(|| "uninstall restore record has no executable flag".to_owned())?;
        let expected = expected_files.get(path);
        if !expected.is_some_and(|(_, expected_hash, expected_executable)| {
            expected_hash == hash && *expected_executable == executable
        }) || !restored.insert(path.to_owned())
        {
            return Err("uninstall restore record is not bound to the ownership receipt".into());
        }
    }
    if !restored.contains(STRESS_PUBLISHED_FILE) {
        return Err("uninstall journal does not cover its required file set".into());
    }
    if expect_committing && restored.len() != expected_files.len() {
        return Err("committed uninstall journal does not cover its exact receipt".into());
    }
    if committing != expect_committing {
        return Err("uninstall journal commit state did not match its expected phase".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precommit_trigger_accepts_only_regular_files_or_absence() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state");
        assert!(!regular_file_present(&path, "fixture").unwrap());
        fs::write(&path, b"state").unwrap();
        assert!(regular_file_present(&path, "fixture").unwrap());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(regular_file_present(&path, "fixture").is_err());
    }

    #[test]
    fn uninstall_journal_parser_distinguishes_pre_and_post_cutover() {
        let receipt_hash = "1".repeat(64);
        let file_hash = "2".repeat(64);
        let mut files = super::super::StressFileTable::new();
        files.insert(STRESS_PUBLISHED_FILE.into(), (16, file_hash.clone(), false));
        let header = json!({
            "kind": "header",
            "format_version": 4,
            "operation": "uninstall",
            "package_id": STRESS_PACKAGE_ID,
            "directory": STRESS_INSTALL_DIRECTORY,
            "install_base": {
                "canonical_path_sha256": "3".repeat(64),
                "filesystem_id": 1,
                "file_id": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            },
            "scope": "user",
            "previous_receipt_sha256": receipt_hash,
        });
        let restore = json!({
            "kind": "restore_file",
            "path": STRESS_PUBLISHED_FILE,
            "sha256": file_hash,
            "executable": false,
        });
        let prefix = format!("{}\n{}\n", header, restore);
        assert!(
            validate_uninstall_journal(prefix.as_bytes(), &files, &"1".repeat(64), false).is_ok()
        );
        assert!(
            validate_uninstall_journal(prefix.as_bytes(), &files, &"1".repeat(64), true).is_err()
        );
        let committed = format!("{}{}\n", prefix, json!({"kind": "committing"}));
        assert!(
            validate_uninstall_journal(committed.as_bytes(), &files, &"1".repeat(64), false)
                .is_err()
        );
        assert!(
            validate_uninstall_journal(committed.as_bytes(), &files, &"1".repeat(64), true).is_ok()
        );
    }

    #[test]
    fn not_installed_result_is_exact() {
        let message = json!({
            "protocolVersion": luxury_spec::JSONL_PROTOCOL_VERSION,
            "type": "result",
            "id": "uninstall_post_cutover_recovery",
            "result": {
                "status": "notInstalled",
                "packageId": STRESS_PACKAGE_ID,
            },
        });
        assert!(validate_not_installed_result(&message, "uninstall_post_cutover_recovery").is_ok());
        let mut extra = message;
        extra["result"]["removedFiles"] = 0.into();
        assert!(validate_not_installed_result(&extra, "uninstall_post_cutover_recovery").is_err());
    }
}
