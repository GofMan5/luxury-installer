use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};

use super::super::{sha256_hex, staging::sha256_file};
use super::{
    HostLayout, InstallProbeEvent, LifecycleSession, STRESS_INSTALL_DIRECTORY, STRESS_PACKAGE_ID,
    STRESS_PUBLISHED_FILE, StressPackage, UninstallProbeEvent, backend_error_code, consume_install,
    consume_uninstall, directory_entry_names, exact_keys, inspect_stress_fixture,
    is_link_or_reparse, is_lower_hex_64, lifecycle_timeout, message_kind, object_string,
    parse_install_event, parse_uninstall_event, path_absent, request_stress_install,
    require_empty_probe_root, require_only_lifecycle_lock_state, require_regular,
    require_stress_published_file, start_stress_install, strict_result, unicode_path,
    validate_install_action_against_inspect, validate_install_against_inspect, value_object,
};

mod uninstall;
pub(crate) use uninstall::probe_uninstall_precommit_crash_recovery;

const MAX_CRASH_JOURNAL_BYTES: u64 = 2 * 1024 * 1024;
const MAX_STRESS_TREE_ENTRIES: usize = 4_096;
const MAX_STRESS_RECEIPT_BYTES: u64 = 1024 * 1024;
type TreeSnapshot = BTreeMap<PathBuf, Option<(u64, [u8; 32], bool)>>;
type StressFileTable = BTreeMap<String, (u64, String, bool)>;

#[derive(Clone, Copy)]
enum CrashOperation {
    Install,
    Uninstall,
}

#[derive(Clone, Copy)]
struct PendingUpgrade<'a> {
    applied_bytes: u64,
    upgrade_hash: [u8; 32],
    upgrade_executable: bool,
    base_hash: [u8; 32],
    base_executable: bool,
    base_receipt: &'a [u8],
    base_receipt_hash: [u8; 32],
}

pub(crate) fn probe_crash_recovery(
    backend: &Path,
    fixture: StressPackage<'_>,
    host: HostLayout,
    probe_root: &Path,
) -> Result<(), String> {
    let StressPackage {
        package,
        source_payload,
        expected,
    } = fixture;
    if !backend.is_absolute() || !package.is_absolute() || !source_payload.is_absolute() {
        return Err("recovery backend and payload must be absolute paths".into());
    }
    require_empty_probe_root(probe_root)?;
    directory_entry_names(source_payload, "source stress payload")?;
    let expected_applied_hash = sha256_file(&source_payload.join(STRESS_PUBLISHED_FILE))?;
    let package_path = unicode_path(package, "recovery payload")?;
    let install_base = probe_root.join("install");
    let state_root = probe_root.join("state");

    let (crashed_inspect, journal_prefix) = LifecycleSession::start(backend)?.run_crashed(
        "crash_install",
        CrashOperation::Install,
        |session| {
            let inspect = inspect_stress_fixture(
                session,
                package_path,
                host,
                "crash_inspect",
                expected.files,
                expected.bytes,
            )?;
            let progress = start_stress_install(
                session,
                "crash_install",
                package_path,
                &install_base,
                &state_root,
                &inspect,
                expected,
            )?;
            if progress.total_files != Some(inspect.payload_files)
                || progress.total_bytes != Some(inspect.payload_bytes)
                || progress.completed_files == 0
            {
                return Err("pre-crash progress did not match the payload".into());
            }
            let journal_prefix = require_pending_crash_state(
                &install_base,
                &state_root,
                expected.applied_bytes,
                expected_applied_hash,
                expected.executable,
            )?;
            Ok((inspect, journal_prefix))
        },
    )?;

    let post_crash_journal = require_pending_crash_state(
        &install_base,
        &state_root,
        expected.applied_bytes,
        expected_applied_hash,
        expected.executable,
    )?;
    if !post_crash_journal.starts_with(&journal_prefix) {
        return Err("pending journal changed its durable pre-crash prefix".into());
    }
    let install_base_text = unicode_path(&install_base, "recovery install root")?;
    let state_root_text = unicode_path(&state_root, "recovery state root")?;
    let installed = LifecycleSession::start(backend)?.run(|session| {
        let inspect = inspect_stress_fixture(
            session,
            package_path,
            host,
            "recovery_inspect",
            expected.files,
            expected.bytes,
        )?;
        if inspect != crashed_inspect {
            return Err("fresh backend inspected a different recovery payload".into());
        }
        require_recovery_prepare(
            session,
            package_path,
            install_base_text,
            state_root_text,
            &inspect.fingerprint,
        )?;
        session.request(
            "recovery_install",
            "install",
            json!({
                "packagePath": package_path,
                "installBase": install_base_text,
                "stateRoot": state_root_text,
                "allowUnsigned": true,
                "allowPublisherMigration": false,
                "expectedFingerprint": inspect.fingerprint,
            }),
        )?;
        let installed = consume_install(session, "recovery_install")?;
        validate_install_against_inspect(&inspect, &installed)?;
        Ok(installed)
    })?;
    verify_exact_tree(source_payload, &install_base.join(STRESS_INSTALL_DIRECTORY))?;
    require_regular(
        &state_root
            .join("receipts")
            .join(format!("{STRESS_PACKAGE_ID}.json")),
        "recovered ownership receipt",
    )?;
    require_recovered_transaction_absence(&install_base, &state_root)?;

    let removed = LifecycleSession::start(backend)?.run(|session| {
        session.request(
            "recovery_uninstall",
            "uninstall",
            json!({
                "packageId": STRESS_PACKAGE_ID,
                "installBase": install_base_text,
                "stateRoot": state_root_text,
            }),
        )?;
        consume_uninstall(session, "recovery_uninstall")
    })?;
    if removed.package_id != STRESS_PACKAGE_ID
        || removed.removed_files != installed.installed_files
        || removed.missing_files != 0
        || removed.preserved_modified_files != 0
    {
        return Err("recovered package uninstall counts were inconsistent".into());
    }

    require_recovery_cleanup(&install_base, &state_root)?;
    Ok(())
}

pub(crate) fn probe_upgrade_crash_recovery(
    backend: &Path,
    base: StressPackage<'_>,
    upgrade: StressPackage<'_>,
    barrier: StressPackage<'_>,
    host: HostLayout,
    probe_root: &Path,
) -> Result<(), String> {
    for path in [
        backend,
        base.package,
        base.source_payload,
        upgrade.package,
        upgrade.source_payload,
        barrier.package,
    ] {
        if !path.is_absolute() {
            return Err("upgrade recovery inputs must be absolute paths".into());
        }
    }
    require_empty_probe_root(probe_root)?;
    let base_large_hash = sha256_file(&base.source_payload.join(STRESS_PUBLISHED_FILE))?;
    let upgrade_large_hash = sha256_file(&upgrade.source_payload.join(STRESS_PUBLISHED_FILE))?;
    if base_large_hash == upgrade_large_hash {
        return Err("upgrade stress payload did not change its anchor file".into());
    }
    let base_package = unicode_path(base.package, "base upgrade payload")?;
    let upgrade_package = unicode_path(upgrade.package, "replacement upgrade payload")?;
    let barrier_package = unicode_path(barrier.package, "downgrade barrier payload")?;
    let install_base = probe_root.join("install");
    let state_root = probe_root.join("state");

    let base_inspect = LifecycleSession::start(backend)?.run(|session| {
        let inspect = inspect_stress_fixture(
            session,
            base_package,
            host,
            "upgrade_base_inspect",
            base.expected.files,
            base.expected.bytes,
        )?;
        if inspect.package_version != "1.0.0" {
            return Err("base upgrade fixture has an unexpected version".into());
        }
        request_stress_install(
            session,
            "upgrade_base_install",
            base_package,
            &install_base,
            &state_root,
            &inspect,
        )?;
        let installed = consume_install(session, "upgrade_base_install")?;
        validate_install_action_against_inspect(&inspect, &installed, "install")?;
        Ok(inspect)
    })?;
    verify_exact_tree(
        base.source_payload,
        &install_base.join(STRESS_INSTALL_DIRECTORY),
    )?;
    require_regular(&receipt_path(&state_root), "base upgrade receipt")?;
    require_recovered_transaction_absence(&install_base, &state_root)?;
    let base_receipt = read_stress_receipt(&state_root)?;
    validate_stress_receipt(
        &base_receipt,
        "1.0.0",
        base.source_payload,
        base.expected.executable,
    )?;
    let base_receipt_hash = sha256_file(&receipt_path(&state_root))?;

    let (upgrade_inspect, journal_prefix) = LifecycleSession::start(backend)?.run_crashed(
        "upgrade_crash_install",
        CrashOperation::Install,
        |session| {
            let inspect = inspect_stress_fixture(
                session,
                upgrade_package,
                host,
                "upgrade_crash_inspect",
                upgrade.expected.files,
                upgrade.expected.bytes,
            )?;
            if inspect.package_version != "2.0.0"
                || inspect.package_id != base_inspect.package_id
                || inspect.install_directory != base_inspect.install_directory
                || inspect.fingerprint == base_inspect.fingerprint
            {
                return Err("replacement upgrade fixture identity is invalid".into());
            }
            let progress = start_stress_install(
                session,
                "upgrade_crash_install",
                upgrade_package,
                &install_base,
                &state_root,
                &inspect,
                upgrade.expected,
            )?;
            if progress.total_files != Some(inspect.payload_files)
                || progress.total_bytes != Some(inspect.payload_bytes)
                || progress.completed_files == 0
            {
                return Err("pre-crash upgrade progress did not match the payload".into());
            }
            let journal_prefix = require_pending_upgrade_state(
                &install_base,
                &state_root,
                PendingUpgrade {
                    applied_bytes: upgrade.expected.applied_bytes,
                    upgrade_hash: upgrade_large_hash,
                    upgrade_executable: upgrade.expected.executable,
                    base_hash: base_large_hash,
                    base_executable: base.expected.executable,
                    base_receipt: &base_receipt,
                    base_receipt_hash,
                },
            )?;
            Ok((inspect, journal_prefix))
        },
    )?;

    let post_crash_journal = require_pending_upgrade_state(
        &install_base,
        &state_root,
        PendingUpgrade {
            applied_bytes: upgrade.expected.applied_bytes,
            upgrade_hash: upgrade_large_hash,
            upgrade_executable: upgrade.expected.executable,
            base_hash: base_large_hash,
            base_executable: base.expected.executable,
            base_receipt: &base_receipt,
            base_receipt_hash,
        },
    )?;
    if !post_crash_journal.starts_with(&journal_prefix) {
        return Err("upgrade journal changed its durable pre-crash prefix".into());
    }

    let install_base_text = unicode_path(&install_base, "upgrade recovery install root")?;
    let state_root_text = unicode_path(&state_root, "upgrade recovery state root")?;
    LifecycleSession::start(backend)?.run(|session| {
        let inspect = inspect_stress_fixture(
            session,
            upgrade_package,
            host,
            "upgrade_recovery_inspect",
            upgrade.expected.files,
            upgrade.expected.bytes,
        )?;
        if inspect != upgrade_inspect {
            return Err("fresh backend inspected a different upgrade payload".into());
        }
        require_recovery_prepare(
            session,
            upgrade_package,
            install_base_text,
            state_root_text,
            &inspect.fingerprint,
        )?;

        let barrier_inspect = inspect_stress_fixture(
            session,
            barrier_package,
            host,
            "upgrade_barrier_inspect",
            barrier.expected.files,
            barrier.expected.bytes,
        )?;
        if barrier_inspect.package_version != "0.9.0"
            || barrier_inspect.package_id != base_inspect.package_id
            || barrier_inspect.install_directory != base_inspect.install_directory
        {
            return Err("downgrade recovery barrier identity is invalid".into());
        }
        request_stress_install(
            session,
            "upgrade_recovery_barrier",
            barrier_package,
            &install_base,
            &state_root,
            &barrier_inspect,
        )?;
        consume_expected_install_error(session, "upgrade_recovery_barrier", "downgrade_denied")?;
        Ok(())
    })?;
    verify_exact_tree(
        base.source_payload,
        &install_base.join(STRESS_INSTALL_DIRECTORY),
    )?;
    if read_stress_receipt(&state_root)? != base_receipt {
        return Err("upgrade recovery did not restore the exact base receipt".into());
    }
    require_recovered_transaction_absence(&install_base, &state_root)?;

    let installed = LifecycleSession::start(backend)?.run(|session| {
        let inspect = inspect_stress_fixture(
            session,
            upgrade_package,
            host,
            "upgrade_retry_inspect",
            upgrade.expected.files,
            upgrade.expected.bytes,
        )?;
        if inspect != upgrade_inspect {
            return Err("retry backend inspected a different upgrade payload".into());
        }
        require_ready_prepare(
            session,
            upgrade_package,
            install_base_text,
            state_root_text,
            &inspect.fingerprint,
            "update",
            "1.0.0",
        )?;

        request_stress_install(
            session,
            "upgrade_recovery_install",
            upgrade_package,
            &install_base,
            &state_root,
            &inspect,
        )?;
        let installed = consume_install(session, "upgrade_recovery_install")?;
        validate_install_action_against_inspect(&inspect, &installed, "update")?;
        Ok(installed)
    })?;
    verify_exact_tree(
        upgrade.source_payload,
        &install_base.join(STRESS_INSTALL_DIRECTORY),
    )?;
    let upgrade_receipt = read_stress_receipt(&state_root)?;
    validate_stress_receipt(
        &upgrade_receipt,
        "2.0.0",
        upgrade.source_payload,
        upgrade.expected.executable,
    )?;
    if upgrade_receipt == base_receipt {
        return Err("completed upgrade kept the base ownership receipt".into());
    }
    require_recovered_transaction_absence(&install_base, &state_root)?;

    let removed = LifecycleSession::start(backend)?.run(|session| {
        require_ready_prepare(
            session,
            upgrade_package,
            install_base_text,
            state_root_text,
            &upgrade_inspect.fingerprint,
            "repair",
            "2.0.0",
        )?;

        session.request(
            "upgrade_recovery_uninstall",
            "uninstall",
            json!({
                "packageId": STRESS_PACKAGE_ID,
                "installBase": install_base_text,
                "stateRoot": state_root_text,
            }),
        )?;
        consume_uninstall(session, "upgrade_recovery_uninstall")
    })?;
    if removed.package_id != STRESS_PACKAGE_ID
        || removed.removed_files != installed.installed_files
        || removed.missing_files != 0
        || removed.preserved_modified_files != 0
    {
        return Err("recovered upgrade uninstall counts were inconsistent".into());
    }

    require_recovery_cleanup(&install_base, &state_root)
}

fn require_pending_crash_state(
    install_base: &Path,
    state_root: &Path,
    expected_applied_bytes: u64,
    expected_applied_hash: [u8; 32],
    expected_executable: bool,
) -> Result<Vec<u8>, String> {
    require_stress_published_hash(
        install_base,
        expected_applied_bytes,
        expected_applied_hash,
        expected_executable,
    )?;
    let receipt = state_root
        .join("receipts")
        .join(format!("{STRESS_PACKAGE_ID}.json"));
    if !path_absent(&receipt, "pre-crash ownership receipt")? {
        return Err("stress install committed before the deliberate crash".into());
    }
    let transaction = state_root.join("transactions").join(STRESS_PACKAGE_ID);
    let transaction_entries = directory_entry_names(&transaction, "pending crash transaction")?;
    if !transaction_entries
        .iter()
        .any(|name| name == "journal.jsonl")
    {
        return Err("pending crash transaction has no journal".into());
    }
    let journal = transaction.join("journal.jsonl");
    let journal_prefix = read_crash_journal_prefix(&journal, expected_applied_hash)?;
    let destination_transaction = install_base.join(format!(".luxury-tx-{STRESS_PACKAGE_ID}"));
    directory_entry_names(&destination_transaction, "pending destination transaction")?;
    Ok(journal_prefix)
}

fn require_pending_upgrade_state(
    install_base: &Path,
    state_root: &Path,
    expected: PendingUpgrade<'_>,
) -> Result<Vec<u8>, String> {
    require_stress_published_hash(
        install_base,
        expected.applied_bytes,
        expected.upgrade_hash,
        expected.upgrade_executable,
    )?;
    if read_stress_receipt(state_root)? != expected.base_receipt {
        return Err("pending upgrade changed the live base receipt".into());
    }
    let transaction = state_root.join("transactions").join(STRESS_PACKAGE_ID);
    let entries = directory_entry_names(&transaction, "pending upgrade transaction")?;
    if !entries.iter().any(|name| name == "journal.jsonl")
        || entries.iter().any(|name| {
            matches!(
                name.as_str(),
                "journal.done" | "receipt.pending" | "receipt.previous"
            )
        })
    {
        return Err("pending upgrade transaction has an invalid pre-commit shape".into());
    }
    let journal = read_bounded_journal_prefix(&transaction.join("journal.jsonl"))?;
    validate_upgrade_journal_prefix(
        &journal,
        expected.upgrade_hash,
        expected.base_hash,
        expected.base_receipt_hash,
        expected.base_executable,
    )?;
    let destination = install_base.join(format!(".luxury-tx-{STRESS_PACKAGE_ID}"));
    directory_entry_names(&destination, "pending upgrade destination transaction")?;
    require_regular_hash(
        &destination.join("removed").join(STRESS_PUBLISHED_FILE),
        expected.applied_bytes,
        expected.base_hash,
        expected.base_executable,
        "pending upgrade backup",
    )?;
    Ok(journal)
}

fn validate_upgrade_journal_prefix(
    prefix: &[u8],
    upgrade_hash: [u8; 32],
    base_hash: [u8; 32],
    base_receipt_hash: [u8; 32],
    base_executable: bool,
) -> Result<(), String> {
    let upgrade_hash = sha256_hex(upgrade_hash);
    let base_hash = sha256_hex(base_hash);
    let base_receipt_hash = sha256_hex(base_receipt_hash);
    let mut stage_index = None;
    let mut restore_index = None;
    let mut remove_index = None;
    for (index, line) in prefix
        .strip_suffix(b"\n")
        .ok_or_else(|| "pending upgrade journal prefix is not terminated".to_owned())?
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if line.is_empty() {
            return Err("pending upgrade journal contains an empty record".into());
        }
        let record: Value = serde_json::from_slice(line)
            .map_err(|_| "pending upgrade journal contains invalid JSON".to_owned())?;
        let fields = value_object(&record, "upgrade journal record")?;
        let kind = object_string(fields, "kind", "upgrade journal kind")?;
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
                "upgrade journal header",
            )?;
            if kind != "header"
                || fields.get("format_version").and_then(Value::as_u64) != Some(4)
                || fields.get("operation").and_then(Value::as_str) != Some("upgrade")
                || fields.get("package_id").and_then(Value::as_str) != Some(STRESS_PACKAGE_ID)
                || fields.get("directory").and_then(Value::as_str) != Some(STRESS_INSTALL_DIRECTORY)
                || fields.get("scope").and_then(Value::as_str) != Some("user")
                || fields
                    .get("previous_receipt_sha256")
                    .and_then(Value::as_str)
                    != Some(base_receipt_hash.as_str())
            {
                return Err("pending upgrade journal has an invalid header".into());
            }
            validate_install_base_identity(
                fields
                    .get("install_base")
                    .ok_or_else(|| "upgrade journal header has no install base".to_owned())?,
            )?;
            continue;
        }
        match kind {
            "remove_directory" => {
                exact_keys(fields, &["kind", "path"], "upgrade directory record")?;
                if !fields
                    .get("path")
                    .is_some_and(|path| path.is_null() || path.is_string())
                {
                    return Err("pending upgrade journal has an invalid directory record".into());
                }
            }
            "stage_file" | "remove_file" => {
                exact_keys(fields, &["kind", "path", "sha256"], "upgrade file record")?;
                let path = object_string(fields, "path", "upgrade journal path")?;
                let sha256 = object_string(fields, "sha256", "upgrade journal hash")?;
                if !is_lower_hex_64(sha256) {
                    return Err("pending upgrade journal has an invalid file hash".into());
                }
                if path == STRESS_PUBLISHED_FILE && sha256 == upgrade_hash {
                    if kind == "stage_file" {
                        stage_index.get_or_insert(index);
                    } else {
                        remove_index.get_or_insert(index);
                    }
                }
            }
            "restore_file" => {
                exact_keys(
                    fields,
                    &["kind", "path", "sha256", "executable"],
                    "upgrade restore record",
                )?;
                let path = object_string(fields, "path", "upgrade restore path")?;
                let sha256 = object_string(fields, "sha256", "upgrade restore hash")?;
                if !is_lower_hex_64(sha256)
                    || !fields.get("executable").is_some_and(Value::is_boolean)
                {
                    return Err("pending upgrade journal has an invalid restore record".into());
                }
                if path == STRESS_PUBLISHED_FILE
                    && sha256 == base_hash
                    && fields.get("executable").and_then(Value::as_bool) == Some(base_executable)
                {
                    restore_index.get_or_insert(index);
                }
            }
            "header" | "pending_receipt" | "committing" | "rolling_back" => {
                return Err("pending upgrade journal advanced beyond the expected prefix".into());
            }
            _ => return Err("pending upgrade journal contains an unknown record".into()),
        }
    }
    if !matches!(
        (stage_index, restore_index, remove_index),
        (Some(stage), Some(restore), Some(remove)) if stage < restore && restore < remove
    ) {
        return Err("pending upgrade journal does not bind the replacement transition".into());
    }
    Ok(())
}

fn receipt_path(state_root: &Path) -> PathBuf {
    state_root
        .join("receipts")
        .join(format!("{STRESS_PACKAGE_ID}.json"))
}

fn read_stress_receipt(state_root: &Path) -> Result<Vec<u8>, String> {
    let path = receipt_path(state_root);
    read_bounded_stress_receipt(&path, "stress ownership receipt")
}

fn read_bounded_stress_receipt(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    require_regular(path, label)?;
    let length = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {label}: {error}"))?
        .len();
    if length == 0 || length > MAX_STRESS_RECEIPT_BYTES {
        return Err(format!("{label} has an invalid size"));
    }
    let bytes = fs::read(path).map_err(|error| format!("could not read {label}: {error}"))?;
    if bytes.len() as u64 != length {
        return Err(format!("{label} changed while reading"));
    }
    Ok(bytes)
}

fn validate_stress_receipt(
    bytes: &[u8],
    expected_version: &str,
    source_payload: &Path,
    expected_published_executable: bool,
) -> Result<(), String> {
    let stored: Value = serde_json::from_slice(bytes)
        .map_err(|_| "stress ownership receipt is not valid JSON".to_owned())?;
    let outer = value_object(&stored, "stored ownership receipt")?;
    exact_keys(
        outer,
        &["format_version", "install_base", "receipt"],
        "stored ownership receipt",
    )?;
    if outer.get("format_version").and_then(Value::as_u64) != Some(2) {
        return Err("stored ownership receipt has an invalid format".into());
    }
    validate_install_base_identity(
        outer
            .get("install_base")
            .ok_or_else(|| "stored receipt has no install-base identity".to_owned())?,
    )?;
    let receipt = value_object(
        outer
            .get("receipt")
            .ok_or_else(|| "stored receipt has no ownership body".to_owned())?,
        "ownership receipt",
    )?;
    exact_keys(
        receipt,
        &[
            "format_version",
            "package_id",
            "version",
            "scope",
            "directory",
            "authorized_publisher",
            "payload_signer",
            "files",
        ],
        "ownership receipt",
    )?;
    if receipt.get("format_version").and_then(Value::as_u64) != Some(4)
        || receipt.get("package_id").and_then(Value::as_str) != Some(STRESS_PACKAGE_ID)
        || receipt.get("version").and_then(Value::as_str) != Some(expected_version)
        || receipt.get("scope").and_then(Value::as_str) != Some("user")
        || receipt.get("directory").and_then(Value::as_str) != Some(STRESS_INSTALL_DIRECTORY)
    {
        return Err("ownership receipt has an invalid package identity".into());
    }
    for field in ["authorized_publisher", "payload_signer"] {
        let identity = value_object(
            receipt
                .get(field)
                .ok_or_else(|| "ownership receipt has no publisher identity".to_owned())?,
            "publisher identity",
        )?;
        exact_keys(identity, &["kind"], "publisher identity")?;
        if identity.get("kind").and_then(Value::as_str) != Some("unsigned") {
            return Err("ownership receipt has an unexpected publisher identity".into());
        }
    }

    let expected_files = stress_file_table(source_payload, expected_published_executable)?;
    let files = receipt
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| "ownership receipt has no file table".to_owned())?;
    let mut actual_files = BTreeMap::new();
    for file in files {
        let fields = value_object(file, "ownership file entry")?;
        exact_keys(
            fields,
            &["path", "size", "sha256", "executable"],
            "ownership file entry",
        )?;
        let path = object_string(fields, "path", "ownership file path")?;
        let size = fields
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| "ownership file entry has no size".to_owned())?;
        let hash = object_string(fields, "sha256", "ownership file hash")?;
        let executable = fields
            .get("executable")
            .and_then(Value::as_bool)
            .ok_or_else(|| "ownership file entry has no executable flag".to_owned())?;
        if !is_lower_hex_64(hash)
            || actual_files
                .insert(path.to_owned(), (size, hash.to_owned(), executable))
                .is_some()
        {
            return Err("ownership receipt has an invalid file entry".into());
        }
    }
    if actual_files != expected_files {
        return Err("ownership receipt file table does not match the source payload".into());
    }
    Ok(())
}

fn stress_file_table(
    source_payload: &Path,
    expected_published_executable: bool,
) -> Result<StressFileTable, String> {
    let mut expected_files = BTreeMap::new();
    for (path, entry) in snapshot_tree(source_payload, "receipt source tree")? {
        let Some((size, hash, source_executable)) = entry else {
            continue;
        };
        let expected_executable =
            path == Path::new(STRESS_PUBLISHED_FILE) && expected_published_executable;
        if source_executable != expected_executable {
            return Err("stress source executable mode does not match its fixture".into());
        }
        let path = path
            .to_str()
            .ok_or_else(|| "receipt source tree contains a non-Unicode path".to_owned())?
            .replace('\\', "/");
        expected_files.insert(path, (size, sha256_hex(hash), expected_executable));
    }
    Ok(expected_files)
}

fn require_regular_hash(
    path: &Path,
    expected_bytes: u64,
    expected_hash: [u8; 32],
    expected_executable: bool,
    label: &str,
) -> Result<(), String> {
    require_regular(path, label)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {label}: {error}"))?;
    if metadata.len() != expected_bytes
        || sha256_file(path)? != expected_hash
        || metadata_executable(&metadata) != expected_executable
    {
        return Err(format!("{label} did not match its expected contents"));
    }
    Ok(())
}

fn read_crash_journal_prefix(path: &Path, expected_hash: [u8; 32]) -> Result<Vec<u8>, String> {
    let prefix = read_bounded_journal_prefix(path)?;
    validate_crash_journal_prefix(&prefix, expected_hash)?;
    Ok(prefix)
}

fn read_bounded_journal_prefix(path: &Path) -> Result<Vec<u8>, String> {
    require_regular(path, "pending crash journal")?;
    let length = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect pending crash journal: {error}"))?
        .len();
    if length == 0 || length > MAX_CRASH_JOURNAL_BYTES {
        return Err("pending crash journal has an invalid size".into());
    }
    let bytes =
        fs::read(path).map_err(|error| format!("could not read pending journal: {error}"))?;
    if bytes.len() as u64 > MAX_CRASH_JOURNAL_BYTES {
        return Err("pending crash journal exceeded its probe limit".into());
    }
    let end = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or_else(|| "pending crash journal has no complete record".to_owned())?;
    let prefix = bytes[..=end].to_vec();
    Ok(prefix)
}

fn validate_crash_journal_prefix(prefix: &[u8], expected_hash: [u8; 32]) -> Result<(), String> {
    let expected_hash = sha256_hex(expected_hash);
    let mut stage_index = None;
    let mut remove_index = None;
    for (index, line) in prefix
        .strip_suffix(b"\n")
        .ok_or_else(|| "pending crash journal prefix is not terminated".to_owned())?
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if line.is_empty() {
            return Err("pending crash journal contains an empty record".into());
        }
        let record: Value = serde_json::from_slice(line)
            .map_err(|_| "pending crash journal contains invalid JSON".to_owned())?;
        let fields = value_object(&record, "crash journal record")?;
        let kind = object_string(fields, "kind", "crash journal kind")?;
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
                ],
                "crash journal header",
            )?;
            if kind != "header"
                || fields.get("format_version").and_then(Value::as_u64) != Some(4)
                || fields.get("operation").and_then(Value::as_str) != Some("install")
                || fields.get("package_id").and_then(Value::as_str) != Some(STRESS_PACKAGE_ID)
                || fields.get("directory").and_then(Value::as_str) != Some(STRESS_INSTALL_DIRECTORY)
                || fields.get("scope").and_then(Value::as_str) != Some("user")
            {
                return Err("pending crash journal has an invalid header".into());
            }
            validate_install_base_identity(
                fields
                    .get("install_base")
                    .ok_or_else(|| "crash journal header has no install base".to_owned())?,
            )?;
            continue;
        }
        match kind {
            "remove_directory" => {
                exact_keys(fields, &["kind", "path"], "remove-directory record")?;
                if !fields
                    .get("path")
                    .is_some_and(|path| path.is_null() || path.is_string())
                {
                    return Err("pending crash journal has an invalid directory record".into());
                }
            }
            "stage_file" | "remove_file" => {
                exact_keys(fields, &["kind", "path", "sha256"], "file journal record")?;
                let path = object_string(fields, "path", "journal file path")?;
                let sha256 = object_string(fields, "sha256", "journal file hash")?;
                if !is_lower_hex_64(sha256) {
                    return Err("pending crash journal has an invalid file hash".into());
                }
                if path == STRESS_PUBLISHED_FILE && sha256 == expected_hash {
                    if kind == "stage_file" {
                        stage_index.get_or_insert(index);
                    } else {
                        remove_index.get_or_insert(index);
                    }
                }
            }
            "header" | "pending_receipt" | "committing" | "rolling_back" | "restore_file" => {
                return Err(
                    "pending crash journal advanced beyond the expected install prefix".into(),
                );
            }
            _ => return Err("pending crash journal contains an unknown record".into()),
        }
    }
    if !matches!((stage_index, remove_index), (Some(stage), Some(remove)) if stage < remove) {
        return Err("pending crash journal does not bind the published stress file".into());
    }
    Ok(())
}

fn validate_install_base_identity(value: &Value) -> Result<(), String> {
    let fields = value_object(value, "install-base identity")?;
    exact_keys(
        fields,
        &["canonical_path_sha256", "filesystem_id", "file_id"],
        "install-base identity",
    )?;
    if !fields
        .get("canonical_path_sha256")
        .and_then(Value::as_str)
        .is_some_and(is_lower_hex_64)
        || fields
            .get("filesystem_id")
            .and_then(Value::as_u64)
            .is_none()
        || !fields
            .get("file_id")
            .and_then(Value::as_array)
            .is_some_and(|bytes| {
                bytes.len() == 16
                    && bytes
                        .iter()
                        .all(|byte| byte.as_u64().is_some_and(|byte| byte <= u64::from(u8::MAX)))
            })
    {
        return Err("pending crash journal has an invalid install-base identity".into());
    }
    Ok(())
}

fn require_stress_published_hash(
    install_base: &Path,
    expected_bytes: u64,
    expected_hash: [u8; 32],
    expected_executable: bool,
) -> Result<(), String> {
    require_stress_published_file(install_base, expected_bytes)?;
    let published = install_base
        .join(STRESS_INSTALL_DIRECTORY)
        .join(STRESS_PUBLISHED_FILE);
    let metadata = fs::symlink_metadata(&published)
        .map_err(|error| format!("could not inspect published stress file: {error}"))?;
    if sha256_file(&published)? != expected_hash
        || metadata_executable(&metadata) != expected_executable
    {
        return Err("published stress file did not match its source".into());
    }
    Ok(())
}

fn require_recovery_prepare(
    session: &mut LifecycleSession,
    package_path: &str,
    install_base: &str,
    state_root: &str,
    fingerprint: &str,
) -> Result<(), String> {
    session.request(
        "recovery_prepare",
        "prepareInstall",
        json!({
            "packagePath": package_path,
            "installBase": install_base,
            "stateRoot": state_root,
            "expectedFingerprint": fingerprint,
        }),
    )?;
    let message = session.next_required("recovery preparation")?;
    let result = strict_result(&message, "recovery_prepare", "recovery preparation")?;
    let fields = value_object(result, "recovery preparation result")?;
    exact_keys(fields, &["status"], "recovery preparation result")?;
    if fields.get("status").and_then(Value::as_str) != Some("recoveryRequired") {
        return Err("fresh backend did not detect required crash recovery".into());
    }
    Ok(())
}

fn consume_expected_install_error(
    session: &mut LifecycleSession,
    request_id: &str,
    expected_code: &str,
) -> Result<(), String> {
    let mut phases = Vec::new();
    loop {
        let message = session.next_required("recovery barrier")?;
        match message_kind(&message, request_id)? {
            "event" => match parse_install_event(&message, request_id)? {
                InstallProbeEvent::Phase(phase) => phases.push(phase),
                InstallProbeEvent::Action(_) | InstallProbeEvent::Progress(_) => {
                    return Err("downgrade barrier reached a mutating install event".into());
                }
            },
            "error" => {
                if backend_error_code(&message, request_id)? != expected_code
                    || phases
                        != [
                            "validating",
                            "verifying",
                            "recovering",
                            "planning",
                            "failed",
                        ]
                {
                    return Err("downgrade barrier returned an unexpected terminal path".into());
                }
                return Ok(());
            }
            "result" => return Err("downgrade barrier unexpectedly installed a package".into()),
            _ => unreachable!("message kind is validated"),
        }
    }
}

fn require_ready_prepare(
    session: &mut LifecycleSession,
    package_path: &str,
    install_base: &str,
    state_root: &str,
    fingerprint: &str,
    expected_action: &str,
    expected_version: &str,
) -> Result<(), String> {
    let request_id = match expected_action {
        "update" => "upgrade_ready_prepare",
        "repair" => "repair_ready_prepare",
        _ => return Err("ready preparation expected an unsupported action".into()),
    };
    session.request(
        request_id,
        "prepareInstall",
        json!({
            "packagePath": package_path,
            "installBase": install_base,
            "stateRoot": state_root,
            "expectedFingerprint": fingerprint,
        }),
    )?;
    let message = session.next_required("ready preparation")?;
    let result = strict_result(&message, request_id, "ready preparation")?;
    let fields = value_object(result, "ready preparation result")?;
    exact_keys(
        fields,
        &[
            "status",
            "action",
            "installedVersion",
            "publisherMigrationRequired",
        ],
        "ready preparation result",
    )?;
    if fields.get("status").and_then(Value::as_str) != Some("ready")
        || fields.get("action").and_then(Value::as_str) != Some(expected_action)
        || fields.get("installedVersion").and_then(Value::as_str) != Some(expected_version)
        || fields
            .get("publisherMigrationRequired")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("ready preparation did not match the recovered installation".into());
    }
    Ok(())
}

fn require_recovered_transaction_absence(
    install_base: &Path,
    state_root: &Path,
) -> Result<(), String> {
    for (path, label) in [
        (
            state_root.join("transactions").join(STRESS_PACKAGE_ID),
            "recovery transaction",
        ),
        (
            install_base.join(format!(".luxury-tx-{STRESS_PACKAGE_ID}")),
            "recovery destination transaction",
        ),
    ] {
        if !path_absent(&path, label)? {
            return Err(format!("{label} remained after the recovered install"));
        }
    }
    Ok(())
}

fn verify_exact_tree(source: &Path, installed: &Path) -> Result<(), String> {
    if snapshot_tree(source, "source stress tree")?
        != snapshot_tree(installed, "installed stress tree")?
    {
        return Err("recovered installation does not exactly match its source payload".into());
    }
    Ok(())
}

fn snapshot_tree(root: &Path, label: &str) -> Result<TreeSnapshot, String> {
    directory_entry_names(root, label)?;
    let mut snapshot = BTreeMap::new();
    let mut pending = vec![(root.to_path_buf(), PathBuf::new())];
    while let Some((directory, relative)) = pending.pop() {
        for entry in
            fs::read_dir(&directory).map_err(|error| format!("could not read {label}: {error}"))?
        {
            let entry = entry.map_err(|error| format!("could not read {label} entry: {error}"))?;
            let path = entry.path();
            let child = relative.join(entry.file_name());
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("could not inspect {label} entry: {error}"))?;
            if is_link_or_reparse(&metadata) {
                return Err(format!("{label} contains a link or reparse point"));
            }
            if snapshot.len() >= MAX_STRESS_TREE_ENTRIES {
                return Err(format!("{label} exceeds the entry limit"));
            }
            if metadata.is_dir() {
                snapshot.insert(child.clone(), None);
                pending.push((path, child));
            } else if metadata.is_file() {
                let length = metadata.len();
                let executable = metadata_executable(&metadata);
                let hash = sha256_file(&path)?;
                let after = fs::symlink_metadata(&path)
                    .map_err(|error| format!("could not recheck {label} entry: {error}"))?;
                if is_link_or_reparse(&after)
                    || !after.is_file()
                    || after.len() != length
                    || metadata_executable(&after) != executable
                {
                    return Err(format!("{label} changed while hashing"));
                }
                snapshot.insert(child, Some((length, hash, executable)));
            } else {
                return Err(format!("{label} contains a special filesystem entry"));
            }
        }
    }
    Ok(snapshot)
}

#[cfg(unix)]
fn metadata_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn metadata_executable(_: &fs::Metadata) -> bool {
    false
}

fn require_recovery_cleanup(install_base: &Path, state_root: &Path) -> Result<(), String> {
    let install_root = install_base.join(STRESS_INSTALL_DIRECTORY);
    let receipt = state_root
        .join("receipts")
        .join(format!("{STRESS_PACKAGE_ID}.json"));
    let transaction = state_root.join("transactions").join(STRESS_PACKAGE_ID);
    let destination_transaction = install_base.join(format!(".luxury-tx-{STRESS_PACKAGE_ID}"));
    for (path, label) in [
        (&install_root, "recovered install payload"),
        (&receipt, "recovered install receipt"),
        (&transaction, "recovered install transaction"),
        (
            &destination_transaction,
            "recovered destination transaction",
        ),
    ] {
        if !path_absent(path, label)? {
            return Err(format!("lifecycle {label} remained after uninstall"));
        }
    }
    require_only_lifecycle_lock_state(install_base, state_root)
}

impl LifecycleSession {
    fn run_crashed<T>(
        mut self,
        active_id: &str,
        crash_operation: CrashOperation,
        operation: impl FnOnce(&mut LifecycleSession) -> Result<T, String>,
    ) -> Result<T, String> {
        match operation(&mut self) {
            Ok(value) => self.crash(active_id, crash_operation).map(|()| value),
            Err(error) => Err(self.abort(error)),
        }
    }

    fn crash(mut self, active_id: &str, crash_operation: CrashOperation) -> Result<(), String> {
        let already_exited = self
            .child
            .try_wait()
            .map_err(|error| format!("could not inspect packaged backend before crash: {error}"))?;
        self.reaped = already_exited.is_some();
        let termination = self
            .containment
            .terminate()
            .map_err(|error| format!("lifecycle containment failed: {error}"));
        self.input.take();
        if termination.is_err() && !self.reaped {
            let _ = self.child.kill();
        }
        let status = match already_exited {
            Some(status) => Ok(status),
            None => self
                .child
                .wait()
                .map_err(|error| format!("could not reap crashed packaged backend: {error}")),
        };
        self.reaped = status.is_ok();
        let output = self.drain_crash_output(active_id, crash_operation);
        let stderr_overflow = self.join_stderr();
        let timed_out = self.containment.timed_out();
        self.containment.disarm();
        if let Err(error) = termination {
            return if timed_out {
                Err(format!("{}; {error}", lifecycle_timeout()))
            } else {
                Err(error)
            };
        }
        if timed_out {
            return Err("packaged backend hit the watchdog before the deliberate crash".into());
        }
        if let Some(status) = already_exited {
            return Err(format!(
                "packaged backend exited before the deliberate crash with {status}"
            ));
        }
        output?;
        let status = status?;
        if stderr_overflow? {
            return Err("packaged backend stderr exceeded the lifecycle limit".into());
        }
        require_forced_crash_status(status)?;
        Ok(())
    }

    fn drain_crash_output(
        &mut self,
        active_id: &str,
        crash_operation: CrashOperation,
    ) -> Result<(), String> {
        while let Some(message) = self.output.next_crash_value()? {
            match message_kind(&message, active_id)? {
                "event" => {
                    let phase = match crash_operation {
                        CrashOperation::Install => {
                            match parse_install_event(&message, active_id)? {
                                InstallProbeEvent::Phase(phase) => Some(phase),
                                InstallProbeEvent::Action(_) | InstallProbeEvent::Progress(_) => {
                                    None
                                }
                            }
                        }
                        CrashOperation::Uninstall => {
                            match parse_uninstall_event(&message, active_id)? {
                                UninstallProbeEvent::Phase(phase) => Some(phase),
                                UninstallProbeEvent::Progress(_) => None,
                            }
                        }
                    };
                    if phase.is_some_and(|phase| {
                        matches!(
                            phase.as_str(),
                            "rollingBack" | "cancelled" | "failed" | "completed"
                        )
                    }) {
                        return Err(
                            "packaged operation reached a terminal phase before the hard crash"
                                .into(),
                        );
                    }
                }
                "result" | "error" => {
                    return Err(
                        "packaged operation reached a terminal message before the hard crash"
                            .into(),
                    );
                }
                _ => unreachable!("message kind is validated"),
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::runner::staging::WorkDirectory;

    #[test]
    fn exact_tree_rejects_executable_mode_mismatch() {
        let work = WorkDirectory::new(&std::env::temp_dir()).unwrap();
        let source = work.path.join("source");
        let installed = work.path.join("installed");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&installed).unwrap();
        fs::write(source.join("app"), b"same bytes").unwrap();
        fs::write(installed.join("app"), b"same bytes").unwrap();
        fs::set_permissions(source.join("app"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(installed.join("app"), fs::Permissions::from_mode(0o644)).unwrap();

        assert!(verify_exact_tree(&source, &installed).is_err());
    }
}

#[cfg(windows)]
fn require_forced_crash_status(status: std::process::ExitStatus) -> Result<(), String> {
    if status.code() == Some(1) {
        Ok(())
    } else {
        Err(format!(
            "packaged backend was not terminated by the Windows crash job: {status}"
        ))
    }
}

#[cfg(unix)]
fn require_forced_crash_status(status: std::process::ExitStatus) -> Result<(), String> {
    use std::os::unix::process::ExitStatusExt;

    if status.signal() == Some(9) {
        Ok(())
    } else {
        Err(format!(
            "packaged backend was not terminated by SIGKILL: {status}"
        ))
    }
}

#[cfg(not(any(windows, unix)))]
fn require_forced_crash_status(status: std::process::ExitStatus) -> Result<(), String> {
    if status.success() {
        Err("packaged backend exited successfully instead of being hard-killed".into())
    } else {
        Ok(())
    }
}
