use std::{
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream},
    path::Path,
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde_json::{Map, Value, json};

use super::{
    HostLayout, LAUNCH_EXIT_ACK, LAUNCH_MARKER_FILE, LAUNCH_MARKER_MAGIC, LAUNCH_MARKER_TEMP_FILE,
    SMOKE_LICENSE, bounded_output, containment::ChildContainment, is_link_or_reparse,
    valid_package_id,
};

mod recovery;
pub(super) use recovery::{
    probe_crash_recovery, probe_uninstall_precommit_crash_recovery, probe_upgrade_crash_recovery,
};

const PROTOCOL_VERSION: u64 = luxury_spec::JSONL_PROTOCOL_VERSION as u64;
const MAX_JSONL_LINE_BYTES: usize = 1024 * 1024;
const MAX_JSONL_LINES: usize = 4_096;
const MAX_STDOUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_STDERR_BYTES: u64 = 64 * 1024;
const LIFECYCLE_WALL_TIMEOUT: Duration = Duration::from_secs(120);
const RUNNER_VERIFY_TIMEOUT: Duration = Duration::from_secs(60);
const AUTHENTICATED_VERIFY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const LAUNCH_PROOF_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LAUNCH_MARKER_BYTES: u64 = 128;
const FOREIGN_BYTES: &[u8] = b"foreign file preserved by lifecycle probe";
const STRESS_PACKAGE_ID: &str = "dev.luxury.demo";
const STRESS_INSTALL_DIRECTORY: &str = "Luxury Demo";
const STRESS_PUBLISHED_FILE: &str = "000-large.bin";
const PRE_MUTATION_PHASES: &[&str] = &[
    "validating",
    "verifying",
    "recovering",
    "planning",
    "applying",
];
#[derive(Clone, Copy)]
pub(super) struct StressExpectation {
    pub(super) files: u64,
    pub(super) bytes: u64,
    pub(super) applied_bytes: u64,
    pub(super) action: &'static str,
    pub(super) executable: bool,
}

#[derive(Clone, Copy)]
pub(super) struct StressPackage<'a> {
    pub(super) package: &'a Path,
    pub(super) source_payload: &'a Path,
    pub(super) expected: StressExpectation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LifecycleProbe {
    pub(super) package_id: String,
    pub(super) package_version: String,
    pub(super) package_fingerprint: String,
    pub(super) install_directory: String,
    pub(super) installed_files: u64,
    pub(super) installed_bytes: u64,
    pub(super) removed_files: u64,
    pub(super) missing_files: u64,
    pub(super) preserved_modified_files: u64,
    pub(super) install_progress_events: usize,
    pub(super) uninstall_progress_events: usize,
    pub(super) hello_verified: bool,
    pub(super) owned_removed: bool,
    pub(super) foreign_preserved: bool,
    pub(super) state_clean: bool,
}

pub(super) fn probe_runner(launcher: &Path) -> Result<(), String> {
    probe_runner_output(launcher, None, true)
}

pub(super) fn probe_studio(launcher: &Path) -> Result<(), String> {
    println!("> packaged Tauri Studio --verify-studio");
    let mut command = Command::new(launcher);
    command
        .arg("--verify-studio")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (child, mut containment) = ChildContainment::spawn(&mut command, RUNNER_VERIFY_TIMEOUT)
        .map_err(|error| format!("could not start packaged Tauri Studio: {error}"))?;
    let output = child.wait_with_output();
    let timed_out = containment.timed_out();
    containment.disarm();
    let output = output
        .map_err(|error| format!("could not collect packaged Tauri Studio output: {error}"))?;
    if timed_out {
        return Err("packaged Tauri Studio verification timed out".into());
    }
    if !output.status.success() {
        return Err(format!(
            "packaged Tauri Studio verification failed with {}; stdout: {}; stderr: {}",
            output.status,
            bounded_output(&output.stdout),
            bounded_output(&output.stderr),
        ));
    }
    require_studio_probe_output(&output.stdout, &output.stderr)
}

fn require_studio_probe_output(stdout: &[u8], stderr: &[u8]) -> Result<(), String> {
    if stdout != b"{\"studioVerified\":true}\n" || !stderr.is_empty() {
        return Err(format!(
            "packaged Tauri Studio returned an invalid verification result; stdout: {}; stderr: {}",
            bounded_output(stdout),
            bounded_output(stderr),
        ));
    }
    Ok(())
}

pub(super) fn probe_container_runner(launcher: &Path, private_temp: &Path) -> Result<(), String> {
    probe_runner_output(launcher, Some(private_temp), false)
}

pub(super) fn probe_authenticated_runner(launcher: &Path) -> Result<(), String> {
    probe_authenticated_runner_output(launcher, None, true)
}

pub(super) fn probe_authenticated_container_runner(
    launcher: &Path,
    private_temp: &Path,
) -> Result<(), String> {
    probe_authenticated_runner_output(launcher, Some(private_temp), false)
}

fn probe_authenticated_runner_output(
    launcher: &Path,
    private_temp: Option<&Path>,
    require_output: bool,
) -> Result<(), String> {
    println!("> signed Tauri runner --verify-authenticated-transport");
    let mut command = Command::new(launcher);
    command
        .args(["--verify-runner", "--verify-authenticated-transport"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(private_temp) = private_temp {
        command.env("TEMP", private_temp).env("TMP", private_temp);
    }
    let (child, mut containment) =
        ChildContainment::spawn(&mut command, AUTHENTICATED_VERIFY_TIMEOUT)
            .map_err(|error| format!("could not start signed Tauri runner: {error}"))?;
    let output = child.wait_with_output();
    let timed_out = containment.timed_out();
    containment.disarm();
    let output =
        output.map_err(|error| format!("could not collect signed Tauri runner output: {error}"))?;
    if timed_out {
        return Err("signed Tauri runner verification timed out".into());
    }
    if !output.status.success() {
        return Err(format!(
            "signed Tauri runner verification failed with {}; stdout: {}; stderr: {}",
            output.status,
            bounded_output(&output.stdout),
            bounded_output(&output.stderr),
        ));
    }
    let exact = output.stdout == b"{\"authenticatedTransportVerified\":true}\n";
    if (!exact && (require_output || !output.stdout.is_empty())) || !output.stderr.is_empty() {
        return Err(format!(
            "signed Tauri runner returned an invalid result; stdout: {}; stderr: {}",
            bounded_output(&output.stdout),
            bounded_output(&output.stderr)
        ));
    }
    Ok(())
}

fn probe_runner_output(
    launcher: &Path,
    private_temp: Option<&Path>,
    require_output: bool,
) -> Result<(), String> {
    println!("> packaged Tauri runner --verify-runner");
    let mut command = Command::new(launcher);
    command
        .arg("--verify-runner")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(private_temp) = private_temp {
        command.env("TEMP", private_temp).env("TMP", private_temp);
    }
    let (child, mut containment) = ChildContainment::spawn(&mut command, RUNNER_VERIFY_TIMEOUT)
        .map_err(|error| format!("could not start packaged Tauri runner: {error}"))?;
    let output = child.wait_with_output();
    let timed_out = containment.timed_out();
    containment.disarm();
    let output = output
        .map_err(|error| format!("could not collect packaged Tauri runner output: {error}"))?;
    if timed_out {
        return Err("packaged Tauri runner verification timed out".into());
    }
    if !output.status.success() {
        return Err(format!(
            "packaged Tauri runner verification failed with {}; stdout: {}; stderr: {}",
            output.status,
            bounded_output(&output.stdout),
            bounded_output(&output.stderr),
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| "packaged Tauri runner returned non-UTF-8 output".to_owned())?;
    let exact = stdout.trim() == "{\"verified\":true}";
    let empty = stdout.trim().is_empty();
    if !exact && (require_output || !empty) {
        return Err(format!(
            "packaged Tauri runner returned an invalid verification result: {}",
            bounded_output(&output.stdout)
        ));
    }
    Ok(())
}

pub(super) fn probe_backend(
    backend: &Path,
    package: &Path,
    host: HostLayout,
) -> Result<String, String> {
    let package = package
        .to_str()
        .ok_or_else(|| "installer payload path is not valid Unicode for JSONL".to_owned())?;
    LifecycleSession::start(backend)?.run(|session| {
        session.request("assemble_defaults", "defaults", json!({}))?;
        session.request(
            "assemble_inspect",
            "inspect",
            json!({ "packagePath": package }),
        )?;
        let defaults = session.next_required("defaults")?;
        let inspect = session.next_required("inspect")?;
        let defaults = strict_result(&defaults, "assemble_defaults", "defaults")?;
        let inspect = strict_result(&inspect, "assemble_inspect", "inspect")?;
        let backend_version = value_string(defaults, "/backendVersion", "backend version")?;
        if backend_version != env!("CARGO_PKG_VERSION") {
            return Err(format!(
                "packaged backend version `{backend_version}` does not match runner version `{}`",
                env!("CARGO_PKG_VERSION")
            ));
        }
        require_target(defaults, host, "backend")?;
        require_target(inspect, host, "payload")?;
        let format_version = value_u64(inspect, "/formatVersion", "package format version")?;
        validate_runner_trust(
            inspect
                .pointer("/trust")
                .ok_or_else(|| "Rust backend response has no package trust".to_owned())?,
            format_version,
        )?;
        let fingerprint = value_string(inspect, "/packageFingerprint", "package fingerprint")?;
        if !is_lower_hex_64(fingerprint) {
            return Err("backend returned an invalid package fingerprint".into());
        }
        Ok(fingerprint.to_owned())
    })
}

pub(super) fn probe_lifecycle(
    backend: &Path,
    package: &Path,
    host: HostLayout,
    probe_root: &Path,
    expected_hello: &[u8],
) -> Result<LifecycleProbe, String> {
    if !backend.is_absolute() || !package.is_absolute() {
        return Err("lifecycle backend and payload must be absolute paths".into());
    }
    require_empty_probe_root(probe_root)?;
    let package_path = unicode_path(package, "payload")?;
    let install_base = probe_root.join("install");
    let state_root = probe_root.join("state");
    let install_base_text = unicode_path(&install_base, "install root")?;
    let state_root_text = unicode_path(&state_root, "state root")?;
    LifecycleSession::start(backend)?.run(|session| {
        session.request(
            "lifecycle_inspect",
            "inspect",
            json!({ "packagePath": package_path }),
        )?;
        let inspect = parse_inspect(session.next_required("inspect")?, "lifecycle_inspect", host)?;

        session.request(
            "lifecycle_license_denied",
            "install",
            json!({
                "packagePath": package_path,
                "installBase": install_base_text,
                "stateRoot": state_root_text,
                "allowUnsigned": true,
                "acceptLicense": false,
                "allowPublisherMigration": false,
                "expectedFingerprint": inspect.fingerprint,
            }),
        )?;
        consume_license_denial(session, "lifecycle_license_denied")?;
        if !path_absent(&install_base, "license-denied install root")?
            || !path_absent(&state_root, "license-denied state root")?
        {
            return Err("license-denied install mutated platform state".into());
        }

        session.request(
            "lifecycle_install",
            "install",
            json!({
                "packagePath": package_path,
                "installBase": install_base_text,
                "stateRoot": state_root_text,
                "allowUnsigned": true,
                "acceptLicense": true,
                "allowPublisherMigration": false,
                "expectedFingerprint": inspect.fingerprint,
            }),
        )?;
        let installed = consume_install(session, "lifecycle_install")?;
        validate_install_against_inspect(&inspect, &installed)?;

        let install_root = install_base.join(&inspect.install_directory);
        let hello = install_root.join("hello.txt");
        let hello_verified = verify_regular_bytes(&hello, expected_hello, "installed payload")?;
        let receipt = state_root
            .join("receipts")
            .join(format!("{}.json", inspect.package_id));
        require_regular(&receipt, "ownership receipt")?;

        let foreign = install_root.join("lifecycle-foreign.keep");
        let mut foreign_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&foreign)
            .map_err(|error| format!("could not create foreign lifecycle file: {error}"))?;
        foreign_file
            .write_all(FOREIGN_BYTES)
            .and_then(|_| foreign_file.sync_all())
            .map_err(|error| format!("could not persist foreign lifecycle file: {error}"))?;
        drop(foreign_file);

        session.request(
            "lifecycle_uninstall",
            "uninstall",
            json!({
                "packageId": inspect.package_id,
                "installBase": install_base_text,
                "stateRoot": state_root_text,
            }),
        )?;
        let removed = consume_uninstall(session, "lifecycle_uninstall")?;
        if removed.package_id != inspect.package_id
            || removed.removed_files != installed.installed_files
            || removed.missing_files != 0
            || removed.preserved_modified_files != 0
        {
            return Err("packaged backend returned inconsistent uninstall counts".into());
        }

        let owned_removed = path_absent(&hello, "owned payload")?;
        if !owned_removed {
            return Err("owned payload remained after uninstall".into());
        }
        let foreign_preserved = verify_regular_bytes(&foreign, FOREIGN_BYTES, "foreign file")?;
        let transaction = state_root.join("transactions").join(&inspect.package_id);
        let destination_transaction =
            install_base.join(format!(".luxury-tx-{}", inspect.package_id));
        let receipt_absent = path_absent(&receipt, "ownership receipt")?;
        let transaction_absent = path_absent(&transaction, "transaction state")?;
        let destination_transaction_absent =
            path_absent(&destination_transaction, "destination transaction")?;
        let state_clean = receipt_absent && transaction_absent && destination_transaction_absent;
        if !state_clean {
            return Err("installer transaction state remained after uninstall".into());
        }

        Ok(LifecycleProbe {
            package_id: inspect.package_id,
            package_version: inspect.package_version,
            package_fingerprint: inspect.fingerprint,
            install_directory: inspect.install_directory,
            installed_files: installed.installed_files,
            installed_bytes: installed.installed_bytes,
            removed_files: removed.removed_files,
            missing_files: removed.missing_files,
            preserved_modified_files: removed.preserved_modified_files,
            install_progress_events: installed.progress_events,
            uninstall_progress_events: removed.progress_events,
            hello_verified,
            owned_removed,
            foreign_preserved,
            state_clean,
        })
    })
}

pub(super) fn probe_launch(
    backend: &Path,
    package: &Path,
    host: HostLayout,
    probe_root: &Path,
    entrypoint: &str,
) -> Result<(), String> {
    if !backend.is_absolute() || !package.is_absolute() {
        return Err("launch backend and payload must be absolute paths".into());
    }
    require_empty_probe_root(probe_root)?;
    let package_path = unicode_path(package, "launch payload")?;
    let install_base = probe_root.join("install");
    let state_root = probe_root.join("state");
    let install_base_text = unicode_path(&install_base, "launch install root")?;
    let state_root_text = unicode_path(&state_root, "launch state root")?;

    LifecycleSession::start(backend)?.run(|session| {
        session.request(
            "launch_inspect",
            "inspect",
            json!({ "packagePath": package_path }),
        )?;
        let inspect = parse_launch_inspect(
            session.next_required("launch inspect")?,
            "launch_inspect",
            host,
        )?;

        session.request(
            "launch_install",
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
        let installed = consume_install(session, "launch_install")?;
        validate_install_against_inspect(&inspect, &installed)?;

        let install_root = install_base.join(&inspect.install_directory);
        let executable = install_root.join(entrypoint);
        require_regular(&executable, "installed launch entrypoint")?;
        let receipt = state_root
            .join("receipts")
            .join(format!("{}.json", inspect.package_id));
        require_regular(&receipt, "launch ownership receipt")?;

        session.request(
            "launch_execute",
            "launch",
            json!({
                "packageId": inspect.package_id,
                "installBase": install_base_text,
                "stateRoot": state_root_text,
            }),
        )?;
        parse_launch_result(
            &session.next_required("launch")?,
            "launch_execute",
            &inspect.package_id,
        )?;

        let marker = install_root.join(LAUNCH_MARKER_FILE);
        wait_for_launch_exit(&marker)?;
        if !path_absent(
            &install_root.join(LAUNCH_MARKER_TEMP_FILE),
            "launch marker staging file",
        )? {
            return Err("launch marker staging file remained after publication".into());
        }
        fs::remove_file(&marker)
            .map_err(|error| format!("could not remove launch marker: {error}"))?;
        if !path_absent(&marker, "removed launch marker")? {
            return Err("launch marker remained after cleanup".into());
        }
        session.request(
            "launch_uninstall",
            "uninstall",
            json!({
                "packageId": inspect.package_id,
                "installBase": install_base_text,
                "stateRoot": state_root_text,
            }),
        )?;
        let removed = consume_uninstall(session, "launch_uninstall")?;
        if removed.package_id != inspect.package_id
            || removed.removed_files != installed.installed_files
            || removed.missing_files != 0
            || removed.preserved_modified_files != 0
        {
            return Err("packaged backend returned inconsistent launch uninstall counts".into());
        }
        if !path_absent(&executable, "launch entrypoint")?
            || !path_absent(&receipt, "launch ownership receipt")?
        {
            return Err("launch lifecycle left owned state behind".into());
        }
        require_only_lifecycle_lock_state(&install_base, &state_root)
    })
}

pub(super) fn probe_install_cancellation(
    backend: &Path,
    package: &Path,
    host: HostLayout,
    probe_root: &Path,
    expected: StressExpectation,
) -> Result<(), String> {
    if !backend.is_absolute() || !package.is_absolute() {
        return Err("cancellation backend and payload must be absolute paths".into());
    }
    require_empty_probe_root(probe_root)?;
    let package_path = unicode_path(package, "cancellation payload")?;
    let install_base = probe_root.join("install");
    let state_root = probe_root.join("state");

    LifecycleSession::start(backend)?.run(|session| {
        const INSTALL_ID: &str = "cancellation_install";
        const CANCEL_ID: &str = "cancellation_request";
        let inspect = inspect_stress_fixture(
            session,
            package_path,
            host,
            "cancellation_inspect",
            expected.files,
            expected.bytes,
        )?;
        let mut progress = start_stress_install(
            session,
            INSTALL_ID,
            package_path,
            &install_base,
            &state_root,
            &inspect,
            expected,
        )?;

        session.request(CANCEL_ID, "cancel", json!({ "requestId": INSTALL_ID }))?;
        let mut cancel_accepted = false;
        let mut install_cancelled = false;
        let mut committing = false;
        let mut rolling_back = false;
        let mut cancelled_phase = false;
        while !cancel_accepted || !install_cancelled {
            let message = session.next_required("install cancellation")?;
            let id = value_object(&message, "cancellation message")?
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| "packaged backend cancellation message has no id".to_owned())?;
            match id {
                CANCEL_ID => {
                    if cancel_accepted {
                        return Err("packaged backend emitted duplicate cancellation result".into());
                    }
                    require_cancel_accepted(&message, CANCEL_ID, INSTALL_ID)?;
                    cancel_accepted = true;
                }
                INSTALL_ID => {
                    if install_cancelled {
                        return Err(
                            "packaged backend emitted install data after cancellation".into()
                        );
                    }
                    match message_kind(&message, INSTALL_ID)? {
                        "event" => match parse_install_event(&message, INSTALL_ID)? {
                            InstallProbeEvent::Action(_) => {
                                return Err(
                                    "packaged backend repeated the install action after cancel"
                                        .into(),
                                );
                            }
                            InstallProbeEvent::Progress(value) if !cancelled_phase => {
                                progress.observe(value, false)?;
                            }
                            InstallProbeEvent::Progress(_) => {
                                return Err(
                                    "packaged backend emitted progress after cancellation".into()
                                );
                            }
                            InstallProbeEvent::Phase(phase) => match phase.as_str() {
                                "committing"
                                    if !committing && !rolling_back && !cancelled_phase =>
                                {
                                    committing = true;
                                }
                                "rollingBack" if !rolling_back && !cancelled_phase => {
                                    rolling_back = true;
                                }
                                "cancelled" if rolling_back && !cancelled_phase => {
                                    cancelled_phase = true;
                                }
                                _ => {
                                    return Err(
                                        "packaged backend emitted an invalid cancellation phase"
                                            .into(),
                                    );
                                }
                            },
                        },
                        "error" => {
                            if backend_error_code(&message, INSTALL_ID)? != "cancelled" {
                                return Err(
                                    "packaged backend rejected cancellation with another error"
                                        .into(),
                                );
                            }
                            install_cancelled = true;
                        }
                        "result" => {
                            return Err(
                                "packaged install committed after accepted cancellation".into()
                            );
                        }
                        _ => unreachable!("message kind is validated"),
                    }
                }
                _ => {
                    return Err(
                        "packaged backend returned an unrelated cancellation message".into(),
                    );
                }
            }
        }
        if !rolling_back || !cancelled_phase {
            return Err("packaged backend omitted cancellation rollback phases".into());
        }
        if progress.total_files != Some(inspect.payload_files)
            || progress.total_bytes != Some(inspect.payload_bytes)
            || progress.completed_files == 0
        {
            return Err("packaged backend cancellation progress did not match the payload".into());
        }
        Ok(inspect)
    })?;

    let install_root = install_base.join("Luxury Demo");
    let receipt = state_root.join("receipts").join("dev.luxury.demo.json");
    let transaction = state_root.join("transactions/dev.luxury.demo");
    let destination_transaction = install_base.join(".luxury-tx-dev.luxury.demo");
    for (path, label) in [
        (&install_root, "cancelled install payload"),
        (&receipt, "cancelled install receipt"),
        (&transaction, "cancelled install transaction"),
        (
            &destination_transaction,
            "cancelled destination transaction",
        ),
    ] {
        if !path_absent(path, label)? {
            return Err(format!("lifecycle {label} remained after rollback"));
        }
    }
    require_only_lifecycle_lock_state(&install_base, &state_root)?;
    Ok(())
}

fn inspect_stress_fixture(
    session: &mut LifecycleSession,
    package_path: &str,
    host: HostLayout,
    request_id: &str,
    expected_files: u64,
    expected_bytes: u64,
) -> Result<InspectIdentity, String> {
    session.request(
        request_id,
        "inspect",
        json!({ "packagePath": package_path }),
    )?;
    let inspect = parse_stress_inspect(
        session.next_required("stress fixture inspect")?,
        request_id,
        host,
    )
    .map_err(|error| format!("{request_id}: {error}"))?;
    if inspect.payload_files != expected_files || inspect.payload_bytes != expected_bytes {
        return Err("stress fixture does not match its expected payload".into());
    }
    if inspect.package_id != STRESS_PACKAGE_ID
        || inspect.install_directory != STRESS_INSTALL_DIRECTORY
    {
        return Err("stress fixture has an unexpected package identity".into());
    }
    Ok(inspect)
}

fn start_stress_install(
    session: &mut LifecycleSession,
    install_id: &str,
    package_path: &str,
    install_base: &Path,
    state_root: &Path,
    inspect: &InspectIdentity,
    expected: StressExpectation,
) -> Result<ProgressTracker, String> {
    request_stress_install(
        session,
        install_id,
        package_path,
        install_base,
        state_root,
        inspect,
    )?;
    let mut action_seen = false;
    let mut phases = PhaseTracker::default();
    let mut progress = ProgressTracker::default();
    loop {
        let message = session.next_required("stress install start")?;
        if message_kind(&message, install_id)? != "event" {
            return Err("packaged backend completed before the stress trigger".into());
        }
        match parse_install_event(&message, install_id)? {
            InstallProbeEvent::Action(action) => {
                if action != expected.action || action_seen {
                    return Err("packaged backend emitted an invalid stress install action".into());
                }
                action_seen = true;
            }
            InstallProbeEvent::Phase(phase) => {
                phases.observe(&phase, PRE_MUTATION_PHASES, "pre-trigger install")?;
            }
            InstallProbeEvent::Progress(value) => {
                progress.observe(value, false)?;
                if value.completed_files > 0 {
                    require_stress_published_file(install_base, expected.applied_bytes)?;
                    break;
                }
            }
        }
    }
    phases.finish(PRE_MUTATION_PHASES, "pre-trigger install")?;
    if !action_seen {
        return Err("packaged backend omitted the stress install action".into());
    }
    Ok(progress)
}

fn request_stress_install(
    session: &mut LifecycleSession,
    install_id: &str,
    package_path: &str,
    install_base: &Path,
    state_root: &Path,
    inspect: &InspectIdentity,
) -> Result<(), String> {
    session.request(
        install_id,
        "install",
        json!({
            "packagePath": package_path,
            "installBase": unicode_path(install_base, "stress install root")?,
            "stateRoot": unicode_path(state_root, "stress state root")?,
            "allowUnsigned": true,
            "allowPublisherMigration": false,
            "expectedFingerprint": inspect.fingerprint,
        }),
    )
}

fn require_stress_published_file(
    install_base: &Path,
    expected_applied_bytes: u64,
) -> Result<(), String> {
    let published = install_base
        .join(STRESS_INSTALL_DIRECTORY)
        .join(STRESS_PUBLISHED_FILE);
    let metadata = fs::symlink_metadata(&published)
        .map_err(|error| format!("could not inspect published stress file: {error}"))?;
    if is_link_or_reparse(&metadata)
        || !metadata.is_file()
        || metadata.len() != expected_applied_bytes
    {
        return Err("nonzero progress did not publish the expected stress file".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InspectIdentity {
    package_id: String,
    package_version: String,
    fingerprint: String,
    install_directory: String,
    payload_files: u64,
    payload_bytes: u64,
}

#[derive(Debug)]
struct InstallTerminal {
    action: String,
    package_id: String,
    install_directory: String,
    installed_files: u64,
    installed_bytes: u64,
    progress_events: usize,
}

#[derive(Debug)]
struct UninstallTerminal {
    package_id: String,
    removed_files: u64,
    missing_files: u64,
    preserved_modified_files: u64,
    progress_events: usize,
}

struct LifecycleSession {
    child: Child,
    containment: ChildContainment,
    input: Option<ChildStdin>,
    output: BoundedJsonl<BufReader<ChildStdout>>,
    stderr: Option<JoinHandle<Result<bool, String>>>,
    reaped: bool,
}

impl LifecycleSession {
    fn start(backend: &Path) -> Result<Self, String> {
        let mut command = Command::new(backend);
        command
            .arg("stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (mut child, mut containment) =
            ChildContainment::spawn(&mut command, LIFECYCLE_WALL_TIMEOUT)
                .map_err(|error| format!("could not start packaged backend lifecycle: {error}"))?;
        let setup = (|| {
            let input = child
                .stdin
                .take()
                .ok_or_else(|| "packaged backend lifecycle stdin was not piped".to_owned())?;
            let output = child
                .stdout
                .take()
                .ok_or_else(|| "packaged backend lifecycle stdout was not piped".to_owned())?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| "packaged backend lifecycle stderr was not piped".to_owned())?;
            let stderr = thread::Builder::new()
                .name("lifecycle-stderr".into())
                .spawn(move || drain_stderr(stderr))
                .map_err(|error| format!("could not start lifecycle stderr reader: {error}"))?;
            Ok((input, output, stderr))
        })();
        let (input, output, stderr) = match setup {
            Ok(setup) => setup,
            Err(error) => {
                let termination = containment.terminate().err();
                terminate_child(&mut child);
                containment.disarm();
                return Err(match termination {
                    Some(termination) => {
                        format!("{error}; lifecycle containment failed: {termination}")
                    }
                    None => error,
                });
            }
        };
        Ok(Self {
            child,
            containment,
            input: Some(input),
            output: BoundedJsonl::new(BufReader::new(output)),
            stderr: Some(stderr),
            reaped: false,
        })
    }

    fn request(&mut self, id: &str, method: &str, params: Value) -> Result<(), String> {
        let result = (|| {
            let input = self
                .input
                .as_mut()
                .ok_or_else(|| "packaged backend lifecycle stdin is closed".to_owned())?;
            serde_json::to_writer(
                &mut *input,
                &json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "id": id,
                    "method": method,
                    "params": params,
                }),
            )
            .map_err(|error| format!("could not encode lifecycle request: {error}"))?;
            input
                .write_all(b"\n")
                .and_then(|_| input.flush())
                .map_err(|error| format!("could not send lifecycle request: {error}"))
        })();
        self.timeout_or(result)
    }

    fn next_required(&mut self, label: &str) -> Result<Value, String> {
        let value = self.output.next_value();
        if self.containment.timed_out() {
            return Err(lifecycle_timeout());
        }
        value?.ok_or_else(|| format!("packaged backend ended before {label} completed"))
    }

    fn run<T>(
        mut self,
        operation: impl FnOnce(&mut LifecycleSession) -> Result<T, String>,
    ) -> Result<T, String> {
        match operation(&mut self) {
            Ok(value) => self.finish().map(|()| value),
            Err(error) => Err(self.abort(error)),
        }
    }

    fn finish(mut self) -> Result<(), String> {
        self.input.take();
        let eof = require_jsonl_eof(&mut self.output);
        if self.containment.timed_out() {
            return Err(self.abort(lifecycle_timeout()));
        }
        if let Err(error) = eof {
            return Err(self.abort(error));
        }
        if let Err(error) = self.containment.wait_for_primary_exit(&self.child) {
            return Err(self.abort(format!(
                "could not wait for packaged backend lifecycle exit: {error}"
            )));
        }
        if self.containment.timed_out() {
            return Err(self.abort(lifecycle_timeout()));
        }
        let termination = self
            .containment
            .terminate()
            .map_err(|error| format!("lifecycle containment failed: {error}"));
        let status = self
            .child
            .wait()
            .map_err(|error| format!("could not wait for packaged backend lifecycle: {error}"));
        self.reaped = status.is_ok();
        let stderr_overflow = self.join_stderr();
        self.containment.disarm();
        if let Err(error) = termination {
            return if self.containment.timed_out() {
                Err(format!("{}; {error}", lifecycle_timeout()))
            } else {
                Err(error)
            };
        }
        if self.containment.timed_out() {
            return Err(lifecycle_timeout());
        }
        let status = status?;
        let stderr_overflow = stderr_overflow?;
        if stderr_overflow {
            return Err("packaged backend stderr exceeded the lifecycle limit".into());
        }
        if !status.success() {
            return Err(format!("packaged backend lifecycle exited with {status}"));
        }
        Ok(())
    }

    fn abort(mut self, cause: String) -> String {
        self.input.take();
        let termination = self.containment.terminate();
        let _ = self.child.kill();
        let reaped = self
            .child
            .wait()
            .map(|_| ())
            .map_err(|error| format!("could not reap packaged backend lifecycle: {error}"));
        self.reaped = reaped.is_ok();
        let stderr_overflow = self.join_stderr();
        let timed_out = self.containment.timed_out();
        self.containment.disarm();

        let mut error = if timed_out {
            lifecycle_timeout()
        } else {
            cause
        };
        if let Err(termination) = termination {
            error.push_str(&format!("; lifecycle containment failed: {termination}"));
        }
        if let Err(reaped) = reaped {
            error.push_str(&format!("; {reaped}"));
        }
        match stderr_overflow {
            Ok(true) => error.push_str("; packaged backend stderr exceeded the lifecycle limit"),
            Ok(false) => {}
            Err(stderr) => error.push_str(&format!("; {stderr}")),
        }
        error
    }

    fn join_stderr(&mut self) -> Result<bool, String> {
        self.stderr
            .take()
            .ok_or_else(|| "lifecycle stderr reader is missing".to_owned())?
            .join()
            .map_err(|_| "lifecycle stderr reader failed".to_owned())?
    }

    fn timeout_or<T>(&self, result: Result<T, String>) -> Result<T, String> {
        if self.containment.timed_out() {
            Err(lifecycle_timeout())
        } else {
            result
        }
    }
}

fn lifecycle_timeout() -> String {
    "packaged backend lifecycle exceeded its wall-clock limit".into()
}

fn require_jsonl_eof<R: BufRead>(output: &mut BoundedJsonl<R>) -> Result<(), String> {
    match output.next_value()? {
        None => Ok(()),
        Some(_) => Err("packaged backend emitted JSONL after the terminal result".into()),
    }
}

impl Drop for LifecycleSession {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.containment.terminate();
        if !self.reaped {
            terminate_child(&mut self.child);
            self.reaped = true;
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
        self.containment.disarm();
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn drain_stderr(stderr: ChildStderr) -> Result<bool, String> {
    let mut bytes = Vec::with_capacity(MAX_STDERR_BYTES as usize + 1);
    stderr
        .take(MAX_STDERR_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read packaged backend stderr".to_owned())?;
    Ok(bytes.len() as u64 > MAX_STDERR_BYTES)
}

struct BoundedJsonl<R> {
    input: R,
    lines: usize,
    bytes: usize,
}

impl<R: BufRead> BoundedJsonl<R> {
    fn new(input: R) -> Self {
        Self {
            input,
            lines: 0,
            bytes: 0,
        }
    }

    fn next_value(&mut self) -> Result<Option<Value>, String> {
        self.next_value_inner(false)
    }

    fn next_crash_value(&mut self) -> Result<Option<Value>, String> {
        self.next_value_inner(true)
    }

    fn next_value_inner(&mut self, allow_incomplete_tail: bool) -> Result<Option<Value>, String> {
        if self.lines >= MAX_JSONL_LINES {
            return Err("packaged backend exceeded the lifecycle event limit".into());
        }
        let Some((mut line, terminated)) = read_bounded_jsonl_line(&mut self.input)? else {
            return Ok(None);
        };
        if terminated && line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            if !terminated && allow_incomplete_tail {
                return Ok(None);
            }
            return Err("packaged backend emitted an empty JSONL line".into());
        }
        self.bytes = self
            .bytes
            .checked_add(line.len() + usize::from(terminated))
            .ok_or_else(|| "packaged backend lifecycle byte count overflowed".to_owned())?;
        if self.bytes > MAX_STDOUT_BYTES {
            return Err("packaged backend exceeded the lifecycle stdout limit".into());
        }
        if !terminated {
            if !allow_incomplete_tail {
                return Err("packaged backend ended with unterminated JSONL".into());
            }
            return match serde_json::from_slice(&line) {
                Ok(value) => {
                    self.lines += 1;
                    Ok(Some(value))
                }
                Err(_) => Ok(None),
            };
        }
        self.lines += 1;
        serde_json::from_slice(&line)
            .map(Some)
            .map_err(|_| "packaged backend emitted invalid lifecycle JSONL".to_owned())
    }
}

fn read_bounded_jsonl_line<R: BufRead>(input: &mut R) -> Result<Option<(Vec<u8>, bool)>, String> {
    let mut line = Vec::new();
    let mut saw_input = false;
    loop {
        let available = input
            .fill_buf()
            .map_err(|error| format!("could not read lifecycle JSONL: {error}"))?;
        if available.is_empty() {
            return if saw_input {
                Ok(Some((line, false)))
            } else {
                Ok(None)
            };
        }
        saw_input = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let content = newline.unwrap_or(available.len());
        if line.len().saturating_add(content) > MAX_JSONL_LINE_BYTES {
            return Err("packaged backend lifecycle JSONL line exceeded the limit".into());
        }
        line.extend_from_slice(&available[..content]);
        let consumed = newline.map_or(available.len(), |index| index + 1);
        let terminated = newline.is_some();
        input.consume(consumed);
        if terminated {
            return Ok(Some((line, true)));
        }
    }
}

fn parse_inspect(
    message: Value,
    expected_id: &str,
    host: HostLayout,
) -> Result<InspectIdentity, String> {
    parse_inspect_with_policy(message, expected_id, host, 3, false, true)
}

fn parse_stress_inspect(
    message: Value,
    expected_id: &str,
    host: HostLayout,
) -> Result<InspectIdentity, String> {
    parse_inspect_with_policy(message, expected_id, host, 1, false, false)
}

fn parse_launch_inspect(
    message: Value,
    expected_id: &str,
    host: HostLayout,
) -> Result<InspectIdentity, String> {
    parse_inspect_with_policy(message, expected_id, host, 2, true, false)
}

fn parse_inspect_with_policy(
    message: Value,
    expected_id: &str,
    host: HostLayout,
    expected_schema: u64,
    expected_entrypoint: bool,
    expected_license: bool,
) -> Result<InspectIdentity, String> {
    let result = strict_result(&message, expected_id, "inspect")?;
    let fields = value_object(result, "inspect result")?;
    exact_keys(
        fields,
        &[
            "formatVersion",
            "schemaVersion",
            "packageFingerprint",
            "trust",
            "publisherRotation",
            "package",
            "target",
            "install",
            "payload",
        ],
        "inspect result",
    )?;
    let target = value_object(
        result
            .get("target")
            .ok_or_else(|| "inspect result has no target".to_owned())?,
        "target",
    )?;
    exact_keys(target, &["os", "arch"], "target")?;
    require_target(result, host, "payload")?;
    let format_version = value_u64(result, "/formatVersion", "package format version")?;
    if value_u64(result, "/schemaVersion", "manifest schema version")? != expected_schema {
        return Err("lifecycle package manifest schema did not match its fixture".into());
    }
    validate_runner_trust(
        result
            .get("trust")
            .ok_or_else(|| "inspect result has no package trust".to_owned())?,
        format_version,
    )?;
    if !result.get("publisherRotation").is_some_and(Value::is_null) {
        return Err("unsigned lifecycle package exposed publisher rotation".into());
    }
    let fingerprint = value_string(result, "/packageFingerprint", "package fingerprint")?;
    if !is_lower_hex_64(fingerprint) {
        return Err("inspect result has an invalid package fingerprint".into());
    }
    let package = value_object(
        result
            .get("package")
            .ok_or_else(|| "inspect result has no package".to_owned())?,
        "package summary",
    )?;
    let package_keys: &[&str] = if expected_license {
        &["id", "name", "publisher", "version", "license"]
    } else {
        &["id", "name", "publisher", "version"]
    };
    exact_keys(package, package_keys, "package summary")?;
    if expected_license && object_string(package, "license", "package license")? != SMOKE_LICENSE {
        return Err("lifecycle package license did not match its fixture".into());
    }
    let package_id = object_string(package, "id", "package id")?;
    if !valid_package_id(package_id) {
        return Err("inspect result has an invalid package id".into());
    }
    let package_version = object_string(package, "version", "package version")?;
    if package_version.is_empty() || package_version.len() > 1_024 {
        return Err("inspect result has an invalid package version".into());
    }
    let install = value_object(
        result
            .get("install")
            .ok_or_else(|| "inspect result has no install policy".to_owned())?,
        "install policy",
    )?;
    exact_keys(
        install,
        &["scope", "directory", "hasEntrypoint"],
        "install policy",
    )?;
    if install.get("hasEntrypoint").and_then(Value::as_bool) != Some(expected_entrypoint) {
        return Err("lifecycle package launch capability did not match its fixture".into());
    }
    if object_string(install, "scope", "install scope")? != "user" {
        return Err("lifecycle package is not a user-scope package".into());
    }
    let install_directory = object_string(install, "directory", "install directory")?;
    if !valid_install_directory(install_directory) {
        return Err("inspect result has an invalid install directory".into());
    }
    let payload = value_object(
        result
            .get("payload")
            .ok_or_else(|| "inspect result has no payload summary".to_owned())?,
        "payload summary",
    )?;
    exact_keys(payload, &["files", "bytes"], "payload summary")?;
    let payload_files = object_u64(payload, "files", "payload file count")?;
    let payload_bytes = object_u64(payload, "bytes", "payload byte count")?;
    Ok(InspectIdentity {
        package_id: package_id.to_owned(),
        package_version: package_version.to_owned(),
        fingerprint: fingerprint.to_owned(),
        install_directory: install_directory.to_owned(),
        payload_files,
        payload_bytes,
    })
}

fn validate_install_against_inspect(
    inspect: &InspectIdentity,
    installed: &InstallTerminal,
) -> Result<(), String> {
    validate_install_action_against_inspect(inspect, installed, "install")
}

fn validate_install_action_against_inspect(
    inspect: &InspectIdentity,
    installed: &InstallTerminal,
    expected_action: &str,
) -> Result<(), String> {
    if installed.action != expected_action
        || installed.package_id != inspect.package_id
        || installed.install_directory != inspect.install_directory
    {
        return Err("packaged backend returned an install result for another package".into());
    }
    if installed.installed_files != inspect.payload_files
        || installed.installed_bytes != inspect.payload_bytes
    {
        return Err("packaged backend install totals did not match inspected payload".into());
    }
    Ok(())
}

fn strict_result<'a>(
    message: &'a Value,
    expected_id: &str,
    label: &str,
) -> Result<&'a Value, String> {
    let kind = message_kind(message, expected_id)?;
    if kind == "error" {
        return Err(backend_rejection(message, expected_id, label));
    }
    if kind != "result" {
        return Err(format!("packaged backend emitted an event before {label}"));
    }
    let fields = value_object(message, "result envelope")?;
    exact_keys(
        fields,
        &["protocolVersion", "type", "id", "result"],
        "result envelope",
    )?;
    fields
        .get("result")
        .ok_or_else(|| format!("packaged backend result for {label} is missing"))
}

fn require_cancel_accepted(
    message: &Value,
    expected_id: &str,
    cancelled_id: &str,
) -> Result<(), String> {
    let result = strict_result(message, expected_id, "cancellation")?;
    let fields = value_object(result, "cancellation result")?;
    exact_keys(fields, &["requestId", "accepted"], "cancellation result")?;
    if fields.get("requestId").and_then(Value::as_str) != Some(cancelled_id)
        || fields.get("accepted").and_then(Value::as_bool) != Some(true)
    {
        return Err("packaged backend did not accept the correlated cancellation".into());
    }
    Ok(())
}

fn message_kind<'a>(message: &'a Value, expected_id: &str) -> Result<&'a str, String> {
    let fields = value_object(message, "protocol message")?;
    if fields.get("protocolVersion").and_then(Value::as_u64) != Some(PROTOCOL_VERSION)
        || fields.get("id").and_then(Value::as_str) != Some(expected_id)
    {
        return Err("packaged backend returned a mismatched lifecycle message".into());
    }
    fields
        .get("type")
        .and_then(Value::as_str)
        .filter(|kind| matches!(*kind, "event" | "result" | "error"))
        .ok_or_else(|| "packaged backend returned an invalid lifecycle message type".into())
}

fn backend_rejection(message: &Value, expected_id: &str, label: &str) -> String {
    let code = backend_error_code(message, expected_id).unwrap_or("backend_error");
    format!("packaged backend rejected {label} with `{code}`")
}

fn backend_error_code<'a>(message: &'a Value, expected_id: &str) -> Result<&'a str, String> {
    if message_kind(message, expected_id)? != "error" {
        return Err("packaged backend did not return an error envelope".into());
    }
    let fields = value_object(message, "error envelope")?;
    exact_keys(
        fields,
        &["protocolVersion", "type", "id", "error"],
        "error envelope",
    )?;
    let error = value_object(
        fields
            .get("error")
            .ok_or_else(|| "packaged backend error body is missing".to_owned())?,
        "error body",
    )?;
    exact_keys(error, &["code", "message"], "error body")?;
    let code = object_string(error, "code", "error code")?;
    if !safe_error_code(code) || !error.get("message").is_some_and(Value::is_string) {
        return Err("packaged backend returned an invalid error body".into());
    }
    Ok(code)
}

fn safe_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn value_object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("packaged backend returned an invalid {label}"))
}

fn exact_keys(value: &Map<String, Value>, expected: &[&str], label: &str) -> Result<(), String> {
    if value.len() == expected.len() && expected.iter().all(|key| value.contains_key(*key)) {
        Ok(())
    } else {
        Err(format!("packaged backend {label} has unexpected fields"))
    }
}

fn object_string<'a>(
    value: &'a Map<String, Value>,
    field: &str,
    label: &str,
) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("packaged backend returned no valid {label}"))
}

fn object_u64(value: &Map<String, Value>, field: &str, label: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("packaged backend returned no valid {label}"))
}

fn valid_install_directory(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !matches!(value, "." | "..")
        && !value.contains(['/', '\\', ':', '\0'])
        && !value.ends_with(['.', ' '])
}

fn unicode_path<'a>(path: &'a Path, label: &str) -> Result<&'a str, String> {
    path.to_str()
        .ok_or_else(|| format!("lifecycle {label} is not valid Unicode"))
}

fn require_empty_probe_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err("lifecycle probe root must be absolute".into());
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("could not inspect lifecycle probe root: {error}"))?;
    if !metadata.is_dir() || is_link_or_reparse(&metadata) {
        return Err("lifecycle probe root must be a real directory".into());
    }
    if fs::read_dir(root)
        .map_err(|error| format!("could not read lifecycle probe root: {error}"))?
        .next()
        .is_some()
    {
        return Err("lifecycle probe root must be empty".into());
    }
    Ok(())
}

fn require_regular(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect lifecycle {label}: {error}"))?;
    if metadata.is_file() && !is_link_or_reparse(&metadata) {
        Ok(())
    } else {
        Err(format!("lifecycle {label} is not a regular file"))
    }
}

fn require_only_lifecycle_lock_state(install_base: &Path, state_root: &Path) -> Result<(), String> {
    if directory_entry_names(install_base, "cancellation install root")? != [".luxury-locks"] {
        return Err("lifecycle left unexpected install-root residue".into());
    }
    let destination_locks = install_base.join(".luxury-locks");
    let lock_names = directory_entry_names(&destination_locks, "destination lock directory")?;
    if lock_names.len() != 1
        || !lock_names[0].starts_with("destination-")
        || !lock_names[0].ends_with(".lock")
    {
        return Err("lifecycle left unexpected destination-lock residue".into());
    }
    require_regular(&destination_locks.join(&lock_names[0]), "destination lock")?;

    if directory_entry_names(state_root, "cancellation state root")?
        != ["locks", "receipts", "transactions"]
    {
        return Err("lifecycle left unexpected state-root residue".into());
    }
    if directory_entry_names(&state_root.join("locks"), "package lock directory")?
        != ["dev.luxury.demo.lock"]
    {
        return Err("lifecycle left unexpected package-lock residue".into());
    }
    require_regular(
        &state_root.join("locks/dev.luxury.demo.lock"),
        "package lock",
    )?;
    for directory in ["receipts", "transactions"] {
        if !directory_entry_names(&state_root.join(directory), directory)?.is_empty() {
            return Err(format!("lifecycle left unexpected {directory} residue"));
        }
    }
    Ok(())
}

fn directory_entry_names(path: &Path, label: &str) -> Result<Vec<String>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect lifecycle {label}: {error}"))?;
    if !metadata.is_dir() || is_link_or_reparse(&metadata) {
        return Err(format!("lifecycle {label} is not a real directory"));
    }
    let mut names = fs::read_dir(path)
        .map_err(|error| format!("could not read lifecycle {label}: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("could not read lifecycle {label} entry: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| format!("lifecycle {label} contains a non-Unicode entry"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_unstable();
    Ok(names)
}

pub(super) fn verify_regular_bytes(
    path: &Path,
    expected: &[u8],
    label: &str,
) -> Result<bool, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect lifecycle {label}: {error}"))?;
    if !metadata.is_file()
        || is_link_or_reparse(&metadata)
        || metadata.len() != expected.len() as u64
    {
        return Err(format!("lifecycle {label} metadata did not match"));
    }
    let found =
        fs::read(path).map_err(|error| format!("could not read lifecycle {label}: {error}"))?;
    if found == expected {
        Ok(true)
    } else {
        Err(format!("lifecycle {label} bytes did not match"))
    }
}

fn path_absent(path: &Path, label: &str) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!("could not inspect lifecycle {label}: {error}")),
        Ok(_) => Ok(false),
    }
}

fn wait_for_launch_exit(path: &Path) -> Result<(), String> {
    let deadline = Instant::now() + LAUNCH_PROOF_TIMEOUT;
    let (port, pid, token) = wait_for_launch_marker(path, deadline)?;
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, launch_time_remaining(deadline)?)
        .map_err(|error| format!("could not connect to launch exit proof: {error}"))?;
    stream
        .set_write_timeout(Some(launch_time_remaining(deadline)?))
        .map_err(|error| format!("could not bound launch proof writes: {error}"))?;
    stream
        .write_all(token.as_bytes())
        .and_then(|_| stream.flush())
        .and_then(|_| stream.shutdown(Shutdown::Write))
        .map_err(|error| format!("could not send launch exit proof: {error}"))?;
    stream
        .set_read_timeout(Some(launch_time_remaining(deadline)?))
        .map_err(|error| format!("could not bound launch proof reads: {error}"))?;
    let mut acknowledgement = [0_u8; LAUNCH_EXIT_ACK.len()];
    stream
        .read_exact(&mut acknowledgement)
        .map_err(|error| format!("could not read launch exit acknowledgement: {error}"))?;
    if acknowledgement != LAUNCH_EXIT_ACK {
        return Err("launch exit acknowledgement did not match".into());
    }
    let mut extra = [0_u8; 1];
    require_launch_stream_close(stream.read(&mut extra))?;
    wait_for_launched_process_exit(pid, deadline)
}

fn require_launch_stream_close(result: io::Result<usize>) -> Result<(), String> {
    match result {
        Ok(0) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => Ok(()),
        Ok(_) => Err("launch exit proof contained trailing bytes".into()),
        Err(error) => Err(format!("could not await launched process exit: {error}")),
    }
}

fn wait_for_launch_marker(path: &Path, deadline: Instant) -> Result<(u16, u32, String), String> {
    loop {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file() || is_link_or_reparse(&metadata) {
                    return Err("launch marker is not a regular file".into());
                }
                if metadata.len() == 0 || metadata.len() > MAX_LAUNCH_MARKER_BYTES {
                    return Err("launch marker has an invalid size".into());
                }
                let bytes = fs::read(path)
                    .map_err(|error| format!("could not read launch marker: {error}"))?;
                return parse_launch_marker(&bytes);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("could not inspect launch marker: {error}")),
        }
        if Instant::now() >= deadline {
            return Err("launched entrypoint did not publish its marker in time".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn parse_launch_marker(bytes: &[u8]) -> Result<(u16, u32, String), String> {
    let marker = std::str::from_utf8(bytes).map_err(|_| "launch marker is not UTF-8")?;
    let mut fields = marker
        .strip_suffix('\n')
        .ok_or_else(|| "launch marker bytes did not match".to_owned())?
        .split('\n');
    let magic = fields
        .next()
        .ok_or_else(|| "launch marker bytes did not match".to_owned())?;
    let port_text = fields
        .next()
        .ok_or_else(|| "launch marker bytes did not match".to_owned())?;
    let token = fields
        .next()
        .filter(|_| fields.next().is_none())
        .ok_or_else(|| "launch marker bytes did not match".to_owned())?;
    let port = port_text
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0 && port.to_string() == port_text)
        .ok_or_else(|| "launch marker port is invalid".to_owned())?;
    let port_suffix = format!("{port:04x}");
    if magic != LAUNCH_MARKER_MAGIC
        || token.len() != 12
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || !token.ends_with(&port_suffix)
    {
        return Err("launch marker token is invalid".into());
    }
    let pid = u32::from_str_radix(&token[..8], 16)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| "launch marker process id is invalid".to_owned())?;
    Ok((port, pid, token.to_owned()))
}

#[cfg(windows)]
fn wait_for_launched_process_exit(pid: u32, deadline: Instant) -> Result<(), String> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };

    // SAFETY: OpenProcess receives a marker-bound numeric PID and requests only wait access.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            launch_time_remaining(deadline).map(|_| ())
        } else {
            Err(format!(
                "could not open launched process {pid} for waiting: {error}"
            ))
        };
    }
    let timeout = u32::try_from(launch_time_remaining(deadline)?.as_millis())
        .map_err(|_| "launch process timeout does not fit Windows wait API".to_owned())?;
    // SAFETY: process is a live owned HANDLE returned by OpenProcess.
    let wait = unsafe { WaitForSingleObject(process, timeout) };
    // SAFETY: process is closed exactly once after the wait.
    let closed = unsafe { CloseHandle(process) };
    if closed == 0 {
        return Err(format!(
            "could not close launched process wait handle: {}",
            io::Error::last_os_error()
        ));
    }
    match wait {
        WAIT_OBJECT_0 => launch_time_remaining(deadline).map(|_| ()),
        WAIT_TIMEOUT => Err("launched entrypoint did not exit in time".into()),
        _ => Err(format!(
            "waiting for launched process failed with status {wait}"
        )),
    }
}

#[cfg(unix)]
fn wait_for_launched_process_exit(pid: u32, deadline: Instant) -> Result<(), String> {
    use rustix::{io::Errno, process};

    let raw = i32::try_from(pid).map_err(|_| "launch marker process id is out of range")?;
    let pid = process::Pid::from_raw(raw).ok_or("launch marker process id is invalid")?;
    loop {
        match process::test_kill_process(pid) {
            Err(Errno::SRCH) => return launch_time_remaining(deadline).map(|_| ()),
            Ok(()) | Err(Errno::PERM) => {}
            Err(error) => {
                return Err(format!("could not inspect launched process state: {error}"));
            }
        }
        thread::sleep(launch_time_remaining(deadline)?.min(Duration::from_millis(10)));
    }
}

fn launch_time_remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "launched entrypoint did not prove exit in time".to_owned())
}

const INSTALL_PHASES: &[&str] = &[
    "validating",
    "verifying",
    "recovering",
    "planning",
    "applying",
    "committing",
    "completed",
];
const UNINSTALL_PHASES: &[&str] = &[
    "recovering",
    "loadingReceipt",
    "removing",
    "committing",
    "completed",
];

#[derive(Debug)]
enum InstallProbeEvent {
    Action(String),
    Phase(String),
    Progress(ProgressValue),
}

#[derive(Debug)]
enum UninstallProbeEvent {
    Phase(String),
    Progress(ProgressValue),
}

#[derive(Debug, Clone, Copy)]
struct ProgressValue {
    completed_files: u64,
    total_files: u64,
    completed_bytes: u64,
    total_bytes: u64,
}

#[derive(Default)]
struct PhaseTracker {
    last: Option<usize>,
    seen: u64,
    completed: bool,
}

impl PhaseTracker {
    fn observe(&mut self, phase: &str, expected: &[&str], label: &str) -> Result<(), String> {
        if self.completed {
            return Err(format!(
                "packaged backend emitted {label} events after completion"
            ));
        }
        let index = expected
            .iter()
            .position(|candidate| *candidate == phase)
            .ok_or_else(|| format!("packaged backend emitted an invalid {label} phase"))?;
        if self.last.is_some_and(|last| index < last) {
            return Err(format!("packaged backend reordered {label} phases"));
        }
        self.last = Some(index);
        self.seen |= 1_u64 << index;
        self.completed = index + 1 == expected.len();
        Ok(())
    }

    fn finish(&self, expected: &[&str], label: &str) -> Result<(), String> {
        let all = (1_u64 << expected.len()) - 1;
        if self.completed && self.seen == all {
            Ok(())
        } else {
            Err(format!("packaged backend omitted required {label} phases"))
        }
    }
}

#[derive(Default)]
struct ProgressTracker {
    events: usize,
    total_files: Option<u64>,
    total_bytes: Option<u64>,
    completed_files: u64,
    completed_bytes: u64,
}

impl ProgressTracker {
    fn observe(&mut self, progress: ProgressValue, zero_bytes: bool) -> Result<(), String> {
        if progress.completed_files > progress.total_files
            || progress.completed_bytes > progress.total_bytes
            || progress.completed_files < self.completed_files
            || progress.completed_bytes < self.completed_bytes
            || self
                .total_files
                .is_some_and(|total| total != progress.total_files)
            || self
                .total_bytes
                .is_some_and(|total| total != progress.total_bytes)
            || (zero_bytes && (progress.completed_bytes != 0 || progress.total_bytes != 0))
        {
            return Err("packaged backend emitted invalid lifecycle progress".into());
        }
        self.events += 1;
        self.total_files = Some(progress.total_files);
        self.total_bytes = Some(progress.total_bytes);
        self.completed_files = progress.completed_files;
        self.completed_bytes = progress.completed_bytes;
        Ok(())
    }

    fn finish(&self, label: &str) -> Result<(u64, u64), String> {
        let (Some(total_files), Some(total_bytes)) = (self.total_files, self.total_bytes) else {
            return Err(format!("packaged backend omitted {label} progress"));
        };
        if self.events > 0
            && self.completed_files == total_files
            && self.completed_bytes == total_bytes
        {
            Ok((total_files, total_bytes))
        } else {
            Err(format!(
                "packaged backend ended with incomplete {label} progress"
            ))
        }
    }
}

fn consume_install(
    session: &mut LifecycleSession,
    expected_id: &str,
) -> Result<InstallTerminal, String> {
    let mut action = None;
    let mut phases = PhaseTracker::default();
    let mut progress = ProgressTracker::default();
    loop {
        let message = session.next_required("install")?;
        match message_kind(&message, expected_id)? {
            "event" => {
                if phases.completed {
                    return Err("packaged backend emitted install events after completion".into());
                }
                match parse_install_event(&message, expected_id)? {
                    InstallProbeEvent::Action(found) => {
                        if action.replace(found).is_some() {
                            return Err("packaged backend emitted duplicate install action".into());
                        }
                    }
                    InstallProbeEvent::Phase(phase) => {
                        phases.observe(&phase, INSTALL_PHASES, "install")?;
                    }
                    InstallProbeEvent::Progress(value) => progress.observe(value, false)?,
                }
            }
            "result" => {
                phases.finish(INSTALL_PHASES, "install")?;
                let (total_files, total_bytes) = progress.finish("install")?;
                let action = action
                    .ok_or_else(|| "packaged backend omitted factual install action".to_owned())?;
                let mut terminal = parse_install_result(&message, expected_id)?;
                if terminal.action != action {
                    return Err("packaged backend install action did not match its events".into());
                }
                if terminal.installed_files != total_files
                    || terminal.installed_bytes != total_bytes
                {
                    return Err("packaged backend install result did not match progress".into());
                }
                terminal.progress_events = progress.events;
                return Ok(terminal);
            }
            "error" => return Err(backend_rejection(&message, expected_id, "install")),
            _ => unreachable!("message kind is validated"),
        }
    }
}

fn consume_license_denial(session: &mut LifecycleSession, expected_id: &str) -> Result<(), String> {
    const EXPECTED_PHASES: [&str; 2] = ["validating", "failed"];
    let mut next_phase = 0;
    loop {
        let message = session.next_required("license rejection")?;
        match message_kind(&message, expected_id)? {
            "event" => match parse_install_event(&message, expected_id)? {
                InstallProbeEvent::Phase(phase)
                    if EXPECTED_PHASES.get(next_phase) == Some(&phase.as_str()) =>
                {
                    next_phase += 1;
                }
                InstallProbeEvent::Phase(_) => {
                    return Err("packaged backend emitted invalid license-denial phases".into());
                }
                InstallProbeEvent::Action(_) | InstallProbeEvent::Progress(_) => {
                    return Err("license-denied install emitted mutation work".into());
                }
            },
            "error" => {
                if next_phase != EXPECTED_PHASES.len()
                    || backend_error_code(&message, expected_id)? != "license_not_accepted"
                {
                    return Err("packaged backend did not enforce license acceptance".into());
                }
                return Ok(());
            }
            "result" => return Err("license-denied install unexpectedly succeeded".into()),
            _ => unreachable!("message kind is validated"),
        }
    }
}

fn consume_uninstall(
    session: &mut LifecycleSession,
    expected_id: &str,
) -> Result<UninstallTerminal, String> {
    let mut phases = PhaseTracker::default();
    let mut progress = ProgressTracker::default();
    loop {
        let message = session.next_required("uninstall")?;
        match message_kind(&message, expected_id)? {
            "event" => {
                if phases.completed {
                    return Err("packaged backend emitted uninstall events after completion".into());
                }
                match parse_uninstall_event(&message, expected_id)? {
                    UninstallProbeEvent::Phase(phase) => {
                        phases.observe(&phase, UNINSTALL_PHASES, "uninstall")?;
                    }
                    UninstallProbeEvent::Progress(value) => progress.observe(value, true)?,
                }
            }
            "result" => {
                phases.finish(UNINSTALL_PHASES, "uninstall")?;
                let (total_files, total_bytes) = progress.finish("uninstall")?;
                if total_bytes != 0 {
                    return Err("packaged backend uninstall progress exposed byte counts".into());
                }
                let mut terminal = parse_uninstall_result(&message, expected_id)?;
                if terminal
                    .removed_files
                    .checked_add(terminal.missing_files)
                    .and_then(|count| count.checked_add(terminal.preserved_modified_files))
                    != Some(total_files)
                {
                    return Err("packaged backend uninstall result did not match progress".into());
                }
                terminal.progress_events = progress.events;
                return Ok(terminal);
            }
            "error" => return Err(backend_rejection(&message, expected_id, "uninstall")),
            _ => unreachable!("message kind is validated"),
        }
    }
}

fn parse_install_result(message: &Value, expected_id: &str) -> Result<InstallTerminal, String> {
    let result = strict_result(message, expected_id, "install")?;
    let fields = value_object(result, "install result")?;
    exact_keys(
        fields,
        &[
            "action",
            "packageId",
            "installedFiles",
            "installedBytes",
            "installDirectory",
        ],
        "install result",
    )?;
    let action = object_string(fields, "action", "install action")?;
    if !matches!(action, "install" | "update" | "repair" | "downgrade") {
        return Err("packaged backend install result has invalid action".into());
    }
    let package_id = object_string(fields, "packageId", "installed package id")?;
    let install_directory = object_string(fields, "installDirectory", "installed directory")?;
    if !valid_package_id(package_id) || !valid_install_directory(install_directory) {
        return Err("packaged backend install result has invalid identity".into());
    }
    Ok(InstallTerminal {
        action: action.to_owned(),
        package_id: package_id.to_owned(),
        install_directory: install_directory.to_owned(),
        installed_files: object_u64(fields, "installedFiles", "installed file count")?,
        installed_bytes: object_u64(fields, "installedBytes", "installed byte count")?,
        progress_events: 0,
    })
}

fn parse_uninstall_result(message: &Value, expected_id: &str) -> Result<UninstallTerminal, String> {
    let result = strict_result(message, expected_id, "uninstall")?;
    let fields = value_object(result, "uninstall result")?;
    let status = object_string(fields, "status", "uninstall status")?;
    if status != "uninstalled" {
        return Err("packaged backend reported package was not installed".into());
    }
    exact_keys(
        fields,
        &[
            "status",
            "packageId",
            "removedFiles",
            "missingFiles",
            "preservedModifiedFiles",
        ],
        "uninstall result",
    )?;
    let package_id = object_string(fields, "packageId", "uninstalled package id")?;
    if !valid_package_id(package_id) {
        return Err("packaged backend uninstall result has invalid identity".into());
    }
    Ok(UninstallTerminal {
        package_id: package_id.to_owned(),
        removed_files: object_u64(fields, "removedFiles", "removed file count")?,
        missing_files: object_u64(fields, "missingFiles", "missing file count")?,
        preserved_modified_files: object_u64(
            fields,
            "preservedModifiedFiles",
            "preserved modified file count",
        )?,
        progress_events: 0,
    })
}

fn parse_launch_result(
    message: &Value,
    expected_id: &str,
    expected_package_id: &str,
) -> Result<(), String> {
    let result = strict_result(message, expected_id, "launch")?;
    let fields = value_object(result, "launch result")?;
    exact_keys(fields, &["status", "packageId"], "launch result")?;
    if fields.get("status").and_then(Value::as_str) != Some("launched")
        || fields.get("packageId").and_then(Value::as_str) != Some(expected_package_id)
    {
        return Err("packaged backend returned an invalid launch result".into());
    }
    Ok(())
}

fn parse_install_event(message: &Value, expected_id: &str) -> Result<InstallProbeEvent, String> {
    let (event, data) = event_parts(message, expected_id, "install")?;
    match event {
        "action" => {
            exact_keys(data, &["action"], "install action event")?;
            let action = object_string(data, "action", "install action")?;
            if matches!(action, "install" | "update" | "repair" | "downgrade") {
                Ok(InstallProbeEvent::Action(action.to_owned()))
            } else {
                Err("packaged backend emitted an invalid install action".into())
            }
        }
        "phase" => {
            exact_keys(data, &["phase"], "install phase event")?;
            Ok(InstallProbeEvent::Phase(
                object_string(data, "phase", "install phase")?.to_owned(),
            ))
        }
        "progress" => Ok(InstallProbeEvent::Progress(parse_progress(data)?)),
        _ => Err("packaged backend emitted an invalid install event".into()),
    }
}

fn parse_uninstall_event(
    message: &Value,
    expected_id: &str,
) -> Result<UninstallProbeEvent, String> {
    let (event, data) = event_parts(message, expected_id, "uninstall")?;
    match event {
        "phase" => {
            exact_keys(data, &["phase"], "uninstall phase event")?;
            Ok(UninstallProbeEvent::Phase(
                object_string(data, "phase", "uninstall phase")?.to_owned(),
            ))
        }
        "progress" => Ok(UninstallProbeEvent::Progress(parse_progress(data)?)),
        _ => Err("packaged backend emitted an invalid uninstall event".into()),
    }
}

fn event_parts<'a>(
    message: &'a Value,
    expected_id: &str,
    label: &str,
) -> Result<(&'a str, &'a Map<String, Value>), String> {
    if message_kind(message, expected_id)? != "event" {
        return Err(format!("packaged backend returned a non-event for {label}"));
    }
    let fields = value_object(message, "event envelope")?;
    exact_keys(
        fields,
        &["protocolVersion", "type", "id", "event", "data"],
        "event envelope",
    )?;
    let event = object_string(fields, "event", "event name")?;
    let data = value_object(
        fields
            .get("data")
            .ok_or_else(|| format!("packaged backend {label} event has no data"))?,
        "event data",
    )?;
    Ok((event, data))
}

fn parse_progress(data: &Map<String, Value>) -> Result<ProgressValue, String> {
    exact_keys(
        data,
        &[
            "completedFiles",
            "totalFiles",
            "completedBytes",
            "totalBytes",
        ],
        "progress event",
    )?;
    Ok(ProgressValue {
        completed_files: object_u64(data, "completedFiles", "completed file count")?,
        total_files: object_u64(data, "totalFiles", "total file count")?,
        completed_bytes: object_u64(data, "completedBytes", "completed byte count")?,
        total_bytes: object_u64(data, "totalBytes", "total byte count")?,
    })
}

fn require_target(value: &Value, host: HostLayout, label: &str) -> Result<(), String> {
    let os = value_string(value, "/target/os", "target OS")?;
    let arch = value_string(value, "/target/arch", "target architecture")?;
    if os == host.rust_os && arch == host.rust_arch {
        Ok(())
    } else {
        Err(format!(
            "{label} target `{os}/{arch}` does not match host `{}/{}`",
            host.rust_os, host.rust_arch
        ))
    }
}

fn value_string<'a>(value: &'a Value, pointer: &str, label: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Rust backend response has no valid {label}"))
}

fn value_u64(value: &Value, pointer: &str, label: &str) -> Result<u64, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("Rust backend response has no valid {label}"))
}

fn validate_runner_trust(value: &Value, format_version: u64) -> Result<(), String> {
    let trust = value
        .as_object()
        .ok_or_else(|| "Rust backend returned an invalid package trust".to_owned())?;
    if trust.len() == 1
        && trust.get("kind").and_then(Value::as_str) == Some("unsigned")
        && format_version == 1
    {
        Ok(())
    } else {
        Err("native runner assembly accepts only unsigned .luxpkg v1 until native container signing establishes the publisher trust anchor".into())
    }
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn studio_probe_requires_exact_stdout_and_empty_stderr() {
        let exact = b"{\"studioVerified\":true}\n";
        assert!(require_studio_probe_output(exact, b"").is_ok());
        for (stdout, stderr) in [
            (&exact[..exact.len() - 1], &b""[..]),
            (&b" {\"studioVerified\":true}\n"[..], &b""[..]),
            (&exact[..], &b"warning"[..]),
            (&b"{\"verified\":true}\n"[..], &b""[..]),
        ] {
            assert!(require_studio_probe_output(stdout, stderr).is_err());
        }
    }

    #[test]
    fn runner_accepts_only_exact_unsigned_v1_trust() {
        assert!(validate_runner_trust(&json!({"kind": "unsigned"}), 1).is_ok());
        assert!(
            validate_runner_trust(
                &json!({"kind": "trustedPublisher", "keyId": "a".repeat(64)}),
                2,
            )
            .is_err()
        );
        assert!(validate_runner_trust(&json!({"kind": "unsigned", "extra": true}), 1).is_err());
        assert!(validate_runner_trust(&json!({"kind": "unsigned"}), 2).is_err());
    }

    #[test]
    fn package_id_contract_matches_core_hyphen_rules() {
        assert!(valid_package_id("dev.foo--bar"));
        assert!(!valid_package_id("devfoo"));
        assert!(!valid_package_id("dev.foo-"));
        assert!(!valid_package_id("dev..foo"));
    }

    #[test]
    fn launch_marker_parser_requires_exact_port_bound_token() {
        let marker = format!("{LAUNCH_MARKER_MAGIC}\n43123\n0000002aa873\n");
        assert_eq!(
            parse_launch_marker(marker.as_bytes()).unwrap(),
            (43123, 42, "0000002aa873".into())
        );
        for invalid in [
            format!("{LAUNCH_MARKER_MAGIC}\n0\n0000002a0000\n"),
            format!("{LAUNCH_MARKER_MAGIC}\n043123\n0000002aa873\n"),
            format!("{LAUNCH_MARKER_MAGIC}\n43123\n00000000a873\n"),
            format!("{LAUNCH_MARKER_MAGIC}\n43123\n0000002a0001\n"),
            format!("{LAUNCH_MARKER_MAGIC}\n43123\n0000002AA873\n"),
            format!("{LAUNCH_MARKER_MAGIC}\n43123\n0000002aa873"),
            "wrong\n43123\n0000002aa873\n".to_owned(),
        ] {
            assert!(parse_launch_marker(invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn launch_exit_transport_accepts_only_eof_or_connection_reset() {
        assert!(require_launch_stream_close(Ok(0)).is_ok());
        assert!(
            require_launch_stream_close(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
                .is_ok()
        );
        assert!(require_launch_stream_close(Ok(1)).is_err());
        assert!(
            require_launch_stream_close(Err(io::Error::other("unexpected transport error")))
                .is_err()
        );
    }

    #[test]
    fn lifecycle_terminal_parsers_are_strict_and_correlated() {
        let install = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "result",
            "id": "lifecycle_install",
            "result": {
                "action": "install",
                "packageId": "dev.luxury.demo",
                "installedFiles": 1,
                "installedBytes": 5,
                "installDirectory": "LuxuryDemo",
            },
        });
        let parsed = parse_install_result(&install, "lifecycle_install").unwrap();
        assert_eq!(parsed.action, "install");
        assert_eq!(parsed.installed_files, 1);
        assert!(parse_install_result(&install, "another_id").is_err());

        let uninstall = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "result",
            "id": "lifecycle_uninstall",
            "result": {
                "status": "uninstalled",
                "packageId": "dev.luxury.demo",
                "removedFiles": 1,
                "missingFiles": 0,
                "preservedModifiedFiles": 0,
            },
        });
        let parsed = parse_uninstall_result(&uninstall, "lifecycle_uninstall").unwrap();
        assert_eq!(parsed.removed_files, 1);

        let launch = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "result",
            "id": "launch_execute",
            "result": {
                "status": "launched",
                "packageId": "dev.luxury.demo",
            },
        });
        parse_launch_result(&launch, "launch_execute", "dev.luxury.demo").unwrap();
        assert!(parse_launch_result(&launch, "launch_execute", "dev.luxury.other").is_err());
        let mut leaked_launch = launch;
        leaked_launch["result"]["path"] = json!(r"C:\private\app.exe");
        let error =
            parse_launch_result(&leaked_launch, "launch_execute", "dev.luxury.demo").unwrap_err();
        assert!(!error.contains("private"));

        let mut leaked = install;
        leaked["result"]["installBase"] = json!(r"C:\private\install");
        let error = parse_install_result(&leaked, "lifecycle_install").unwrap_err();
        assert!(!error.contains("private"));
        assert!(!error.contains(r"C:\"));

        let rejection = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "error",
            "id": "lifecycle_install",
            "error": {
                "code": "io_error",
                "message": r"failed at C:\private\modified.txt",
            },
        });
        let error = strict_result(&rejection, "lifecycle_install", "install").unwrap_err();
        assert!(error.contains("io_error"));
        assert!(!error.contains("private"));
        assert!(!error.contains("modified.txt"));

        let mut cancellation = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "result",
            "id": "cancellation_request",
            "result": {"requestId": "cancellation_install", "accepted": true},
        });
        require_cancel_accepted(
            &cancellation,
            "cancellation_request",
            "cancellation_install",
        )
        .unwrap();
        cancellation["result"]["accepted"] = json!(false);
        assert!(
            require_cancel_accepted(
                &cancellation,
                "cancellation_request",
                "cancellation_install"
            )
            .is_err()
        );

        let cancelled = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "error",
            "id": "cancellation_install",
            "error": {"code": "cancelled", "message": r"rolled back C:\private\file"},
        });
        assert_eq!(
            backend_error_code(&cancelled, "cancellation_install").unwrap(),
            "cancelled"
        );
    }

    #[test]
    fn lifecycle_install_totals_are_bound_to_inspected_payload() {
        let host = HostLayout::new(std::env::consts::OS, std::env::consts::ARCH).unwrap();
        let inspect = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "result",
            "id": "lifecycle_inspect",
            "result": {
                "formatVersion": 1,
                "schemaVersion": 3,
                "packageFingerprint": "a".repeat(64),
                "trust": { "kind": "unsigned" },
                "publisherRotation": null,
                "package": {
                    "id": "dev.luxury.demo",
                    "name": "Luxury Demo",
                    "publisher": "Luxury Software",
                    "version": "1.0.0",
                    "license": SMOKE_LICENSE,
                },
                "target": { "os": host.rust_os, "arch": host.rust_arch },
                "install": {
                    "scope": "user",
                    "directory": "LuxuryDemo",
                    "hasEntrypoint": false,
                },
                "payload": { "files": 1, "bytes": 5 },
            },
        });
        let mut launch_inspect = inspect.clone();
        launch_inspect["id"] = json!("launch_inspect");
        launch_inspect["result"]["schemaVersion"] = json!(2);
        launch_inspect["result"]["install"]["hasEntrypoint"] = json!(true);
        launch_inspect["result"]["package"]
            .as_object_mut()
            .unwrap()
            .remove("license");
        let launch_inspect = parse_launch_inspect(launch_inspect, "launch_inspect", host).unwrap();
        assert_eq!(launch_inspect.payload_files, 1);

        let inspect = parse_inspect(inspect, "lifecycle_inspect", host).unwrap();
        assert_eq!(inspect.payload_files, 1);
        assert_eq!(inspect.payload_bytes, 5);

        let mut installed = InstallTerminal {
            action: "install".into(),
            package_id: "dev.luxury.demo".into(),
            install_directory: "LuxuryDemo".into(),
            installed_files: 1,
            installed_bytes: 5,
            progress_events: 2,
        };
        validate_install_against_inspect(&inspect, &installed).unwrap();
        installed.installed_bytes = 6;
        assert!(validate_install_against_inspect(&inspect, &installed).is_err());
        installed.installed_bytes = 5;
        installed.installed_files = 2;
        assert!(validate_install_against_inspect(&inspect, &installed).is_err());
    }

    #[test]
    fn lifecycle_event_parsers_reject_paths_and_uninstall_bytes() {
        let action = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "event",
            "id": "lifecycle_install",
            "event": "action",
            "data": { "action": "install" },
        });
        assert!(matches!(
            parse_install_event(&action, "lifecycle_install").unwrap(),
            InstallProbeEvent::Action(action) if action == "install"
        ));

        let mut leaked = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "event",
            "id": "lifecycle_uninstall",
            "event": "progress",
            "data": {
                "completedFiles": 1,
                "totalFiles": 1,
                "completedBytes": 0,
                "totalBytes": 0,
                "path": r"C:\private\modified.txt",
            },
        });
        let error = parse_uninstall_event(&leaked, "lifecycle_uninstall").unwrap_err();
        assert!(!error.contains("private"));
        assert!(!error.contains("modified.txt"));

        leaked["data"].as_object_mut().unwrap().remove("path");
        leaked["data"]["completedBytes"] = json!(1);
        leaked["data"]["totalBytes"] = json!(1);
        let UninstallProbeEvent::Progress(progress) =
            parse_uninstall_event(&leaked, "lifecycle_uninstall").unwrap()
        else {
            panic!("expected uninstall progress");
        };
        assert!(ProgressTracker::default().observe(progress, true).is_err());
    }

    #[test]
    fn lifecycle_reader_rejects_any_line_after_terminal() {
        let terminal = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "result",
            "id": "lifecycle_uninstall",
            "result": {
                "status": "uninstalled",
                "packageId": "dev.luxury.demo",
                "removedFiles": 1,
                "missingFiles": 0,
                "preservedModifiedFiles": 0,
            },
        });
        let trailing = json!({ "path": r"C:\private\modified.txt" });
        let input = format!("{terminal}\n{trailing}\n");
        let mut reader = BoundedJsonl::new(Cursor::new(input));
        let first = reader.next_value().unwrap().unwrap();
        parse_uninstall_result(&first, "lifecycle_uninstall").unwrap();
        let error = require_jsonl_eof(&mut reader).unwrap_err();
        assert!(error.contains("after the terminal result"));
        assert!(!error.contains("private"));
        assert!(!error.contains("modified.txt"));
    }

    #[test]
    fn crash_reader_ignores_only_a_bounded_invalid_tail() {
        let partial = format!(r#"{{"protocolVersion":{PROTOCOL_VERSION},"type":"event""#);
        let mut reader = BoundedJsonl::new(Cursor::new(partial));
        assert!(reader.next_crash_value().unwrap().is_none());

        let terminal = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "result",
            "id": "crash_install",
            "result": {},
        })
        .to_string();
        let mut crash_reader = BoundedJsonl::new(Cursor::new(&terminal));
        assert_eq!(
            crash_reader.next_crash_value().unwrap().unwrap()["type"],
            "result"
        );

        let mut normal_reader = BoundedJsonl::new(Cursor::new(terminal));
        assert!(
            normal_reader
                .next_value()
                .unwrap_err()
                .contains("unterminated")
        );
    }
}
