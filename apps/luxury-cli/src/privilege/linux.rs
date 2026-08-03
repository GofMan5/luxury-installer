use std::{
    cell::Cell,
    env,
    ffi::OsString,
    fs::{File, Metadata},
    io::{self, IoSliceMut, Read},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::{ffi::OsStringExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use luxury_engine::{
    install::{
        InstallAction, InstallCommand, InstallEvent, InstallPhase, InstallProgress, install,
        prepare_system_install,
    },
    launch::{LaunchCommand, launch},
    uninstall::{
        UninstallCommand, UninstallEvent, UninstallOutcome, UninstallPhase, UninstallProgress,
        uninstall,
    },
};
use luxury_platform::{LinuxSystemLaunchAdapter, LocalInstallAdapter, LocalUninstallAdapter};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendFlags, UCred, recvmsg,
    sockopt::{Timeout, set_socket_timeout, socket_passcred, socket_peercred},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const PROTOCOL_VERSION: u8 = 1;
const MAX_FRAME_BYTES: usize = 4 * 1024;
const MAX_ENVIRONMENT_BYTES: usize = 64 * 1024;
const HELPER_PATH: &str = "/usr/libexec/luxury-installer-helper";
const LAUNCHER_PATH: &str = "/usr/bin/luxury-installer";
const POLICY_PATH: &str = "/usr/share/polkit-1/actions/software.luxury.installer.policy";
const POLICY_BYTES: &[u8] =
    include_bytes!("../../../../packaging/linux/software.luxury.installer.policy");

pub(super) fn guard_command(command: &std::ffi::OsStr) -> io::Result<()> {
    let restricted = running_as_installed_helper()?;
    if helper_command_allowed(restricted, command) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "installed privilege helper accepts only a system action",
        ))
    }
}

fn running_as_installed_helper() -> io::Result<bool> {
    let installed = match rustix::fs::open(
        HELPER_PATH,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(error) => return Err(os_error(error)),
    };
    let running = File::open("/proc/self/exe")?;
    Ok(file_identity(&installed.metadata()?) == file_identity(&running.metadata()?))
}

fn helper_command_allowed(restricted: bool, command: &std::ffi::OsStr) -> bool {
    !restricted
        || matches!(
            command.to_str(),
            Some(
                "privilege-authorize-install"
                    | "privilege-install-system"
                    | "privilege-uninstall-system"
                    | "privilege-launch-system"
            )
        )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SystemMode {
    AuthorizeInstall,
    Install,
    Uninstall,
    Launch,
}

impl SystemMode {
    const fn challenge_action(self) -> &'static str {
        match self {
            Self::AuthorizeInstall => "authorizeInstall",
            Self::Install => "install",
            Self::Uninstall => "uninstall",
            Self::Launch => "launch",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Challenge {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: String,
    operation_id: String,
    action: String,
    caller_pid: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Ready<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
    caller_pid: u32,
    caller_uid: u32,
    helper_pid: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorizationRequest {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: String,
    operation_id: String,
    action: String,
    package_id: String,
    package_fingerprint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallAuthorized<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
    package_id: &'a str,
    package_fingerprint: &'a str,
    preparation: &'a crate::stdio::PrepareInstallResult,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SystemInstallRequest {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: String,
    operation_id: String,
    action: String,
    package_id: String,
    package_fingerprint: String,
    allow_unsigned: bool,
    accept_license: bool,
    allow_publisher_migration: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SystemMaintenanceRequest {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: String,
    operation_id: String,
    action: String,
    package_id: String,
    package_fingerprint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CancelOperationRequest {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: String,
    operation_id: String,
    action: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallPhaseFrame<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    phase: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallActionFrame<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallProgressFrame<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    completed_files: u64,
    total_files: u64,
    completed_bytes: u64,
    total_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallCompleteFrame<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
    package_id: &'a str,
    install_directory: &'a str,
    installed_files: u64,
    installed_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallFailedFrame<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    code: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UninstallPhaseFrame<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    phase: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UninstallProgressFrame<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    processed_files: u64,
    total_files: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UninstallCompleteFrame<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    status: &'static str,
    package_id: &'a str,
    removed_files: u64,
    missing_files: u64,
    preserved_modified_files: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UninstallFailedFrame<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    code: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LaunchCompleteFrame<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    status: &'static str,
    package_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LaunchFailedFrame<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    code: &'static str,
}

#[derive(Clone)]
struct CallerIdentity {
    credentials: UCred,
    groups: Vec<u32>,
    environment: Vec<(OsString, OsString)>,
}

struct TransportState {
    cancelled: Arc<AtomicBool>,
    failed: Arc<Mutex<Option<io::Error>>>,
}

pub(super) fn run(args: &[OsString], mode: SystemMode) -> io::Result<()> {
    if !args.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Linux privilege helper accepts no arguments",
        ));
    }
    if !rustix::process::getuid().is_root()
        || !rustix::process::geteuid().is_root()
        || !rustix::process::getgid().is_root()
        || !rustix::process::getegid().is_root()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "polkit helper did not receive root credentials",
        ));
    }
    verify_installed_identity()?;

    let stdin = io::stdin();
    let socket = stdin.as_fd();
    if !socket_passcred(socket).map_err(os_error)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "polkit transport did not require kernel credentials",
        ));
    }
    let peer = socket_peercred(socket).map_err(os_error)?;
    let caller = validate_caller(peer)?;
    let (challenge, descriptor) = receive_frame::<Challenge, _>(socket, caller.credentials, false)?;
    if descriptor.is_some() || !challenge_matches(&challenge, mode, &caller) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "polkit challenge did not match the authenticated caller",
        ));
    }
    send_frame(
        socket,
        &Ready {
            protocol_version: PROTOCOL_VERSION,
            kind: "ready",
            operation_id: &challenge.operation_id,
            action: mode.challenge_action(),
            caller_pid: caller.credentials.pid.as_raw_pid() as u32,
            caller_uid: caller.credentials.uid.as_raw(),
            helper_pid: std::process::id(),
        },
    )?;

    match mode {
        SystemMode::AuthorizeInstall => authorize_install(socket, &caller, &challenge.operation_id),
        SystemMode::Install => execute_system_install(socket, caller, &challenge.operation_id),
        SystemMode::Uninstall => execute_system_uninstall(socket, caller, &challenge.operation_id),
        SystemMode::Launch => execute_system_launch(socket, caller, &challenge.operation_id),
    }
}

fn authorize_install(
    socket: BorrowedFd<'_>,
    caller: &CallerIdentity,
    operation_id: &str,
) -> io::Result<()> {
    let (request, package) =
        receive_frame::<AuthorizationRequest, _>(socket, caller.credentials, true)?;
    if !authorization_matches(&request, operation_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system install authorization request was invalid",
        ));
    }
    let package = File::from(package.ok_or_else(missing_package_descriptor)?);
    let (bundle, install_base, state_root) =
        validate_authorized_package(package, &request.package_id, &request.package_fingerprint)?;
    let manifest = bundle.manifest().clone();
    let mut adapter = LocalInstallAdapter::for_system(bundle, install_base, state_root);
    let preparation = prepare_system_install(manifest, &mut adapter)
        .map_err(|_| io::Error::other("system installation preparation failed"))?;
    let preparation = crate::stdio::PrepareInstallResult::from_outcome(preparation)
        .map_err(|_| io::Error::other("system preparation result was invalid"))?;
    send_frame(
        socket,
        &InstallAuthorized {
            protocol_version: PROTOCOL_VERSION,
            kind: "installAuthorized",
            operation_id,
            action: "install",
            package_id: &request.package_id,
            package_fingerprint: &request.package_fingerprint,
            preparation: &preparation,
        },
    )
}

fn execute_system_install(
    socket: BorrowedFd<'_>,
    caller: CallerIdentity,
    operation_id: &str,
) -> io::Result<()> {
    let (request, package) =
        receive_frame::<SystemInstallRequest, _>(socket, caller.credentials, true)?;
    if !system_install_matches(&request, operation_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system install request was invalid",
        ));
    }
    let package = File::from(package.ok_or_else(missing_package_descriptor)?);
    let (bundle, install_base, state_root) =
        validate_authorized_package(package, &request.package_id, &request.package_fingerprint)?;
    let manifest = bundle.manifest().clone();
    if !request.allow_unsigned || request.accept_license != manifest.package.license.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "system install consent did not match the authorized package",
        ));
    }
    let transport = start_cancel_reader(socket, caller.credentials, operation_id, "install")?;
    let install_directory = manifest.install.directory.as_str().to_owned();
    let command = InstallCommand::for_system(manifest)
        .with_license_acceptance(request.accept_license)
        .with_publisher_migration_approval(request.allow_publisher_migration);
    let mut adapter = LocalInstallAdapter::for_system(bundle, install_base, state_root);
    let last_progress = Cell::new(None::<u64>);
    let result = install(
        command,
        &mut adapter,
        || transport.cancelled.load(Ordering::Acquire),
        |event| {
            if transport_failed(&transport) {
                return;
            }
            if let Err(error) = write_install_event(socket, operation_id, event, &last_progress) {
                fail_transport(&transport, error);
            }
        },
    );
    require_transport(&transport)?;
    match result {
        Ok(outcome) => send_frame(
            socket,
            &InstallCompleteFrame {
                protocol_version: PROTOCOL_VERSION,
                kind: "installComplete",
                operation_id,
                action: install_action(outcome.action),
                package_id: outcome.package_id.as_str(),
                install_directory: &install_directory,
                installed_files: outcome.installed_files as u64,
                installed_bytes: outcome.installed_bytes,
            },
        ),
        Err(error) => send_frame(
            socket,
            &InstallFailedFrame {
                protocol_version: PROTOCOL_VERSION,
                kind: "installFailed",
                operation_id,
                code: crate::stdio::install_error_code(&error),
            },
        ),
    }
}

fn execute_system_uninstall(
    socket: BorrowedFd<'_>,
    caller: CallerIdentity,
    operation_id: &str,
) -> io::Result<()> {
    let (request, package) =
        receive_frame::<SystemMaintenanceRequest, _>(socket, caller.credentials, true)?;
    if !system_maintenance_matches(&request, operation_id, "uninstall", "uninstallSystem") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system uninstall request was invalid",
        ));
    }
    let package = File::from(package.ok_or_else(missing_package_descriptor)?);
    let (bundle, install_base, state_root) =
        validate_authorized_package(package, &request.package_id, &request.package_fingerprint)?;
    let package_id = bundle.manifest().package.id.clone();
    drop(bundle);
    let transport = start_cancel_reader(socket, caller.credentials, operation_id, "uninstall")?;
    let mut adapter = LocalUninstallAdapter::for_system(install_base, state_root);
    let last_progress = Cell::new(None::<u64>);
    let result = uninstall(
        UninstallCommand::for_system(package_id.clone()),
        &mut adapter,
        || transport.cancelled.load(Ordering::Acquire),
        |event| {
            if transport_failed(&transport) {
                return;
            }
            if let Err(error) = write_uninstall_event(socket, operation_id, event, &last_progress) {
                fail_transport(&transport, error);
            }
        },
    );
    require_transport(&transport)?;
    match result {
        Ok(UninstallOutcome::NotInstalled) => send_frame(
            socket,
            &UninstallCompleteFrame {
                protocol_version: PROTOCOL_VERSION,
                kind: "uninstallComplete",
                operation_id,
                status: "notInstalled",
                package_id: package_id.as_str(),
                removed_files: 0,
                missing_files: 0,
                preserved_modified_files: 0,
            },
        ),
        Ok(UninstallOutcome::Uninstalled {
            removed_files,
            missing_files,
            preserved_modified_files,
        }) => send_frame(
            socket,
            &UninstallCompleteFrame {
                protocol_version: PROTOCOL_VERSION,
                kind: "uninstallComplete",
                operation_id,
                status: "uninstalled",
                package_id: package_id.as_str(),
                removed_files: removed_files as u64,
                missing_files: missing_files as u64,
                preserved_modified_files: preserved_modified_files as u64,
            },
        ),
        Err(error) => send_frame(
            socket,
            &UninstallFailedFrame {
                protocol_version: PROTOCOL_VERSION,
                kind: "uninstallFailed",
                operation_id,
                code: crate::stdio::uninstall_error_code(&error),
            },
        ),
    }
}

fn execute_system_launch(
    socket: BorrowedFd<'_>,
    caller: CallerIdentity,
    operation_id: &str,
) -> io::Result<()> {
    let (request, package) =
        receive_frame::<SystemMaintenanceRequest, _>(socket, caller.credentials, true)?;
    if !system_maintenance_matches(&request, operation_id, "launch", "launchSystem") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system launch request was invalid",
        ));
    }
    let package = File::from(package.ok_or_else(missing_package_descriptor)?);
    let (bundle, install_base, state_root) =
        validate_authorized_package(package, &request.package_id, &request.package_fingerprint)?;
    let package_id = bundle.manifest().package.id.clone();
    drop(bundle);
    let mut adapter = LinuxSystemLaunchAdapter::new(
        install_base,
        state_root,
        caller.credentials.uid.as_raw(),
        caller.credentials.gid.as_raw(),
        caller.groups,
        caller.environment,
    );
    match launch(LaunchCommand::for_system(package_id.clone()), &mut adapter) {
        Ok(()) => send_frame(
            socket,
            &LaunchCompleteFrame {
                protocol_version: PROTOCOL_VERSION,
                kind: "launchComplete",
                operation_id,
                status: "launched",
                package_id: package_id.as_str(),
            },
        ),
        Err(error) => send_frame(
            socket,
            &LaunchFailedFrame {
                protocol_version: PROTOCOL_VERSION,
                kind: "launchFailed",
                operation_id,
                code: crate::stdio::launch_error_code(&error),
            },
        ),
    }
}

fn start_cancel_reader(
    socket: BorrowedFd<'_>,
    credentials: UCred,
    operation_id: &str,
    action: &str,
) -> io::Result<TransportState> {
    set_socket_timeout(socket, Timeout::Recv, None).map_err(os_error)?;
    let reader = rustix::io::dup(socket).map_err(os_error)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(Mutex::new(None));
    let thread_cancelled = Arc::clone(&cancelled);
    let thread_failed = Arc::clone(&failed);
    let operation_id = operation_id.to_owned();
    let action = action.to_owned();
    thread::Builder::new()
        .name("luxury-system-cancel".into())
        .spawn(move || {
            let result = receive_frame::<CancelOperationRequest, _>(&reader, credentials, false)
                .and_then(|(request, descriptor)| {
                    if descriptor.is_none()
                        && request.protocol_version == PROTOCOL_VERSION
                        && request.kind == "cancelOperation"
                        && request.operation_id == operation_id
                        && request.action == action
                    {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "system operation cancellation frame was invalid",
                        ))
                    }
                });
            match result {
                Ok(()) => thread_cancelled.store(true, Ordering::Release),
                Err(error) => {
                    *thread_failed
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
                    thread_cancelled.store(true, Ordering::Release);
                }
            }
        })?;
    Ok(TransportState { cancelled, failed })
}

fn transport_failed(transport: &TransportState) -> bool {
    transport
        .failed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

fn fail_transport(transport: &TransportState, error: io::Error) {
    let mut failed = transport
        .failed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if failed.is_none() {
        *failed = Some(error);
    }
    transport.cancelled.store(true, Ordering::Release);
}

fn require_transport(transport: &TransportState) -> io::Result<()> {
    let mut failed = transport
        .failed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match failed.take() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn write_install_event(
    socket: BorrowedFd<'_>,
    operation_id: &str,
    event: InstallEvent,
    last_progress: &Cell<Option<u64>>,
) -> io::Result<()> {
    match event {
        InstallEvent::Phase(phase) => send_frame(
            socket,
            &InstallPhaseFrame {
                protocol_version: PROTOCOL_VERSION,
                kind: "installPhase",
                operation_id,
                phase: install_phase(phase),
            },
        ),
        InstallEvent::Action(action) => send_frame(
            socket,
            &InstallActionFrame {
                protocol_version: PROTOCOL_VERSION,
                kind: "installAction",
                operation_id,
                action: install_action(action),
            },
        ),
        InstallEvent::Progress(progress) => {
            let completed = progress.completed_files as u64;
            let total = progress.total_files as u64;
            if !should_emit_progress(last_progress.get(), completed, total) {
                return Ok(());
            }
            last_progress.set(Some(completed));
            write_install_progress(socket, operation_id, progress)
        }
    }
}

fn write_install_progress(
    socket: BorrowedFd<'_>,
    operation_id: &str,
    progress: InstallProgress,
) -> io::Result<()> {
    send_frame(
        socket,
        &InstallProgressFrame {
            protocol_version: PROTOCOL_VERSION,
            kind: "installProgress",
            operation_id,
            completed_files: progress.completed_files as u64,
            total_files: progress.total_files as u64,
            completed_bytes: progress.completed_bytes,
            total_bytes: progress.total_bytes,
        },
    )
}

fn write_uninstall_event(
    socket: BorrowedFd<'_>,
    operation_id: &str,
    event: UninstallEvent,
    last_progress: &Cell<Option<u64>>,
) -> io::Result<()> {
    match event {
        UninstallEvent::Phase(phase) => send_frame(
            socket,
            &UninstallPhaseFrame {
                protocol_version: PROTOCOL_VERSION,
                kind: "uninstallPhase",
                operation_id,
                phase: uninstall_phase(phase),
            },
        ),
        UninstallEvent::Progress(progress) => {
            let completed = progress.processed_files as u64;
            let total = progress.total_files as u64;
            if !should_emit_progress(last_progress.get(), completed, total) {
                return Ok(());
            }
            last_progress.set(Some(completed));
            write_uninstall_progress(socket, operation_id, progress)
        }
        UninstallEvent::PreservedModified(_) => Ok(()),
    }
}

fn write_uninstall_progress(
    socket: BorrowedFd<'_>,
    operation_id: &str,
    progress: UninstallProgress,
) -> io::Result<()> {
    send_frame(
        socket,
        &UninstallProgressFrame {
            protocol_version: PROTOCOL_VERSION,
            kind: "uninstallProgress",
            operation_id,
            processed_files: progress.processed_files as u64,
            total_files: progress.total_files as u64,
        },
    )
}

fn should_emit_progress(previous: Option<u64>, completed: u64, total: u64) -> bool {
    let stride = total.div_ceil(512).max(1);
    completed == 0
        || completed == total
        || previous.is_none_or(|previous| completed.saturating_sub(previous) >= stride)
}

const fn install_phase(phase: InstallPhase) -> &'static str {
    match phase {
        InstallPhase::Validating => "validating",
        InstallPhase::Verifying => "verifying",
        InstallPhase::Recovering => "recovering",
        InstallPhase::Planning => "planning",
        InstallPhase::Applying => "applying",
        InstallPhase::Committing => "committing",
        InstallPhase::RollingBack => "rollingBack",
        InstallPhase::Completed => "completed",
        InstallPhase::Cancelled => "cancelled",
        InstallPhase::Failed => "failed",
    }
}

const fn uninstall_phase(phase: UninstallPhase) -> &'static str {
    match phase {
        UninstallPhase::Recovering => "recovering",
        UninstallPhase::LoadingReceipt => "loadingReceipt",
        UninstallPhase::Removing => "removing",
        UninstallPhase::Committing => "committing",
        UninstallPhase::RollingBack => "rollingBack",
        UninstallPhase::Completed => "completed",
        UninstallPhase::Cancelled => "cancelled",
        UninstallPhase::Failed => "failed",
    }
}

const fn install_action(action: InstallAction) -> &'static str {
    match action {
        InstallAction::Install => "install",
        InstallAction::Update => "update",
        InstallAction::Repair => "repair",
        InstallAction::Downgrade => "downgrade",
    }
}

fn validate_authorized_package(
    package: File,
    package_id: &str,
    package_fingerprint: &str,
) -> io::Result<(luxury_bundle::Bundle, PathBuf, PathBuf)> {
    require_trusted_root_metadata(&package.metadata()?, false)?;
    let expected_id = luxury_spec::PackageId::parse(package_id).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "authorized package ID is invalid",
        )
    })?;
    let bundle = luxury_bundle::open_bundle(package, None).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "authorized package could not be verified",
        )
    })?;
    let manifest = bundle.manifest();
    if bundle.trust() != luxury_bundle::PackageTrust::Unsigned
        || manifest.format_version != luxury_spec::FORMAT_VERSION
        || manifest.package.id != expected_id
        || manifest.target != luxury_spec::Target::host()
        || manifest.install.scope != luxury_spec::InstallScope::System
        || bundle.review_fingerprint() != package_fingerprint
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authorized package identity, target, scope, or fingerprint did not match",
        ));
    }
    let (install_base, state_root) = luxury_platform::default_system_roots()?;
    if !install_base.is_absolute()
        || !state_root.is_absolute()
        || install_base.starts_with(&state_root)
        || state_root.starts_with(&install_base)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system installation roots are invalid",
        ));
    }
    Ok((bundle, install_base, state_root))
}

fn validate_caller(credentials: UCred) -> io::Result<CallerIdentity> {
    if credentials.uid.is_root() || credentials.gid.is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "polkit caller must be unprivileged",
        ));
    }
    let pkexec_uid = env::var("PKEXEC_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| value.to_string() == env::var("PKEXEC_UID").unwrap_or_default())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "polkit caller UID was not supplied canonically",
            )
        })?;
    if pkexec_uid != credentials.uid.as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "polkit caller UID did not match kernel credentials",
        ));
    }
    verify_caller_executable(credentials.pid.as_raw_pid() as u32)?;
    let status = read_process_file(credentials.pid.as_raw_pid() as u32, "status")?;
    let groups = parse_groups(&status)?;
    let environment = read_safe_environment(credentials.pid.as_raw_pid() as u32)?;
    Ok(CallerIdentity {
        credentials,
        groups,
        environment,
    })
}

fn verify_installed_identity() -> io::Result<()> {
    let installed = open_trusted_root_file(Path::new(HELPER_PATH), true, None)?;
    let running = File::open("/proc/self/exe")?;
    if file_identity(&installed.metadata()?) != file_identity(&running.metadata()?) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "running helper did not match the installed root-owned helper",
        ));
    }
    let _launcher = open_trusted_root_file(Path::new(LAUNCHER_PATH), true, None)?;
    let _policy = open_trusted_root_file(Path::new(POLICY_PATH), false, Some(POLICY_BYTES))?;
    Ok(())
}

fn verify_caller_executable(pid: u32) -> io::Result<()> {
    let installed = open_trusted_root_file(Path::new(LAUNCHER_PATH), true, None)?;
    let running = File::open(format!("/proc/{pid}/exe"))?;
    if file_identity(&installed.metadata()?) != file_identity(&running.metadata()?) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "polkit caller did not match the installed Tauri launcher",
        ));
    }
    Ok(())
}

fn open_trusted_root_file(
    path: &Path,
    executable: bool,
    exact_bytes: Option<&[u8]>,
) -> io::Result<File> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(os_error)?;
    let mut file = File::from(fd);
    require_trusted_root_metadata(&file.metadata()?, executable)?;
    if let Some(expected) = exact_bytes {
        let mut bytes = Vec::with_capacity(expected.len().saturating_add(1));
        file.by_ref()
            .take((expected.len() + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installed polkit policy did not match the reviewed policy",
            ));
        }
    }
    Ok(file)
}

fn require_trusted_root_metadata(metadata: &Metadata, executable: bool) -> io::Result<()> {
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || executable && metadata.mode() & 0o111 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "privileged input was not a private root-owned regular file",
        ));
    }
    Ok(())
}

fn file_identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn read_process_file(pid: u32, name: &str) -> io::Result<Vec<u8>> {
    let path = format!("/proc/{pid}/{name}");
    let mut bytes = Vec::new();
    File::open(path)?
        .take((MAX_ENVIRONMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_ENVIRONMENT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "caller process metadata exceeded its bound",
        ));
    }
    Ok(bytes)
}

fn parse_groups(status: &[u8]) -> io::Result<Vec<u32>> {
    let status = std::str::from_utf8(status)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "caller status was invalid"))?;
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "caller groups were absent"))?;
    let mut groups = Vec::new();
    for value in line.split_ascii_whitespace() {
        let group = value
            .parse::<u32>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "caller group was invalid"))?;
        if group == 0 || groups.len() >= 128 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "caller supplementary groups were privileged or excessive",
            ));
        }
        if !groups.contains(&group) {
            groups.push(group);
        }
    }
    Ok(groups)
}

fn read_safe_environment(pid: u32) -> io::Result<Vec<(OsString, OsString)>> {
    let bytes = read_process_file(pid, "environ")?;
    let mut environment = Vec::new();
    for entry in bytes
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let Some(separator) = entry.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let (name, value) = (&entry[..separator], &entry[separator + 1..]);
        if value.len() > 4_096 || !safe_environment_name(name) || unsafe_environment_value(value) {
            continue;
        }
        environment.push((
            OsString::from_vec(name.to_vec()),
            OsString::from_vec(value.to_vec()),
        ));
    }
    Ok(environment)
}

fn safe_environment_name(name: &[u8]) -> bool {
    const SAFE: &[&[u8]] = &[
        b"HOME",
        b"USER",
        b"LOGNAME",
        b"LANG",
        b"LANGUAGE",
        b"DISPLAY",
        b"WAYLAND_DISPLAY",
        b"XAUTHORITY",
        b"XDG_RUNTIME_DIR",
        b"DBUS_SESSION_BUS_ADDRESS",
        b"DESKTOP_STARTUP_ID",
    ];
    SAFE.contains(&name)
        || name.len() > 3
            && name.starts_with(b"LC_")
            && name[3..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || *byte == b'_')
}

fn unsafe_environment_value(value: &[u8]) -> bool {
    value.iter().any(u8::is_ascii_control)
}

fn challenge_matches(challenge: &Challenge, mode: SystemMode, caller: &CallerIdentity) -> bool {
    challenge.protocol_version == PROTOCOL_VERSION
        && challenge.kind == "challenge"
        && challenge.action == mode.challenge_action()
        && challenge.caller_pid == caller.credentials.pid.as_raw_pid() as u32
        && valid_operation_id(&challenge.operation_id)
}

fn authorization_matches(request: &AuthorizationRequest, operation_id: &str) -> bool {
    request.protocol_version == PROTOCOL_VERSION
        && request.kind == "authorizeInstall"
        && request.operation_id == operation_id
        && request.action == "install"
        && luxury_spec::PackageId::parse(&request.package_id).is_ok()
        && valid_lower_hex_64(&request.package_fingerprint)
}

fn system_install_matches(request: &SystemInstallRequest, operation_id: &str) -> bool {
    request.protocol_version == PROTOCOL_VERSION
        && request.kind == "installSystem"
        && request.operation_id == operation_id
        && request.action == "install"
        && luxury_spec::PackageId::parse(&request.package_id).is_ok()
        && valid_lower_hex_64(&request.package_fingerprint)
}

fn system_maintenance_matches(
    request: &SystemMaintenanceRequest,
    operation_id: &str,
    action: &str,
    kind: &str,
) -> bool {
    request.protocol_version == PROTOCOL_VERSION
        && request.kind == kind
        && request.operation_id == operation_id
        && request.action == action
        && luxury_spec::PackageId::parse(&request.package_id).is_ok()
        && valid_lower_hex_64(&request.package_fingerprint)
}

fn valid_operation_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn send_frame<T: Serialize, Fd: AsFd>(socket: Fd, frame: &T) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "polkit protocol frame exceeded its bound",
        ));
    }
    let sent = rustix::net::send(socket, &bytes, SendFlags::NOSIGNAL).map_err(os_error)?;
    if sent == bytes.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "polkit protocol frame was truncated",
        ))
    }
}

fn receive_frame<T: DeserializeOwned, Fd: AsFd>(
    socket: Fd,
    expected_credentials: UCred,
    expect_descriptor: bool,
) -> io::Result<(T, Option<OwnedFd>)> {
    let mut bytes = [0_u8; MAX_FRAME_BYTES + 1];
    let mut iov = [IoSliceMut::new(&mut bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message =
        recvmsg(&socket, &mut iov, &mut ancillary, RecvFlags::CMSG_CLOEXEC).map_err(|error| {
            if error == rustix::io::Errno::AGAIN {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "polkit peer did not send a frame in time",
                )
            } else {
                os_error(error)
            }
        })?;
    if message.bytes == 0
        || message.bytes > MAX_FRAME_BYTES
        || message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "polkit protocol frame had an invalid size",
        ));
    }
    let mut credentials = None;
    let mut descriptor = None;
    for item in ancillary.drain() {
        match item {
            RecvAncillaryMessage::ScmCredentials(found) if credentials.is_none() => {
                credentials = Some(found);
            }
            RecvAncillaryMessage::ScmRights(mut descriptors) if descriptor.is_none() => {
                descriptor = descriptors.next();
                if descriptors.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "polkit frame carried multiple package descriptors",
                    ));
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "polkit frame carried unexpected ancillary data",
                ));
            }
        }
    }
    if credentials != Some(expected_credentials) || descriptor.is_some() != expect_descriptor {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "polkit frame credentials or package descriptor did not match",
        ));
    }
    let payload = &bytes[..message.bytes];
    let json = payload.strip_suffix(b"\n").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "polkit protocol frame was not JSONL",
        )
    })?;
    if json.is_empty() || json.contains(&b'\n') || json.contains(&b'\r') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "polkit protocol frame contained an invalid line",
        ));
    }
    let frame = serde_json::from_slice(json)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "polkit frame was invalid"))?;
    Ok((frame, descriptor))
}

fn missing_package_descriptor() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "polkit request had no pinned package descriptor",
    )
}

fn os_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_transport_binds_credentials_and_one_package_descriptor() {
        use std::io::IoSlice;

        use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, sendmsg};

        let (sender, receiver) = std::os::unix::net::UnixDatagram::pair().unwrap();
        rustix::net::sockopt::set_socket_passcred(&receiver, true).unwrap();
        let package = tempfile::tempfile().unwrap();
        let mut frame = serde_json::to_vec(&serde_json::json!({
            "protocolVersion": 1,
            "type": "launchSystem",
            "operationId": "a".repeat(32),
            "action": "launch",
            "packageId": "dev.luxury.demo",
            "packageFingerprint": "b".repeat(64),
        }))
        .unwrap();
        frame.push(b'\n');
        let iov = [IoSlice::new(&frame)];
        let descriptors = [package.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        assert_eq!(
            sendmsg(&sender, &iov, &mut ancillary, SendFlags::NOSIGNAL).unwrap(),
            frame.len()
        );

        let credentials = socket_peercred(&receiver).unwrap();
        let (request, received) =
            receive_frame::<SystemMaintenanceRequest, _>(&receiver, credentials, true).unwrap();
        assert!(system_maintenance_matches(
            &request,
            &"a".repeat(32),
            "launch",
            "launchSystem"
        ));
        let received = File::from(received.unwrap());
        assert_eq!(
            file_identity(&package.metadata().unwrap()),
            file_identity(&received.metadata().unwrap())
        );
    }

    #[test]
    fn requests_are_pathless_strict_and_action_bound() {
        let value = serde_json::json!({
            "protocolVersion": 1,
            "type": "installSystem",
            "operationId": "a".repeat(32),
            "action": "install",
            "packageId": "dev.luxury.demo",
            "packageFingerprint": "b".repeat(64),
            "allowUnsigned": true,
            "acceptLicense": false,
            "allowPublisherMigration": false,
        });
        let request = serde_json::from_value::<SystemInstallRequest>(value.clone()).unwrap();
        assert!(system_install_matches(&request, &"a".repeat(32)));
        let mut injected = value;
        injected["packagePath"] = serde_json::json!("/tmp/attacker.luxpkg");
        assert!(serde_json::from_value::<SystemInstallRequest>(injected).is_err());
    }

    #[test]
    fn environment_allowlist_excludes_loader_and_shell_control() {
        assert!(safe_environment_name(b"DISPLAY"));
        assert!(safe_environment_name(b"LC_ALL"));
        assert!(!safe_environment_name(b"PATH"));
        assert!(!safe_environment_name(b"LD_PRELOAD"));
        assert!(!safe_environment_name(b"BASH_ENV"));
    }

    #[test]
    fn installed_helper_rejects_every_generic_cli_command() {
        for command in ["stdio", "install", "uninstall", "launch", "build", "help"] {
            assert!(!helper_command_allowed(true, std::ffi::OsStr::new(command)));
        }
        for command in [
            "privilege-authorize-install",
            "privilege-install-system",
            "privilege-uninstall-system",
            "privilege-launch-system",
        ] {
            assert!(helper_command_allowed(true, std::ffi::OsStr::new(command)));
        }
        assert!(helper_command_allowed(false, std::ffi::OsStr::new("stdio")));
    }

    #[test]
    fn progress_is_bounded() {
        assert!(should_emit_progress(None, 0, 100_000));
        assert!(!should_emit_progress(Some(0), 1, 100_000));
        assert!(should_emit_progress(Some(0), 196, 100_000));
        assert!(should_emit_progress(Some(99_999), 100_000, 100_000));
    }
}
