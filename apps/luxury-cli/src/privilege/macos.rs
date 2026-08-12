use std::{
    cell::Cell,
    env,
    ffi::{CStr, CString, OsStr, OsString, c_char, c_int, c_void},
    fs::{File, Metadata},
    io::{self, IoSliceMut},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStringExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use luxury_engine::{
    install::{
        InstallAction, InstallCommand, InstallEvent, InstallPhase, install, prepare_system_install,
    },
    launch::{LaunchCommand, launch},
    uninstall::{UninstallCommand, UninstallEvent, UninstallOutcome, UninstallPhase, uninstall},
};
use luxury_macos_trust::{CodeRole, VerifiedPeer, verify_peer, verify_self};
use luxury_platform::{LocalInstallAdapter, LocalUninstallAdapter, MacosSystemLaunchAdapter};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendFlags, accept, recvmsg,
    sockopt::{Timeout, set_socket_nosigpipe, set_socket_timeout},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const PROTOCOL_VERSION: u8 = 2;
const MAX_FRAME_BYTES: usize = 4 * 1024;
const MAX_ACCOUNT_BUFFER: usize = 64 * 1024;
const ACTIVATED_SOCKET_NAME: &[u8] = b"Listener\0";
const HELPER_FILE_NAME: &str = "luxury-installer-helper";

pub(super) fn guard_command(command: &OsStr) -> io::Result<()> {
    let restricted = env::current_exe()?
        .file_name()
        .is_some_and(|name| name == HELPER_FILE_NAME);
    if helper_command_allowed(restricted, command) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "installed privilege helper accepts only a system action",
        ))
    }
}

fn helper_command_allowed(restricted: bool, command: &OsStr) -> bool {
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

macro_rules! output_frame {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct $name<'a> {
            protocol_version: u8,
            #[serde(rename = "type")]
            kind: &'static str,
            operation_id: &'a str,
            $($field: $ty),*
        }
    };
}

output_frame!(InstallPhaseFrame { phase: &'static str });
output_frame!(InstallActionFrame { action: &'static str });
output_frame!(InstallProgressFrame {
    completed_files: u64,
    total_files: u64,
    completed_bytes: u64,
    total_bytes: u64,
});
output_frame!(InstallCompleteFrame {
    action: &'static str,
    package_id: &'a str,
    install_directory: &'a str,
    installed_files: u64,
    installed_bytes: u64,
    system_preparation: Option<&'a crate::stdio::PrepareInstallResult>,
});
output_frame!(InstallFailedFrame { code: &'static str });
output_frame!(UninstallPhaseFrame { phase: &'static str });
output_frame!(UninstallProgressFrame {
    processed_files: u64,
    total_files: u64,
});
output_frame!(UninstallCompleteFrame {
    status: &'static str,
    package_id: &'a str,
    removed_files: u64,
    missing_files: u64,
    preserved_modified_files: u64,
    system_preparation: Option<&'a crate::stdio::PrepareInstallResult>,
});
output_frame!(UninstallFailedFrame { code: &'static str });
output_frame!(LaunchCompleteFrame {
    status: &'static str,
    package_id: &'a str,
});
output_frame!(LaunchFailedFrame { code: &'static str });

struct CallerAccount {
    username: OsString,
    home: OsString,
    groups: Vec<u32>,
}

struct TransportState {
    cancelled: Arc<AtomicBool>,
    failed: Arc<Mutex<Option<io::Error>>>,
}

pub(super) fn run(args: &[OsString], mode: SystemMode) -> io::Result<()> {
    if !args.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "macOS privilege helper accepts no arguments",
        ));
    }
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "launchd helper did not receive root credentials",
        ));
    }
    verify_self(CodeRole::Helper).map_err(trust_error)?;
    let listener = activated_listener()?;
    let socket = accept(&listener).map_err(os_error)?;
    rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC).map_err(os_error)?;
    set_socket_nosigpipe(&socket, true).map_err(os_error)?;
    drop(listener);
    set_socket_timeout(
        &socket,
        Timeout::Recv,
        Some(std::time::Duration::from_secs(15)),
    )
    .map_err(os_error)?;
    let caller = verified_caller(socket.as_fd())?;
    let (challenge, descriptor) = receive_frame::<Challenge, _>(&socket, false)?;
    if descriptor.is_some() || !challenge_matches(&challenge, mode, &caller) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launchd challenge did not match the authenticated caller",
        ));
    }
    send_frame(
        &socket,
        &Ready {
            protocol_version: PROTOCOL_VERSION,
            kind: "ready",
            operation_id: &challenge.operation_id,
            action: mode.challenge_action(),
            caller_pid: caller.pid,
            caller_uid: caller.uid,
            helper_pid: std::process::id(),
        },
    )?;
    match mode {
        SystemMode::AuthorizeInstall => {
            authorize_install(socket.as_fd(), &caller, &challenge.operation_id)
        }
        SystemMode::Install => {
            execute_system_install(socket.as_fd(), &caller, &challenge.operation_id)
        }
        SystemMode::Uninstall => {
            execute_system_uninstall(socket.as_fd(), &caller, &challenge.operation_id)
        }
        SystemMode::Launch => execute_system_launch(
            socket.as_fd(),
            &caller,
            account_for(&caller)?,
            &challenge.operation_id,
        ),
    }
}

fn authorize_install(
    socket: BorrowedFd<'_>,
    caller: &VerifiedPeer,
    operation_id: &str,
) -> io::Result<()> {
    let (request, package) = receive_frame::<AuthorizationRequest, _>(socket, true)?;
    if !authorization_matches(&request, operation_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system install authorization request was invalid",
        ));
    }
    let package = File::from(package.ok_or_else(missing_package_descriptor)?);
    let (bundle, install_base, state_root) = validate_authorized_package(
        socket,
        caller,
        package,
        &request.package_id,
        &request.package_fingerprint,
    )?;
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
    caller: &VerifiedPeer,
    operation_id: &str,
) -> io::Result<()> {
    let (request, package) = receive_frame::<SystemInstallRequest, _>(socket, true)?;
    if !system_install_matches(&request, operation_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system install request was invalid",
        ));
    }
    let package = File::from(package.ok_or_else(missing_package_descriptor)?);
    let (bundle, install_base, state_root) = validate_authorized_package(
        socket,
        caller,
        package,
        &request.package_id,
        &request.package_fingerprint,
    )?;
    let manifest = bundle.manifest().clone();
    if !request.allow_unsigned || request.accept_license != manifest.package.license.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "system install consent did not match the authorized package",
        ));
    }
    let transport = start_cancel_reader(socket, operation_id, "install")?;
    let install_directory = manifest.install.directory.as_str().to_owned();
    let preparation_manifest = manifest.clone();
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
            if !transport_failed(&transport)
                && let Err(error) = write_install_event(socket, operation_id, event, &last_progress)
            {
                fail_transport(&transport, error);
            }
        },
    );
    require_transport(&transport)?;
    match result {
        Ok(outcome) => {
            let preparation = super::system_preparation(preparation_manifest, &mut adapter);
            send_frame(
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
                    system_preparation: preparation.as_ref(),
                },
            )
        }
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
    caller: &VerifiedPeer,
    operation_id: &str,
) -> io::Result<()> {
    let (request, package) = receive_frame::<SystemMaintenanceRequest, _>(socket, true)?;
    if !system_maintenance_matches(&request, operation_id, "uninstall", "uninstallSystem") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system uninstall request was invalid",
        ));
    }
    let package = File::from(package.ok_or_else(missing_package_descriptor)?);
    let (bundle, install_base, state_root) = validate_authorized_package(
        socket,
        caller,
        package,
        &request.package_id,
        &request.package_fingerprint,
    )?;
    let manifest = bundle.manifest().clone();
    let package_id = manifest.package.id.clone();
    let mut preparation_adapter =
        LocalInstallAdapter::for_system(bundle, install_base.clone(), state_root.clone());
    let transport = start_cancel_reader(socket, operation_id, "uninstall")?;
    let mut adapter = LocalUninstallAdapter::for_system(install_base, state_root);
    let last_progress = Cell::new(None::<u64>);
    let result = uninstall(
        UninstallCommand::for_system(package_id.clone()),
        &mut adapter,
        || transport.cancelled.load(Ordering::Acquire),
        |event| {
            if !transport_failed(&transport)
                && let Err(error) =
                    write_uninstall_event(socket, operation_id, event, &last_progress)
            {
                fail_transport(&transport, error);
            }
        },
    );
    require_transport(&transport)?;
    match result {
        Ok(UninstallOutcome::NotInstalled) => send_uninstall_complete(
            socket,
            operation_id,
            &package_id,
            "notInstalled",
            (0, 0, 0),
            super::system_preparation(manifest, &mut preparation_adapter).as_ref(),
        ),
        Ok(UninstallOutcome::Uninstalled {
            removed_files,
            missing_files,
            preserved_modified_files,
        }) => send_uninstall_complete(
            socket,
            operation_id,
            &package_id,
            "uninstalled",
            (
                removed_files as u64,
                missing_files as u64,
                preserved_modified_files as u64,
            ),
            super::system_preparation(manifest, &mut preparation_adapter).as_ref(),
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
    caller: &VerifiedPeer,
    account: CallerAccount,
    operation_id: &str,
) -> io::Result<()> {
    let (request, package) = receive_frame::<SystemMaintenanceRequest, _>(socket, true)?;
    if !system_maintenance_matches(&request, operation_id, "launch", "launchSystem") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system launch request was invalid",
        ));
    }
    let package = File::from(package.ok_or_else(missing_package_descriptor)?);
    let (bundle, install_base, state_root) = validate_authorized_package(
        socket,
        caller,
        package,
        &request.package_id,
        &request.package_fingerprint,
    )?;
    let package_id = bundle.manifest().package.id.clone();
    drop(bundle);
    let mut adapter = MacosSystemLaunchAdapter::new(
        install_base,
        state_root,
        caller.uid,
        caller.gid,
        account.groups,
        account.username,
        account.home,
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

fn send_uninstall_complete(
    socket: BorrowedFd<'_>,
    operation_id: &str,
    package_id: &luxury_spec::PackageId,
    status: &'static str,
    counts: (u64, u64, u64),
    system_preparation: Option<&crate::stdio::PrepareInstallResult>,
) -> io::Result<()> {
    let (removed_files, missing_files, preserved_modified_files) = counts;
    send_frame(
        socket,
        &UninstallCompleteFrame {
            protocol_version: PROTOCOL_VERSION,
            kind: "uninstallComplete",
            operation_id,
            status,
            package_id: package_id.as_str(),
            removed_files,
            missing_files,
            preserved_modified_files,
            system_preparation,
        },
    )
}

fn validate_authorized_package(
    socket: BorrowedFd<'_>,
    caller: &VerifiedPeer,
    package: File,
    package_id: &str,
    package_fingerprint: &str,
) -> io::Result<(luxury_bundle::Bundle, PathBuf, PathBuf)> {
    let confirmed = verified_caller(socket)?;
    if &confirmed != caller {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "caller identity changed",
        ));
    }
    let expected_path = caller_payload_path(&caller.code_path)?;
    let expected = open_nofollow(&expected_path)?;
    let package_metadata = package.metadata()?;
    let expected_metadata = expected.metadata()?;
    if !package_metadata.is_file()
        || package_metadata.nlink() != 1
        || file_identity(&package_metadata) != file_identity(&expected_metadata)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "package descriptor was not the signed app resource",
        ));
    }
    let expected_id = luxury_spec::PackageId::parse(package_id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "package ID is invalid"))?;
    let bundle = luxury_bundle::open_bundle(package, None)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "package could not be verified"))?;
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
            "system roots are invalid",
        ));
    }
    Ok((bundle, install_base, state_root))
}

fn caller_payload_path(code_path: &Path) -> io::Result<PathBuf> {
    let app = code_path
        .ancestors()
        .find(|path| path.extension() == Some(OsStr::new("app")))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "caller is not an app bundle",
            )
        })?;
    Ok(app
        .join("Contents")
        .join("Resources")
        .join("payload")
        .join("package.luxpkg"))
}

fn verified_caller(socket: BorrowedFd<'_>) -> io::Result<VerifiedPeer> {
    let peer = verify_peer(socket, CodeRole::App).map_err(trust_error)?;
    if peer.uid == 0 || peer.gid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "caller must be unprivileged",
        ));
    }
    Ok(peer)
}

fn account_for(peer: &VerifiedPeer) -> io::Result<CallerAccount> {
    let mut buffer = vec![0_u8; account_buffer_size()?];
    let mut record = MaybeUninit::<libc::passwd>::zeroed();
    let mut result = ptr::null_mut();
    // SAFETY: record/result and the bounded byte buffer are writable for their exact sizes.
    let status = unsafe {
        libc::getpwuid_r(
            peer.uid as libc::uid_t,
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast::<c_char>(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "caller account was not found",
        ));
    }
    let record = unsafe { record.assume_init() };
    let username = c_string(record.pw_name)?;
    let home = c_string(record.pw_dir)?;
    if !Path::new(&home).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "caller home is not absolute",
        ));
    }
    let groups = account_groups(&username, peer.gid)?;
    Ok(CallerAccount {
        username,
        home,
        groups,
    })
}

fn account_buffer_size() -> io::Result<usize> {
    let found = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let size = if found <= 0 {
        16 * 1024
    } else {
        found as usize
    };
    if (1..=MAX_ACCOUNT_BUFFER).contains(&size) {
        Ok(size)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "account buffer size is invalid",
        ))
    }
}

fn c_string(value: *const c_char) -> io::Result<OsString> {
    if value.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "account field was absent",
        ));
    }
    let bytes = unsafe { CStr::from_ptr(value) }.to_bytes();
    if bytes.is_empty() || bytes.len() > 4_096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "account field was invalid",
        ));
    }
    Ok(OsString::from_vec(bytes.to_vec()))
}

fn account_groups(username: &OsString, base_gid: u32) -> io::Result<Vec<u32>> {
    let username = CString::new(username.clone().into_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "account name contained NUL"))?;
    let base_gid = c_int::try_from(base_gid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "base group is invalid"))?;
    let mut count = 16_i32;
    let mut groups = vec![0_i32; count as usize];
    let mut status =
        unsafe { libc::getgrouplist(username.as_ptr(), base_gid, groups.as_mut_ptr(), &mut count) };
    if status < 0 {
        if !(1..=128).contains(&count) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "group count is invalid",
            ));
        }
        groups.resize(count as usize, 0);
        status = unsafe {
            libc::getgrouplist(username.as_ptr(), base_gid, groups.as_mut_ptr(), &mut count)
        };
    }
    if status < 0 || count < 1 || count as usize > groups.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "groups could not be resolved",
        ));
    }
    groups.truncate(count as usize);
    let groups = groups
        .into_iter()
        .map(u32::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "group was invalid"))?;
    if groups.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "caller belongs to root group",
        ));
    }
    Ok(groups)
}

fn activated_listener() -> io::Result<OwnedFd> {
    let mut descriptors: *mut c_int = ptr::null_mut();
    let mut count = 0_usize;
    let status = unsafe {
        launch_activate_socket(
            ACTIVATED_SOCKET_NAME.as_ptr().cast::<c_char>(),
            &mut descriptors,
            &mut count,
        )
    };
    if status != 0 || count != 1 || descriptors.is_null() {
        if !descriptors.is_null() {
            unsafe { libc::free(descriptors.cast::<c_void>()) };
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "launchd socket was unavailable",
        ));
    }
    let raw = unsafe { *descriptors };
    unsafe { libc::free(descriptors.cast::<c_void>()) };
    if raw < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launchd returned an invalid socket",
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn start_cancel_reader(
    socket: BorrowedFd<'_>,
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
            let result = receive_frame::<CancelOperationRequest, _>(&reader, false).and_then(
                |(request, descriptor)| {
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
                            "cancellation frame was invalid",
                        ))
                    }
                },
            );
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

fn transport_failed(state: &TransportState) -> bool {
    state
        .failed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

fn fail_transport(state: &TransportState, error: io::Error) {
    let mut failed = state
        .failed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if failed.is_none() {
        *failed = Some(error);
    }
    state.cancelled.store(true, Ordering::Release);
}

fn require_transport(state: &TransportState) -> io::Result<()> {
    match state
        .failed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
    {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn write_install_event(
    socket: BorrowedFd<'_>,
    operation_id: &str,
    event: InstallEvent,
    last: &Cell<Option<u64>>,
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
            if !should_emit_progress(last.get(), completed, total) {
                return Ok(());
            }
            last.set(Some(completed));
            send_frame(
                socket,
                &InstallProgressFrame {
                    protocol_version: PROTOCOL_VERSION,
                    kind: "installProgress",
                    operation_id,
                    completed_files: completed,
                    total_files: total,
                    completed_bytes: progress.completed_bytes,
                    total_bytes: progress.total_bytes,
                },
            )
        }
    }
}

fn write_uninstall_event(
    socket: BorrowedFd<'_>,
    operation_id: &str,
    event: UninstallEvent,
    last: &Cell<Option<u64>>,
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
            if !should_emit_progress(last.get(), completed, total) {
                return Ok(());
            }
            last.set(Some(completed));
            send_frame(
                socket,
                &UninstallProgressFrame {
                    protocol_version: PROTOCOL_VERSION,
                    kind: "uninstallProgress",
                    operation_id,
                    processed_files: completed,
                    total_files: total,
                },
            )
        }
        UninstallEvent::PreservedModified(_) => Ok(()),
    }
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

fn challenge_matches(challenge: &Challenge, mode: SystemMode, caller: &VerifiedPeer) -> bool {
    challenge.protocol_version == PROTOCOL_VERSION
        && challenge.kind == "challenge"
        && challenge.action == mode.challenge_action()
        && challenge.caller_pid == caller.pid
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

fn open_nofollow(path: &Path) -> io::Result<File> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(os_error)
}

fn file_identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn send_frame<T: Serialize, Fd: AsFd>(socket: Fd, frame: &T) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeded bound",
        ));
    }
    let sent = rustix::net::send(socket, &bytes, SendFlags::empty()).map_err(os_error)?;
    if sent == bytes.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "frame was truncated",
        ))
    }
}

fn receive_frame<T: DeserializeOwned, Fd: AsFd>(
    socket: Fd,
    expect_descriptor: bool,
) -> io::Result<(T, Option<OwnedFd>)> {
    let mut bytes = [0_u8; MAX_FRAME_BYTES + 1];
    let mut iov = [IoSliceMut::new(&mut bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message =
        recvmsg(&socket, &mut iov, &mut ancillary, RecvFlags::empty()).map_err(os_error)?;
    if message.bytes == 0
        || message.bytes > MAX_FRAME_BYTES
        || message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame had invalid size",
        ));
    }
    let mut descriptor = None;
    for item in ancillary.drain() {
        match item {
            RecvAncillaryMessage::ScmRights(mut descriptors) if descriptor.is_none() => {
                descriptor = descriptors.next();
                if descriptors.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "multiple descriptors",
                    ));
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected ancillary data",
                ));
            }
        }
    }
    if descriptor.is_some() != expect_descriptor {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "descriptor did not match",
        ));
    }
    if let Some(descriptor) = &descriptor {
        rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::CLOEXEC).map_err(os_error)?;
    }
    let payload = &bytes[..message.bytes];
    let json = payload
        .strip_suffix(b"\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "frame was not JSONL"))?;
    if json.is_empty() || json.contains(&b'\n') || json.contains(&b'\r') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid JSONL line",
        ));
    }
    let frame = serde_json::from_slice(json)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame was invalid"))?;
    Ok((frame, descriptor))
}

fn missing_package_descriptor() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "request had no package descriptor",
    )
}
fn trust_error(_: luxury_macos_trust::TrustError) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "code identity was not trusted",
    )
}
fn os_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

unsafe extern "C" {
    fn launch_activate_socket(
        name: *const c_char,
        fds: *mut *mut c_int,
        count: *mut usize,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_rejects_generic_cli_commands() {
        assert!(!helper_command_allowed(true, OsStr::new("stdio")));
        assert!(!helper_command_allowed(true, OsStr::new("install")));
        assert!(helper_command_allowed(
            true,
            OsStr::new("privilege-install-system")
        ));
    }

    #[test]
    fn requests_are_strict_pathless_and_action_bound() {
        let value = serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "launchSystem",
            "operationId": "a".repeat(32),
            "action": "launch",
            "packageId": "dev.luxury.demo",
            "packageFingerprint": "b".repeat(64),
        });
        let request = serde_json::from_value::<SystemMaintenanceRequest>(value.clone()).unwrap();
        assert!(system_maintenance_matches(
            &request,
            &"a".repeat(32),
            "launch",
            "launchSystem"
        ));
        let mut injected = value;
        injected["packagePath"] = serde_json::json!("/tmp/attacker.luxpkg");
        assert!(serde_json::from_value::<SystemMaintenanceRequest>(injected).is_err());
    }
}
