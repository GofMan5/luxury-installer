use std::{error::Error, ffi::OsString};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos;

fn system_preparation(
    manifest: luxury_spec::Manifest,
    adapter: &mut luxury_platform::LocalInstallAdapter,
) -> Option<crate::stdio::PrepareInstallResult> {
    luxury_engine::install::prepare_system_install(manifest, adapter)
        .ok()
        .and_then(|outcome| crate::stdio::PrepareInstallResult::from_outcome(outcome).ok())
}

#[cfg(target_os = "linux")]
pub(super) fn guard_command(command: &std::ffi::OsStr) -> std::io::Result<()> {
    linux::guard_command(command)
}

#[cfg(target_os = "macos")]
pub(super) fn guard_command(command: &std::ffi::OsStr) -> std::io::Result<()> {
    macos::guard_command(command)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn guard_command(_: &std::ffi::OsStr) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn run_probe(_: &[OsString]) -> Result<(), Box<dyn Error>> {
    Err("privilege probe is supported only on Windows".into())
}

#[cfg(not(windows))]
pub(super) fn run_elevated_probe(_: &[OsString]) -> Result<(), Box<dyn Error>> {
    Err("elevated privilege probe is supported only on Windows".into())
}

#[cfg(not(windows))]
pub(super) fn run_authenticated_probe(_: &[OsString]) -> Result<(), Box<dyn Error>> {
    Err("authenticated privilege probe is supported only on Windows".into())
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
pub(super) fn run_install_authorization(_: &[OsString]) -> Result<(), Box<dyn Error>> {
    Err("system install authorization is not implemented on this platform".into())
}

#[cfg(target_os = "linux")]
pub(super) fn run_install_authorization(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    linux::run(args, linux::SystemMode::AuthorizeInstall).map_err(Into::into)
}

#[cfg(target_os = "macos")]
pub(super) fn run_install_authorization(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    macos::run(args, macos::SystemMode::AuthorizeInstall).map_err(Into::into)
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
pub(super) fn run_system_install(_: &[OsString]) -> Result<(), Box<dyn Error>> {
    Err("system install helper is not implemented on this platform".into())
}

#[cfg(target_os = "linux")]
pub(super) fn run_system_install(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    linux::run(args, linux::SystemMode::Install).map_err(Into::into)
}

#[cfg(target_os = "macos")]
pub(super) fn run_system_install(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    macos::run(args, macos::SystemMode::Install).map_err(Into::into)
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
pub(super) fn run_system_uninstall(_: &[OsString]) -> Result<(), Box<dyn Error>> {
    Err("system uninstall helper is not implemented on this platform".into())
}

#[cfg(target_os = "linux")]
pub(super) fn run_system_uninstall(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    linux::run(args, linux::SystemMode::Uninstall).map_err(Into::into)
}

#[cfg(target_os = "macos")]
pub(super) fn run_system_uninstall(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    macos::run(args, macos::SystemMode::Uninstall).map_err(Into::into)
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
pub(super) fn run_system_launch(_: &[OsString]) -> Result<(), Box<dyn Error>> {
    Err("system launch helper is not implemented on this platform".into())
}

#[cfg(target_os = "macos")]
pub(super) fn run_system_launch(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    macos::run(args, macos::SystemMode::Launch).map_err(Into::into)
}

#[cfg(target_os = "linux")]
pub(super) fn run_system_launch(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    linux::run(args, linux::SystemMode::Launch).map_err(Into::into)
}

#[cfg(windows)]
pub(super) fn run_probe(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    windows::run_probe(args, false, false, windows::SystemMode::None).map_err(Into::into)
}

#[cfg(windows)]
pub(super) fn run_elevated_probe(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    windows::run_probe(args, true, false, windows::SystemMode::None).map_err(Into::into)
}

#[cfg(windows)]
pub(super) fn run_authenticated_probe(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    windows::run_probe(args, true, true, windows::SystemMode::None).map_err(Into::into)
}

#[cfg(windows)]
pub(super) fn run_install_authorization(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    windows::run_probe(args, true, true, windows::SystemMode::AuthorizeInstall).map_err(Into::into)
}

#[cfg(windows)]
pub(super) fn run_system_install(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    windows::run_probe(args, true, true, windows::SystemMode::Install).map_err(Into::into)
}

#[cfg(windows)]
pub(super) fn run_system_uninstall(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    windows::run_probe(args, true, true, windows::SystemMode::Uninstall).map_err(Into::into)
}

#[cfg(windows)]
pub(super) fn run_system_launch(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    windows::run_probe(args, true, true, windows::SystemMode::Launch).map_err(Into::into)
}

#[cfg(windows)]
mod windows {
    use std::{
        cell::{Cell, RefCell},
        fs::{File, OpenOptions},
        io,
        mem::size_of,
        os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
        path::{Path, PathBuf},
        ptr::null_mut,
        thread,
        time::{Duration, Instant},
    };

    use luxury_engine::install::{
        InstallAction, InstallCommand, InstallEvent, InstallPhase, InstallProgress, install,
        prepare_system_install,
    };
    use luxury_engine::launch::{LaunchCommand, launch};
    use luxury_engine::uninstall::{
        UninstallCommand, UninstallEvent, UninstallOutcome, UninstallPhase, UninstallProgress,
        uninstall,
    };
    use luxury_platform::{LocalInstallAdapter, LocalUninstallAdapter, WindowsSystemLaunchAdapter};
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use windows_sys::Win32::{
        Foundation::{
            DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_FILE_NOT_FOUND, ERROR_NO_DATA,
            ERROR_PIPE_BUSY, HANDLE,
        },
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            GetFileInformationByHandle, ReadFile, WriteFile,
        },
        System::{
            Pipes::{
                GetNamedPipeServerProcessId, PIPE_NOWAIT, PIPE_READMODE_MESSAGE,
                SetNamedPipeHandleState,
            },
            Threading::{
                GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_DUP_HANDLE,
                PROCESS_QUERY_INFORMATION,
            },
        },
    };

    use super::OsString;

    const PROTOCOL_VERSION: u8 = 2;
    const MAX_FRAME_BYTES: usize = 4 * 1024;
    const PIPE_TIMEOUT: Duration = Duration::from_secs(15);
    const PIPE_PREFIX: &str = r"\\.\pipe\luxury-installer-";

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum SystemMode {
        None,
        AuthorizeInstall,
        Install,
        Uninstall,
        Launch,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Challenge {
        protocol_version: u8,
        #[serde(rename = "type")]
        kind: String,
        operation_id: String,
        server_pid: u32,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Ready<'a> {
        protocol_version: u8,
        #[serde(rename = "type")]
        kind: &'static str,
        operation_id: &'a str,
        server_pid: u32,
        helper_pid: u32,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Accepted {
        protocol_version: u8,
        #[serde(rename = "type")]
        kind: String,
        operation_id: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct InstallAuthorizationRequest {
        protocol_version: u8,
        #[serde(rename = "type")]
        kind: String,
        operation_id: String,
        action: String,
        package_id: String,
        package_fingerprint: String,
        source_handle: u64,
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
        source_handle: u64,
        allow_unsigned: bool,
        accept_license: bool,
        allow_publisher_migration: bool,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct SystemUninstallRequest {
        protocol_version: u8,
        #[serde(rename = "type")]
        kind: String,
        operation_id: String,
        action: String,
        package_id: String,
        package_fingerprint: String,
        source_handle: u64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct SystemLaunchRequest {
        protocol_version: u8,
        #[serde(rename = "type")]
        kind: String,
        operation_id: String,
        action: String,
        package_id: String,
        package_fingerprint: String,
        source_handle: u64,
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
        system_preparation: Option<&'a crate::stdio::PrepareInstallResult>,
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
        system_preparation: Option<&'a crate::stdio::PrepareInstallResult>,
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

    pub(super) fn run_probe(
        args: &[OsString],
        require_elevated: bool,
        require_authenticode: bool,
        system_mode: SystemMode,
    ) -> io::Result<()> {
        if (require_authenticode && !require_elevated)
            || (system_mode != SystemMode::None && !require_authenticode)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "authenticated privilege probe must require elevation",
            ));
        }
        if require_elevated && !is_elevated()? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "privilege helper did not receive an elevated token",
            ));
        }
        let [pipe_name, server_pid] = args else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "privilege-probe expects pipe name and server PID",
            ));
        };
        let pipe_name = pipe_name
            .to_str()
            .filter(|value| valid_pipe_name(value))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid pipe name"))?;
        let expected_server_pid = server_pid
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value != 0 && value.to_string() == server_pid.to_string_lossy())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid server PID"))?;
        let pipe = open_pipe(pipe_name, Instant::now() + PIPE_TIMEOUT)?;
        let handle = pipe.as_raw_handle() as HANDLE;
        let mode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
        // SAFETY: `handle` is an open named-pipe client and `mode` is readable.
        if unsafe { SetNamedPipeHandleState(handle, &mode, null_mut(), null_mut()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut actual_server_pid = 0_u32;
        // SAFETY: `handle` is an open named pipe and the PID output is writable.
        if unsafe { GetNamedPipeServerProcessId(handle, &mut actual_server_pid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if actual_server_pid != expected_server_pid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "named-pipe server PID did not match expected parent",
            ));
        }
        let authenticated_server = if require_authenticode {
            let process =
                verify_authenticode_peer(actual_server_pid, system_mode != SystemMode::None)?;
            let mut confirmed_server_pid = 0_u32;
            // SAFETY: `handle` remains connected and the PID output is writable.
            if unsafe { GetNamedPipeServerProcessId(handle, &mut confirmed_server_pid) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if confirmed_server_pid != actual_server_pid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "named-pipe server identity changed during Authenticode verification",
                ));
            }
            Some(process)
        } else {
            None
        };
        let challenge: Challenge = read_frame(handle, Instant::now() + PIPE_TIMEOUT)?;
        if !challenge_matches(&challenge, pipe_name, actual_server_pid) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "privilege server returned an invalid challenge",
            ));
        }
        write_frame(
            handle,
            &Ready {
                protocol_version: PROTOCOL_VERSION,
                kind: "ready",
                operation_id: &challenge.operation_id,
                server_pid: actual_server_pid,
                helper_pid: std::process::id(),
            },
        )?;
        let accepted: Accepted = read_frame(handle, Instant::now() + PIPE_TIMEOUT)?;
        if !accepted_matches(&accepted, &challenge.operation_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "privilege server returned an invalid acceptance",
            ));
        }
        if system_mode != SystemMode::None {
            let server = authenticated_server.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "system operation has no authenticated server handle",
                )
            })?;
            match system_mode {
                SystemMode::None => unreachable!(),
                SystemMode::AuthorizeInstall => {
                    authorize_install_request(handle, server, &challenge.operation_id)?;
                }
                SystemMode::Install => {
                    execute_system_install(handle, server, &challenge.operation_id)?;
                }
                SystemMode::Uninstall => {
                    execute_system_uninstall(handle, server, &challenge.operation_id)?;
                }
                SystemMode::Launch => {
                    execute_system_launch(handle, server, &challenge.operation_id)?;
                }
            }
        }
        Ok(())
    }

    fn verify_authenticode_peer(
        server_pid: u32,
        require_duplicate_handle: bool,
    ) -> io::Result<OwnedHandle> {
        let access = PROCESS_QUERY_INFORMATION
            | if require_duplicate_handle {
                PROCESS_DUP_HANDLE
            } else {
                0
            };
        let process = open_process(server_pid, access)?;
        let helper = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) };
        luxury_windows_trust::verify_same_process_authenticode_signer(helper, process.as_handle())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "privilege helper and server Authenticode identities were not trusted and equal",
                )
            })?;
        Ok(process)
    }

    fn open_process(process_id: u32, access: u32) -> io::Result<OwnedHandle> {
        // SAFETY: the PID is kernel-reported by the connected pipe; inheritance is disabled.
        let raw = unsafe { OpenProcess(access, 0, process_id) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: OpenProcess returned one owned real handle on success.
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    fn authorize_install_request(
        pipe: HANDLE,
        server_process: &OwnedHandle,
        operation_id: &str,
    ) -> io::Result<()> {
        let request: InstallAuthorizationRequest = read_frame(pipe, Instant::now() + PIPE_TIMEOUT)?;
        if !install_request_matches(&request, operation_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "privilege install authorization request was invalid",
            ));
        }
        let package = duplicate_package_handle(server_process, request.source_handle)?;
        let (bundle, install_base, state_root) = validate_authorized_package(
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
        write_frame(
            pipe,
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
        pipe: HANDLE,
        server_process: &OwnedHandle,
        operation_id: &str,
    ) -> io::Result<()> {
        let request: SystemInstallRequest = read_frame(pipe, Instant::now() + PIPE_TIMEOUT)?;
        if !system_install_request_matches(&request, operation_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "system install request was invalid",
            ));
        }
        let package = duplicate_package_handle(server_process, request.source_handle)?;
        let (bundle, install_base, state_root) = validate_authorized_package(
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

        let install_directory = manifest.install.directory.as_str().to_owned();
        let preparation_manifest = manifest.clone();
        let command = InstallCommand::for_system(manifest)
            .with_license_acceptance(request.accept_license)
            .with_publisher_migration_approval(request.allow_publisher_migration);
        let mut adapter = LocalInstallAdapter::for_system(bundle, install_base, state_root);
        let cancelled = Cell::new(false);
        let transport_error = RefCell::new(None);
        let last_progress = Cell::new(None::<u64>);
        let result = install(
            command,
            &mut adapter,
            || {
                if cancelled.get() {
                    return true;
                }
                match poll_operation_cancel(pipe, operation_id, "install") {
                    Ok(value) => {
                        cancelled.set(value);
                        value
                    }
                    Err(error) => {
                        *transport_error.borrow_mut() = Some(error);
                        cancelled.set(true);
                        true
                    }
                }
            },
            |event| {
                if transport_error.borrow().is_some() {
                    return;
                }
                if let Err(error) = write_install_event(pipe, operation_id, event, &last_progress) {
                    *transport_error.borrow_mut() = Some(error);
                    cancelled.set(true);
                }
            },
        );
        if let Some(error) = transport_error.into_inner() {
            return Err(error);
        }
        match result {
            Ok(outcome) => {
                let preparation = super::system_preparation(preparation_manifest, &mut adapter);
                write_frame(
                    pipe,
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
            Err(error) => write_frame(
                pipe,
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
        pipe: HANDLE,
        server_process: &OwnedHandle,
        operation_id: &str,
    ) -> io::Result<()> {
        let request: SystemUninstallRequest = read_frame(pipe, Instant::now() + PIPE_TIMEOUT)?;
        if !system_uninstall_request_matches(&request, operation_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "system uninstall request was invalid",
            ));
        }
        let package = duplicate_package_handle(server_process, request.source_handle)?;
        let (bundle, install_base, state_root) = validate_authorized_package(
            package,
            &request.package_id,
            &request.package_fingerprint,
        )?;
        let manifest = bundle.manifest().clone();
        let package_id = manifest.package.id.clone();
        let mut preparation_adapter =
            LocalInstallAdapter::for_system(bundle, install_base.clone(), state_root.clone());

        let mut adapter = LocalUninstallAdapter::for_system(install_base, state_root);
        let cancelled = Cell::new(false);
        let transport_error = RefCell::new(None);
        let last_progress = Cell::new(None::<u64>);
        let result = uninstall(
            UninstallCommand::for_system(package_id.clone()),
            &mut adapter,
            || {
                if cancelled.get() {
                    return true;
                }
                match poll_operation_cancel(pipe, operation_id, "uninstall") {
                    Ok(value) => {
                        cancelled.set(value);
                        value
                    }
                    Err(error) => {
                        *transport_error.borrow_mut() = Some(error);
                        cancelled.set(true);
                        true
                    }
                }
            },
            |event| {
                if transport_error.borrow().is_some() {
                    return;
                }
                if let Err(error) = write_uninstall_event(pipe, operation_id, event, &last_progress)
                {
                    *transport_error.borrow_mut() = Some(error);
                    cancelled.set(true);
                }
            },
        );
        if let Some(error) = transport_error.into_inner() {
            return Err(error);
        }
        match result {
            Ok(UninstallOutcome::NotInstalled) => {
                let preparation = super::system_preparation(manifest, &mut preparation_adapter);
                write_frame(
                    pipe,
                    &UninstallCompleteFrame {
                        protocol_version: PROTOCOL_VERSION,
                        kind: "uninstallComplete",
                        operation_id,
                        status: "notInstalled",
                        package_id: package_id.as_str(),
                        removed_files: 0,
                        missing_files: 0,
                        preserved_modified_files: 0,
                        system_preparation: preparation.as_ref(),
                    },
                )
            }
            Ok(UninstallOutcome::Uninstalled {
                removed_files,
                missing_files,
                preserved_modified_files,
            }) => {
                let preparation = super::system_preparation(manifest, &mut preparation_adapter);
                write_frame(
                    pipe,
                    &UninstallCompleteFrame {
                        protocol_version: PROTOCOL_VERSION,
                        kind: "uninstallComplete",
                        operation_id,
                        status: "uninstalled",
                        package_id: package_id.as_str(),
                        removed_files: removed_files as u64,
                        missing_files: missing_files as u64,
                        preserved_modified_files: preserved_modified_files as u64,
                        system_preparation: preparation.as_ref(),
                    },
                )
            }
            Err(error) => write_frame(
                pipe,
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
        pipe: HANDLE,
        server_process: &OwnedHandle,
        operation_id: &str,
    ) -> io::Result<()> {
        let request: SystemLaunchRequest = read_frame(pipe, Instant::now() + PIPE_TIMEOUT)?;
        if !system_launch_request_matches(&request, operation_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "system launch request was invalid",
            ));
        }
        let package = duplicate_package_handle(server_process, request.source_handle)?;
        let (bundle, install_base, state_root) = validate_authorized_package(
            package,
            &request.package_id,
            &request.package_fingerprint,
        )?;
        let package_id = bundle.manifest().package.id.clone();
        drop(bundle);
        let mut adapter =
            WindowsSystemLaunchAdapter::new(install_base, state_root, server_process.as_handle());
        match launch(LaunchCommand::for_system(package_id.clone()), &mut adapter) {
            Ok(()) => write_frame(
                pipe,
                &LaunchCompleteFrame {
                    protocol_version: PROTOCOL_VERSION,
                    kind: "launchComplete",
                    operation_id,
                    status: "launched",
                    package_id: package_id.as_str(),
                },
            ),
            Err(error) => write_frame(
                pipe,
                &LaunchFailedFrame {
                    protocol_version: PROTOCOL_VERSION,
                    kind: "launchFailed",
                    operation_id,
                    code: crate::stdio::launch_error_code(&error),
                },
            ),
        }
    }

    fn write_uninstall_event(
        pipe: HANDLE,
        operation_id: &str,
        event: UninstallEvent,
        last_progress: &Cell<Option<u64>>,
    ) -> io::Result<()> {
        match event {
            UninstallEvent::Phase(phase) => write_frame(
                pipe,
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
                write_uninstall_progress(pipe, operation_id, progress)
            }
            UninstallEvent::PreservedModified(_) => Ok(()),
        }
    }

    fn write_uninstall_progress(
        pipe: HANDLE,
        operation_id: &str,
        progress: UninstallProgress,
    ) -> io::Result<()> {
        write_frame(
            pipe,
            &UninstallProgressFrame {
                protocol_version: PROTOCOL_VERSION,
                kind: "uninstallProgress",
                operation_id,
                processed_files: progress.processed_files as u64,
                total_files: progress.total_files as u64,
            },
        )
    }

    fn write_install_event(
        pipe: HANDLE,
        operation_id: &str,
        event: InstallEvent,
        last_progress: &Cell<Option<u64>>,
    ) -> io::Result<()> {
        match event {
            InstallEvent::Phase(phase) => write_frame(
                pipe,
                &InstallPhaseFrame {
                    protocol_version: PROTOCOL_VERSION,
                    kind: "installPhase",
                    operation_id,
                    phase: install_phase(phase),
                },
            ),
            InstallEvent::Action(action) => write_frame(
                pipe,
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
                write_progress(pipe, operation_id, progress)
            }
        }
    }

    fn write_progress(
        pipe: HANDLE,
        operation_id: &str,
        progress: InstallProgress,
    ) -> io::Result<()> {
        write_frame(
            pipe,
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

    fn poll_operation_cancel(pipe: HANDLE, operation_id: &str, action: &str) -> io::Result<bool> {
        let Some(cancel) = try_read_frame::<CancelOperationRequest>(pipe)? else {
            return Ok(false);
        };
        if cancel_operation_matches(&cancel, operation_id, action) {
            Ok(true)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "system operation cancellation frame was invalid",
            ))
        }
    }

    fn cancel_operation_matches(
        cancel: &CancelOperationRequest,
        operation_id: &str,
        action: &str,
    ) -> bool {
        cancel.protocol_version == PROTOCOL_VERSION
            && cancel.kind == "cancelOperation"
            && cancel.operation_id == operation_id
            && cancel.action == action
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

    fn duplicate_package_handle(
        server_process: &OwnedHandle,
        source_handle: u64,
    ) -> io::Result<File> {
        let source_handle = usize::try_from(source_handle)
            .ok()
            .filter(|value| *value != 0)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "package handle is invalid")
            })? as HANDLE;
        let mut raw_package: HANDLE = null_mut();
        // SAFETY: source process/handle identify the authenticated peer; target and output are valid.
        if unsafe {
            DuplicateHandle(
                server_process.as_raw_handle() as HANDLE,
                source_handle,
                GetCurrentProcess(),
                &mut raw_package,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: DuplicateHandle returned one owned real handle on success.
        let package = unsafe { OwnedHandle::from_raw_handle(raw_package) };
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the duplicated handle is live and `information` is writable.
        if unsafe {
            GetFileInformationByHandle(package.as_raw_handle() as HANDLE, &mut information)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
            || information.nNumberOfLinks != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicated package handle is not a regular single-link file",
            ));
        }
        Ok(File::from(package))
    }

    fn validate_authorized_package(
        package: File,
        package_id: &str,
        package_fingerprint: &str,
    ) -> io::Result<(luxury_bundle::Bundle, PathBuf, PathBuf)> {
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

    fn install_request_matches(request: &InstallAuthorizationRequest, operation_id: &str) -> bool {
        request.protocol_version == PROTOCOL_VERSION
            && request.kind == "authorizeInstall"
            && request.operation_id == operation_id
            && request.action == "install"
            && luxury_spec::PackageId::parse(&request.package_id).is_ok()
            && valid_lower_hex_64(&request.package_fingerprint)
            && request.source_handle != 0
            && usize::try_from(request.source_handle).is_ok()
    }

    fn system_install_request_matches(request: &SystemInstallRequest, operation_id: &str) -> bool {
        request.protocol_version == PROTOCOL_VERSION
            && request.kind == "installSystem"
            && request.operation_id == operation_id
            && request.action == "install"
            && luxury_spec::PackageId::parse(&request.package_id).is_ok()
            && valid_lower_hex_64(&request.package_fingerprint)
            && request.source_handle != 0
            && usize::try_from(request.source_handle).is_ok()
    }

    fn system_uninstall_request_matches(
        request: &SystemUninstallRequest,
        operation_id: &str,
    ) -> bool {
        request.protocol_version == PROTOCOL_VERSION
            && request.kind == "uninstallSystem"
            && request.operation_id == operation_id
            && request.action == "uninstall"
            && luxury_spec::PackageId::parse(&request.package_id).is_ok()
            && valid_lower_hex_64(&request.package_fingerprint)
            && request.source_handle != 0
            && usize::try_from(request.source_handle).is_ok()
    }

    fn system_launch_request_matches(request: &SystemLaunchRequest, operation_id: &str) -> bool {
        request.protocol_version == PROTOCOL_VERSION
            && request.kind == "launchSystem"
            && request.operation_id == operation_id
            && request.action == "launch"
            && luxury_spec::PackageId::parse(&request.package_id).is_ok()
            && valid_lower_hex_64(&request.package_fingerprint)
            && request.source_handle != 0
            && usize::try_from(request.source_handle).is_ok()
    }

    fn is_elevated() -> io::Result<bool> {
        let mut raw_token: HANDLE = null_mut();
        // SAFETY: the current-process pseudo handle is valid and `raw_token` is writable.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: OpenProcessToken returned one owned real handle on success.
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0_u32;
        // SAFETY: `elevation` is writable for its exact size and the token remains open.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if returned != size_of::<TOKEN_ELEVATION>() as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned malformed token elevation data",
            ));
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    fn valid_pipe_name(value: &str) -> bool {
        value
            .strip_prefix(PIPE_PREFIX)
            .is_some_and(valid_operation_id)
    }

    fn challenge_matches(challenge: &Challenge, pipe_name: &str, server_pid: u32) -> bool {
        challenge.protocol_version == PROTOCOL_VERSION
            && challenge.kind == "challenge"
            && challenge.server_pid == server_pid
            && valid_operation_id(&challenge.operation_id)
            && pipe_name.ends_with(&challenge.operation_id)
    }

    fn accepted_matches(accepted: &Accepted, operation_id: &str) -> bool {
        accepted.protocol_version == PROTOCOL_VERSION
            && accepted.kind == "accepted"
            && accepted.operation_id == operation_id
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

    fn open_pipe(path: &str, deadline: Instant) -> io::Result<File> {
        loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .open(Path::new(path))
            {
                Ok(pipe) => return Ok(pipe),
                Err(error)
                    if matches!(
                        error.raw_os_error().map(|code| code as u32),
                        Some(ERROR_FILE_NOT_FOUND) | Some(ERROR_PIPE_BUSY)
                    ) && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn write_frame<T: Serialize>(handle: HANDLE, frame: &T) -> io::Result<()> {
        let bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "privilege frame exceeded its bound",
            ));
        }
        let mut written = 0_u32;
        // SAFETY: `bytes` is readable for its exact length and `written` is writable.
        if unsafe {
            WriteFile(
                handle,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut written,
                null_mut(),
            )
        } == 0
            || written as usize != bytes.len()
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_frame<T: DeserializeOwned>(handle: HANDLE, deadline: Instant) -> io::Result<T> {
        loop {
            match try_read_frame(handle)? {
                Some(frame) => return Ok(frame),
                None if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "privilege peer did not send a frame in time",
                    ));
                }
            }
        }
    }

    fn try_read_frame<T: DeserializeOwned>(handle: HANDLE) -> io::Result<Option<T>> {
        let mut bytes = [0_u8; MAX_FRAME_BYTES + 1];
        let mut read = 0_u32;
        // SAFETY: `bytes` is writable for its exact length and `read` is writable.
        if unsafe {
            ReadFile(
                handle,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut read,
                null_mut(),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error().map(|code| code as u32) == Some(ERROR_NO_DATA) {
                return Ok(None);
            }
            return Err(error);
        }
        let read = read as usize;
        if read == 0 || read > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "privilege frame had an invalid size",
            ));
        }
        serde_json::from_slice(&bytes[..read])
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "privilege frame was invalid"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn pipe_names_and_operation_ids_are_exact() {
            assert!(valid_operation_id(&"a".repeat(32)));
            assert!(valid_pipe_name(&format!("{PIPE_PREFIX}{}", "0".repeat(32))));
            for invalid in [
                "a".repeat(31),
                "A".repeat(32),
                format!("{}g", "a".repeat(31)),
            ] {
                assert!(!valid_operation_id(&invalid));
            }
            assert!(!valid_pipe_name(
                r"\\.\pipe\other-00000000000000000000000000000000"
            ));
        }

        #[test]
        fn challenge_and_acceptance_reject_unknown_fields() {
            let challenge = serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "type": "challenge",
                "operationId": "a".repeat(32),
                "serverPid": 1,
            });
            let parsed = serde_json::from_value::<Challenge>(challenge.clone()).unwrap();
            let pipe = format!("{PIPE_PREFIX}{}", "a".repeat(32));
            assert!(challenge_matches(&parsed, &pipe, 1));
            assert!(!challenge_matches(&parsed, &pipe, 2));
            assert!(!challenge_matches(
                &parsed,
                &format!("{PIPE_PREFIX}{}", "b".repeat(32)),
                1,
            ));
            let mut extra = challenge;
            extra["extra"] = serde_json::json!(true);
            assert!(serde_json::from_value::<Challenge>(extra).is_err());

            let accepted = Accepted {
                protocol_version: PROTOCOL_VERSION,
                kind: "accepted".into(),
                operation_id: "a".repeat(32),
            };
            assert!(accepted_matches(&accepted, &"a".repeat(32)));
            assert!(!accepted_matches(&accepted, &"b".repeat(32)));
        }

        #[test]
        fn install_authorization_request_is_strict_and_action_bound() {
            let value = serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "type": "authorizeInstall",
                "operationId": "a".repeat(32),
                "action": "install",
                "packageId": "dev.luxury.demo",
                "packageFingerprint": "b".repeat(64),
                "sourceHandle": 1,
            });
            let request =
                serde_json::from_value::<InstallAuthorizationRequest>(value.clone()).unwrap();
            assert!(install_request_matches(&request, &"a".repeat(32)));
            assert!(!install_request_matches(&request, &"c".repeat(32)));

            let mut wrong_action = value.clone();
            wrong_action["action"] = serde_json::json!("uninstall");
            let request =
                serde_json::from_value::<InstallAuthorizationRequest>(wrong_action).unwrap();
            assert!(!install_request_matches(&request, &"a".repeat(32)));

            let mut extra = value;
            extra["installBase"] = serde_json::json!(r"C:\attacker-selected");
            assert!(serde_json::from_value::<InstallAuthorizationRequest>(extra).is_err());
        }

        #[test]
        fn system_install_request_is_consent_bound_and_contains_no_paths() {
            let value = serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "type": "installSystem",
                "operationId": "a".repeat(32),
                "action": "install",
                "packageId": "dev.luxury.demo",
                "packageFingerprint": "b".repeat(64),
                "sourceHandle": 1,
                "allowUnsigned": true,
                "acceptLicense": false,
                "allowPublisherMigration": false,
            });
            let request = serde_json::from_value::<SystemInstallRequest>(value.clone()).unwrap();
            assert!(system_install_request_matches(&request, &"a".repeat(32)));
            assert!(request.allow_unsigned);
            assert!(!request.accept_license);
            assert!(!request.allow_publisher_migration);

            let mut injected = value;
            injected["stateRoot"] = serde_json::json!(r"C:\attacker-state");
            assert!(serde_json::from_value::<SystemInstallRequest>(injected).is_err());

            let cancel = CancelOperationRequest {
                protocol_version: PROTOCOL_VERSION,
                kind: "cancelOperation".into(),
                operation_id: "a".repeat(32),
                action: "install".into(),
            };
            assert!(cancel_operation_matches(
                &cancel,
                &"a".repeat(32),
                "install"
            ));
            assert!(!cancel_operation_matches(
                &cancel,
                &"c".repeat(32),
                "install"
            ));
            assert!(!cancel_operation_matches(
                &cancel,
                &"a".repeat(32),
                "uninstall"
            ));

            assert!(should_emit_progress(None, 0, 10_000));
            assert!(!should_emit_progress(Some(0), 1, 10_000));
            assert!(should_emit_progress(Some(0), 20, 10_000));
            assert!(should_emit_progress(Some(9_999), 10_000, 10_000));
        }

        #[test]
        fn system_uninstall_request_is_pathless_and_action_bound() {
            let value = serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "type": "uninstallSystem",
                "operationId": "a".repeat(32),
                "action": "uninstall",
                "packageId": "dev.luxury.demo",
                "packageFingerprint": "b".repeat(64),
                "sourceHandle": 1,
            });
            let request = serde_json::from_value::<SystemUninstallRequest>(value.clone()).unwrap();
            assert!(system_uninstall_request_matches(&request, &"a".repeat(32)));

            let mut wrong_action = value.clone();
            wrong_action["action"] = serde_json::json!("install");
            let request = serde_json::from_value::<SystemUninstallRequest>(wrong_action).unwrap();
            assert!(!system_uninstall_request_matches(&request, &"a".repeat(32)));

            let mut injected = value;
            injected["installBase"] = serde_json::json!(r"C:\attacker-selected");
            assert!(serde_json::from_value::<SystemUninstallRequest>(injected).is_err());
        }

        #[test]
        fn system_launch_request_is_pathless_and_action_bound() {
            let value = serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "type": "launchSystem",
                "operationId": "a".repeat(32),
                "action": "launch",
                "packageId": "dev.luxury.demo",
                "packageFingerprint": "b".repeat(64),
                "sourceHandle": 1,
            });
            let request = serde_json::from_value::<SystemLaunchRequest>(value.clone()).unwrap();
            assert!(system_launch_request_matches(&request, &"a".repeat(32)));

            let mut wrong_action = value.clone();
            wrong_action["action"] = serde_json::json!("install");
            let request = serde_json::from_value::<SystemLaunchRequest>(wrong_action).unwrap();
            assert!(!system_launch_request_matches(&request, &"a".repeat(32)));

            let mut injected = value;
            injected["entrypoint"] = serde_json::json!(r"C:\attacker.exe");
            assert!(serde_json::from_value::<SystemLaunchRequest>(injected).is_err());
        }

        #[test]
        fn duplicated_handle_authorizes_only_the_exact_system_package() {
            let temp = tempfile::tempdir().unwrap();
            let project = temp.path().join("project");
            let package = temp.path().join("system.luxpkg");
            luxury_compiler::init_project(&project).unwrap();
            let config = project.join("luxury.toml");
            let source = std::fs::read_to_string(&config).unwrap();
            assert_eq!(source.matches("scope = \"user\"").count(), 1);
            std::fs::write(
                &config,
                source.replace("scope = \"user\"", "scope = \"system\""),
            )
            .unwrap();
            luxury_compiler::compile_project(&project, &package).unwrap();
            let inspected = luxury_bundle::open_bundle_file(&package, None).unwrap();
            let fingerprint = inspected.review_fingerprint().to_owned();
            drop(inspected);

            let source = File::open(&package).unwrap();
            let request = InstallAuthorizationRequest {
                protocol_version: PROTOCOL_VERSION,
                kind: "authorizeInstall".into(),
                operation_id: "a".repeat(32),
                action: "install".into(),
                package_id: "dev.luxury.demo".into(),
                package_fingerprint: fingerprint,
                source_handle: source.as_raw_handle() as usize as u64,
            };
            let server_process = open_process(
                std::process::id(),
                PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
            )
            .unwrap();
            let duplicated =
                duplicate_package_handle(&server_process, request.source_handle).unwrap();
            validate_authorized_package(
                duplicated,
                &request.package_id,
                &request.package_fingerprint,
            )
            .unwrap();

            let mut wrong = request;
            wrong.package_fingerprint = "0".repeat(64);
            let duplicated =
                duplicate_package_handle(&server_process, wrong.source_handle).unwrap();
            assert!(
                validate_authorized_package(
                    duplicated,
                    &wrong.package_id,
                    &wrong.package_fingerprint,
                )
                .is_err(),
                "a different reviewed fingerprint must be rejected"
            );
        }
    }
}
