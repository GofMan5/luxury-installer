use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
        process::CommandExt,
    },
    path::Path,
    process::{Child, Command, Stdio},
    ptr::{null, null_mut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use windows_sys::Win32::{
    Foundation::{
        ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, FILETIME, HANDLE,
        INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        GetFileInformationByHandle, PIPE_ACCESS_DUPLEX, ReadFile, SYNCHRONIZE, WriteFile,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_NOWAIT,
            PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
            SetNamedPipeHandleState,
        },
        Threading::{
            CREATE_NO_WINDOW, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess,
            GetProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
            PROCESS_QUERY_INFORMATION, TerminateProcess, WaitForSingleObject,
        },
    },
    UI::{
        Shell::{
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
            ShellExecuteExW,
        },
        WindowsAndMessaging::SW_HIDE,
    },
};

const PROTOCOL_VERSION: u8 = super::SYSTEM_PROTOCOL_VERSION;
const MAX_FRAME_BYTES: usize = 4 * 1024;
const PIPE_TIMEOUT: Duration = Duration::from_secs(15);
const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SYSTEM_INSTALL_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const SYSTEM_INSTALL_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Challenge<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    server_pid: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: String,
    operation_id: String,
    server_pid: u32,
    helper_pid: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Accepted<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallAuthorizationRequest<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
    package_id: &'a str,
    package_fingerprint: &'a str,
    source_handle: u64,
}

struct InstallAuthorization<'a> {
    action: &'static str,
    package_id: &'a str,
    package_fingerprint: &'a str,
    source_handle: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallAuthorized {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: String,
    operation_id: String,
    action: String,
    package_id: String,
    package_fingerprint: String,
    preparation: crate::backend::PrepareInstallResult,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInstallRequest<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
    package_id: &'a str,
    package_fingerprint: &'a str,
    source_handle: u64,
    allow_unsigned: bool,
    accept_license: bool,
    allow_publisher_migration: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemUninstallRequest<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
    package_id: &'a str,
    package_fingerprint: &'a str,
    source_handle: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemLaunchRequest<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
    package_id: &'a str,
    package_fingerprint: &'a str,
    source_handle: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CancelOperationRequest<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
}

enum SystemRequest {
    Install {
        allow_unsigned: bool,
        accept_license: bool,
        allow_publisher_migration: bool,
    },
    Uninstall,
    Launch,
}

impl SystemRequest {
    const fn action(&self) -> &'static str {
        match self {
            Self::Install { .. } => "install",
            Self::Uninstall => "uninstall",
            Self::Launch => "launch",
        }
    }

    const fn helper_command(&self) -> &'static str {
        match self {
            Self::Install { .. } => "privilege-install-system",
            Self::Uninstall => "privilege-uninstall-system",
            Self::Launch => "privilege-launch-system",
        }
    }
}

struct SystemJob {
    executable: std::path::PathBuf,
    package: File,
    package_id: String,
    package_fingerprint: String,
    request: SystemRequest,
    operation_id: String,
    cancel: Arc<AtomicBool>,
    sender: mpsc::Sender<crate::backend::OperationMessage>,
}

pub(super) fn is_elevated() -> io::Result<bool> {
    // SAFETY: GetCurrentProcess returns a valid pseudo handle for this process.
    process_is_elevated(unsafe { GetCurrentProcess() })
}

pub(super) fn verify_container_parent() -> io::Result<()> {
    let parent_pid = parent_process_id()?;
    let raw_parent = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, 0, parent_pid) };
    if raw_parent.is_null() {
        return Err(io::Error::last_os_error());
    }
    let parent = unsafe { OwnedHandle::from_raw_handle(raw_parent) };
    let parent_handle = parent.as_raw_handle() as HANDLE;
    let parent_created = process_creation_time(parent_handle)?;
    let current_created = unsafe { process_creation_time(GetCurrentProcess()) }?;
    if parent_created >= current_created || !process_is_active(parent_handle)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "container parent process identity is stale or invalid",
        ));
    }
    let current = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) };
    luxury_windows_trust::verify_same_process_authenticode_signer(current, parent.as_handle())
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "container parent Authenticode signer does not match the launcher",
            )
        })?;
    if process_creation_time(parent_handle)? != parent_created || !process_is_active(parent_handle)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "container parent identity changed during verification",
        ));
    }
    Ok(())
}

fn parent_process_id() -> io::Result<u32> {
    let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw_snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw_snapshot) };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    if unsafe { Process32FirstW(snapshot.as_raw_handle() as HANDLE, &mut entry) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let current_pid = unsafe { GetCurrentProcessId() };
    loop {
        if entry.th32ProcessID == current_pid {
            return (entry.th32ParentProcessID != 0 && entry.th32ParentProcessID != current_pid)
                .then_some(entry.th32ParentProcessID)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "invalid container parent PID",
                    )
                });
        }
        if unsafe { Process32NextW(snapshot.as_raw_handle() as HANDLE, &mut entry) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "current process was absent from the native process snapshot",
            ));
        }
    }
}

fn process_creation_time(process: HANDLE) -> io::Result<u64> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

fn process_is_active(process: HANDLE) -> io::Result<bool> {
    match unsafe { WaitForSingleObject(process, 0) } {
        WAIT_TIMEOUT => Ok(true),
        WAIT_OBJECT_0 => Ok(false),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        status => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Windows returned an invalid process wait status: {status}"),
        )),
    }
}

fn process_is_elevated(process: HANDLE) -> io::Result<bool> {
    let mut raw_token: HANDLE = null_mut();
    // SAFETY: `process` is a live process handle and `raw_token` is writable.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned one owned real handle on success.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0_u32;
    // SAFETY: `elevation` is writable for its exact declared size and the token remains open.
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

pub(super) fn verify_backend_transport(executable: &Path) -> io::Result<()> {
    let operation_id = random_operation_id()?;
    let pipe_name = format!(r"\\.\pipe\luxury-installer-{operation_id}");
    let pipe = create_pipe(&pipe_name)?;
    let server_pid = std::process::id();
    let mut child = Command::new(executable)
        .arg("privilege-probe")
        .arg(&pipe_name)
        .arg(server_pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()?;
    let result = run_server(&pipe, &operation_id, server_pid, child.id(), None);
    if result.is_err() {
        let _ = child.kill();
    }
    let exit = wait_child(&mut child, PIPE_TIMEOUT)?;
    result?;
    if !exit.success() {
        return Err(io::Error::other("privilege probe helper failed"));
    }
    Ok(())
}

pub(super) fn verify_elevated_backend_transport(executable: &Path) -> io::Result<()> {
    verify_elevated_backend_transport_command(executable, "privilege-probe-elevated")
}

pub(super) fn verify_authenticated_backend_transport(executable: &Path) -> io::Result<()> {
    run_elevated_backend_command(executable, "privilege-probe-authenticated", true, None)
        .map(|_| ())
}

pub(super) fn authorize_system_install(
    executable: &Path,
    package: &Path,
    package_id: &str,
    package_fingerprint: &str,
) -> io::Result<crate::backend::PrepareInstallResult> {
    if !crate::app::valid_package_id(package_id) || !valid_lower_hex_64(package_fingerprint) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "system install identity is invalid",
        ));
    }
    let package = open_pinned_file(package)?;
    let result = run_elevated_backend_command(
        executable,
        "privilege-authorize-install",
        true,
        Some(InstallAuthorization {
            action: "install",
            package_id,
            package_fingerprint,
            source_handle: package.as_raw_handle() as usize as u64,
        }),
    );
    drop(package);
    result?.ok_or_else(|| io::Error::other("system preparation result was missing"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "reviewed package identity and three explicit user consents cross the privilege boundary"
)]
pub(super) fn start_system_install(
    executable: &Path,
    package: &Path,
    package_id: &str,
    package_fingerprint: &str,
    allow_unsigned: bool,
    accept_license: bool,
    allow_publisher_migration: bool,
) -> io::Result<super::SystemOperation> {
    start_system_operation(
        executable,
        package,
        package_id,
        package_fingerprint,
        SystemRequest::Install {
            allow_unsigned,
            accept_license,
            allow_publisher_migration,
        },
    )
}

pub(super) fn start_system_uninstall(
    executable: &Path,
    package: &Path,
    package_id: &str,
    package_fingerprint: &str,
) -> io::Result<super::SystemOperation> {
    start_system_operation(
        executable,
        package,
        package_id,
        package_fingerprint,
        SystemRequest::Uninstall,
    )
}

pub(super) fn start_system_launch(
    executable: &Path,
    package: &Path,
    package_id: &str,
    package_fingerprint: &str,
) -> io::Result<super::SystemOperation> {
    start_system_operation(
        executable,
        package,
        package_id,
        package_fingerprint,
        SystemRequest::Launch,
    )
}

fn start_system_operation(
    executable: &Path,
    package: &Path,
    package_id: &str,
    package_fingerprint: &str,
    request: SystemRequest,
) -> io::Result<super::SystemOperation> {
    if !crate::app::valid_package_id(package_id) || !valid_lower_hex_64(package_fingerprint) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "system operation identity is invalid",
        ));
    }
    let package = open_pinned_file(package)?;
    let operation_id = random_operation_id()?;
    let cancel = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel();
    let thread_name = format!("luxury-system-{}", request.action());
    let job = SystemJob {
        executable: executable.to_path_buf(),
        package,
        package_id: package_id.to_owned(),
        package_fingerprint: package_fingerprint.to_owned(),
        request,
        operation_id: operation_id.clone(),
        cancel: Arc::clone(&cancel),
        sender,
    };
    thread::Builder::new().name(thread_name).spawn(move || {
        let failure_sender = job.sender.clone();
        if let Err(error) = run_system_operation_command(job) {
            let code = if error.raw_os_error() == Some(1223) {
                "cancelled"
            } else if error.kind() == io::ErrorKind::TimedOut {
                "backend_timeout"
            } else {
                "backend_unavailable"
            };
            let _ = failure_sender.send(crate::backend::OperationMessage::Complete(Err(
                crate::backend::BackendError::new(code, "system operation helper failed"),
            )));
        }
    })?;
    Ok(super::SystemOperation {
        operation_id,
        receiver,
        cancel,
    })
}

fn verify_elevated_backend_transport_command(
    executable: &Path,
    helper_command: &'static str,
) -> io::Result<()> {
    run_elevated_backend_command(executable, helper_command, false, None).map(|_| ())
}

fn run_elevated_backend_command(
    executable: &Path,
    helper_command: &'static str,
    require_authenticode: bool,
    authorization: Option<InstallAuthorization<'_>>,
) -> io::Result<Option<crate::backend::PrepareInstallResult>> {
    let operation_id = random_operation_id()?;
    let pipe_name = format!(r"\\.\pipe\luxury-installer-{operation_id}");
    let pipe = create_pipe(&pipe_name)?;
    let server_pid = std::process::id();
    let process = launch_elevated(
        executable,
        helper_command,
        &pipe_name,
        server_pid,
        require_authenticode,
    )?;
    let process_handle = process.as_raw_handle() as HANDLE;
    let helper_pid = unsafe { GetProcessId(process_handle) };
    if helper_pid == 0 {
        let error = io::Error::last_os_error();
        terminate_process(&process);
        return Err(error);
    }
    match process_is_elevated(process_handle) {
        Ok(true) => {}
        Ok(false) => {
            terminate_process(&process);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "launched privilege helper was not elevated",
            ));
        }
        Err(error) => {
            terminate_process(&process);
            return Err(error);
        }
    }
    let result = run_server(&pipe, &operation_id, server_pid, helper_pid, authorization);
    if result.is_err() {
        terminate_process(&process);
    }
    let exit_code = wait_process(&process, PIPE_TIMEOUT)?;
    let preparation = result?;
    if exit_code != 0 {
        return Err(io::Error::other("elevated privilege probe helper failed"));
    }
    Ok(preparation)
}

fn run_system_operation_command(job: SystemJob) -> io::Result<()> {
    let pipe_name = format!(r"\\.\pipe\luxury-installer-{}", job.operation_id);
    let pipe = create_pipe(&pipe_name)?;
    let server_pid = std::process::id();
    let process = launch_elevated(
        &job.executable,
        job.request.helper_command(),
        &pipe_name,
        server_pid,
        true,
    )?;
    let process_handle = process.as_raw_handle() as HANDLE;
    let helper_pid = unsafe { GetProcessId(process_handle) };
    if helper_pid == 0 {
        let error = io::Error::last_os_error();
        terminate_process(&process);
        return Err(error);
    }
    match process_is_elevated(process_handle) {
        Ok(true) => {}
        Ok(false) => {
            terminate_process(&process);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "launched system operation helper was not elevated",
            ));
        }
        Err(error) => {
            terminate_process(&process);
            return Err(error);
        }
    }
    let terminal = run_system_operation_server(&pipe, server_pid, helper_pid, &job);
    if terminal.is_err() {
        terminate_process(&process);
    }
    let exit_code = wait_process(&process, PIPE_TIMEOUT)?;
    let terminal = terminal?;
    if exit_code != 0 {
        return Err(io::Error::other("system operation helper failed"));
    }
    super::send_operation(&job.sender, terminal)
}

fn run_system_operation_server(
    pipe: &File,
    server_pid: u32,
    helper_pid: u32,
    job: &SystemJob,
) -> io::Result<crate::backend::OperationMessage> {
    let handle = accept_helper(pipe, &job.operation_id, server_pid, helper_pid)?;
    match &job.request {
        SystemRequest::Install {
            allow_unsigned,
            accept_license,
            allow_publisher_migration,
        } => write_frame(
            handle,
            &SystemInstallRequest {
                protocol_version: PROTOCOL_VERSION,
                kind: "installSystem",
                operation_id: &job.operation_id,
                action: "install",
                package_id: &job.package_id,
                package_fingerprint: &job.package_fingerprint,
                source_handle: job.package.as_raw_handle() as usize as u64,
                allow_unsigned: *allow_unsigned,
                accept_license: *accept_license,
                allow_publisher_migration: *allow_publisher_migration,
            },
        )?,
        SystemRequest::Uninstall => write_frame(
            handle,
            &SystemUninstallRequest {
                protocol_version: PROTOCOL_VERSION,
                kind: "uninstallSystem",
                operation_id: &job.operation_id,
                action: "uninstall",
                package_id: &job.package_id,
                package_fingerprint: &job.package_fingerprint,
                source_handle: job.package.as_raw_handle() as usize as u64,
            },
        )?,
        SystemRequest::Launch => write_frame(
            handle,
            &SystemLaunchRequest {
                protocol_version: PROTOCOL_VERSION,
                kind: "launchSystem",
                operation_id: &job.operation_id,
                action: "launch",
                package_id: &job.package_id,
                package_fingerprint: &job.package_fingerprint,
                source_handle: job.package.as_raw_handle() as usize as u64,
            },
        )?,
    }

    let started = Instant::now();
    let mut last_frame = started;
    let mut cancel_sent = false;
    loop {
        if !cancel_sent && job.cancel.load(Ordering::Acquire) {
            write_frame(
                handle,
                &CancelOperationRequest {
                    protocol_version: PROTOCOL_VERSION,
                    kind: "cancelOperation",
                    operation_id: &job.operation_id,
                    action: job.request.action(),
                },
            )?;
            cancel_sent = true;
        }
        if let Some(frame) = try_read_frame::<super::SystemOperationFrame>(handle)? {
            last_frame = Instant::now();
            if let Some(terminal) = super::forward_system_operation_frame(
                frame,
                job.request.action(),
                &job.operation_id,
                &job.package_id,
                &job.sender,
            )? {
                return Ok(terminal);
            }
            continue;
        }
        let now = Instant::now();
        if now.duration_since(started) >= SYSTEM_INSTALL_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "system operation exceeded its deadline",
            ));
        }
        if now.duration_since(last_frame) >= SYSTEM_INSTALL_IDLE_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "system operation stopped reporting progress",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn open_pinned_file(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bound package path must be absolute",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file handle is live and `information` is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || information.nNumberOfLinks != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bound package must be a regular single-link non-reparse file",
        ));
    }
    Ok(file)
}

fn open_elevated_executable(path: &Path, require_authenticode: bool) -> io::Result<File> {
    let file = open_pinned_file(path)?;
    if require_authenticode {
        let current = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) };
        let launcher =
            luxury_windows_trust::verify_process_authenticode_signer(current).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "running launcher Authenticode identity is invalid",
                )
            })?;
        let helper = luxury_windows_trust::verify_authenticode_signer(path).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "privilege helper Authenticode identity is invalid",
            )
        })?;
        if launcher != helper {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "launcher and privilege helper Authenticode identities differ",
            ));
        }
    }
    Ok(file)
}

fn launch_elevated(
    executable: &Path,
    helper_command: &'static str,
    pipe_name: &str,
    server_pid: u32,
    require_authenticode: bool,
) -> io::Result<OwnedHandle> {
    if !executable.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "privilege helper path must be absolute",
        ));
    }
    let _executable = open_elevated_executable(executable, require_authenticode)?;
    let verb = wide_nul(OsStr::new("runas"))?;
    let file = wide_nul(executable.as_os_str())?;
    let parameters = wide_nul(OsStr::new(&format!(
        "{helper_command} {pipe_name} {server_pid}"
    )))?;
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_HIDE,
        ..Default::default()
    };
    // SAFETY: all pointers reference NUL-terminated buffers alive for the synchronous call.
    if unsafe { ShellExecuteExW(&mut execute) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if execute.hProcess.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows did not return the launched helper process handle",
        ));
    }
    // SAFETY: SEE_MASK_NOCLOSEPROCESS returns one owned process handle on success.
    Ok(unsafe { OwnedHandle::from_raw_handle(execute.hProcess) })
}

fn wide_nul(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows argument contained NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn wait_process(process: &OwnedHandle, timeout: Duration) -> io::Result<u32> {
    let handle = process.as_raw_handle() as HANDLE;
    // SAFETY: `handle` remains live and the timeout is bounded.
    match unsafe { WaitForSingleObject(handle, timeout.as_millis() as u32) } {
        WAIT_OBJECT_0 => {
            let mut exit_code = 0_u32;
            // SAFETY: the process is signaled and `exit_code` is writable.
            if unsafe { GetExitCodeProcess(handle, &mut exit_code) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(exit_code)
            }
        }
        WAIT_TIMEOUT => {
            terminate_process(process);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "elevated privilege helper did not exit in time",
            ))
        }
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid process wait result",
        )),
    }
}

fn terminate_process(process: &OwnedHandle) {
    let handle = process.as_raw_handle() as HANDLE;
    // SAFETY: `handle` remains live; this cleanup is used only by the one-shot probe.
    let _ = unsafe { TerminateProcess(handle, 1) };
    // SAFETY: `handle` remains live and the cleanup wait is bounded.
    let _ = unsafe { WaitForSingleObject(handle, PIPE_TIMEOUT.as_millis() as u32) };
}

fn run_server(
    pipe: &File,
    operation_id: &str,
    server_pid: u32,
    expected_helper_pid: u32,
    authorization: Option<InstallAuthorization<'_>>,
) -> io::Result<Option<crate::backend::PrepareInstallResult>> {
    let handle = accept_helper(pipe, operation_id, server_pid, expected_helper_pid)?;
    let preparation = if let Some(authorization) = authorization {
        let request = InstallAuthorizationRequest {
            protocol_version: PROTOCOL_VERSION,
            kind: "authorizeInstall",
            operation_id,
            action: authorization.action,
            package_id: authorization.package_id,
            package_fingerprint: authorization.package_fingerprint,
            source_handle: authorization.source_handle,
        };
        write_frame(handle, &request)?;
        let authorized: InstallAuthorized =
            read_frame(handle, Instant::now() + AUTHORIZATION_TIMEOUT)?;
        if !authorization_matches(&authorized, &request) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "privilege helper returned an invalid install authorization",
            ));
        }
        Some(authorized.preparation)
    } else {
        None
    };
    Ok(preparation)
}

fn accept_helper(
    pipe: &File,
    operation_id: &str,
    server_pid: u32,
    expected_helper_pid: u32,
) -> io::Result<HANDLE> {
    connect(pipe, Instant::now() + PIPE_TIMEOUT)?;
    let handle = pipe.as_raw_handle() as HANDLE;
    let mut helper_pid = 0_u32;
    // SAFETY: `handle` is a connected named pipe and the PID output is writable.
    if unsafe { GetNamedPipeClientProcessId(handle, &mut helper_pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if helper_pid != expected_helper_pid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "named-pipe client PID did not match launched helper",
        ));
    }
    write_frame(
        handle,
        &Challenge {
            protocol_version: PROTOCOL_VERSION,
            kind: "challenge",
            operation_id,
            server_pid,
        },
    )?;
    let ready: Ready = read_frame(handle, Instant::now() + PIPE_TIMEOUT)?;
    if !ready_matches(&ready, operation_id, server_pid, helper_pid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "privilege helper returned an invalid ready frame",
        ));
    }
    write_frame(
        handle,
        &Accepted {
            protocol_version: PROTOCOL_VERSION,
            kind: "accepted",
            operation_id,
        },
    )?;
    Ok(handle)
}

fn ready_matches(ready: &Ready, operation_id: &str, server_pid: u32, helper_pid: u32) -> bool {
    ready.protocol_version == PROTOCOL_VERSION
        && ready.kind == "ready"
        && ready.operation_id == operation_id
        && ready.server_pid == server_pid
        && ready.helper_pid == helper_pid
}

fn authorization_matches(
    authorized: &InstallAuthorized,
    request: &InstallAuthorizationRequest<'_>,
) -> bool {
    authorized.protocol_version == PROTOCOL_VERSION
        && authorized.kind == "installAuthorized"
        && authorized.operation_id == request.operation_id
        && authorized.action == request.action
        && authorized.package_id == request.package_id
        && authorized.package_fingerprint == request.package_fingerprint
}

fn valid_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn create_pipe(name: &str) -> io::Result<File> {
    let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    // SAFETY: `wide` is NUL-terminated, buffer sizes are bounded, and default security is used.
    let raw = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_FRAME_BYTES as u32,
            MAX_FRAME_BYTES as u32,
            PIPE_TIMEOUT.as_millis() as u32,
            null(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateNamedPipeW returned one owned real handle on success.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(raw) }))
}

fn connect(pipe: &File, deadline: Instant) -> io::Result<()> {
    let handle = pipe.as_raw_handle() as HANDLE;
    loop {
        // SAFETY: `handle` is a listening named-pipe handle and null requests synchronous mode.
        if unsafe { ConnectNamedPipe(handle, null_mut()) } != 0 {
            break;
        }
        match io::Error::last_os_error()
            .raw_os_error()
            .map(|code| code as u32)
        {
            Some(ERROR_PIPE_CONNECTED) => break,
            Some(ERROR_PIPE_LISTENING) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            _ if Instant::now() >= deadline => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "privilege helper did not connect in time",
                ));
            }
            _ => return Err(io::Error::last_os_error()),
        }
    }
    let mode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
    // SAFETY: `handle` is connected and `mode` is a valid readable mode value.
    if unsafe { SetNamedPipeHandleState(handle, &mode, null_mut(), null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn random_operation_id() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    // SAFETY: the system-preferred RNG accepts a null algorithm and this exact writable buffer.
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(io::Error::other("Windows random generation failed"));
    }
    let mut output = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
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
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
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

fn wait_child(child: &mut Child, timeout: Duration) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(exit) = child.try_wait()? {
            return Ok(exit);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "privilege helper did not exit in time",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privilege::{
        SystemOperationFrame, SystemPreparation, forward_system_operation_frame,
        require_system_frame, system_frame_action,
    };

    #[test]
    fn ready_contract_rejects_unknown_fields_and_wrong_values() {
        let valid = serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "ready",
            "operationId": "a".repeat(32),
            "serverPid": 1,
            "helperPid": 2,
        });
        let ready = serde_json::from_value::<Ready>(valid.clone()).unwrap();
        assert!(ready_matches(&ready, &"a".repeat(32), 1, 2));
        assert!(!ready_matches(&ready, &"b".repeat(32), 1, 2));
        assert!(!ready_matches(&ready, &"a".repeat(32), 1, 3));
        let mut extra = valid;
        extra["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Ready>(extra).is_err());
    }

    #[test]
    fn operation_ids_are_random_lower_hex() {
        let first = random_operation_id().unwrap();
        let second = random_operation_id().unwrap();
        assert_ne!(first, second);
        for value in [first, second] {
            assert_eq!(value.len(), 32);
            assert!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            );
        }
    }

    #[test]
    fn elevated_executable_is_pinned_and_authenticated_before_launch() {
        let current_executable = std::env::current_exe().unwrap();
        let root = std::env::temp_dir().join(format!(
            "luxury-elevation-preflight-{}",
            random_operation_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        let executable = root.join("helper.exe");
        let moved = root.join("helper.moved.exe");
        std::fs::copy(&current_executable, &executable).unwrap();

        let guard = open_elevated_executable(&executable, false).unwrap();
        assert!(std::fs::rename(&executable, &moved).is_err());
        drop(guard);
        std::fs::rename(&executable, &moved).unwrap();

        let current = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) };
        let current_is_signed =
            luxury_windows_trust::verify_process_authenticode_signer(current).is_ok();
        assert_eq!(
            open_elevated_executable(&current_executable, true).is_ok(),
            current_is_signed
        );

        std::fs::remove_file(moved).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn windows_arguments_are_nul_terminated_and_reject_embedded_nul() {
        assert_eq!(
            wide_nul(OsStr::new("runas")).unwrap(),
            [114, 117, 110, 97, 115, 0]
        );
        assert!(wide_nul(OsStr::new("bad\0argument")).is_err());
    }

    #[test]
    fn install_authorization_response_is_exact() {
        let request = InstallAuthorizationRequest {
            protocol_version: PROTOCOL_VERSION,
            kind: "authorizeInstall",
            operation_id: "a",
            action: "install",
            package_id: "dev.luxury.demo",
            package_fingerprint: &"b".repeat(64),
            source_handle: 42,
        };
        let wire = serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "installAuthorized",
            "operationId": "a",
            "action": "install",
            "packageId": "dev.luxury.demo",
            "packageFingerprint": "b".repeat(64),
            "preparation": {
                "status": "ready",
                "action": "install",
                "installedVersion": null,
                "publisherMigrationRequired": false,
            },
        });
        let mut authorized = serde_json::from_value::<InstallAuthorized>(wire.clone()).unwrap();
        assert!(authorization_matches(&authorized, &request));
        authorized.action = "uninstall".into();
        assert!(!authorization_matches(&authorized, &request));
        let mut missing = wire.clone();
        missing.as_object_mut().unwrap().remove("preparation");
        assert!(serde_json::from_value::<InstallAuthorized>(missing).is_err());
        let mut extra = wire;
        extra["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<InstallAuthorized>(extra).is_err());
        assert!(valid_lower_hex_64(&"b".repeat(64)));
        assert!(!valid_lower_hex_64(&"B".repeat(64)));
    }

    #[test]
    fn system_install_protocol_is_pathless_strict_and_operation_bound() {
        let request = SystemInstallRequest {
            protocol_version: PROTOCOL_VERSION,
            kind: "installSystem",
            operation_id: "a",
            action: "install",
            package_id: "dev.luxury.demo",
            package_fingerprint: &"b".repeat(64),
            source_handle: 42,
            allow_unsigned: true,
            accept_license: false,
            allow_publisher_migration: false,
        };
        let encoded = serde_json::to_value(&request).unwrap();
        assert!(encoded.get("packagePath").is_none());
        assert!(encoded.get("installBase").is_none());
        assert!(encoded.get("stateRoot").is_none());

        let frame = serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "installProgress",
            "operationId": "a",
            "completedFiles": 1,
            "totalFiles": 2,
            "completedBytes": 3,
            "totalBytes": 4,
        });
        assert!(serde_json::from_value::<SystemOperationFrame>(frame.clone()).is_ok());
        let mut extra = frame;
        extra["path"] = serde_json::json!(r"C:\private");
        assert!(serde_json::from_value::<SystemOperationFrame>(extra).is_err());
        assert!(require_system_frame(PROTOCOL_VERSION, "a", "a").is_ok());
        assert!(require_system_frame(PROTOCOL_VERSION, "b", "a").is_err());
        assert!(require_system_frame(1, "a", "a").is_err());

        let missing_preparation = serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "installComplete",
            "operationId": "a",
            "action": "install",
            "packageId": "dev.luxury.demo",
            "installDirectory": "Luxury Demo",
            "installedFiles": 1,
            "installedBytes": 2,
        });
        let frame = serde_json::from_value::<SystemOperationFrame>(missing_preparation).unwrap();
        let SystemOperationFrame::Complete {
            system_preparation, ..
        } = frame
        else {
            panic!("install completion parsed as another frame");
        };
        assert!(system_preparation.0.is_null());
    }

    #[test]
    fn system_uninstall_protocol_is_pathless_and_action_separated() {
        let request = SystemUninstallRequest {
            protocol_version: PROTOCOL_VERSION,
            kind: "uninstallSystem",
            operation_id: "a",
            action: "uninstall",
            package_id: "dev.luxury.demo",
            package_fingerprint: &"b".repeat(64),
            source_handle: 42,
        };
        let encoded = serde_json::to_value(&request).unwrap();
        assert!(encoded.get("packagePath").is_none());
        assert!(encoded.get("installBase").is_none());
        assert!(encoded.get("stateRoot").is_none());

        let frame = serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "uninstallProgress",
            "operationId": "a",
            "processedFiles": 1,
            "totalFiles": 2,
        });
        let frame = serde_json::from_value::<SystemOperationFrame>(frame).unwrap();
        assert_eq!(system_frame_action(&frame), "uninstall");

        let cancel = CancelOperationRequest {
            protocol_version: PROTOCOL_VERSION,
            kind: "cancelOperation",
            operation_id: "a",
            action: "uninstall",
        };
        assert_eq!(
            serde_json::to_value(cancel).unwrap(),
            serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "type": "cancelOperation",
                "operationId": "a",
                "action": "uninstall",
            })
        );
    }

    #[test]
    fn system_launch_protocol_is_pathless_and_terminal_only() {
        let request = SystemLaunchRequest {
            protocol_version: PROTOCOL_VERSION,
            kind: "launchSystem",
            operation_id: "a",
            action: "launch",
            package_id: "dev.luxury.demo",
            package_fingerprint: &"b".repeat(64),
            source_handle: 42,
        };
        let encoded = serde_json::to_value(request).unwrap();
        assert!(encoded.get("packagePath").is_none());
        assert!(encoded.get("installBase").is_none());
        assert!(encoded.get("stateRoot").is_none());

        let frame = serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "launchComplete",
            "operationId": "a",
            "status": "launched",
            "packageId": "dev.luxury.demo",
        });
        let frame = serde_json::from_value::<SystemOperationFrame>(frame).unwrap();
        assert_eq!(system_frame_action(&frame), "launch");
    }

    #[test]
    fn terminal_frame_is_withheld_until_the_helper_exit_is_checked() {
        let executable = std::env::current_exe().unwrap();
        let package = File::open(&executable).unwrap();
        let (sender, receiver) = mpsc::channel();
        let job = SystemJob {
            executable,
            package,
            package_id: "dev.luxury.demo".into(),
            package_fingerprint: "b".repeat(64),
            request: SystemRequest::Install {
                allow_unsigned: true,
                accept_license: false,
                allow_publisher_migration: false,
            },
            operation_id: "a".into(),
            cancel: Arc::new(AtomicBool::new(false)),
            sender,
        };
        let terminal = forward_system_operation_frame(
            SystemOperationFrame::Complete {
                protocol_version: PROTOCOL_VERSION,
                operation_id: "a".into(),
                action: crate::backend::InstallResultAction::Install,
                package_id: "dev.luxury.demo".into(),
                install_directory: "Luxury Demo".into(),
                installed_files: 1,
                installed_bytes: 2,
                system_preparation: SystemPreparation(serde_json::json!({
                    "status": "recoveryRequired"
                })),
            },
            job.request.action(),
            &job.operation_id,
            &job.package_id,
            &job.sender,
        )
        .unwrap();

        assert!(matches!(
            &terminal,
            Some(crate::backend::OperationMessage::Complete(Ok(_)))
        ));
        let Some(crate::backend::OperationMessage::Complete(Ok(value))) = terminal else {
            unreachable!();
        };
        assert_eq!(value["systemPreparation"]["status"], "recoveryRequired");
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        let wrong_action = match forward_system_operation_frame(
            SystemOperationFrame::UninstallComplete {
                protocol_version: PROTOCOL_VERSION,
                operation_id: "a".into(),
                status: "notInstalled".into(),
                package_id: "dev.luxury.demo".into(),
                removed_files: 0,
                missing_files: 0,
                preserved_modified_files: 0,
                system_preparation: SystemPreparation(serde_json::Value::Null),
            },
            job.request.action(),
            &job.operation_id,
            &job.package_id,
            &job.sender,
        ) {
            Err(error) => error,
            Ok(_) => panic!("an uninstall frame must not complete an install job"),
        };
        assert_eq!(wrong_action.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn system_uninstall_terminal_is_aggregate_and_withheld() {
        let executable = std::env::current_exe().unwrap();
        let package = File::open(&executable).unwrap();
        let (sender, receiver) = mpsc::channel();
        let job = SystemJob {
            executable,
            package,
            package_id: "dev.luxury.demo".into(),
            package_fingerprint: "b".repeat(64),
            request: SystemRequest::Uninstall,
            operation_id: "a".into(),
            cancel: Arc::new(AtomicBool::new(false)),
            sender,
        };
        let terminal = forward_system_operation_frame(
            SystemOperationFrame::UninstallComplete {
                protocol_version: PROTOCOL_VERSION,
                operation_id: "a".into(),
                status: "uninstalled".into(),
                package_id: "dev.luxury.demo".into(),
                removed_files: 2,
                missing_files: 1,
                preserved_modified_files: 3,
                system_preparation: SystemPreparation(serde_json::Value::Null),
            },
            job.request.action(),
            &job.operation_id,
            &job.package_id,
            &job.sender,
        )
        .unwrap();

        let Some(crate::backend::OperationMessage::Complete(Ok(value))) = terminal else {
            panic!("uninstall terminal frame did not produce one held result");
        };
        assert_eq!(value["status"], "uninstalled");
        assert_eq!(value["removedFiles"], 2);
        assert_eq!(value["missingFiles"], 1);
        assert_eq!(value["preservedModifiedFiles"], 3);
        assert!(value.get("path").is_none());
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn system_launch_terminal_is_bound_and_withheld() {
        let executable = std::env::current_exe().unwrap();
        let package = File::open(&executable).unwrap();
        let (sender, receiver) = mpsc::channel();
        let job = SystemJob {
            executable,
            package,
            package_id: "dev.luxury.demo".into(),
            package_fingerprint: "b".repeat(64),
            request: SystemRequest::Launch,
            operation_id: "a".into(),
            cancel: Arc::new(AtomicBool::new(false)),
            sender,
        };
        let terminal = forward_system_operation_frame(
            SystemOperationFrame::LaunchComplete {
                protocol_version: PROTOCOL_VERSION,
                operation_id: "a".into(),
                status: "launched".into(),
                package_id: "dev.luxury.demo".into(),
            },
            job.request.action(),
            &job.operation_id,
            &job.package_id,
            &job.sender,
        )
        .unwrap();
        let Some(crate::backend::OperationMessage::Complete(Ok(value))) = terminal else {
            panic!("launch terminal frame did not produce one held result");
        };
        assert_eq!(value["status"], "launched");
        assert_eq!(value["packageId"], "dev.luxury.demo");
        assert!(value.get("path").is_none());
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }
}
