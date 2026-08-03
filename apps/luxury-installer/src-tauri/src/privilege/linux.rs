use std::{
    fs::{File, Metadata},
    io::{self, IoSlice, IoSliceMut, Read},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::{fs::MetadataExt, net::UnixDatagram},
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, UCred, recvmsg, sendmsg,
    sockopt::{Timeout, set_socket_passcred, set_socket_timeout},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const PROTOCOL_VERSION: u8 = 1;
const MAX_FRAME_BYTES: usize = 4 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(15);
const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SYSTEM_OPERATION_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const SYSTEM_OPERATION_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const PKEXEC_PATH: &str = "/usr/bin/pkexec";
const HELPER_PATH: &str = "/usr/libexec/luxury-installer-helper";
const POLICY_PATH: &str = "/usr/share/polkit-1/actions/software.luxury.installer.policy";
const POLICY_BYTES: &[u8] =
    include_bytes!("../../../../../packaging/linux/software.luxury.installer.policy");
const ECANCELED: i32 = 125;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Challenge<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
    caller_pid: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: String,
    operation_id: String,
    action: String,
    caller_pid: u32,
    caller_uid: u32,
    helper_pid: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationRequest<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
    package_id: &'a str,
    package_fingerprint: &'a str,
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
    allow_unsigned: bool,
    accept_license: bool,
    allow_publisher_migration: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemMaintenanceRequest<'a> {
    protocol_version: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    action: &'static str,
    package_id: &'a str,
    package_fingerprint: &'a str,
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

    const fn request_kind(&self) -> &'static str {
        match self {
            Self::Install { .. } => "installSystem",
            Self::Uninstall => "uninstallSystem",
            Self::Launch => "launchSystem",
        }
    }
}

struct SystemJob {
    package: File,
    package_id: String,
    package_fingerprint: String,
    request: SystemRequest,
    operation_id: String,
    cancel: Arc<AtomicBool>,
    sender: mpsc::Sender<crate::backend::OperationMessage>,
}

pub(super) fn authorize_system_install(
    _executable: &Path,
    package: &Path,
    package_id: &str,
    package_fingerprint: &str,
) -> io::Result<crate::backend::PrepareInstallResult> {
    validate_identity(package_id, package_fingerprint)?;
    let package = open_pinned_package(package)?;
    let operation_id = random_operation_id()?;
    let (socket, mut child) = launch_helper("privilege-authorize-install")?;
    let result = run_authorization(
        &socket,
        &mut child,
        &operation_id,
        package_id,
        package_fingerprint,
        &package,
    );
    finish_child(result, &mut child, HELPER_TIMEOUT)
}

#[allow(
    clippy::too_many_arguments,
    reason = "reviewed package identity and three explicit user consents cross the privilege boundary"
)]
pub(super) fn start_system_install(
    _executable: &Path,
    package: &Path,
    package_id: &str,
    package_fingerprint: &str,
    allow_unsigned: bool,
    accept_license: bool,
    allow_publisher_migration: bool,
) -> io::Result<super::SystemOperation> {
    start_system_operation(
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
    _executable: &Path,
    package: &Path,
    package_id: &str,
    package_fingerprint: &str,
) -> io::Result<super::SystemOperation> {
    start_system_operation(
        package,
        package_id,
        package_fingerprint,
        SystemRequest::Uninstall,
    )
}

pub(super) fn start_system_launch(
    _executable: &Path,
    package: &Path,
    package_id: &str,
    package_fingerprint: &str,
) -> io::Result<super::SystemOperation> {
    start_system_operation(
        package,
        package_id,
        package_fingerprint,
        SystemRequest::Launch,
    )
}

fn start_system_operation(
    package: &Path,
    package_id: &str,
    package_fingerprint: &str,
    request: SystemRequest,
) -> io::Result<super::SystemOperation> {
    validate_identity(package_id, package_fingerprint)?;
    let package = open_pinned_package(package)?;
    let operation_id = random_operation_id()?;
    let cancel = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel();
    let thread_name = format!("luxury-system-{}", request.action());
    let job = SystemJob {
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
        if let Err(error) = run_system_operation(job) {
            let code = if error.raw_os_error() == Some(ECANCELED) {
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

fn run_authorization(
    socket: &UnixDatagram,
    child: &mut Child,
    operation_id: &str,
    package_id: &str,
    package_fingerprint: &str,
    package: &File,
) -> io::Result<crate::backend::PrepareInstallResult> {
    authenticate_helper(
        socket,
        child,
        operation_id,
        "authorizeInstall",
        AUTHORIZATION_TIMEOUT,
    )?;
    send_frame_with_fd(
        socket,
        &AuthorizationRequest {
            protocol_version: PROTOCOL_VERSION,
            kind: "authorizeInstall",
            operation_id,
            action: "install",
            package_id,
            package_fingerprint,
        },
        package.as_fd(),
    )?;
    let (authorized, credentials) = read_frame_until::<InstallAuthorized>(
        socket,
        child,
        Instant::now() + AUTHORIZATION_TIMEOUT,
    )?;
    require_helper_credentials(credentials, child.id())?;
    if authorized.protocol_version != PROTOCOL_VERSION
        || authorized.kind != "installAuthorized"
        || authorized.operation_id != operation_id
        || authorized.action != "install"
        || authorized.package_id != package_id
        || authorized.package_fingerprint != package_fingerprint
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "polkit helper returned an invalid authorization",
        ));
    }
    Ok(authorized.preparation)
}

fn run_system_operation(job: SystemJob) -> io::Result<()> {
    let (socket, mut child) = launch_helper(job.request.helper_command())?;
    let result = run_system_operation_inner(&socket, &mut child, &job);
    let terminal = match result {
        Ok(terminal) => terminal,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let status = wait_child(&mut child, HELPER_TIMEOUT)?;
    if !status.success() {
        return Err(exit_error(&status));
    }
    super::send_operation(&job.sender, terminal)
}

fn run_system_operation_inner(
    socket: &UnixDatagram,
    child: &mut Child,
    job: &SystemJob,
) -> io::Result<crate::backend::OperationMessage> {
    authenticate_helper(
        socket,
        child,
        &job.operation_id,
        job.request.action(),
        AUTHORIZATION_TIMEOUT,
    )?;
    match &job.request {
        SystemRequest::Install {
            allow_unsigned,
            accept_license,
            allow_publisher_migration,
        } => send_frame_with_fd(
            socket,
            &SystemInstallRequest {
                protocol_version: PROTOCOL_VERSION,
                kind: job.request.request_kind(),
                operation_id: &job.operation_id,
                action: job.request.action(),
                package_id: &job.package_id,
                package_fingerprint: &job.package_fingerprint,
                allow_unsigned: *allow_unsigned,
                accept_license: *accept_license,
                allow_publisher_migration: *allow_publisher_migration,
            },
            job.package.as_fd(),
        )?,
        SystemRequest::Uninstall | SystemRequest::Launch => send_frame_with_fd(
            socket,
            &SystemMaintenanceRequest {
                protocol_version: PROTOCOL_VERSION,
                kind: job.request.request_kind(),
                operation_id: &job.operation_id,
                action: job.request.action(),
                package_id: &job.package_id,
                package_fingerprint: &job.package_fingerprint,
            },
            job.package.as_fd(),
        )?,
    }

    let started = Instant::now();
    let mut last_frame = started;
    let mut cancel_sent = false;
    loop {
        if !cancel_sent && job.cancel.load(Ordering::Acquire) {
            send_frame(
                socket,
                &CancelOperationRequest {
                    protocol_version: PROTOCOL_VERSION,
                    kind: "cancelOperation",
                    operation_id: &job.operation_id,
                    action: job.request.action(),
                },
            )?;
            cancel_sent = true;
        }
        match try_read_frame::<super::SystemOperationFrame>(socket) {
            Ok(Some((frame, credentials))) => {
                require_helper_credentials(credentials, child.id())?;
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
            }
            Ok(None) => {}
            Err(error) => return Err(error),
        }
        if let Some(status) = child.try_wait()? {
            return Err(exit_error(&status));
        }
        let now = Instant::now();
        if now.duration_since(started) >= SYSTEM_OPERATION_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "system operation exceeded its deadline",
            ));
        }
        if now.duration_since(last_frame) >= SYSTEM_OPERATION_IDLE_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "system operation stopped reporting progress",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn authenticate_helper(
    socket: &UnixDatagram,
    child: &mut Child,
    operation_id: &str,
    action: &'static str,
    timeout: Duration,
) -> io::Result<()> {
    send_frame(
        socket,
        &Challenge {
            protocol_version: PROTOCOL_VERSION,
            kind: "challenge",
            operation_id,
            action,
            caller_pid: std::process::id(),
        },
    )?;
    let (ready, credentials) = read_frame_until::<Ready>(socket, child, Instant::now() + timeout)?;
    require_helper_credentials(credentials, child.id())?;
    if ready.protocol_version != PROTOCOL_VERSION
        || ready.kind != "ready"
        || ready.operation_id != operation_id
        || ready.action != action
        || ready.caller_pid != std::process::id()
        || ready.caller_uid != rustix::process::geteuid().as_raw()
        || ready.helper_pid != child.id()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "polkit helper identity did not match the operation",
        ));
    }
    verify_running_helper(child.id())
}

fn launch_helper(command: &'static str) -> io::Result<(UnixDatagram, Child)> {
    verify_installed_layout()?;
    let (parent, child_socket) = UnixDatagram::pair()?;
    set_socket_passcred(&parent, true).map_err(os_error)?;
    set_socket_passcred(&child_socket, true).map_err(os_error)?;
    set_socket_timeout(&child_socket, Timeout::Recv, Some(HELPER_TIMEOUT)).map_err(os_error)?;
    let child_input = child_socket.try_clone()?;
    let mut child = Command::new(PKEXEC_PATH)
        .arg("--disable-internal-agent")
        .arg(HELPER_PATH)
        .arg(command)
        .stdin(Stdio::from(OwnedFd::from(child_input)))
        .stdout(Stdio::from(OwnedFd::from(child_socket)))
        .stderr(Stdio::null())
        .spawn()?;
    parent.set_nonblocking(true)?;
    if let Some(status) = child.try_wait()? {
        return Err(exit_error(&status));
    }
    Ok((parent, child))
}

fn verify_installed_layout() -> io::Result<()> {
    let _pkexec = open_trusted_root_file(Path::new(PKEXEC_PATH), true, None)?;
    let _helper = open_trusted_root_file(Path::new(HELPER_PATH), true, None)?;
    let _policy = open_trusted_root_file(Path::new(POLICY_PATH), false, Some(POLICY_BYTES))?;
    Ok(())
}

fn verify_running_helper(pid: u32) -> io::Result<()> {
    let installed = open_trusted_root_file(Path::new(HELPER_PATH), true, None)?;
    let running = File::open(format!("/proc/{pid}/exe"))?;
    if file_identity(&installed.metadata()?) != file_identity(&running.metadata()?) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "running polkit helper did not match the root-owned helper",
        ));
    }
    Ok(())
}

fn open_pinned_package(path: &Path) -> io::Result<File> {
    open_trusted_root_file(path, false, None)
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
            "system helper input was not a private root-owned regular file",
        ));
    }
    Ok(())
}

fn file_identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn validate_identity(package_id: &str, package_fingerprint: &str) -> io::Result<()> {
    if crate::app::valid_package_id(package_id) && valid_lower_hex_64(package_fingerprint) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "system operation identity is invalid",
        ))
    }
}

fn valid_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn random_operation_id() -> io::Result<String> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut result = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in random {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(result)
}

fn send_frame<T: Serialize>(socket: &UnixDatagram, frame: &T) -> io::Result<()> {
    let bytes = encode_frame(frame)?;
    let sent = socket.send(&bytes)?;
    if sent == bytes.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "polkit protocol frame was truncated",
        ))
    }
}

fn send_frame_with_fd<T: Serialize>(
    socket: &UnixDatagram,
    frame: &T,
    fd: BorrowedFd<'_>,
) -> io::Result<()> {
    let bytes = encode_frame(frame)?;
    let iov = [IoSlice::new(&bytes)];
    let fds = [fd];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(io::Error::other("could not encode package descriptor"));
    }
    let sent = sendmsg(socket, &iov, &mut ancillary, SendFlags::NOSIGNAL).map_err(os_error)?;
    if sent == bytes.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "polkit package frame was truncated",
        ))
    }
}

fn encode_frame<T: Serialize>(frame: &T) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "polkit protocol frame exceeded its bound",
        ));
    }
    Ok(bytes)
}

fn read_frame_until<T: DeserializeOwned>(
    socket: &UnixDatagram,
    child: &mut Child,
    deadline: Instant,
) -> io::Result<(T, UCred)> {
    loop {
        match try_read_frame(socket)? {
            Some(frame) => return Ok(frame),
            None if Instant::now() < deadline => {
                if let Some(status) = child.try_wait()? {
                    return Err(exit_error(&status));
                }
                thread::sleep(Duration::from_millis(10));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "polkit helper did not send a frame in time",
                ));
            }
        }
    }
}

fn try_read_frame<T: DeserializeOwned>(socket: &UnixDatagram) -> io::Result<Option<(T, UCred)>> {
    let mut bytes = [0_u8; MAX_FRAME_BYTES + 1];
    let mut iov = [IoSliceMut::new(&mut bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = match recvmsg(socket, &mut iov, &mut ancillary, RecvFlags::CMSG_CLOEXEC) {
        Ok(message) => message,
        Err(error) if error == rustix::io::Errno::AGAIN => return Ok(None),
        Err(error) => return Err(os_error(error)),
    };
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
    let mut descriptor_count = 0;
    for item in ancillary.drain() {
        match item {
            RecvAncillaryMessage::ScmCredentials(found) if credentials.is_none() => {
                credentials = Some(found);
            }
            RecvAncillaryMessage::ScmRights(descriptors) => {
                descriptor_count += descriptors.count();
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "polkit protocol carried unexpected ancillary data",
                ));
            }
        }
    }
    if descriptor_count != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "polkit helper response carried a file descriptor",
        ));
    }
    let credentials = credentials.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "polkit helper response had no kernel credentials",
        )
    })?;
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
    Ok(Some((frame, credentials)))
}

fn require_helper_credentials(credentials: UCred, helper_pid: u32) -> io::Result<()> {
    if credentials.pid.as_raw_pid() == helper_pid as i32
        && credentials.uid.is_root()
        && credentials.gid.as_raw() == 0
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "polkit frame did not come from the launched root helper",
        ))
    }
}

fn finish_child<T>(result: io::Result<T>, child: &mut Child, timeout: Duration) -> io::Result<T> {
    if result.is_err() {
        let _ = child.kill();
    }
    let status = wait_child(child, timeout)?;
    let value = result?;
    if status.success() {
        Ok(value)
    } else {
        Err(exit_error(&status))
    }
}

fn wait_child(child: &mut Child, timeout: Duration) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "polkit helper did not exit in time",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn exit_error(status: &std::process::ExitStatus) -> io::Error {
    match status.code() {
        Some(126 | 127) => io::Error::from_raw_os_error(ECANCELED),
        _ => io::Error::other("polkit helper failed"),
    }
}

fn os_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_single_bounded_json_lines() {
        let frame = encode_frame(&Challenge {
            protocol_version: PROTOCOL_VERSION,
            kind: "challenge",
            operation_id: &"a".repeat(32),
            action: "install",
            caller_pid: 42,
        })
        .unwrap();
        assert!(frame.ends_with(b"\n"));
        assert_eq!(frame.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert!(frame.len() <= MAX_FRAME_BYTES);
    }

    #[test]
    fn package_identity_is_canonical() {
        assert!(validate_identity("dev.luxury.demo", &"a".repeat(64)).is_ok());
        assert!(validate_identity("../demo", &"a".repeat(64)).is_err());
        assert!(validate_identity("dev.luxury.demo", &"A".repeat(64)).is_err());
    }
}
