use std::{
    ffi::{c_char, c_void},
    fs::File,
    io::{self, IoSlice, IoSliceMut, Read},
    mem::{MaybeUninit, transmute},
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use core_foundation::{base::TCFType, string::CFString};
use luxury_macos_trust::{CodeRole, verify_peer, verify_self};
use rustix::{
    event::kqueue::{Event, EventFilter, EventFlags, ProcessEvents, kevent, kqueue},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags, SocketAddrUnix, SocketType, connect, recvmsg, sendmsg,
        socket,
        sockopt::{Timeout, set_socket_nosigpipe, set_socket_timeout},
    },
    process::Pid,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const PROTOCOL_VERSION: u8 = 1;
const MAX_FRAME_BYTES: usize = 4 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(15);
const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SYSTEM_OPERATION_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const SYSTEM_OPERATION_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const SOCKET_PATH: &str = "/var/run/software.luxury.installer.helper.sock";
const HELPER_PLIST: &str = "software.luxury.installer.helper.plist";

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

struct HelperConnection {
    socket: OwnedFd,
    process: ProcessWatch,
}

struct ProcessWatch {
    queue: OwnedFd,
    pid: Pid,
}

pub(super) fn authorize_system_install(
    _executable: &Path,
    package: &Path,
    package_id: &str,
    package_fingerprint: &str,
) -> io::Result<crate::backend::PrepareInstallResult> {
    ensure_service_enabled()?;
    validate_identity(package_id, package_fingerprint)?;
    let package = open_pinned_package(package)?;
    let operation_id = random_operation_id()?;
    let connection = connect_helper(&operation_id, "authorizeInstall", AUTHORIZATION_TIMEOUT)?;
    send_frame_with_fd(
        &connection.socket,
        &AuthorizationRequest {
            protocol_version: PROTOCOL_VERSION,
            kind: "authorizeInstall",
            operation_id: &operation_id,
            action: "install",
            package_id,
            package_fingerprint,
        },
        package.as_fd(),
    )?;
    let authorized = read_frame::<InstallAuthorized>(&connection.socket)?;
    if authorized.protocol_version != PROTOCOL_VERSION
        || authorized.kind != "installAuthorized"
        || authorized.operation_id != operation_id
        || authorized.action != "install"
        || authorized.package_id != package_id
        || authorized.package_fingerprint != package_fingerprint
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launchd helper returned an invalid authorization",
        ));
    }
    let preparation = authorized.preparation;
    finish_helper(connection)?;
    Ok(preparation)
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
    ensure_service_enabled()?;
    validate_identity(package_id, package_fingerprint)?;
    let package = open_pinned_package(package)?;
    let operation_id = random_operation_id()?;
    let cancel = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel();
    let job = SystemJob {
        package,
        package_id: package_id.to_owned(),
        package_fingerprint: package_fingerprint.to_owned(),
        request,
        operation_id: operation_id.clone(),
        cancel: Arc::clone(&cancel),
        sender,
    };
    thread::Builder::new()
        .name(format!("luxury-system-{}", job.request.action()))
        .spawn(move || {
            let failure_sender = job.sender.clone();
            if let Err(error) = run_system_operation(job) {
                let code = if error.kind() == io::ErrorKind::TimedOut {
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

fn run_system_operation(job: SystemJob) -> io::Result<()> {
    let connection = connect_helper(
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
            &connection.socket,
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
            &connection.socket,
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

    rustix::fs::fcntl_setfl(&connection.socket, rustix::fs::OFlags::NONBLOCK).map_err(os_error)?;
    let started = Instant::now();
    let mut last_frame = started;
    let mut cancel_sent = false;
    let terminal = loop {
        if !cancel_sent && job.cancel.load(Ordering::Acquire) {
            send_frame(
                &connection.socket,
                &CancelOperationRequest {
                    protocol_version: PROTOCOL_VERSION,
                    kind: "cancelOperation",
                    operation_id: &job.operation_id,
                    action: job.request.action(),
                },
            )?;
            cancel_sent = true;
        }
        match try_read_frame::<super::SystemOperationFrame>(&connection.socket)? {
            Some(frame) => {
                last_frame = Instant::now();
                if let Some(terminal) = super::forward_system_operation_frame(
                    frame,
                    job.request.action(),
                    &job.operation_id,
                    &job.package_id,
                    &job.sender,
                )? {
                    break terminal;
                }
            }
            None => thread::sleep(Duration::from_millis(10)),
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
    };
    finish_helper(connection)?;
    super::send_operation(&job.sender, terminal)
}

fn connect_helper(
    operation_id: &str,
    action: &'static str,
    timeout: Duration,
) -> io::Result<HelperConnection> {
    ensure_service_enabled()?;
    let socket = socket(AddressFamily::UNIX, SocketType::SEQPACKET, None).map_err(os_error)?;
    rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC).map_err(os_error)?;
    set_socket_nosigpipe(&socket, true).map_err(os_error)?;
    set_socket_timeout(&socket, Timeout::Recv, Some(timeout)).map_err(os_error)?;
    let address = SocketAddrUnix::new(SOCKET_PATH).map_err(os_error)?;
    let deadline = Instant::now() + timeout;
    loop {
        match connect(&socket, &address) {
            Ok(()) => break,
            Err(error)
                if matches!(
                    error,
                    rustix::io::Errno::NOENT | rustix::io::Errno::CONNREFUSED
                ) && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(os_error(error)),
        }
    }
    send_frame(
        &socket,
        &Challenge {
            protocol_version: PROTOCOL_VERSION,
            kind: "challenge",
            operation_id,
            action,
            caller_pid: std::process::id(),
        },
    )?;
    let ready = read_frame::<Ready>(&socket)?;
    let helper = verify_peer(socket.as_fd(), CodeRole::Helper).map_err(trust_error)?;
    if helper.uid != 0
        || helper.gid != 0
        || ready.protocol_version != PROTOCOL_VERSION
        || ready.kind != "ready"
        || ready.operation_id != operation_id
        || ready.action != action
        || ready.caller_pid != std::process::id()
        || ready.caller_uid != rustix::process::geteuid().as_raw()
        || ready.helper_pid != helper.pid
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "launchd helper identity did not match the operation",
        ));
    }
    let process = ProcessWatch::new(helper.pid)?;
    Ok(HelperConnection { socket, process })
}

impl ProcessWatch {
    fn new(pid: u32) -> io::Result<Self> {
        let pid =
            Pid::from_raw(i32::try_from(pid).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "helper PID is invalid")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "helper PID is zero"))?;
        let queue = kqueue().map_err(os_error)?;
        let change = Event::new(
            EventFilter::Proc {
                pid,
                flags: ProcessEvents::EXIT,
            },
            EventFlags::ADD | EventFlags::ONESHOT,
            ptr::null_mut(),
        );
        let mut events = Vec::<Event>::with_capacity(1);
        // SAFETY: the process filter contains no borrowed descriptor and the queue stays alive.
        unsafe {
            kevent(
                &queue,
                &[change],
                rustix::buffer::spare_capacity(&mut events),
                Some(Duration::ZERO),
            )
        }
        .map_err(os_error)?;
        if !events.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "launchd helper exited during authentication",
            ));
        }
        Ok(Self { queue, pid })
    }

    fn wait(self) -> io::Result<()> {
        let mut events = Vec::<Event>::with_capacity(1);
        // SAFETY: the registered process filter remains valid until this owned queue is dropped.
        unsafe {
            kevent(
                &self.queue,
                &[],
                rustix::buffer::spare_capacity(&mut events),
                Some(HELPER_TIMEOUT),
            )
        }
        .map_err(os_error)?;
        if events.len() == 1
            && matches!(
                events[0].filter(),
                EventFilter::Proc { pid, flags }
                    if pid == self.pid && flags.contains(ProcessEvents::EXIT)
            )
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "launchd helper did not exit cleanly in time",
            ))
        }
    }
}

fn finish_helper(connection: HelperConnection) -> io::Result<()> {
    rustix::fs::fcntl_setfl(&connection.socket, rustix::fs::OFlags::empty()).map_err(os_error)?;
    set_socket_timeout(&connection.socket, Timeout::Recv, Some(HELPER_TIMEOUT))
        .map_err(os_error)?;
    let mut byte = [0_u8; 1];
    let (_, read) =
        rustix::net::recv(&connection.socket, &mut byte, RecvFlags::empty()).map_err(os_error)?;
    if read != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launchd helper sent data after its terminal frame",
        ));
    }
    connection.process.wait()
}

fn ensure_service_enabled() -> io::Result<()> {
    verify_self(CodeRole::App).map_err(trust_error)?;
    service_management::ensure_enabled()
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

fn open_pinned_package(path: &Path) -> io::Result<File> {
    let file = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(os_error)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bound package is not a regular single-link file",
        ));
    }
    Ok(file)
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

fn send_frame<T: Serialize, Fd: AsFd>(socket: Fd, frame: &T) -> io::Result<()> {
    let bytes = encode_frame(frame)?;
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

fn send_frame_with_fd<T: Serialize>(
    socket: &OwnedFd,
    frame: &T,
    descriptor: BorrowedFd<'_>,
) -> io::Result<()> {
    let bytes = encode_frame(frame)?;
    let iov = [IoSlice::new(&bytes)];
    let descriptors = [descriptor];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(io::Error::other("could not encode package descriptor"));
    }
    let sent = sendmsg(socket, &iov, &mut ancillary, SendFlags::empty()).map_err(os_error)?;
    if sent == bytes.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "frame was truncated",
        ))
    }
}

fn encode_frame<T: Serialize>(frame: &T) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeded its bound",
        ));
    }
    Ok(bytes)
}

fn read_frame<T: DeserializeOwned>(socket: &OwnedFd) -> io::Result<T> {
    try_read_frame(socket)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "launchd helper did not send a frame in time",
        )
    })
}

fn try_read_frame<T: DeserializeOwned>(socket: &OwnedFd) -> io::Result<Option<T>> {
    let mut bytes = [0_u8; MAX_FRAME_BYTES + 1];
    let mut iov = [IoSliceMut::new(&mut bytes)];
    let mut ancillary = RecvAncillaryBuffer::default();
    let message = match recvmsg(socket, &mut iov, &mut ancillary, RecvFlags::empty()) {
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
            "frame had invalid size",
        ));
    }
    if ancillary.drain().next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "helper response carried ancillary data",
        ));
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
    serde_json::from_slice(json)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame was invalid"))
}

fn trust_error(_: luxury_macos_trust::TrustError) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "macOS code identity was not trusted",
    )
}

fn os_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[allow(unsafe_code)]
mod service_management {
    use super::*;

    const NOT_REGISTERED: isize = 0;
    const ENABLED: isize = 1;
    const REQUIRES_APPROVAL: isize = 2;
    const NOT_FOUND: isize = 3;

    pub(super) fn ensure_enabled() -> io::Result<()> {
        let _pool = AutoreleasePool::new();
        let class = unsafe { objc_getClass(c"SMAppService".as_ptr()) };
        if class.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SMAppService requires macOS 13 or later",
            ));
        }
        let plist = CFString::new(HELPER_PLIST);
        let selector = unsafe { sel_registerName(c"daemonServiceWithPlistName:".as_ptr()) };
        let send: unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_void) -> *mut c_void =
            unsafe { transmute(objc_msgSend as *const ()) };
        let service = unsafe {
            send(
                class,
                selector,
                plist.as_concrete_TypeRef().cast::<c_void>(),
            )
        };
        if service.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMAppService could not load the helper plist",
            ));
        }
        let mut status = service_status(service);
        if status == NOT_REGISTERED {
            let selector = unsafe { sel_registerName(c"registerAndReturnError:".as_ptr()) };
            let send: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> i8 =
                unsafe { transmute(objc_msgSend as *const ()) };
            let mut error = ptr::null_mut();
            if unsafe { send(service, selector, &mut error) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "launch daemon registration was denied",
                ));
            }
            status = service_status(service);
        }
        match status {
            ENABLED => Ok(()),
            REQUIRES_APPROVAL => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "launch daemon requires approval in System Settings",
            )),
            NOT_FOUND => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "launch daemon plist was not found in the app bundle",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "launch daemon is not enabled",
            )),
        }
    }

    fn service_status(service: *mut c_void) -> isize {
        let selector = unsafe { sel_registerName(c"status".as_ptr()) };
        let send: unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize =
            unsafe { transmute(objc_msgSend as *const ()) };
        unsafe { send(service, selector) }
    }

    struct AutoreleasePool(*mut c_void);

    impl AutoreleasePool {
        fn new() -> Self {
            Self(unsafe { objc_autoreleasePoolPush() })
        }
    }

    impl Drop for AutoreleasePool {
        fn drop(&mut self) {
            unsafe { objc_autoreleasePoolPop(self.0) };
        }
    }

    #[link(name = "ServiceManagement", kind = "framework")]
    unsafe extern "C" {}

    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn objc_msgSend();
        fn objc_autoreleasePoolPush() -> *mut c_void;
        fn objc_autoreleasePoolPop(pool: *mut c_void);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_identity_is_canonical() {
        assert!(validate_identity("dev.luxury.demo", &"a".repeat(64)).is_ok());
        assert!(validate_identity("../demo", &"a".repeat(64)).is_err());
        assert!(validate_identity("dev.luxury.demo", &"A".repeat(64)).is_err());
    }

    #[test]
    fn frames_are_single_bounded_json_lines() {
        let frame = encode_frame(&Challenge {
            protocol_version: 1,
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
}
