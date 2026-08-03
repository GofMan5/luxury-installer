use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::protocol::{
    BackendEvent, BackendLine, BackendRequest, CancelResult, OperationKind, PROTOCOL_VERSION,
    parse_event, strict_value,
};

const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_PENDING_REQUESTS: usize = 32;
const MAX_QUEUED_PROGRESS: usize = 256;
const MAX_QUEUED_CONTROL_EVENTS: usize = 64;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const OPERATION_REQUEST_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CANCELLATION_GRACE: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub(crate) struct BackendError {
    pub(crate) code: String,
}

impl BackendError {
    pub(crate) fn new(code: impl Into<String>, _message: impl Into<String>) -> Self {
        Self { code: code.into() }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::new("backend_unavailable", message)
    }

    fn invalid_output(message: impl Into<String>) -> Self {
        Self::new("invalid_backend_output", message)
    }
}

#[derive(Clone)]
pub(crate) struct BackendClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    executable: PathBuf,
    trusted_publisher_key: Option<PathBuf>,
    process: Mutex<Option<Arc<BackendProcess>>>,
    shutdown: Mutex<()>,
    closing: AtomicBool,
}

pub(crate) struct BackendOperation {
    pub(crate) operation_id: String,
    receiver: Receiver<OperationMessage>,
    budget: Arc<OperationQueueBudget>,
}

impl BackendOperation {
    pub(crate) fn recv(&self) -> Result<OperationMessage, BackendError> {
        let message = self
            .receiver
            .recv()
            .map_err(|_| BackendError::unavailable("backend operation channel closed"))?;
        if let OperationMessage::Event(event) = &message {
            self.budget.release(event);
        }
        Ok(message)
    }
}

pub(crate) enum OperationMessage {
    Event(BackendEvent),
    Complete(Result<Value, BackendError>),
}

type BackendResponse = Result<Value, BackendError>;
type ResponseReceiver = Receiver<BackendResponse>;

enum Pending {
    Request(SyncSender<BackendResponse>),
    Operation {
        kind: OperationKind,
        sender: mpsc::Sender<OperationMessage>,
        budget: Arc<OperationQueueBudget>,
    },
}

#[derive(Default)]
struct OperationQueueBudget {
    progress: AtomicUsize,
    control: AtomicUsize,
}

impl OperationQueueBudget {
    fn reserve(&self, event: &BackendEvent) -> bool {
        let (counter, maximum) = self.counter(event);
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                (queued < maximum).then_some(queued + 1)
            })
            .is_ok()
    }

    fn release(&self, event: &BackendEvent) {
        let (counter, _) = self.counter(event);
        let previous = counter.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "operation queue budget underflow");
    }

    fn counter(&self, event: &BackendEvent) -> (&AtomicUsize, usize) {
        if matches!(event, BackendEvent::Progress { .. }) {
            (&self.progress, MAX_QUEUED_PROGRESS)
        } else {
            (&self.control, MAX_QUEUED_CONTROL_EVENTS)
        }
    }
}

struct BackendProcess {
    stdin: Mutex<Option<ChildStdin>>,
    child: Mutex<Option<Child>>,
    pending: Mutex<HashMap<String, Pending>>,
    failed: AtomicBool,
    closing: AtomicBool,
}

impl BackendClient {
    pub(crate) fn new(
        executable: PathBuf,
        trusted_publisher_key: Option<PathBuf>,
    ) -> Result<Self, BackendError> {
        if !executable.is_absolute() {
            return Err(BackendError::new(
                "invalid_backend_path",
                "backend path must be absolute",
            ));
        }
        Ok(Self {
            inner: Arc::new(ClientInner {
                executable,
                trusted_publisher_key,
                process: Mutex::new(None),
                shutdown: Mutex::new(()),
                closing: AtomicBool::new(false),
            }),
        })
    }

    pub(crate) fn request<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: Value,
        timeout: Option<Duration>,
    ) -> Result<T, BackendError> {
        let (process, _, receiver) = self.begin_request(method, params)?;
        let result = match timeout {
            Some(timeout) => match receiver.recv_timeout(timeout) {
                Ok(result) => result,
                Err(RecvTimeoutError::Timeout) => {
                    process.fail(
                        BackendError::new(
                            "backend_timeout",
                            format!("backend {method} request timed out"),
                        ),
                        true,
                    );
                    return Err(BackendError::new(
                        "backend_timeout",
                        format!("backend {method} request timed out"),
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(BackendError::unavailable("backend response channel closed"));
                }
            },
            None => receiver
                .recv()
                .map_err(|_| BackendError::unavailable("backend response channel closed"))?,
        };
        decode_result(result, method)
    }

    pub(crate) fn executable(&self) -> Result<&Path, BackendError> {
        validate_executable(&self.inner.executable)?;
        Ok(&self.inner.executable)
    }

    pub(crate) fn request_short<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<T, BackendError> {
        self.request(method, params, Some(REQUEST_TIMEOUT))
    }

    pub(crate) fn request_operation<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<T, BackendError> {
        let (process, id, receiver) = self.begin_request(method, params)?;
        let result = match receiver.recv_timeout(OPERATION_REQUEST_TIMEOUT) {
            Ok(result) => result,
            Err(RecvTimeoutError::Disconnected) => {
                return Err(BackendError::unavailable("backend response channel closed"));
            }
            Err(RecvTimeoutError::Timeout) => {
                match receiver.try_recv() {
                    Ok(result) => return decode_result(result, method),
                    Err(mpsc::TryRecvError::Disconnected) => {
                        return Err(BackendError::unavailable("backend response channel closed"));
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
                match self.cancel(&id) {
                    Ok(()) => {}
                    Err(error) if error.code == "cancel_rejected" => {}
                    Err(error) => {
                        process.fail(error.clone(), true);
                        return Err(error);
                    }
                }
                match receiver.recv_timeout(CANCELLATION_GRACE) {
                    Ok(result) => result,
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err(BackendError::unavailable("backend response channel closed"));
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        let error = BackendError::new(
                            "backend_timeout",
                            format!("backend {method} cancellation timed out"),
                        );
                        process.fail(error.clone(), true);
                        return Err(error);
                    }
                }
            }
        };
        decode_result(result, method)
    }

    fn begin_request(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<(Arc<BackendProcess>, String, ResponseReceiver), BackendError> {
        let process = self.ensure_process()?;
        let id = request_id();
        let (sender, receiver) = mpsc::sync_channel(1);
        process.submit(&id, method, params, Pending::Request(sender))?;
        Ok((process, id, receiver))
    }

    pub(crate) fn start_operation(
        &self,
        method: &'static str,
        params: Value,
        kind: OperationKind,
    ) -> Result<BackendOperation, BackendError> {
        let process = self.ensure_process()?;
        let operation_id = request_id();
        let (sender, receiver) = mpsc::channel();
        let budget = Arc::new(OperationQueueBudget::default());
        process.submit(
            &operation_id,
            method,
            params,
            Pending::Operation {
                kind,
                sender,
                budget: Arc::clone(&budget),
            },
        )?;
        Ok(BackendOperation {
            operation_id,
            receiver,
            budget,
        })
    }

    pub(crate) fn cancel(&self, operation_id: &str) -> Result<(), BackendError> {
        self.cancel_with_timeout(operation_id, REQUEST_TIMEOUT)
    }

    pub(crate) fn cancel_with_timeout(
        &self,
        operation_id: &str,
        timeout: Duration,
    ) -> Result<(), BackendError> {
        let result: CancelResult = self.request(
            "cancel",
            json!({ "requestId": operation_id }),
            Some(timeout.min(REQUEST_TIMEOUT)),
        )?;
        if result.request_id != operation_id || !result.accepted {
            return Err(BackendError::new(
                "cancel_rejected",
                "backend did not accept cancellation",
            ));
        }
        Ok(())
    }

    pub(crate) fn close(&self) {
        let _shutdown = self
            .inner
            .shutdown
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.inner.closing.store(true, Ordering::Release);
        let process = self
            .inner
            .process
            .lock()
            .ok()
            .and_then(|mut process| process.take());
        if let Some(process) = process {
            process.close_gracefully();
        }
    }

    fn ensure_process(&self) -> Result<Arc<BackendProcess>, BackendError> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(BackendError::unavailable("backend is closing"));
        }
        let mut slot = self
            .inner
            .process
            .lock()
            .map_err(|_| BackendError::unavailable("backend state lock is poisoned"))?;
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(BackendError::unavailable("backend is closing"));
        }
        if let Some(process) = slot.as_ref()
            && !process.failed.load(Ordering::Acquire)
        {
            return Ok(Arc::clone(process));
        }
        if let Some(previous) = slot.take() {
            previous.terminate();
        }
        let process = BackendProcess::spawn(
            &self.inner.executable,
            self.inner.trusted_publisher_key.as_deref(),
        )?;
        *slot = Some(Arc::clone(&process));
        Ok(process)
    }
}

impl BackendProcess {
    fn spawn(
        executable: &Path,
        trusted_publisher_key: Option<&Path>,
    ) -> Result<Arc<Self>, BackendError> {
        #[cfg(windows)]
        let _executable_lock = lock_executable(executable)?;
        #[cfg(not(windows))]
        validate_executable(executable)?;
        let mut command = Command::new(executable);
        command
            .arg("stdio")
            .current_dir(executable.parent().ok_or_else(|| {
                BackendError::new("invalid_backend_path", "backend path has no parent")
            })?)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(key) = trusted_publisher_key {
            command.arg("--trusted-publisher-key").arg(key);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = command.spawn().map_err(|error| {
            BackendError::new(
                "backend_spawn_failed",
                format!("could not start backend: {error}"),
            )
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| BackendError::unavailable("backend stdin is unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BackendError::unavailable("backend stdout is unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BackendError::unavailable("backend stderr is unavailable"))?;
        let process = Arc::new(Self {
            stdin: Mutex::new(Some(stdin)),
            child: Mutex::new(Some(child)),
            pending: Mutex::new(HashMap::new()),
            failed: AtomicBool::new(false),
            closing: AtomicBool::new(false),
        });

        thread::Builder::new()
            .name("luxury-backend-stdout".into())
            .spawn({
                let process = Arc::clone(&process);
                move || read_stdout(stdout, process)
            })
            .map_err(|error| {
                process.terminate();
                BackendError::unavailable(format!("could not start backend reader: {error}"))
            })?;
        thread::Builder::new()
            .name("luxury-backend-stderr".into())
            .spawn(move || {
                let _ = io::copy(&mut stderr.take(u64::MAX), &mut io::sink());
            })
            .map_err(|error| {
                process.terminate();
                BackendError::unavailable(format!("could not start backend stderr drain: {error}"))
            })?;
        Ok(process)
    }

    fn submit(
        &self,
        id: &str,
        method: &str,
        params: Value,
        pending: Pending,
    ) -> Result<(), BackendError> {
        if self.failed.load(Ordering::Acquire) || self.closing.load(Ordering::Acquire) {
            return Err(BackendError::unavailable("backend is not available"));
        }
        let mut line = serde_json::to_vec(&BackendRequest {
            protocol_version: PROTOCOL_VERSION,
            id,
            method,
            params,
        })
        .map_err(|_| BackendError::invalid_output("could not serialize backend request"))?;
        if line.len() >= MAX_LINE_BYTES {
            return Err(BackendError::new(
                "invalid_request",
                "backend request exceeds the line limit",
            ));
        }
        line.push(b'\n');
        {
            let mut requests = self
                .pending
                .lock()
                .map_err(|_| BackendError::unavailable("backend request lock is poisoned"))?;
            if requests.len() >= MAX_PENDING_REQUESTS {
                return Err(BackendError::new(
                    "too_many_requests",
                    "too many backend requests",
                ));
            }
            if requests.contains_key(id) {
                return Err(BackendError::new(
                    "invalid_request",
                    "duplicate backend request id",
                ));
            }
            requests.insert(id.to_owned(), pending);
        }
        let write = self
            .stdin
            .lock()
            .map_err(|_| BackendError::unavailable("backend stdin lock is poisoned"))
            .and_then(|mut stdin| {
                stdin
                    .as_mut()
                    .ok_or_else(|| BackendError::unavailable("backend stdin is closed"))?
                    .write_all(&line)
                    .map_err(|error| {
                        BackendError::new(
                            "backend_write_failed",
                            format!("could not write backend request: {error}"),
                        )
                    })
            });
        if let Err(failure) = write {
            self.fail(failure.clone(), true);
            return Err(failure);
        }
        Ok(())
    }

    fn consume_line(&self, bytes: &[u8]) -> Result<(), BackendError> {
        let line: BackendLine = serde_json::from_slice(bytes)
            .map_err(|_| BackendError::invalid_output("backend emitted invalid JSONL"))?;
        match line {
            BackendLine::Result {
                protocol_version,
                id,
                result,
            } => {
                require_protocol(protocol_version)?;
                require_request_id(&id)?;
                let pending = self.take_pending(&id)?;
                complete_pending(pending, Ok(result))?;
            }
            BackendLine::Error {
                protocol_version,
                id,
                error,
            } => {
                require_protocol(protocol_version)?;
                require_backend_error(&error.code, &error.message)?;
                let error = BackendError::new(error.code, error.message);
                let Some(id) = id else {
                    self.fail(error, true);
                    return Ok(());
                };
                require_request_id(&id)?;
                let pending = self.take_pending(&id)?;
                complete_pending(pending, Err(error))?;
            }
            BackendLine::Event {
                protocol_version,
                id,
                event,
                data,
            } => {
                require_protocol(protocol_version)?;
                require_request_id(&id)?;
                if event.is_empty() || event.len() > 32 {
                    return Err(BackendError::invalid_output(
                        "backend event name is invalid",
                    ));
                }
                let (kind, sender, budget) = {
                    let requests = self.pending.lock().map_err(|_| {
                        BackendError::unavailable("backend request lock is poisoned")
                    })?;
                    let Some(Pending::Operation {
                        kind,
                        sender,
                        budget,
                    }) = requests.get(&id)
                    else {
                        return Err(BackendError::invalid_output(
                            "backend emitted an unsolicited event",
                        ));
                    };
                    (*kind, sender.clone(), Arc::clone(budget))
                };
                let event =
                    parse_event(kind, id, &event, data).map_err(BackendError::invalid_output)?;
                queue_event(&sender, &budget, event)?;
            }
        }
        Ok(())
    }

    fn take_pending(&self, id: &str) -> Result<Pending, BackendError> {
        self.pending
            .lock()
            .map_err(|_| BackendError::unavailable("backend request lock is poisoned"))?
            .remove(id)
            .ok_or_else(|| BackendError::invalid_output("backend returned an unknown request id"))
    }

    fn fail(&self, error: BackendError, kill: bool) {
        if self.failed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(mut stdin) = self.stdin.lock() {
            stdin.take();
        }
        let pending = self
            .pending
            .lock()
            .ok()
            .map(|mut pending| {
                pending
                    .drain()
                    .map(|(_, pending)| pending)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for pending in pending {
            let _ = complete_pending(pending, Err(error.clone()));
        }
        if kill {
            self.terminate_child();
        }
    }

    fn close_gracefully(&self) {
        self.closing.store(true, Ordering::Release);
        if let Ok(mut stdin) = self.stdin.lock() {
            stdin.take();
        }
        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            let exited = match self.child.lock() {
                Ok(mut child) => match child.as_mut() {
                    Some(child) => matches!(child.try_wait(), Ok(Some(_))),
                    None => true,
                },
                Err(_) => true,
            };
            if exited {
                self.reap_child();
                self.fail(
                    BackendError::unavailable("backend closed during application shutdown"),
                    false,
                );
                return;
            }
            if Instant::now() >= deadline {
                self.terminate_child();
                self.fail(
                    BackendError::unavailable("backend shutdown timed out"),
                    false,
                );
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn terminate(&self) {
        self.closing.store(true, Ordering::Release);
        if let Ok(mut stdin) = self.stdin.lock() {
            stdin.take();
        }
        self.terminate_child();
    }

    fn terminate_child(&self) {
        if let Ok(mut child) = self.child.lock()
            && let Some(mut child) = child.take()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn reap_child(&self) {
        if let Ok(mut child) = self.child.lock()
            && let Some(mut child) = child.take()
        {
            let _ = child.wait();
        }
    }
}

fn read_stdout(mut stdout: impl Read, process: Arc<BackendProcess>) {
    let mut line = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = match stdout.read(&mut chunk) {
            Ok(read) => read,
            Err(error) => {
                process.fail(
                    BackendError::invalid_output(format!("could not read backend stdout: {error}")),
                    true,
                );
                return;
            }
        };
        if read == 0 {
            if !line.is_empty() {
                process.fail(
                    BackendError::invalid_output("backend stdout ended with a partial line"),
                    true,
                );
            } else if !process.closing.load(Ordering::Acquire) {
                process.fail(
                    BackendError::unavailable("backend exited unexpectedly"),
                    true,
                );
            }
            return;
        }
        for byte in &chunk[..read] {
            if *byte == b'\n' {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.is_empty() {
                    process.fail(
                        BackendError::invalid_output("backend emitted an empty line"),
                        true,
                    );
                    return;
                }
                if let Err(error) = process.consume_line(&line) {
                    process.fail(error, true);
                    return;
                }
                line.clear();
            } else {
                if line.len() >= MAX_LINE_BYTES {
                    process.fail(
                        BackendError::invalid_output("backend line exceeds the size limit"),
                        true,
                    );
                    return;
                }
                line.push(*byte);
            }
        }
    }
}

fn complete_pending(pending: Pending, result: BackendResponse) -> Result<(), BackendError> {
    match pending {
        Pending::Request(sender) => sender.try_send(result).map_err(|error| match error {
            mpsc::TrySendError::Full(_) => {
                BackendError::invalid_output("backend response queue overflow")
            }
            mpsc::TrySendError::Disconnected(_) => {
                BackendError::unavailable("backend response receiver closed")
            }
        }),
        Pending::Operation { sender, .. } => sender
            .send(OperationMessage::Complete(result))
            .map_err(|_| BackendError::unavailable("backend operation receiver closed")),
    }
}

fn decode_result<T: DeserializeOwned>(
    result: BackendResponse,
    method: &str,
) -> Result<T, BackendError> {
    strict_value(result?, method).map_err(BackendError::invalid_output)
}

fn queue_event(
    sender: &mpsc::Sender<OperationMessage>,
    budget: &OperationQueueBudget,
    event: BackendEvent,
) -> Result<(), BackendError> {
    if !budget.reserve(&event) {
        return if matches!(event, BackendEvent::Progress { .. }) {
            Ok(())
        } else {
            Err(BackendError::invalid_output(
                "backend control event queue overflow",
            ))
        };
    }
    if sender.send(OperationMessage::Event(event.clone())).is_err() {
        budget.release(&event);
        return Err(BackendError::unavailable(
            "backend operation receiver closed",
        ));
    }
    Ok(())
}

fn request_id() -> String {
    format!(
        "tauri-{}-{}",
        std::process::id(),
        NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
    )
}

fn require_protocol(version: u64) -> Result<(), BackendError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(BackendError::invalid_output(
            "backend protocol version mismatch",
        ))
    }
}

fn require_request_id(id: &str) -> Result<(), BackendError> {
    if !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        Ok(())
    } else {
        Err(BackendError::invalid_output(
            "backend request id is invalid",
        ))
    }
}

fn require_backend_error(code: &str, message: &str) -> Result<(), BackendError> {
    if code.is_empty()
        || code.len() > 64
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        || message.is_empty()
        || message.len() > 1024
        || message.chars().any(char::is_control)
    {
        Err(BackendError::invalid_output(
            "backend error payload is invalid",
        ))
    } else {
        Ok(())
    }
}

fn validate_executable(path: &Path) -> Result<(), BackendError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        BackendError::new(
            "backend_missing",
            format!("could not inspect backend `{}`: {error}", path.display()),
        )
    })?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() || metadata.len() == 0 {
        return Err(BackendError::new(
            "invalid_backend_path",
            "backend must be a non-empty regular file",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn lock_executable(path: &Path) -> Result<fs::File, BackendError> {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            BackendError::new(
                "backend_missing",
                format!("could not open backend `{}`: {error}", path.display()),
            )
        })?;
    let metadata = file.metadata().map_err(|error| {
        BackendError::new(
            "backend_missing",
            format!("could not inspect backend `{}`: {error}", path.display()),
        )
    })?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() || metadata.len() == 0 {
        return Err(BackendError::new(
            "invalid_backend_path",
            "backend must be a non-empty regular file",
        ));
    }
    Ok(file)
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn process() -> Arc<BackendProcess> {
        Arc::new(BackendProcess {
            stdin: Mutex::new(None),
            child: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            failed: AtomicBool::new(false),
            closing: AtomicBool::new(true),
        })
    }

    #[cfg(windows)]
    #[test]
    fn backend_lock_allows_spawn_but_blocks_path_replacement() {
        use std::os::windows::process::CommandExt;

        use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

        let root = std::env::temp_dir().join(format!(
            "luxury-backend-lock-{}-{}",
            std::process::id(),
            NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let executable = root.join("backend.exe");
        let moved = root.join("backend.moved.exe");
        let source = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        fs::copy(source, &executable).unwrap();
        let original = fs::read(&executable).unwrap();
        let locked = lock_executable(&executable).unwrap();
        let status = Command::new(&executable)
            .args(["-NoProfile", "-Command", "exit 0"])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
        let rename = fs::rename(&executable, &moved);

        assert!(status.unwrap().success());
        assert!(rename.is_err());
        assert_eq!(fs::read(&executable).unwrap(), original);
        assert!(!moved.exists());

        drop(locked);
        let _ = fs::remove_file(&executable);
        let _ = fs::remove_file(&moved);
        let _ = fs::remove_dir(&root);
    }

    #[test]
    fn bounded_reader_routes_one_correlated_result() {
        let process = process();
        let (sender, receiver) = mpsc::sync_channel(1);
        process
            .pending
            .lock()
            .unwrap()
            .insert("one".into(), Pending::Request(sender));
        read_stdout(
            Cursor::new(
                br#"{"protocolVersion":2,"type":"result","id":"one","result":{"ok":true}}
"#,
            ),
            Arc::clone(&process),
        );
        assert_eq!(receiver.recv().unwrap().unwrap(), json!({ "ok": true }));
        assert!(!process.failed.load(Ordering::Acquire));
    }

    #[test]
    fn bounded_reader_rejects_oversized_unterminated_line() {
        let process = process();
        read_stdout(
            Cursor::new(vec![b'x'; MAX_LINE_BYTES + 1]),
            Arc::clone(&process),
        );
        assert!(process.failed.load(Ordering::Acquire));
    }

    #[test]
    fn unknown_response_id_fails_the_process() {
        let process = process();
        read_stdout(
            Cursor::new(
                br#"{"protocolVersion":2,"type":"result","id":"unknown","result":{}}
"#,
            ),
            Arc::clone(&process),
        );
        assert!(process.failed.load(Ordering::Acquire));
    }

    #[test]
    fn error_payload_rejects_control_characters_and_unknown_codes() {
        assert!(require_backend_error("valid_code", "safe message").is_ok());
        assert!(require_backend_error("INVALID", "safe message").is_err());
        assert!(require_backend_error("valid_code", "unsafe\nmessage").is_err());
    }

    #[test]
    fn progress_overflow_is_dropped_but_terminal_is_delivered() {
        let (sender, receiver) = mpsc::channel();
        let budget = Arc::new(OperationQueueBudget::default());
        for completed_files in 0..=MAX_QUEUED_PROGRESS {
            queue_event(
                &sender,
                &budget,
                BackendEvent::Progress {
                    operation_id: "one".into(),
                    completed_files: completed_files as u64,
                    total_files: MAX_QUEUED_PROGRESS as u64,
                    completed_bytes: completed_files as u64,
                    total_bytes: MAX_QUEUED_PROGRESS as u64,
                },
            )
            .unwrap();
        }
        complete_pending(
            Pending::Operation {
                kind: OperationKind::Install,
                sender,
                budget: Arc::clone(&budget),
            },
            Ok(json!({ "committed": true })),
        )
        .unwrap();
        let operation = BackendOperation {
            operation_id: "one".into(),
            receiver,
            budget,
        };
        for _ in 0..MAX_QUEUED_PROGRESS {
            assert!(matches!(
                operation.recv().unwrap(),
                OperationMessage::Event(_)
            ));
        }
        assert!(matches!(
            operation.recv().unwrap(),
            OperationMessage::Complete(Ok(value)) if value == json!({ "committed": true })
        ));
    }
}
