use std::{
    io,
    process::{Child, Command},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub(super) struct ChildContainment {
    containment: Arc<SharedContainment>,
    timed_out: Arc<AtomicBool>,
    stop: Option<SyncSender<()>>,
    watchdog: Option<JoinHandle<()>>,
}

impl ChildContainment {
    pub(super) fn spawn(command: &mut Command, timeout: Duration) -> io::Result<(Child, Self)> {
        let prepared = PreparedContainment::new(command)?;
        let mut child = command.spawn()?;
        let platform = match prepared.attach(&child) {
            Ok(platform) => platform,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let (stop, receiver) = mpsc::sync_channel(1);
        let timed_out = Arc::new(AtomicBool::new(false));
        let containment = Arc::new(SharedContainment::new(platform));
        let watchdog_containment = Arc::clone(&containment);
        let watchdog_timed_out = Arc::clone(&timed_out);
        let watchdog = match thread::Builder::new()
            .name("lifecycle-watchdog".into())
            .spawn(move || {
                if matches!(
                    receiver.recv_timeout(timeout),
                    Err(RecvTimeoutError::Timeout)
                ) {
                    watchdog_timed_out.store(true, Ordering::Release);
                    let _ = watchdog_containment.terminate();
                }
            }) {
            Ok(watchdog) => watchdog,
            Err(error) => {
                let termination = containment.terminate().err();
                let _ = child.kill();
                let _ = child.wait();
                return Err(match termination {
                    Some(termination) => io::Error::new(
                        error.kind(),
                        format!("{error}; lifecycle containment failed: {termination}"),
                    ),
                    None => error,
                });
            }
        };
        Ok((
            child,
            Self {
                containment,
                timed_out,
                stop: Some(stop),
                watchdog: Some(watchdog),
            },
        ))
    }

    pub(super) fn timed_out(&self) -> bool {
        self.timed_out.load(Ordering::Acquire)
    }

    pub(super) fn terminate(&self) -> io::Result<()> {
        self.containment.terminate()
    }

    pub(super) fn wait_for_primary_exit(&self, child: &Child) -> io::Result<()> {
        self.containment.platform.wait_for_primary_exit(child)
    }

    pub(super) fn disarm(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.try_send(());
        }
        if let Some(watchdog) = self.watchdog.take() {
            let _ = watchdog.join();
        }
    }
}

impl Drop for ChildContainment {
    fn drop(&mut self) {
        let _ = self.terminate();
        self.disarm();
    }
}

struct SharedContainment {
    platform: PlatformContainment,
    termination: OnceLock<Result<(), StoredIoError>>,
}

impl SharedContainment {
    fn new(platform: PlatformContainment) -> Self {
        Self {
            platform,
            termination: OnceLock::new(),
        }
    }

    fn terminate(&self) -> io::Result<()> {
        match self
            .termination
            .get_or_init(|| self.platform.terminate().map_err(StoredIoError::from))
        {
            Ok(()) => Ok(()),
            Err(error) => Err(error.to_io_error()),
        }
    }
}

struct StoredIoError {
    kind: io::ErrorKind,
    message: String,
}

impl From<io::Error> for StoredIoError {
    fn from(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl StoredIoError {
    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

#[cfg(windows)]
struct PreparedContainment {
    job: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
impl PreparedContainment {
    fn new(command: &mut Command) -> io::Result<Self> {
        use std::{
            mem::size_of,
            os::windows::{
                io::{AsRawHandle, FromRawHandle},
                process::CommandExt,
            },
            ptr::null,
        };

        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

        command.creation_flags(CREATE_SUSPENDED);

        // SAFETY: null security/name pointers request a private unnamed job object.
        let raw = unsafe { CreateJobObjectW(null(), null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateJobObjectW returned an owned real handle.
        let job = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the job handle is valid and `limits` is readable for its exact size.
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { job })
    }

    fn attach(self, child: &Child) -> io::Result<PlatformContainment> {
        use std::os::windows::io::AsRawHandle;

        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        // SAFETY: both the job and child process handles are valid for the call.
        if unsafe { AssignProcessToJobObject(self.job.as_raw_handle(), child.as_raw_handle()) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        resume_process_threads(child.id())?;
        Ok(PlatformContainment { job: self.job })
    }
}

#[cfg(windows)]
fn resume_process_threads(process_id: u32) -> io::Result<()> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::{
        Foundation::{ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE, TRUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            Threading::{
                GetProcessIdOfThread, OpenThread, ResumeThread, THREAD_QUERY_LIMITED_INFORMATION,
                THREAD_SUSPEND_RESUME,
            },
        },
    };

    // SAFETY: this takes a read-only snapshot of the current thread table.
    let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw_snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the snapshot API returned an owned handle distinct from INVALID_HANDLE_VALUE.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw_snapshot) };
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    let mut primary = None;
    // SAFETY: the snapshot and correctly sized writable entry are valid.
    let mut has_entry = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) } == TRUE;
    if !has_entry {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
            return Err(error);
        }
    }
    while has_entry {
        if entry.th32OwnerProcessID == process_id {
            // SAFETY: the thread id comes from the live snapshot and the output is an owned handle.
            let raw_thread = unsafe {
                OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                    0,
                    entry.th32ThreadID,
                )
            };
            if raw_thread.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: OpenThread returned an owned real handle.
            let thread = unsafe { OwnedHandle::from_raw_handle(raw_thread) };
            // SAFETY: the thread handle remains live and was opened from the snapshot id.
            let owner = unsafe { GetProcessIdOfThread(thread.as_raw_handle()) };
            if owner == 0 {
                return Err(io::Error::last_os_error());
            }
            if owner != process_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "suspended child thread changed owner",
                ));
            }
            if primary.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "suspended child exposed multiple primary threads",
                ));
            }
            primary = Some(thread);
        }
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        // SAFETY: the snapshot and writable entry remain valid.
        has_entry = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) } == TRUE;
        if !has_entry {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                return Err(error);
            }
        }
    }
    let primary = primary.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "suspended child exposed no primary thread",
        )
    })?;
    // SAFETY: enumeration proved there is exactly one owned thread and the handle has
    // THREAD_SUSPEND_RESUME access.
    match unsafe { ResumeThread(primary.as_raw_handle()) } {
        u32::MAX => Err(io::Error::last_os_error()),
        1 => Ok(()),
        count => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("suspended child thread had unexpected suspend count {count}"),
        )),
    }
}

#[cfg(windows)]
struct PlatformContainment {
    job: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
impl PlatformContainment {
    fn wait_for_primary_exit(&self, child: &Child) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;

        use windows_sys::Win32::{
            Foundation::{WAIT_FAILED, WAIT_OBJECT_0},
            System::Threading::{INFINITE, WaitForSingleObject},
        };

        // SAFETY: the child process handle remains owned while this blocking wait runs.
        match unsafe { WaitForSingleObject(child.as_raw_handle(), INFINITE) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            result => Err(io::Error::other(format!(
                "waiting for child returned unexpected status {result}"
            ))),
        }
    }

    fn terminate(&self) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;

        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        // SAFETY: the job handle remains owned for the duration of the call.
        if unsafe { TerminateJobObject(self.job.as_raw_handle(), 1) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct PreparedContainment;

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PreparedContainment {
    fn new(command: &mut Command) -> io::Result<Self> {
        use std::os::unix::process::CommandExt;

        command.process_group(0);
        Ok(Self)
    }

    fn attach(self, child: &Child) -> io::Result<PlatformContainment> {
        let raw = i32::try_from(child.id())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "child PID overflow"))?;
        let process_group = rustix::process::Pid::from_raw(raw)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "child PID is zero"))?;
        Ok(PlatformContainment { process_group })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct PlatformContainment {
    process_group: rustix::process::Pid,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PlatformContainment {
    fn wait_for_primary_exit(&self, _: &Child) -> io::Result<()> {
        use rustix::process::{WaitId, WaitIdOptions, waitid};

        loop {
            match waitid(
                WaitId::Pid(self.process_group),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
            ) {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => continue,
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(io::Error::from(error)),
            }
        }
    }

    fn terminate(&self) -> io::Result<()> {
        match rustix::process::kill_process_group(self.process_group, rustix::process::Signal::KILL)
        {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(error) => Err(io::Error::from(error)),
        }
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
struct PreparedContainment;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
impl PreparedContainment {
    fn new(_: &mut Command) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "child process containment is unsupported on this platform",
        ))
    }

    fn attach(self, _: &Child) -> io::Result<PlatformContainment> {
        unreachable!("unsupported containment never spawns a child")
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
struct PlatformContainment;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
impl PlatformContainment {
    fn wait_for_primary_exit(&self, _: &Child) -> io::Result<()> {
        Ok(())
    }

    fn terminate(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        io::Read,
        process::Stdio,
        thread,
        time::{Duration, Instant},
    };

    use tempfile::tempdir;

    use super::*;

    const HELPER_MODE: &str = "LUXURY_CONTAINMENT_HELPER";
    const READY_PATH: &str = "LUXURY_CONTAINMENT_READY";
    const SENTINEL_PATH: &str = "LUXURY_CONTAINMENT_SENTINEL";

    #[test]
    fn watchdog_terminates_the_descendant_tree_and_closes_its_pipe() {
        match env::var(HELPER_MODE).as_deref() {
            Ok("parent") => return helper_parent(),
            Ok("grandchild") => return helper_grandchild(),
            _ => {}
        }

        let temp = tempdir().unwrap();
        let ready = temp.path().join("descendant-started");
        let sentinel = temp.path().join("descendant-survived");
        let executable = env::current_exe().unwrap();
        let test_name = helper_test_name();
        let mut command = Command::new(executable);
        command
            .args(["--exact", &test_name, "--nocapture"])
            .env(HELPER_MODE, "parent")
            .env(READY_PATH, &ready)
            .env(SENTINEL_PATH, &sentinel)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let started = Instant::now();
        let (mut child, mut containment) =
            ChildContainment::spawn(&mut command, Duration::from_millis(1_500)).unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).unwrap();
            bytes
        });

        containment.wait_for_primary_exit(&child).unwrap();
        containment.terminate().unwrap();
        let status = child.wait().unwrap();
        let output = reader.join().unwrap();
        let timed_out = containment.timed_out();
        containment.disarm();
        let containment_elapsed = started.elapsed();
        thread::sleep(Duration::from_millis(1_200));

        assert!(
            ready.exists(),
            "grandchild never reached its ready handshake"
        );
        assert!(timed_out);
        assert!(!status.success());
        assert!(containment_elapsed < Duration::from_secs(3));
        assert!(!sentinel.exists());
        assert!(output.len() < 64 * 1024);
    }

    fn helper_parent() {
        thread::sleep(Duration::from_millis(75));
        let executable = env::current_exe().unwrap();
        let test_name = helper_test_name();
        let mut grandchild = Command::new(executable)
            .args(["--exact", &test_name, "--nocapture"])
            .env(HELPER_MODE, "grandchild")
            .env(READY_PATH, env::var_os(READY_PATH).unwrap())
            .env(SENTINEL_PATH, env::var_os(SENTINEL_PATH).unwrap())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_secs(5));
        let _ = grandchild.kill();
        let _ = grandchild.wait();
    }

    fn helper_grandchild() {
        fs::write(env::var_os(READY_PATH).unwrap(), b"ready").unwrap();
        thread::sleep(Duration::from_millis(2_500));
        fs::write(env::var_os(SENTINEL_PATH).unwrap(), b"escaped").unwrap();
        thread::sleep(Duration::from_secs(5));
    }

    fn helper_test_name() -> String {
        let module = module_path!()
            .strip_prefix(concat!(env!("CARGO_CRATE_NAME"), "::"))
            .unwrap_or(module_path!());
        format!("{module}::watchdog_terminates_the_descendant_tree_and_closes_its_pipe")
    }
}
