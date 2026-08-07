use std::{
    fs::File,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::OsString;

#[cfg(target_os = "linux")]
use std::os::{
    fd::{AsRawFd, OwnedFd},
    unix::process::CommandExt,
};

#[cfg(windows)]
use std::os::windows::io::BorrowedHandle;

#[cfg(unix)]
use std::{sync::mpsc, thread};

use luxury_engine::{PortError, PortErrorKind, launch::LaunchPort, uninstall::OwnershipReceipt};
use luxury_spec::{FileEntry, InstallScope, PackageId};

use super::{
    install_recovery_pending, load_receipt,
    transaction::{
        acquire_destination_lock, hash_opened_file, io_error, lock_package, state_error,
        validate_directory, validate_directory_chain, validate_open_regular,
    },
};

pub struct LocalLaunchAdapter {
    install_base: PathBuf,
    state_root: PathBuf,
    scope: InstallScope,
}

impl LocalLaunchAdapter {
    pub fn new(install_base: impl Into<PathBuf>, state_root: impl Into<PathBuf>) -> Self {
        Self::with_scope(install_base, state_root, InstallScope::User)
    }

    pub fn for_system(install_base: impl Into<PathBuf>, state_root: impl Into<PathBuf>) -> Self {
        Self::with_scope(install_base, state_root, InstallScope::System)
    }

    fn with_scope(
        install_base: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        scope: InstallScope,
    ) -> Self {
        Self {
            install_base: install_base.into(),
            state_root: state_root.into(),
            scope,
        }
    }

    fn launch_owned_entrypoint_with<F>(
        &mut self,
        expected: &OwnershipReceipt,
        file: &FileEntry,
        launch: F,
    ) -> Result<(), PortError>
    where
        F: FnOnce(&Path, &Path, &LaunchGuards) -> Result<(), PortError>,
    {
        if expected.scope() != self.scope {
            return Err(state_error(
                "launch receipt scope does not match adapter authority",
            ));
        }
        let _package_lock = lock_package(&self.state_root, expected.package_id(), self.scope)?;
        let _destination_lock =
            acquire_destination_lock(&self.install_base, expected.directory(), self.scope)?;

        if install_recovery_pending(&self.install_base, &self.state_root, expected.package_id())? {
            return Err(PortError::with_kind(
                PortErrorKind::Recovery,
                "pending transaction must be recovered before launch",
            ));
        }
        let current = load_receipt(
            &self.install_base,
            &self.state_root,
            expected.package_id(),
            self.scope,
        )?
        .ok_or_else(|| state_error("ownership receipt disappeared before launch"))?;
        if &current != expected {
            return Err(state_error("ownership receipt changed before launch"));
        }
        if !current.files().iter().any(|owned| owned == file) {
            return Err(state_error(
                "launch entrypoint is not owned by the current receipt",
            ));
        }

        let install_base = std::path::absolute(&self.install_base).map_err(|source| {
            io_error("resolving launch install base", &self.install_base, source)
        })?;
        let install_root = install_base.join(current.directory().as_str());
        validate_directory_chain(&install_root)?;
        validate_directory(&install_root)?;
        let executable = install_root.join(file.path.to_native_path());
        if let Some(parent) = executable.parent() {
            validate_directory_chain(parent)?;
        }

        let guards = verify_entrypoint(&executable, &install_root, file)?;
        launch(&executable, &install_root, &guards)
    }
}

impl LaunchPort for LocalLaunchAdapter {
    fn recovery_pending(&mut self, package_id: &PackageId) -> Result<bool, PortError> {
        install_recovery_pending(&self.install_base, &self.state_root, package_id)
    }

    fn load_receipt(
        &mut self,
        package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError> {
        load_receipt(&self.install_base, &self.state_root, package_id, self.scope)
    }

    fn launch_owned_entrypoint(
        &mut self,
        expected: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<(), PortError> {
        self.launch_owned_entrypoint_with(expected, file, launch_direct)
    }
}

#[cfg(target_os = "linux")]
fn launch_direct(
    executable: &Path,
    install_root: &Path,
    guards: &LaunchGuards,
) -> Result<(), PortError> {
    let working_directory = clone_linux_working_directory(install_root, &guards.working_directory)?;
    let reaper = start_launch_reaper(executable)?;
    let (mut command, executable_fd) = linux_verified_command(executable, &guards.file)?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe fchdir and fcntl run after fork. The opened directory and
    // executable descriptors bind both process inputs without resolving their old pathnames.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || prepare_linux_exec(&executable_fd, &working_directory));
    }
    let child = command
        .spawn()
        .map_err(|source| io_error("launching verified entrypoint", executable, source))?;
    if let Err(error) = reaper.send(child) {
        let mut child = error.0;
        let _ = child.wait();
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn launch_direct(
    executable: &Path,
    install_root: &Path,
    _guards: &LaunchGuards,
) -> Result<(), PortError> {
    #[cfg(unix)]
    let reaper = start_launch_reaper(executable)?;
    let child = Command::new(executable)
        .current_dir(install_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| io_error("launching owned entrypoint", executable, source))?;
    #[cfg(unix)]
    if let Err(error) = reaper.send(child) {
        // The receiver cannot normally disappear, but the child is already running here.
        // Reap synchronously rather than report a false launch failure or leave a zombie.
        let mut child = error.0;
        let _ = child.wait();
    }
    #[cfg(not(unix))]
    drop(child);
    Ok(())
}

#[cfg(windows)]
pub struct WindowsSystemLaunchAdapter<'a> {
    inner: LocalLaunchAdapter,
    parent_process: BorrowedHandle<'a>,
}

#[cfg(target_os = "linux")]
pub struct LinuxSystemLaunchAdapter {
    inner: LocalLaunchAdapter,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    environment: Vec<(OsString, OsString)>,
}

#[cfg(target_os = "linux")]
impl LinuxSystemLaunchAdapter {
    pub fn new(
        install_base: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        uid: u32,
        gid: u32,
        groups: Vec<u32>,
        environment: Vec<(OsString, OsString)>,
    ) -> Self {
        Self {
            inner: LocalLaunchAdapter::for_system(install_base, state_root),
            uid,
            gid,
            groups,
            environment,
        }
    }
}

#[cfg(target_os = "linux")]
impl LaunchPort for LinuxSystemLaunchAdapter {
    fn recovery_pending(&mut self, package_id: &PackageId) -> Result<bool, PortError> {
        LaunchPort::recovery_pending(&mut self.inner, package_id)
    }

    fn load_receipt(
        &mut self,
        package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError> {
        LaunchPort::load_receipt(&mut self.inner, package_id)
    }

    fn launch_owned_entrypoint(
        &mut self,
        expected: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<(), PortError> {
        let uid = self.uid;
        let gid = self.gid;
        let groups = &self.groups;
        let environment = &self.environment;
        self.inner.launch_owned_entrypoint_with(
            expected,
            file,
            |executable, install_root, guards| {
                launch_as_linux_user(
                    executable,
                    install_root,
                    guards,
                    uid,
                    gid,
                    groups,
                    environment,
                )
            },
        )
    }
}

#[cfg(target_os = "linux")]
fn launch_as_linux_user(
    executable: &Path,
    install_root: &Path,
    guards: &LaunchGuards,
    uid: u32,
    gid: u32,
    groups: &[u32],
    environment: &[(OsString, OsString)],
) -> Result<(), PortError> {
    if uid == 0 || gid == 0 || groups.contains(&0) {
        return Err(PortError::with_kind(
            PortErrorKind::Permission,
            "system entrypoint launch identity must be unprivileged",
        ));
    }
    let working_directory = clone_linux_working_directory(install_root, &guards.working_directory)?;
    let reaper = start_launch_reaper(executable)?;
    let (mut command, executable_fd) = linux_verified_command(executable, &guards.file)?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .envs(environment.iter().map(|(name, value)| (name, value)));
    let groups = groups
        .iter()
        .copied()
        .map(rustix::process::Gid::from_raw)
        .collect::<Vec<_>>();
    let uid = rustix::process::Uid::from_raw(uid);
    let gid = rustix::process::Gid::from_raw(gid);
    // SAFETY: only async-signal-safe credential, fchdir and fcntl syscalls run after fork. Both
    // launch descriptors are already verified; no attacker-controlled pathname is resolved.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            rustix::thread::set_thread_groups(&groups).map_err(rustix_error)?;
            rustix::thread::set_thread_res_gid(gid, gid, gid).map_err(rustix_error)?;
            rustix::thread::set_thread_res_uid(uid, uid, uid).map_err(rustix_error)?;
            prepare_linux_exec(&executable_fd, &working_directory)
        });
    }
    let child = command.spawn().map_err(|source| {
        io_error(
            "launching system entrypoint as interactive user",
            executable,
            source,
        )
    })?;
    if let Err(error) = reaper.send(child) {
        let mut child = error.0;
        let _ = child.wait();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_verified_command(
    executable: &Path,
    verified: &File,
) -> Result<(Command, File), PortError> {
    let executable_fd = verified
        .try_clone()
        .map_err(|source| io_error("duplicating launch entrypoint", executable, source))?;
    let program = format!("/proc/self/fd/{}", executable_fd.as_raw_fd());
    Ok((Command::new(program), executable_fd))
}

#[cfg(target_os = "linux")]
fn clone_linux_working_directory(
    install_root: &Path,
    working_directory: &OwnedFd,
) -> Result<OwnedFd, PortError> {
    rustix::io::fcntl_dupfd_cloexec(working_directory, 0).map_err(|source| {
        io_error(
            "duplicating launch working directory",
            install_root,
            rustix_error(source),
        )
    })
}

#[cfg(target_os = "linux")]
fn prepare_linux_exec(executable_fd: &File, working_directory: &OwnedFd) -> std::io::Result<()> {
    rustix::process::fchdir(working_directory).map_err(rustix_error)?;
    clear_linux_exec_cloexec(executable_fd)
}

#[cfg(target_os = "linux")]
fn clear_linux_exec_cloexec(executable_fd: &File) -> std::io::Result<()> {
    rustix::io::fcntl_setfd(executable_fd, rustix::io::FdFlags::empty()).map_err(rustix_error)
}

#[cfg(target_os = "linux")]
fn rustix_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(target_os = "macos")]
pub struct MacosSystemLaunchAdapter {
    inner: LocalLaunchAdapter,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    username: OsString,
    home: OsString,
}

#[cfg(target_os = "macos")]
impl MacosSystemLaunchAdapter {
    pub fn new(
        install_base: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        uid: u32,
        gid: u32,
        groups: Vec<u32>,
        username: OsString,
        home: OsString,
    ) -> Self {
        Self {
            inner: LocalLaunchAdapter::for_system(install_base, state_root),
            uid,
            gid,
            groups,
            username,
            home,
        }
    }
}

#[cfg(target_os = "macos")]
impl LaunchPort for MacosSystemLaunchAdapter {
    fn recovery_pending(&mut self, package_id: &PackageId) -> Result<bool, PortError> {
        LaunchPort::recovery_pending(&mut self.inner, package_id)
    }

    fn load_receipt(
        &mut self,
        package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError> {
        LaunchPort::load_receipt(&mut self.inner, package_id)
    }

    fn launch_owned_entrypoint(
        &mut self,
        expected: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<(), PortError> {
        let uid = self.uid;
        let gid = self.gid;
        let groups = &self.groups;
        let username = &self.username;
        let home = &self.home;
        self.inner.launch_owned_entrypoint_with(
            expected,
            file,
            |executable, install_root, _guards| {
                launch_as_macos_user(executable, install_root, uid, gid, groups, username, home)
            },
        )
    }
}

#[cfg(target_os = "macos")]
fn launch_as_macos_user(
    executable: &Path,
    install_root: &Path,
    uid: u32,
    gid: u32,
    groups: &[u32],
    username: &OsString,
    home: &OsString,
) -> Result<(), PortError> {
    use std::os::unix::process::CommandExt;

    if uid == 0 || gid == 0 || groups.contains(&0) || username.is_empty() || home.is_empty() {
        return Err(PortError::with_kind(
            PortErrorKind::Permission,
            "system entrypoint launch identity must be unprivileged",
        ));
    }
    let group_count = libc::c_int::try_from(groups.len()).map_err(|_| {
        PortError::with_kind(
            PortErrorKind::Permission,
            "system entrypoint launch has too many supplementary groups",
        )
    })?;
    let groups = groups
        .iter()
        .copied()
        .map(|group| group as libc::gid_t)
        .collect::<Vec<_>>();
    let uid_argument = uid.to_string();
    let reaper = start_launch_reaper(executable)?;
    let mut command = Command::new("/bin/launchctl");
    command
        .arg("asuser")
        .arg(uid_argument)
        .arg(executable)
        .current_dir(install_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("USER", username)
        .env("LOGNAME", username);
    // SAFETY: only async-signal-safe credential syscalls run in the post-fork child. The fixed
    // launchctl broker then enters the target user's bootstrap namespace and direct-execs the
    // already verified entrypoint without application arguments.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(group_count, groups.as_ptr()) != 0
                || libc::setgid(gid as libc::gid_t) != 0
                || libc::setuid(uid as libc::uid_t) != 0
            {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let child = command.spawn().map_err(|source| {
        io_error(
            "launching system entrypoint as interactive user",
            executable,
            source,
        )
    })?;
    if let Err(error) = reaper.send(child) {
        let mut child = error.0;
        let _ = child.wait();
    }
    Ok(())
}

#[cfg(windows)]
impl<'a> WindowsSystemLaunchAdapter<'a> {
    pub fn new(
        install_base: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        parent_process: BorrowedHandle<'a>,
    ) -> Self {
        Self {
            inner: LocalLaunchAdapter::for_system(install_base, state_root),
            parent_process,
        }
    }
}

#[cfg(windows)]
impl LaunchPort for WindowsSystemLaunchAdapter<'_> {
    fn recovery_pending(&mut self, package_id: &PackageId) -> Result<bool, PortError> {
        LaunchPort::recovery_pending(&mut self.inner, package_id)
    }

    fn load_receipt(
        &mut self,
        package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError> {
        LaunchPort::load_receipt(&mut self.inner, package_id)
    }

    fn launch_owned_entrypoint(
        &mut self,
        expected: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<(), PortError> {
        let parent_process = self.parent_process;
        self.inner.launch_owned_entrypoint_with(
            expected,
            file,
            |executable, install_root, _guards| {
                super::windows::launch_with_process_token(parent_process, executable, install_root)
                    .map_err(|source| {
                        io_error(
                            "launching system entrypoint as interactive user",
                            executable,
                            source,
                        )
                    })
            },
        )
    }
}

#[cfg(unix)]
fn start_launch_reaper(path: &Path) -> Result<mpsc::SyncSender<std::process::Child>, PortError> {
    let (sender, receiver) = mpsc::sync_channel::<std::process::Child>(1);
    let _reaper = thread::Builder::new()
        .name("luxury-launch-reaper".into())
        .spawn(move || {
            if let Ok(mut child) = receiver.recv() {
                let _ = child.wait();
            }
        })
        .map_err(|source| io_error("starting launch reaper", path, source))?;
    Ok(sender)
}

#[cfg(windows)]
struct LaunchGuards {
    _parent_guards: Vec<File>,
    _write_guard: File,
    _delete_guard: File,
}

#[cfg(target_os = "linux")]
struct LaunchGuards {
    file: File,
    working_directory: OwnedFd,
}

#[cfg(all(unix, not(target_os = "linux")))]
struct LaunchGuards {
    _file: File,
}

fn verify_entrypoint(
    path: &Path,
    install_root: &Path,
    expected: &FileEntry,
) -> Result<LaunchGuards, PortError> {
    #[cfg(windows)]
    {
        let _ = install_root;
        let (path, parent_guards) = super::windows::open_real_parent_chain(path)
            .map_err(|source| io_error("opening launch parent directories", path, source))?;
        let (mut write_guard, delete_guard) = super::windows::open_launch_guards_nofollow(&path)
            .map_err(|source| io_error("opening launch entrypoint", &path, source))?;
        validate_open_regular(&path, &write_guard, false)?;
        validate_open_regular(&path, &delete_guard, false)?;
        let write_identity = super::windows::file_identity(&write_guard)
            .map_err(|source| io_error("reading launch entrypoint identity", &path, source))?;
        let delete_identity = super::windows::file_identity(&delete_guard)
            .map_err(|source| io_error("reading launch entrypoint identity", &path, source))?;
        if write_identity != delete_identity {
            return Err(state_error("launch entrypoint changed while it was opened"));
        }
        let (size, sha256) = hash_opened_file(&path, &mut write_guard, false)?;
        if size != expected.size || sha256 != expected.sha256 {
            return Err(PortError::with_kind(
                PortErrorKind::Integrity,
                "launch entrypoint bytes do not match the ownership receipt",
            ));
        }
        Ok(LaunchGuards {
            _parent_guards: parent_guards,
            _write_guard: write_guard,
            _delete_guard: delete_guard,
        })
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;

        let working_directory = super::unix::open_directory(install_root)
            .map_err(|source| io_error("opening launch working directory", install_root, source))?;
        let mut file =
            super::unix::open_file_beneath(&working_directory, expected.path.to_native_path())
                .map_err(|source| io_error("opening launch entrypoint", path, source))?;
        let (size, sha256) = hash_opened_file(path, &mut file, false)?;
        let metadata = validate_open_regular(path, &file, false)?;
        let executable = metadata.permissions().mode() & 0o111 != 0;
        if size != expected.size || sha256 != expected.sha256 || executable != expected.executable {
            return Err(PortError::with_kind(
                PortErrorKind::Integrity,
                "launch entrypoint bytes or executable mode do not match the ownership receipt",
            ));
        }
        Ok(LaunchGuards {
            file,
            working_directory,
        })
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::os::unix::fs::PermissionsExt;

        let _ = install_root;
        let mut file = super::transaction::open_existing_nofollow(path)?;
        let (size, sha256) = hash_opened_file(path, &mut file, false)?;
        let metadata = validate_open_regular(path, &file, false)?;
        let executable = metadata.permissions().mode() & 0o111 != 0;
        if size != expected.size || sha256 != expected.sha256 || executable != expected.executable {
            return Err(PortError::with_kind(
                PortErrorKind::Integrity,
                "launch entrypoint bytes or executable mode do not match the ownership receipt",
            ));
        }
        Ok(LaunchGuards { _file: file })
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, install_root, expected);
        Err(PortError::with_kind(
            PortErrorKind::Unsupported,
            "launch verification is unsupported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    #[cfg(any(windows, target_os = "linux"))]
    use std::{thread, time::Duration};

    use luxury_engine::{
        PortErrorKind,
        install::PackageIdentity,
        launch::{LaunchCommand, LaunchError, LaunchPort, launch},
        uninstall::OwnershipReceipt,
    };
    use luxury_spec::{
        FileEntry, InstallDirectory, InstallScope, PackageId, PackagePath, Sha256Digest,
    };
    use semver::Version;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tempfile::{TempDir, tempdir, tempdir_in};

    use super::*;
    use crate::local::{
        STORED_RECEIPT_FORMAT_VERSION, StoredReceipt,
        transaction::{
            DESTINATION_LOCK_DIRECTORY, ensure_directory, install_base_identity, transaction_paths,
        },
    };

    struct LaunchFixture {
        _temp: TempDir,
        install_base: PathBuf,
        state_root: PathBuf,
        installed: PathBuf,
        receipt: OwnershipReceipt,
        file: FileEntry,
    }

    impl LaunchFixture {
        fn new() -> Self {
            Self::from_temp(tempdir().unwrap())
        }

        fn new_in(parent: &Path) -> Self {
            Self::from_temp(tempdir_in(parent).unwrap())
        }

        fn from_temp(temp: TempDir) -> Self {
            let install_base = temp.path().join("install");
            let state_root = temp.path().join("state");
            let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
            let relative = PackagePath::parse(entrypoint_path()).unwrap();
            let install_root = install_base.join(directory.as_str());
            let installed = install_root.join(relative.to_native_path());
            ensure_directory(installed.parent().unwrap(), None).unwrap();
            ensure_directory(
                &install_base.join(DESTINATION_LOCK_DIRECTORY),
                Some(InstallScope::User),
            )
            .unwrap();
            ensure_directory(&state_root.join("receipts"), Some(InstallScope::User)).unwrap();
            ensure_directory(&state_root.join("transactions"), Some(InstallScope::User)).unwrap();
            ensure_directory(&state_root.join("locks"), Some(InstallScope::User)).unwrap();
            fs::copy(host_executable(), &installed).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
            }
            let bytes = fs::read(&installed).unwrap();
            let file = FileEntry {
                path: relative.clone(),
                size: bytes.len() as u64,
                sha256: Sha256Digest::parse(hex::encode(Sha256::digest(&bytes))).unwrap(),
                executable: cfg!(unix),
            };
            let package_id = PackageId::parse("dev.luxury.launch-test").unwrap();
            let base = OwnershipReceipt::new(
                package_id.clone(),
                Version::new(1, 0, 0),
                InstallScope::User,
                directory,
                PackageIdentity::Unsigned,
                vec![file.clone()],
            )
            .unwrap();
            let mut encoded = serde_json::to_value(base).unwrap();
            encoded["entrypoint"] = json!(relative.as_str());
            let receipt: OwnershipReceipt = serde_json::from_value(encoded).unwrap();
            receipt.validate().unwrap();
            let paths = transaction_paths(&install_base, &state_root, &package_id);
            let stored = StoredReceipt {
                format_version: STORED_RECEIPT_FORMAT_VERSION,
                install_base: install_base_identity(&install_base).unwrap(),
                receipt: receipt.clone(),
            };
            fs::write(&paths.receipt, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();
            Self {
                _temp: temp,
                install_base,
                state_root,
                installed,
                receipt,
                file,
            }
        }

        fn adapter(&self) -> LocalLaunchAdapter {
            LocalLaunchAdapter::new(&self.install_base, &self.state_root)
        }

        #[cfg(any(target_os = "linux", windows))]
        fn install_root(&self) -> PathBuf {
            self.install_base.join(self.receipt.directory().as_str())
        }

        fn paths(&self) -> super::super::transaction::TransactionPaths {
            transaction_paths(
                &self.install_base,
                &self.state_root,
                self.receipt.package_id(),
            )
        }
    }

    #[cfg(windows)]
    fn wait_for_image_release(path: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if fs::OpenOptions::new().write(true).open(path).is_ok() {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "launched test executable did not release {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(not(windows))]
    fn wait_for_image_release(_: &Path) {}

    #[test]
    fn launches_exact_owned_entrypoint_without_transaction_state() {
        let fixture = LaunchFixture::new();
        let paths = fixture.paths();
        let receipt_bytes = fs::read(&paths.receipt).unwrap();
        let mut adapter = fixture.adapter();

        launch(
            LaunchCommand::new(fixture.receipt.package_id().clone()),
            &mut adapter,
        )
        .unwrap();

        assert_eq!(fs::read(&paths.receipt).unwrap(), receipt_bytes);
        assert!(!paths.state_dir.exists());
        assert!(!paths.destination_dir.exists());
        wait_for_image_release(&fixture.installed);
    }

    #[test]
    fn launches_with_relative_human_cli_roots() {
        let current = std::env::current_dir().unwrap();
        let fixture = LaunchFixture::new_in(&current);
        let install_base = fixture.install_base.strip_prefix(&current).unwrap();
        let state_root = fixture.state_root.strip_prefix(&current).unwrap();
        let mut adapter = LocalLaunchAdapter::new(install_base, state_root);

        launch(
            LaunchCommand::new(fixture.receipt.package_id().clone()),
            &mut adapter,
        )
        .unwrap();
        wait_for_image_release(&fixture.installed);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_system_launch_rejects_root_identity_before_spawn() {
        let guards = LaunchGuards {
            file: File::open("/bin/true").unwrap(),
            working_directory: super::super::unix::open_directory(Path::new("/")).unwrap(),
        };
        let error = launch_as_linux_user(
            Path::new("/bin/true"),
            Path::new("/"),
            &guards,
            0,
            1000,
            &[1000],
            &[],
        )
        .unwrap_err();
        assert_eq!(error.kind(), PortErrorKind::Permission);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_launch_executes_verified_descriptor_after_path_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let executable = temp.path().join("app");
        let verified_name = temp.path().join("verified-app");
        let marker = temp.path().join("marker");
        let marker_text = marker.to_str().unwrap();
        assert!(!marker_text.contains('\''));
        let script = |value: &str| format!("#!/bin/sh\nprintf '%s' '{value}' > '{marker_text}'\n");
        fs::write(&executable, script("verified")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let verified = File::open(&executable).unwrap();
        fs::rename(&executable, &verified_name).unwrap();
        fs::write(&executable, script("replacement")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let working_directory = super::super::unix::open_directory(temp.path()).unwrap();
        launch_direct(
            &executable,
            temp.path(),
            &LaunchGuards {
                file: verified,
                working_directory,
            },
        )
        .unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !marker.is_file() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::read_to_string(marker).unwrap(), "verified");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_launch_keeps_the_verified_working_directory_after_path_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = LaunchFixture::new();
        let install_root = fixture.install_root();
        let moved_root = fixture._temp.path().join("verified-root");
        let marker = fixture._temp.path().join("cwd-marker");
        let marker_text = marker.to_str().unwrap();
        assert!(!marker_text.contains('\''));
        fs::write(install_root.join("identity"), b"verified").unwrap();
        fs::write(
            &fixture.installed,
            format!("#!/bin/sh\nread value < identity\nprintf '%s' \"$value\" > '{marker_text}'\n"),
        )
        .unwrap();
        fs::set_permissions(&fixture.installed, fs::Permissions::from_mode(0o755)).unwrap();
        let bytes = fs::read(&fixture.installed).unwrap();
        fixture.file.size = bytes.len() as u64;
        fixture.file.sha256 = Sha256Digest::parse(hex::encode(Sha256::digest(&bytes))).unwrap();
        fixture.file.executable = true;
        let guards = verify_entrypoint(&fixture.installed, &install_root, &fixture.file).unwrap();
        assert!(
            rustix::io::fcntl_getfd(&guards.file)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(
            rustix::io::fcntl_getfd(&guards.working_directory)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );

        fs::rename(&install_root, &moved_root).unwrap();
        fs::create_dir(&install_root).unwrap();
        fs::write(install_root.join("identity"), b"replacement").unwrap();
        launch_direct(&fixture.installed, &install_root, &guards).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !matches!(fs::read_to_string(&marker), Ok(value) if !value.is_empty())
            && std::time::Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::read_to_string(marker).unwrap(), "verified");
        assert!(
            rustix::io::fcntl_getfd(&guards.working_directory)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_system_launch_rejects_root_identity_before_spawn() {
        let error = launch_as_macos_user(
            Path::new("/usr/bin/true"),
            Path::new("/"),
            0,
            20,
            &[20],
            &OsString::from("user"),
            &OsString::from("/Users/user"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), PortErrorKind::Permission);
    }

    #[test]
    fn rejects_modified_and_multi_link_entrypoints() {
        let modified = LaunchFixture::new();
        fs::write(&modified.installed, b"modified").unwrap();
        let error = launch(
            LaunchCommand::new(modified.receipt.package_id().clone()),
            &mut modified.adapter(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            LaunchError::Port { source, .. } if source.kind() == PortErrorKind::Integrity
        ));
        assert!(!modified.paths().state_dir.exists());

        let linked = LaunchFixture::new();
        fs::hard_link(&linked.installed, linked.installed.with_extension("alias")).unwrap();
        let error = launch(
            LaunchCommand::new(linked.receipt.package_id().clone()),
            &mut linked.adapter(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            LaunchError::Port { source, .. } if source.kind() == PortErrorKind::State
        ));
        assert!(!linked.paths().state_dir.exists());
    }

    #[test]
    fn locked_launch_recheck_preserves_pending_state() {
        let fixture = LaunchFixture::new();
        let paths = fixture.paths();
        let receipt_bytes = fs::read(&paths.receipt).unwrap();
        ensure_directory(&paths.state_dir, Some(InstallScope::User)).unwrap();
        let mut adapter = fixture.adapter();

        let error = adapter
            .launch_owned_entrypoint(&fixture.receipt, &fixture.file)
            .unwrap_err();

        assert_eq!(error.kind(), PortErrorKind::Recovery);
        assert!(paths.state_dir.is_dir());
        assert_eq!(fs::read_dir(&paths.state_dir).unwrap().count(), 0);
        assert_eq!(fs::read(&paths.receipt).unwrap(), receipt_bytes);
    }

    #[cfg(windows)]
    #[test]
    fn windows_launch_guards_deny_write_and_delete() {
        use std::fs::OpenOptions;

        let fixture = LaunchFixture::new();
        let _guards =
            verify_entrypoint(&fixture.installed, &fixture.install_root(), &fixture.file).unwrap();

        assert!(
            OpenOptions::new()
                .write(true)
                .open(&fixture.installed)
                .is_err()
        );
        assert!(fs::remove_file(&fixture.installed).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_launch_rejects_an_intermediate_reparse_after_validation() {
        let fixture = LaunchFixture::new();
        let parent = fixture.installed.parent().unwrap();
        validate_directory_chain(parent).unwrap();
        let external = fixture._temp.path().join("external-bin");
        fs::create_dir(&external).unwrap();
        fs::copy(&fixture.installed, external.join("app.exe")).unwrap();
        let original = parent.with_extension("original");
        fs::rename(parent, &original).unwrap();
        let status = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(parent)
            .arg(&external)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "creating directory junction failed");

        let rejection =
            match verify_entrypoint(&fixture.installed, &fixture.install_root(), &fixture.file) {
                Ok(guards) => {
                    drop(guards);
                    None
                }
                Err(error) => Some(error),
            };
        fs::remove_dir(parent).unwrap();
        fs::rename(original, parent).unwrap();
        let error = rejection.unwrap_or_else(|| panic!("replaced parent reparse point accepted"));
        assert_eq!(error.kind(), PortErrorKind::Io);
        assert!(
            error
                .to_string()
                .contains("opening launch parent directories")
        );
    }

    #[cfg(windows)]
    fn entrypoint_path() -> &'static str {
        "bin/app.exe"
    }

    #[cfg(unix)]
    fn entrypoint_path() -> &'static str {
        "bin/app"
    }

    #[cfg(windows)]
    fn host_executable() -> PathBuf {
        PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set"))
            .join("System32")
            .join("whoami.exe")
    }

    #[cfg(target_os = "linux")]
    fn host_executable() -> PathBuf {
        PathBuf::from("/bin/true")
    }

    #[cfg(target_os = "macos")]
    fn host_executable() -> PathBuf {
        PathBuf::from("/usr/bin/true")
    }
}
