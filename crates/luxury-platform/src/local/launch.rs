use std::{
    fs::File,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::OsString;

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
        F: FnOnce(&Path, &Path) -> Result<(), PortError>,
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

        let _guards = verify_entrypoint(&executable, file)?;
        launch(&executable, &install_root)
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

fn launch_direct(executable: &Path, install_root: &Path) -> Result<(), PortError> {
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
        self.inner
            .launch_owned_entrypoint_with(expected, file, |executable, install_root| {
                launch_as_linux_user(executable, install_root, uid, gid, groups, environment)
            })
    }
}

#[cfg(target_os = "linux")]
fn launch_as_linux_user(
    executable: &Path,
    install_root: &Path,
    uid: u32,
    gid: u32,
    groups: &[u32],
    environment: &[(OsString, OsString)],
) -> Result<(), PortError> {
    use std::os::unix::process::CommandExt;

    if uid == 0 || gid == 0 || groups.contains(&0) {
        return Err(PortError::with_kind(
            PortErrorKind::Permission,
            "system entrypoint launch identity must be unprivileged",
        ));
    }
    let reaper = start_launch_reaper(executable)?;
    let mut command = Command::new(executable);
    command
        .current_dir(install_root)
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
    // SAFETY: the closure performs only raw credential syscalls in the post-fork child. It
    // allocates nothing, touches no shared state, and returns before the exact direct exec.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            rustix::thread::set_thread_groups(&groups).map_err(rustix_error)?;
            rustix::thread::set_thread_res_gid(gid, gid, gid).map_err(rustix_error)?;
            rustix::thread::set_thread_res_uid(uid, uid, uid).map_err(rustix_error)
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
        self.inner
            .launch_owned_entrypoint_with(expected, file, |executable, install_root| {
                launch_as_macos_user(executable, install_root, uid, gid, groups, username, home)
            })
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
        self.inner
            .launch_owned_entrypoint_with(expected, file, |executable, install_root| {
                super::windows::launch_with_process_token(parent_process, executable, install_root)
                    .map_err(|source| {
                        io_error(
                            "launching system entrypoint as interactive user",
                            executable,
                            source,
                        )
                    })
            })
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
    _write_guard: File,
    _delete_guard: File,
}

#[cfg(unix)]
struct LaunchGuards {
    _file: File,
}

fn verify_entrypoint(path: &Path, expected: &FileEntry) -> Result<LaunchGuards, PortError> {
    #[cfg(windows)]
    {
        let (mut write_guard, delete_guard) = super::windows::open_launch_guards_nofollow(path)
            .map_err(|source| io_error("opening launch entrypoint", path, source))?;
        validate_open_regular(path, &write_guard, false)?;
        validate_open_regular(path, &delete_guard, false)?;
        let write_identity = super::windows::file_identity(&write_guard)
            .map_err(|source| io_error("reading launch entrypoint identity", path, source))?;
        let delete_identity = super::windows::file_identity(&delete_guard)
            .map_err(|source| io_error("reading launch entrypoint identity", path, source))?;
        if write_identity != delete_identity {
            return Err(state_error("launch entrypoint changed while it was opened"));
        }
        let (size, sha256) = hash_opened_file(path, &mut write_guard, false)?;
        if size != expected.size || sha256 != expected.sha256 {
            return Err(PortError::with_kind(
                PortErrorKind::Integrity,
                "launch entrypoint bytes do not match the ownership receipt",
            ));
        }
        Ok(LaunchGuards {
            _write_guard: write_guard,
            _delete_guard: delete_guard,
        })
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

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
        // The verified descriptor remains live through spawn. Unix Command still resolves the
        // pathname again; hostile same-user namespace replacement remains the documented ceiling.
        Ok(LaunchGuards { _file: file })
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, expected);
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
        thread,
        time::Duration,
    };

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
        let error = launch_as_linux_user(
            Path::new("/bin/true"),
            Path::new("/"),
            0,
            1000,
            &[1000],
            &[],
        )
        .unwrap_err();
        assert_eq!(error.kind(), PortErrorKind::Permission);
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
        let _guards = verify_entrypoint(&fixture.installed, &fixture.file).unwrap();

        assert!(
            OpenOptions::new()
                .write(true)
                .open(&fixture.installed)
                .is_err()
        );
        assert!(fs::remove_file(&fixture.installed).is_err());
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
