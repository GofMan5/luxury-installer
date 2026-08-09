//! Windows-native shortcut encoding and trusted Known Folder resolution.
//!
//! This module deliberately knows nothing about install transactions. It produces one
//! validated `.lnk` in caller-owned staging and reports the exact bytes that a later
//! transaction slice may publish and own.

use std::{
    ffi::OsString,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};

use luxury_engine::{PortError, PortErrorKind};
use luxury_spec::{PackageId, Sha256Digest};
use sha2::{Digest, Sha256};
use windows::{
    Win32::{
        Foundation::RPC_E_CHANGED_MODE,
        Storage::FileSystem::WIN32_FIND_DATAW,
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
            CoTaskMemFree, CoUninitialize, IPersistFile, STGM_READ, STGM_SHARE_DENY_WRITE,
        },
        UI::Shell::{
            FOLDERID_Desktop, FOLDERID_Programs, IShellLinkW, KF_FLAG_DEFAULT,
            SHGetKnownFolderPath, SLGP_RAWPATH, ShellLink,
        },
    },
    core::{Interface, PCWSTR},
};

const MAX_SHORTCUT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SHELL_PATH_UNITS: usize = 32_768;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowsShortcutLocation {
    ApplicationMenu,
    Desktop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WindowsShortcutRoots {
    application_menu: PathBuf,
    desktop: PathBuf,
}

impl WindowsShortcutRoots {
    /// Resolve the current user's two trusted shell roots. Package data never enters this path.
    pub(super) fn resolve() -> Result<Self, PortError> {
        Ok(Self {
            application_menu: known_folder(&FOLDERID_Programs)?,
            desktop: known_folder(&FOLDERID_Desktop)?,
        })
    }

    /// Explicit roots exist for native tests and later privileged composition only.
    pub(super) fn explicit(
        application_menu: impl Into<PathBuf>,
        desktop: impl Into<PathBuf>,
    ) -> Result<Self, PortError> {
        let roots = Self {
            application_menu: application_menu.into(),
            desktop: desktop.into(),
        };
        require_absolute(&roots.application_menu, "application-menu shortcut root")?;
        require_absolute(&roots.desktop, "desktop shortcut root")?;
        Ok(roots)
    }

    pub(super) fn root(&self, location: WindowsShortcutLocation) -> &Path {
        match location {
            WindowsShortcutLocation::ApplicationMenu => &self.application_menu,
            WindowsShortcutLocation::Desktop => &self.desktop,
        }
    }

    pub(super) fn destination(
        &self,
        location: WindowsShortcutLocation,
        package_id: &PackageId,
    ) -> PathBuf {
        self.root(location)
            .join(format!("{}.lnk", package_id.as_str()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EncodedWindowsShortcut {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: Sha256Digest,
}

/// Create and independently reload one staged link. The destination must not exist.
pub(super) fn create_staged_shortcut(
    staging: &Path,
    target: &Path,
    working_directory: &Path,
) -> Result<EncodedWindowsShortcut, PortError> {
    validate_output_path(staging)?;
    validate_target(target)?;
    validate_working_directory(working_directory)?;

    let com = ComApartment::initialize()?;
    let shell_link = create_shell_link()?;
    let target_wide = wide_path(target, "shortcut target")?;
    let working_wide = wide_path(working_directory, "shortcut working directory")?;
    let staging_wide = wide_path(staging, "shortcut staging path")?;
    unsafe {
        // SAFETY: all strings are valid, NUL-terminated UTF-16 and remain alive for each call.
        shell_link
            .SetPath(PCWSTR(target_wide.as_ptr()))
            .map_err(|error| com_error("setting shortcut target", error))?;
        shell_link
            .SetWorkingDirectory(PCWSTR(working_wide.as_ptr()))
            .map_err(|error| com_error("setting shortcut working directory", error))?;
        shell_link
            .SetArguments(windows::core::w!(""))
            .map_err(|error| com_error("clearing shortcut arguments", error))?;
        shell_link
            .SetIconLocation(PCWSTR(target_wide.as_ptr()), 0)
            .map_err(|error| com_error("setting shortcut icon", error))?;
        let persist: IPersistFile = shell_link
            .cast()
            .map_err(|error| com_error("opening shortcut persistence interface", error))?;
        persist
            .Save(PCWSTR(staging_wide.as_ptr()), true)
            .map_err(|error| com_error("saving staged shortcut", error))?;
    }
    drop(shell_link);
    drop(com);

    let mut file = verify_loaded_shortcut(staging, target, working_directory)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("seeking staged shortcut", staging, source))?;
    let (size, sha256) = hash_bounded(&mut file, staging)?;
    Ok(EncodedWindowsShortcut {
        path: staging.to_path_buf(),
        size,
        sha256,
    })
}

fn create_shell_link() -> Result<IShellLinkW, PortError> {
    unsafe {
        // SAFETY: ShellLink is an in-process system COM class and the requested interface is typed.
        CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| com_error("creating shell-link object", error))
    }
}

fn verify_loaded_shortcut(
    path: &Path,
    expected_target: &Path,
    expected_working_directory: &Path,
) -> Result<File, PortError> {
    // Pin the complete parent chain and final single-link file *before* COM opens by
    // pathname. The leaf guard denies write/delete sharing, so a successful open both
    // excludes an already-compatible mutator and prevents replacement or byte mutation
    // through semantic verification and hashing. COM and the returned handle therefore
    // necessarily observe the same object and bytes.
    let (absolute, _parent_guards) = super::windows::open_real_parent_chain(path)
        .map_err(|source| io_error("opening shortcut parent chain", path, source))?;
    let file = super::windows::open_immutable_read_nofollow(&absolute)
        .map_err(|source| io_error("pinning staged shortcut", &absolute, source))?;
    super::transaction::validate_open_regular(&absolute, &file, false).map_err(|error| {
        PortError::with_kind(
            PortErrorKind::Integrity,
            format!("shortcut path is not a single-link regular file: {error}"),
        )
    })?;
    let _com = ComApartment::initialize()?;
    let shell_link = create_shell_link()?;
    let persist: IPersistFile = shell_link
        .cast()
        .map_err(|error| com_error("opening staged shortcut persistence interface", error))?;
    let path_wide = wide_path(&absolute, "shortcut staging path")?;
    unsafe {
        // SAFETY: Load reads the caller-owned regular file. Resolve is intentionally never called.
        persist
            .Load(
                PCWSTR(path_wide.as_ptr()),
                STGM_READ | STGM_SHARE_DENY_WRITE,
            )
            .map_err(|error| com_error("loading staged shortcut", error))?;
    }

    let mut target = vec![0_u16; MAX_SHELL_PATH_UNITS];
    let mut find_data = WIN32_FIND_DATAW::default();
    let mut working = vec![0_u16; MAX_SHELL_PATH_UNITS];
    let mut arguments = vec![0_u16; MAX_SHELL_PATH_UNITS];
    let mut icon = vec![0_u16; MAX_SHELL_PATH_UNITS];
    let mut icon_index = i32::MIN;
    unsafe {
        // SAFETY: each mutable buffer has the advertised capacity for the typed COM call.
        shell_link
            .GetPath(&mut target, &mut find_data, SLGP_RAWPATH.0 as u32)
            .map_err(|error| com_error("reading staged shortcut target", error))?;
        shell_link
            .GetWorkingDirectory(&mut working)
            .map_err(|error| com_error("reading staged shortcut working directory", error))?;
        shell_link
            .GetArguments(&mut arguments)
            .map_err(|error| com_error("reading staged shortcut arguments", error))?;
        shell_link
            .GetIconLocation(&mut icon, &mut icon_index)
            .map_err(|error| com_error("reading staged shortcut icon", error))?;
    }

    let target = path_from_buffer(&target, "shortcut target")?;
    let working = path_from_buffer(&working, "shortcut working directory")?;
    let icon = path_from_buffer(&icon, "shortcut icon")?;
    if target != expected_target
        || working != expected_working_directory
        || !empty_buffer(&arguments)
        || icon != expected_target
        || icon_index != 0
    {
        return Err(PortError::with_kind(
            PortErrorKind::Integrity,
            "staged shortcut semantics do not match the requested target",
        ));
    }
    Ok(file)
}

fn known_folder(id: &windows::core::GUID) -> Result<PathBuf, PortError> {
    let raw = unsafe {
        // SAFETY: `id` is one of the two static Known Folder identifiers above.
        SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None)
            .map_err(|error| com_error("resolving Windows shortcut root", error))?
    };
    if raw.is_null() {
        return Err(state_error("Windows returned an empty shortcut root"));
    }
    let length = unsafe { raw.len() };
    let result = if length == 0 || length >= MAX_SHELL_PATH_UNITS {
        Err(state_error("Windows returned an invalid shortcut root"))
    } else {
        let path = PathBuf::from(OsString::from_wide(unsafe { raw.as_wide() }));
        require_absolute(&path, "Windows shortcut root").map(|()| path)
    };
    unsafe {
        // SAFETY: SHGetKnownFolderPath returned task-allocated memory.
        CoTaskMemFree(Some(raw.as_ptr().cast()));
    }
    result
}

fn validate_output_path(path: &Path) -> Result<(), PortError> {
    require_absolute(path, "shortcut staging path")?;
    if path.extension().and_then(|value| value.to_str()) != Some("lnk") {
        return Err(state_error("shortcut staging path must end in `.lnk`"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| state_error("shortcut staging path has no parent"))?;
    require_safe_directory(parent, "shortcut staging directory")?;
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspecting shortcut staging path", path, source)),
        Ok(_) => Err(PortError::with_kind(
            PortErrorKind::Collision,
            "shortcut staging path already exists",
        )),
    }
}

fn validate_target(path: &Path) -> Result<(), PortError> {
    require_absolute(path, "shortcut target")?;
    let file = super::windows::open_pinned_nofollow(path)
        .map_err(|source| io_error("opening shortcut target", path, source))?;
    super::transaction::validate_open_regular(path, &file, false).map_err(|error| {
        PortError::with_kind(
            PortErrorKind::Integrity,
            format!("shortcut target is not a single-link regular file: {error}"),
        )
    })?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("reading shortcut target metadata", path, source))?;
    if metadata.len() == 0 {
        return Err(PortError::with_kind(
            PortErrorKind::Integrity,
            "shortcut target is empty",
        ));
    }
    Ok(())
}

fn validate_working_directory(path: &Path) -> Result<(), PortError> {
    require_absolute(path, "shortcut working directory")?;
    require_safe_directory(path, "shortcut working directory")
}

fn require_safe_directory(path: &Path, label: &str) -> Result<(), PortError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error(&format!("inspecting {label}"), path, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(PortError::with_kind(
            PortErrorKind::Integrity,
            format!("{label} is not a real directory"),
        ));
    }
    Ok(())
}

fn hash_bounded(file: &mut File, path: &Path) -> Result<(u64, Sha256Digest), PortError> {
    let length = file
        .metadata()
        .map_err(|source| io_error("reading staged shortcut metadata", path, source))?
        .len();
    if length == 0 || length > MAX_SHORTCUT_BYTES {
        return Err(PortError::with_kind(
            PortErrorKind::Integrity,
            "staged shortcut has an invalid size",
        ));
    }
    let mut hasher = Sha256::new();
    let mut remaining = length;
    let mut buffer = [0_u8; 16 * 1024];
    while remaining > 0 {
        let limit = remaining.min(buffer.len() as u64) as usize;
        let read = file
            .read(&mut buffer[..limit])
            .map_err(|source| io_error("hashing staged shortcut", path, source))?;
        if read == 0 {
            return Err(state_error("staged shortcut changed while hashing"));
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    let digest = hex::encode(hasher.finalize());
    Ok((
        length,
        Sha256Digest::parse(digest).expect("SHA-256 encoder emits a valid digest"),
    ))
}

fn wide_path(path: &Path, label: &str) -> Result<Vec<u16>, PortError> {
    let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if value.is_empty() || value.len() >= MAX_SHELL_PATH_UNITS || value.contains(&0) {
        return Err(state_error(format!("{label} is not a valid Windows path")));
    }
    value.push(0);
    Ok(value)
}

fn path_from_buffer(buffer: &[u16], label: &str) -> Result<PathBuf, PortError> {
    let Some(end) = buffer.iter().position(|unit| *unit == 0) else {
        return Err(state_error(format!("{label} exceeds the native buffer")));
    };
    if end == 0 {
        return Err(state_error(format!("{label} is empty")));
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..end])))
}

fn empty_buffer(buffer: &[u16]) -> bool {
    buffer.first() == Some(&0)
}

fn require_absolute(path: &Path, label: &str) -> Result<(), PortError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(state_error(format!("{label} must be absolute")))
    }
}

struct ComApartment(bool);

impl ComApartment {
    fn initialize() -> Result<Self, PortError> {
        let status = unsafe {
            // SAFETY: initializes COM for the current thread without passing reserved data.
            CoInitializeEx(None, COINIT_APARTMENTTHREADED)
        };
        if status == RPC_E_CHANGED_MODE {
            return Err(PortError::with_kind(
                PortErrorKind::Unsupported,
                "shortcut codec requires an STA-compatible thread",
            ));
        }
        status
            .ok()
            .map_err(|error| com_error("initializing shortcut COM apartment", error))?;
        Ok(Self(true))
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe {
                // SAFETY: balances this instance's successful CoInitializeEx call.
                CoUninitialize();
            }
        }
    }
}

fn com_error(action: &str, source: windows::core::Error) -> PortError {
    PortError::with_kind(PortErrorKind::Io, format!("{action} failed: {source}"))
}

fn io_error(action: &str, path: &Path, source: std::io::Error) -> PortError {
    PortError::with_kind(
        PortErrorKind::Io,
        format!("{action} `{}` failed: {source}", path.display()),
    )
}

fn state_error(message: impl Into<String>) -> PortError {
    PortError::with_kind(PortErrorKind::State, message)
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};

    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    use super::*;

    #[test]
    fn explicit_roots_keep_tests_out_of_the_real_profile() {
        let temp = tempfile::tempdir().unwrap();
        let menu = temp.path().join("menu");
        let desktop = temp.path().join("desktop");
        fs::create_dir_all(&menu).unwrap();
        fs::create_dir_all(&desktop).unwrap();
        let roots = WindowsShortcutRoots::explicit(&menu, &desktop).unwrap();
        let package_id = PackageId::parse("dev.luxury.demo").unwrap();
        assert_eq!(
            roots.destination(WindowsShortcutLocation::ApplicationMenu, &package_id),
            menu.join("dev.luxury.demo.lnk")
        );
        assert_eq!(
            roots.destination(WindowsShortcutLocation::Desktop, &package_id),
            desktop.join("dev.luxury.demo.lnk")
        );
    }

    #[test]
    fn codec_round_trips_exact_semantics_in_private_staging() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let target = std::env::current_exe().unwrap();
        let staging = root.join("dev.luxury.demo.lnk");

        let encoded = create_staged_shortcut(&staging, &target, &root).unwrap();
        assert_eq!(encoded.path, staging);
        assert!(encoded.size > 0);
        assert_eq!(fs::metadata(&encoded.path).unwrap().len(), encoded.size);
        drop(verify_loaded_shortcut(&encoded.path, &target, &root).unwrap());
    }

    #[test]
    fn immutable_guard_denies_write_and_replace_before_com_load() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let target = std::env::current_exe().unwrap();
        let staging = root.join("guarded.lnk");
        create_staged_shortcut(&staging, &target, &root).unwrap();

        let (absolute, parent_guards) =
            super::super::windows::open_real_parent_chain(&staging).unwrap();
        let guard = super::super::windows::open_immutable_read_nofollow(&absolute).unwrap();
        super::super::transaction::validate_open_regular(&absolute, &guard, false).unwrap();

        assert!(OpenOptions::new().write(true).open(&absolute).is_err());
        let replacement = root.join("replacement.lnk");
        fs::write(&replacement, b"different").unwrap();
        assert!(fs::rename(&replacement, &absolute).is_err());
        assert!(absolute.exists());
        assert!(replacement.exists());

        drop(guard);
        drop(parent_guards);
        assert!(
            OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&absolute)
                .is_ok()
        );
    }

    #[test]
    fn verifier_reads_a_readonly_shortcut_without_write_authority() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let target = std::env::current_exe().unwrap();
        let staging = root.join("readonly.lnk");
        create_staged_shortcut(&staging, &target, &root).unwrap();
        let mut permissions = fs::metadata(&staging).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&staging, permissions).unwrap();

        drop(verify_loaded_shortcut(&staging, &target, &root).unwrap());
    }

    #[test]
    fn verifier_rejects_a_hard_linked_shortcut() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let target = std::env::current_exe().unwrap();
        let staging = root.join("linked.lnk");
        create_staged_shortcut(&staging, &target, &root).unwrap();
        fs::hard_link(&staging, root.join("alias.lnk")).unwrap();

        assert_eq!(
            verify_loaded_shortcut(&staging, &target, &root)
                .unwrap_err()
                .kind(),
            PortErrorKind::Integrity
        );
    }

    #[test]
    fn codec_rejects_relative_inputs_and_existing_output() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let target = std::env::current_exe().unwrap();
        let staging = root.join("exists.lnk");
        fs::write(&staging, b"occupied").unwrap();

        assert_eq!(
            create_staged_shortcut(Path::new("relative.lnk"), &target, &root)
                .unwrap_err()
                .kind(),
            PortErrorKind::State
        );
        assert_eq!(
            create_staged_shortcut(&staging, &target, &root)
                .unwrap_err()
                .kind(),
            PortErrorKind::Collision
        );
    }

    #[test]
    fn production_known_folders_are_absolute_without_writing_them() {
        let roots = WindowsShortcutRoots::resolve().unwrap();
        assert!(
            roots
                .root(WindowsShortcutLocation::ApplicationMenu)
                .is_absolute()
        );
        assert!(roots.root(WindowsShortcutLocation::Desktop).is_absolute());
    }
}
