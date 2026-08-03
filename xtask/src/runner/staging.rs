use std::{
    ffi::OsString,
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, copy},
    path::{Component, Path, PathBuf},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

const MAX_FRONTEND_ENTRIES: usize = 4_096;
const MAX_FRONTEND_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FRONTEND_PATH_BYTES: usize = 4_096;

pub(super) fn checked_input(path: &Path, label: &str) -> Result<PathBuf, String> {
    require_regular_file(path, label)?;
    fs::canonicalize(path).map_err(|error| {
        format!(
            "could not canonicalize {label} `{}`: {error}",
            path.display()
        )
    })
}

pub(super) fn require_only_file(directory: &Path, filename: &str) -> Result<(), String> {
    require_real_directory(directory, "packaged resource directory")?;
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("could not read `{}`: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("could not read a packaged resource entry: {error}"))?;
    if entries.len() != 1 || entries[0].file_name() != filename {
        return Err(format!(
            "packaged resource directory `{}` must contain only `{filename}`",
            directory.display()
        ));
    }
    require_regular_file(&directory.join(filename), "packaged resource")
}

pub(super) fn require_only_entries(
    directory: &Path,
    expected: &[&str],
    label: &str,
) -> Result<(), String> {
    require_real_directory(directory, label)?;
    let mut actual = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("could not read {label} `{}`: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("could not read {label} entry: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("could not inspect {label} entry: {error}"))?;
        if is_reparse_or_symlink(&metadata) {
            return Err(format!("{label} `{}` contains a link", directory.display()));
        }
        actual.push(entry.file_name());
    }
    actual.sort();
    let mut expected = expected.iter().map(OsString::from).collect::<Vec<_>>();
    expected.sort();
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} `{}` does not contain exactly the expected entries",
            directory.display()
        ))
    }
}

pub(super) fn copy_file(source: &Path, destination: &Path) -> Result<(), String> {
    let mut source_file = File::open(source)
        .map_err(|error| format!("could not open `{}`: {error}", source.display()))?;
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            format!(
                "could not create `{}` without overwriting it: {error}",
                destination.display()
            )
        })?;
    copy(&mut source_file, &mut destination_file).map_err(|error| {
        format!(
            "could not copy `{}` to `{}`: {error}",
            source.display(),
            destination.display()
        )
    })?;
    require_regular_file(destination, "staged file")
}

pub(super) fn sha256_file(path: &Path) -> Result<[u8; 32], String> {
    let mut file = File::open(path)
        .map_err(|error| format!("could not hash `{}`: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("could not hash `{}`: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[derive(Debug)]
struct FrontendEntry {
    relative: String,
    path: PathBuf,
    directory: bool,
    bytes: u64,
}

pub(super) fn hash_frontend_tree(root: &Path) -> Result<[u8; 32], String> {
    require_real_directory(root, "frontend build output")?;
    let mut entries = Vec::new();
    let mut total_bytes = 0_u64;
    collect_frontend_tree(root, root, &mut entries, &mut total_bytes)?;
    if entries.is_empty() {
        return Err("frontend build output is empty".into());
    }
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));

    let mut hasher = Sha256::new();
    hasher.update(b"luxury-frontend-tree-v1\0");
    for entry in entries {
        hasher.update(if entry.directory { b"d" } else { b"f" });
        let relative = entry.relative.as_bytes();
        let relative_len = u32::try_from(relative.len())
            .map_err(|_| "frontend path is too long to hash".to_owned())?;
        hasher.update(relative_len.to_le_bytes());
        hasher.update(relative);
        if !entry.directory {
            hasher.update(entry.bytes.to_le_bytes());
            let mut file = File::open(&entry.path).map_err(|error| {
                format!(
                    "could not hash frontend file `{}`: {error}",
                    entry.path.display()
                )
            })?;
            let mut remaining = entry.bytes;
            let mut buffer = [0_u8; 64 * 1024];
            while remaining != 0 {
                let limit = usize::try_from(remaining.min(buffer.len() as u64))
                    .expect("bounded read length fits usize");
                let read = file.read(&mut buffer[..limit]).map_err(|error| {
                    format!(
                        "could not hash frontend file `{}`: {error}",
                        entry.path.display()
                    )
                })?;
                if read == 0 {
                    return Err(format!(
                        "frontend file `{}` changed while it was hashed",
                        entry.path.display()
                    ));
                }
                hasher.update(&buffer[..read]);
                remaining -= read as u64;
            }
            let mut extra = [0_u8; 1];
            if file.read(&mut extra).map_err(|error| {
                format!(
                    "could not finish hashing frontend file `{}`: {error}",
                    entry.path.display()
                )
            })? != 0
            {
                return Err(format!(
                    "frontend file `{}` changed while it was hashed",
                    entry.path.display()
                ));
            }
        }
    }
    Ok(hasher.finalize().into())
}

fn collect_frontend_tree(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<FrontendEntry>,
    total_bytes: &mut u64,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "could not read frontend tree `{}`: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| format!("could not read frontend entry: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "could not inspect frontend entry `{}`: {error}",
                path.display()
            )
        })?;
        if is_reparse_or_symlink(&metadata) {
            return Err(format!(
                "frontend build output `{}` contains a link",
                path.display()
            ));
        }
        let relative_path = path
            .strip_prefix(root)
            .map_err(|_| "frontend entry escaped its root".to_owned())?;
        let relative = portable_relative_path(relative_path)?;
        let directory_entry = metadata.is_dir();
        if !directory_entry && !metadata.is_file() {
            return Err(format!(
                "frontend entry `{}` is not a regular file or directory",
                path.display()
            ));
        }
        let bytes = if directory_entry { 0 } else { metadata.len() };
        *total_bytes = total_bytes
            .checked_add(bytes)
            .filter(|bytes| *bytes <= MAX_FRONTEND_BYTES)
            .ok_or_else(|| format!("frontend build output exceeds {MAX_FRONTEND_BYTES} bytes"))?;
        entries.push(FrontendEntry {
            relative,
            path: path.clone(),
            directory: directory_entry,
            bytes,
        });
        if entries.len() > MAX_FRONTEND_ENTRIES {
            return Err(format!(
                "frontend build output exceeds {MAX_FRONTEND_ENTRIES} entries"
            ));
        }
        if directory_entry {
            collect_frontend_tree(root, &path, entries, total_bytes)?;
        }
    }
    Ok(())
}

fn portable_relative_path(path: &Path) -> Result<String, String> {
    let mut output = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err("frontend tree contains a non-portable path".into());
        };
        let component = component
            .to_str()
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
            .ok_or_else(|| "frontend tree contains a non-portable path".to_owned())?;
        if !output.is_empty() {
            output.push('/');
        }
        output.push_str(component);
        if output.len() > MAX_FRONTEND_PATH_BYTES {
            return Err(format!(
                "frontend path exceeds {MAX_FRONTEND_PATH_BYTES} bytes"
            ));
        }
    }
    if output.is_empty() {
        Err("frontend tree contains an empty path".into())
    } else {
        Ok(output)
    }
}

pub(super) fn require_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {label} `{}`: {error}", path.display()))?;
    if is_reparse_or_symlink(&metadata) || !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "{label} `{}` must be a non-empty regular file, not a link",
            path.display()
        ));
    }
    Ok(())
}

fn require_real_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect {label} `{}`: {error}", path.display()))?;
    if is_reparse_or_symlink(&metadata) || !metadata.is_dir() {
        return Err(format!(
            "{label} `{}` must be a real directory",
            path.display()
        ));
    }
    Ok(())
}

pub(super) fn ensure_real_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => require_real_directory(path, "artifact directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(path)
            .map_err(|error| format!("could not create `{}`: {error}", path.display())),
        Err(error) => Err(format!("could not inspect `{}`: {error}", path.display())),
    }
}

pub(super) fn require_missing(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not inspect {label} `{}`: {error}",
            path.display()
        )),
        Ok(_) => Err(format!(
            "{label} `{}` already exists; refusing to overwrite it",
            path.display()
        )),
    }
}

fn is_reparse_or_symlink(metadata: &Metadata) -> bool {
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

#[cfg(unix)]
pub(super) fn set_runner_permissions(
    launcher: &Path,
    backend: &Path,
    payload: Option<&Path>,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(launcher, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("could not set Tauri launcher permissions: {error}"))?;
    fs::set_permissions(backend, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("could not set backend permissions: {error}"))?;
    if let Some(payload) = payload {
        fs::set_permissions(payload, fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("could not set payload permissions: {error}"))?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn set_runner_permissions(_: &Path, _: &Path, _: Option<&Path>) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
pub(super) fn publish_directory_no_clobber(
    source: &Path,
    destination: &Path,
) -> Result<(), String> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        format!(
            "could not publish `{}` without overwriting `{}`: {error}",
            source.display(),
            destination.display()
        )
    })
}

#[cfg(windows)]
pub(super) fn publish_directory_no_clobber(
    source: &Path,
    destination: &Path,
) -> Result<(), String> {
    retry_transient_io(|| fs::rename(source, destination)).map_err(|error| {
        format!(
            "could not publish `{}` without overwriting `{}`: {error}",
            source.display(),
            destination.display()
        )
    })
}

#[cfg(unix)]
pub(super) fn require_executable(path: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .map_err(|error| format!("could not inspect {label} permissions: {error}"))?
        .permissions()
        .mode();
    if mode & 0o111 == 0 {
        Err(format!("{label} `{}` is not executable", path.display()))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
pub(super) fn require_executable(_: &Path, _: &str) -> Result<(), String> {
    Ok(())
}

pub(super) struct WorkDirectory {
    pub path: PathBuf,
}

pub(super) fn retry_transient_io(
    mut operation: impl FnMut() -> std::io::Result<()>,
) -> std::io::Result<()> {
    const ATTEMPTS: usize = 20;
    for attempt in 0..ATTEMPTS {
        match operation() {
            Ok(()) => return Ok(()),
            Err(error)
                if cfg!(windows)
                    && error.kind() == std::io::ErrorKind::PermissionDenied
                    && attempt + 1 < ATTEMPTS =>
            {
                thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the final retry returns")
}

impl WorkDirectory {
    pub(super) fn new(parent: &Path) -> Result<Self, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
            .as_nanos();
        for attempt in 0..16_u8 {
            let path = parent.join(format!(
                ".luxury-assemble-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "could not create fresh assembly directory `{}`: {error}",
                        path.display()
                    ));
                }
            }
        }
        Err("could not allocate a fresh assembly directory".into())
    }

    pub(super) fn cleanup(mut self) -> Result<(), String> {
        let path = std::mem::take(&mut self.path);
        retry_transient_io(|| fs::remove_dir_all(&path)).map_err(|error| {
            format!(
                "could not remove work directory `{}`: {error}",
                path.display()
            )
        })
    }
}

impl Drop for WorkDirectory {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = retry_transient_io(|| fs::remove_dir_all(&self.path));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn retry_does_not_hide_non_transient_errors() {
        let attempts = Cell::new(0);
        let error = retry_transient_io(|| {
            attempts.set(attempts.get() + 1);
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
        })
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(attempts.get(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn retry_accepts_a_bounded_windows_handle_lag() {
        let attempts = Cell::new(0);
        retry_transient_io(|| {
            attempts.set(attempts.get() + 1);
            if attempts.get() < 3 {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "scanner still holds the file",
                ))
            } else {
                Ok(())
            }
        })
        .unwrap();

        assert_eq!(attempts.get(), 3);
    }

    #[cfg(windows)]
    #[test]
    fn retry_stops_after_the_windows_handle_lag_budget() {
        let attempts = Cell::new(0);
        let error = retry_transient_io(|| {
            attempts.set(attempts.get() + 1);
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "scanner never released the file",
            ))
        })
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(attempts.get(), 20);
    }

    #[test]
    fn copy_file_refuses_to_overwrite_existing_bytes() {
        let work = WorkDirectory::new(&std::env::temp_dir()).unwrap();
        let source = work.path.join("source");
        let destination = work.path.join("destination");
        fs::write(&source, b"first").unwrap();
        copy_file(&source, &destination).unwrap();

        fs::write(&source, b"second").unwrap();
        assert!(copy_file(&source, &destination).is_err());
        assert_eq!(fs::read(destination).unwrap(), b"first");
    }

    #[test]
    fn frontend_tree_hash_is_deterministic_and_content_bound() {
        let work = WorkDirectory::new(&std::env::temp_dir()).unwrap();
        let frontend = work.path.join("frontend");
        let assets = frontend.join("assets");
        fs::create_dir_all(&assets).unwrap();
        fs::write(frontend.join("index.html"), b"first").unwrap();
        fs::write(assets.join("app.js"), b"script").unwrap();

        let first = hash_frontend_tree(&frontend).unwrap();
        assert_eq!(hash_frontend_tree(&frontend).unwrap(), first);
        fs::write(assets.join("app.js"), b"SCRIPT").unwrap();
        assert_ne!(hash_frontend_tree(&frontend).unwrap(), first);
    }

    #[test]
    fn frontend_tree_hash_rejects_an_empty_tree() {
        let work = WorkDirectory::new(&std::env::temp_dir()).unwrap();
        let frontend = work.path.join("frontend");
        fs::create_dir(&frontend).unwrap();
        assert!(hash_frontend_tree(&frontend).is_err());
    }

    #[test]
    fn portable_publication_is_atomic_and_no_clobber() {
        let work = WorkDirectory::new(&std::env::temp_dir()).unwrap();
        let source = work.path.join("source");
        let destination = work.path.join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("marker"), b"first").unwrap();

        publish_directory_no_clobber(&source, &destination).unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(destination.join("marker")).unwrap(), b"first");

        let second = work.path.join("second");
        fs::create_dir(&second).unwrap();
        fs::write(second.join("marker"), b"second").unwrap();
        assert!(publish_directory_no_clobber(&second, &destination).is_err());
        assert_eq!(fs::read(destination.join("marker")).unwrap(), b"first");
        assert_eq!(fs::read(second.join("marker")).unwrap(), b"second");
    }

    #[test]
    fn explicit_cleanup_removes_the_work_directory() {
        let work = WorkDirectory::new(&std::env::temp_dir()).unwrap();
        let path = work.path.clone();
        work.cleanup().unwrap();
        assert!(!path.exists());
    }
}
