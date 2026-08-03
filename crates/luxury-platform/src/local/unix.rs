use std::{
    io,
    path::{Component, Path, PathBuf},
};

use rustix::{
    fd::OwnedFd,
    fs::{AtFlags, FileType, Mode, OFlags, RenameFlags},
};

struct OpenedPath {
    parent: OwnedFd,
    name: PathBuf,
}

#[must_use = "a successful rename is not durable until its opened parents are synced"]
#[derive(Debug)]
pub(super) struct RenameDurability {
    source_parent: OwnedFd,
    destination_parent: OwnedFd,
}

impl RenameDurability {
    pub(super) fn sync(self) -> io::Result<()> {
        sync_directory(&self.destination_parent)?;
        sync_directory(&self.source_parent)
    }
}

pub(super) fn rename_noreplace(source: &Path, destination: &Path) -> io::Result<RenameDurability> {
    let (source_parent, source_name) = path_parts(source)?;
    let (destination_parent, destination_name) = path_parts(destination)?;
    let source_parent_fd = open_directory(&source_parent)?;
    let destination_parent_fd = if source_parent == destination_parent {
        rustix::io::fcntl_dupfd_cloexec(&source_parent_fd, 0).map_err(io::Error::from)?
    } else {
        open_directory(&destination_parent)?
    };
    rename_opened(
        OpenedPath {
            parent: source_parent_fd,
            name: source_name,
        },
        OpenedPath {
            parent: destination_parent_fd,
            name: destination_name,
        },
    )
}

pub(super) fn remove_file(path: &Path) -> io::Result<()> {
    unlink_opened(&open_parent(path)?, AtFlags::empty(), FileType::RegularFile)
}

pub(super) fn remove_directory(path: &Path) -> io::Result<()> {
    unlink_opened(&open_parent(path)?, AtFlags::REMOVEDIR, FileType::Directory)
}

fn rename_opened(source: OpenedPath, destination: OpenedPath) -> io::Result<RenameDurability> {
    rustix::fs::renameat_with(
        &source.parent,
        &source.name,
        &destination.parent,
        &destination.name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        let error = io::Error::from(error);
        if matches!(
            error.kind(),
            io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
        ) {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "filesystem does not support atomic no-clobber rename",
            )
        } else {
            error
        }
    })?;
    Ok(RenameDurability {
        source_parent: source.parent,
        destination_parent: destination.parent,
    })
}

fn unlink_opened(path: &OpenedPath, flags: AtFlags, expected: FileType) -> io::Result<()> {
    let metadata = rustix::fs::statat(&path.parent, &path.name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)?;
    if FileType::from_raw_mode(metadata.st_mode) != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unlink target changed type",
        ));
    }
    rustix::fs::unlinkat(&path.parent, &path.name, flags).map_err(io::Error::from)?;
    sync_directory(&path.parent)
}

fn sync_directory(directory: &OwnedFd) -> io::Result<()> {
    loop {
        match sync_directory_once(directory) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(
                rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::NOTTY,
            ) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "filesystem does not support durable directory sync",
                ));
            }
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

#[cfg(target_os = "linux")]
fn sync_directory_once(directory: &OwnedFd) -> rustix::io::Result<()> {
    rustix::fs::fsync(directory)
}

#[cfg(target_os = "macos")]
fn sync_directory_once(directory: &OwnedFd) -> rustix::io::Result<()> {
    rustix::fs::fcntl_fullfsync(directory)
}

fn open_parent(path: &Path) -> io::Result<OpenedPath> {
    let (parent, name) = path_parts(path)?;
    Ok(OpenedPath {
        parent: open_directory(&parent)?,
        name,
    })
}

fn path_parts(path: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let absolute = std::path::absolute(path)?;
    let name = absolute
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no final name"))?
        .into();
    let parent = absolute
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory"))?
        .to_path_buf();
    Ok((parent, name))
}

fn open_directory(path: &Path) -> io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = rustix::fs::open("/", flags, Mode::empty()).map_err(io::Error::from)?;
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not rooted",
        ));
    }
    for component in components {
        match component {
            Component::Normal(name) => {
                directory = rustix::fs::openat(&directory, name, flags, Mode::empty())
                    .map_err(io::Error::from)?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path contains an unsupported directory component",
                ));
            }
        }
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn rename_rejects_a_symlinked_parent() {
        let temp = tempdir().unwrap();
        let source_parent = temp.path().join("source");
        let external = temp.path().join("external");
        let root = temp.path().join("root");
        fs::create_dir(&source_parent).unwrap();
        fs::create_dir(&external).unwrap();
        fs::create_dir(external.join("nested")).unwrap();
        fs::create_dir(&root).unwrap();
        let source = source_parent.join("owned.bin");
        fs::write(&source, b"owned").unwrap();
        symlink(&external, root.join("linked")).unwrap();

        assert!(rename_noreplace(&source, &root.join("linked/nested/owned.bin")).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"owned");
        assert!(!external.join("nested/owned.bin").exists());
    }

    #[test]
    fn same_parent_rename_token_holds_one_directory_identity() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("source.bin");
        let destination = temp.path().join("destination.bin");
        fs::write(&source, b"owned").unwrap();

        let durability = rename_noreplace(&source, &destination).unwrap();
        let source_parent = rustix::fs::fstat(&durability.source_parent).unwrap();
        let destination_parent = rustix::fs::fstat(&durability.destination_parent).unwrap();

        assert_eq!(
            (source_parent.st_dev, source_parent.st_ino),
            (destination_parent.st_dev, destination_parent.st_ino)
        );
        assert!(
            rustix::io::fcntl_getfd(&durability.source_parent)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(
            rustix::io::fcntl_getfd(&durability.destination_parent)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        durability.sync().unwrap();
        assert_eq!(fs::read(destination).unwrap(), b"owned");
    }

    #[test]
    fn opened_parents_remain_bound_after_path_replacement() {
        let temp = tempdir().unwrap();
        let source_parent = temp.path().join("source");
        let destination_parent = temp.path().join("destination");
        fs::create_dir(&source_parent).unwrap();
        fs::create_dir(&destination_parent).unwrap();
        let source = source_parent.join("owned.bin");
        let destination = destination_parent.join("owned.bin");
        fs::write(&source, b"owned").unwrap();
        let opened_source = open_parent(&source).unwrap();
        let opened_destination = open_parent(&destination).unwrap();

        let moved_source = temp.path().join("source-moved");
        let moved_destination = temp.path().join("destination-moved");
        let external = temp.path().join("external");
        fs::rename(&source_parent, &moved_source).unwrap();
        fs::rename(&destination_parent, &moved_destination).unwrap();
        fs::create_dir(&source_parent).unwrap();
        fs::create_dir(&external).unwrap();
        symlink(&external, &destination_parent).unwrap();
        fs::write(source_parent.join("owned.bin"), b"replacement").unwrap();

        let durability = rename_opened(opened_source, opened_destination).unwrap();
        fs::remove_file(&destination_parent).unwrap();
        fs::remove_dir(&external).unwrap();
        durability.sync().unwrap();

        assert!(!moved_source.join("owned.bin").exists());
        assert_eq!(
            fs::read(moved_destination.join("owned.bin")).unwrap(),
            b"owned"
        );
        assert_eq!(
            fs::read(source_parent.join("owned.bin")).unwrap(),
            b"replacement"
        );
        assert!(!external.join("owned.bin").exists());
    }

    #[test]
    fn relative_paths_resolve_from_the_process_directory() {
        let current = std::env::current_dir().unwrap();
        let temp = tempfile::Builder::new()
            .prefix("luxury-relative-rename-")
            .tempdir_in(&current)
            .unwrap();
        let relative = temp.path().strip_prefix(&current).unwrap();
        let source_parent = relative.join("source");
        fs::create_dir(temp.path().join("source")).unwrap();
        fs::write(temp.path().join("source/owned.bin"), b"owned").unwrap();

        let opened = open_parent(&source_parent.join("owned.bin")).unwrap();
        let metadata =
            rustix::fs::statat(&opened.parent, &opened.name, AtFlags::SYMLINK_NOFOLLOW).unwrap();

        assert_eq!(
            FileType::from_raw_mode(metadata.st_mode),
            FileType::RegularFile
        );
    }

    #[test]
    fn opened_parent_keeps_file_removal_in_the_original_tree() {
        let temp = tempdir().unwrap();
        let parent = temp.path().join("parent");
        fs::create_dir(&parent).unwrap();
        let owned = parent.join("owned.bin");
        fs::write(&owned, b"owned").unwrap();
        let opened = open_parent(&owned).unwrap();

        let moved = temp.path().join("parent-moved");
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(parent.join("owned.bin"), b"replacement").unwrap();

        unlink_opened(&opened, AtFlags::empty(), FileType::RegularFile).unwrap();

        assert!(!moved.join("owned.bin").exists());
        assert_eq!(fs::read(parent.join("owned.bin")).unwrap(), b"replacement");
    }

    #[test]
    fn remove_directory_rejects_a_symlinked_intermediate_parent() {
        let temp = tempdir().unwrap();
        let external = temp.path().join("external");
        let root = temp.path().join("root");
        fs::create_dir(&external).unwrap();
        fs::create_dir(external.join("empty")).unwrap();
        fs::create_dir(&root).unwrap();
        symlink(&external, root.join("linked")).unwrap();

        assert!(remove_directory(&root.join("linked/empty")).is_err());
        assert!(external.join("empty").is_dir());
    }

    #[test]
    fn remove_file_rejects_a_symlink_leaf_without_touching_its_target() {
        let temp = tempdir().unwrap();
        let external = temp.path().join("external.bin");
        let linked = temp.path().join("linked.bin");
        fs::write(&external, b"external").unwrap();
        symlink(&external, &linked).unwrap();

        assert!(remove_file(&linked).is_err());
        assert!(linked.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&external).unwrap(), b"external");
    }
}
