use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use flate2::{Compression, GzBuilder};
use tar::{Builder, EntryType, Header, HeaderMode};

const DIRECTORY_MODE: u32 = 0o755;
const FILE_MODE: u32 = 0o644;
const EXECUTABLE_MODE: u32 = 0o755;

pub(super) fn create(source: &Path) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("could not inspect portable artifact: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("portable artifact must be a real directory".into());
    }
    let parent = source
        .parent()
        .ok_or_else(|| "portable artifact has no parent directory".to_owned())?;
    let filename = source
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "portable artifact name is not valid Unicode".to_owned())?;
    let destination = parent.join(format!("{filename}.tar.gz"));
    let temporary = parent.join(format!(".{filename}.tar.gz.{}.tmp", std::process::id()));
    let mut temporary_created = false;
    let mut published = false;

    let result = (|| {
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("could not create portable archive temp file: {error}"))?;
        temporary_created = true;
        let gzip = GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(output, Compression::default());
        let mut archive = Builder::new(gzip);
        archive.mode(HeaderMode::Deterministic);
        append_directory(&mut archive, source, Path::new(filename))?;
        for entry in entries(source)? {
            let archive_path = Path::new(filename).join(&entry.relative);
            if entry.directory {
                append_directory(&mut archive, &entry.path, &archive_path)?;
            } else {
                append_file(&mut archive, &entry.path, &archive_path)?;
            }
        }
        archive
            .finish()
            .map_err(|error| format!("could not finish portable tar archive: {error}"))?;
        let gzip = archive
            .into_inner()
            .map_err(|error| format!("could not recover portable gzip writer: {error}"))?;
        let output = gzip
            .finish()
            .map_err(|error| format!("could not finish portable gzip archive: {error}"))?;
        output
            .sync_all()
            .map_err(|error| format!("could not sync portable archive: {error}"))?;
        drop(output);
        fs::hard_link(&temporary, &destination).map_err(|error| {
            format!("could not publish portable archive without overwriting: {error}")
        })?;
        published = true;
        fs::remove_file(&temporary)
            .map_err(|error| format!("could not remove portable archive temp file: {error}"))?;
        temporary_created = false;
        Ok(())
    })();

    if let Err(error) = result {
        if published {
            let _ = fs::remove_file(&destination);
        }
        if temporary_created {
            let _ = fs::remove_file(&temporary);
        }
        return Err(error);
    }
    Ok(destination)
}

struct ArchiveEntry {
    path: PathBuf,
    relative: PathBuf,
    directory: bool,
}

fn entries(root: &Path) -> Result<Vec<ArchiveEntry>, String> {
    let mut entries = Vec::new();
    let mut pending = vec![(root.to_path_buf(), PathBuf::new())];
    while let Some((directory, relative)) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("could not read portable artifact directory: {error}"))?
        {
            let entry = entry.map_err(|error| format!("could not read artifact entry: {error}"))?;
            let path = entry.path();
            let relative = relative.join(entry.file_name());
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("could not inspect artifact entry: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err("portable artifact archive refuses links".into());
            }
            let directory = metadata.is_dir();
            if directory {
                pending.push((path.clone(), relative.clone()));
            } else if !metadata.is_file() {
                return Err("portable artifact archive refuses special entries".into());
            }
            entries.push(ArchiveEntry {
                path,
                relative,
                directory,
            });
        }
    }
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(entries)
}

fn append_directory(
    archive: &mut Builder<flate2::write::GzEncoder<File>>,
    source: &Path,
    archive_path: &Path,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("could not inspect artifact directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("portable artifact directory changed while archiving".into());
    }
    let mut header = deterministic_header(EntryType::Directory, DIRECTORY_MODE, 0);
    archive
        .append_data(&mut header, archive_path, io::empty())
        .map_err(|error| format!("could not append artifact directory: {error}"))
}

fn append_file(
    archive: &mut Builder<flate2::write::GzEncoder<File>>,
    source: &Path,
    archive_path: &Path,
) -> Result<(), String> {
    let before = fs::symlink_metadata(source)
        .map_err(|error| format!("could not inspect artifact file: {error}"))?;
    if before.file_type().is_symlink() || !before.is_file() || before.nlink() != 1 {
        return Err("portable artifact file must be a single-link regular file".into());
    }
    let mut file =
        File::open(source).map_err(|error| format!("could not open artifact file: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("could not inspect opened artifact file: {error}"))?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.len() != before.len()
        || opened.nlink() != 1
    {
        return Err("portable artifact file changed before archiving".into());
    }
    let executable = opened.permissions().mode() & 0o111 != 0;
    let mode = if executable {
        EXECUTABLE_MODE
    } else {
        FILE_MODE
    };
    let mut header = deterministic_header(EntryType::Regular, mode, opened.len());
    archive
        .append_data(&mut header, archive_path, &mut file)
        .map_err(|error| format!("could not append artifact file: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("could not recheck archived file: {error}"))?;
    if after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != opened.len()
        || after.permissions().mode() & 0o777 != opened.permissions().mode() & 0o777
        || after.nlink() != 1
    {
        return Err("portable artifact file changed while archiving".into());
    }
    Ok(())
}

fn deterministic_header(entry_type: EntryType, mode: u32, size: u64) -> Header {
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(size);
    header.set_cksum();
    header
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Read, os::unix::fs::PermissionsExt};

    use flate2::read::GzDecoder;

    use super::*;

    #[test]
    fn archive_is_deterministic_preserves_executability_and_never_overwrites() {
        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("studio");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::create_dir_all(source.join("share")).unwrap();
        fs::write(source.join("bin/app"), b"executable").unwrap();
        fs::write(source.join("share/data.txt"), b"data").unwrap();
        fs::set_permissions(source.join("bin/app"), fs::Permissions::from_mode(0o755)).unwrap();

        let first = create(&source).unwrap();
        let first_bytes = fs::read(&first).unwrap();
        assert_eq!(&first_bytes[..2], &[0x1f, 0x8b]);
        assert_eq!(&first_bytes[4..8], &[0, 0, 0, 0]);
        assert_eq!(first_bytes[9], 255);
        assert!(create(&source).is_err());
        assert_eq!(fs::read(&first).unwrap(), first_bytes);

        fs::remove_file(&first).unwrap();
        let second = create(&source).unwrap();
        assert_eq!(fs::read(&second).unwrap(), first_bytes);

        let mut archive = tar::Archive::new(GzDecoder::new(first_bytes.as_slice()));
        let mut entries = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry
                .path()
                .unwrap()
                .to_string_lossy()
                .trim_end_matches('/')
                .to_owned();
            let header = entry.header().clone();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            entries.push((path, header.mode().unwrap(), header.mtime().unwrap(), bytes));
            assert_eq!(header.uid().unwrap(), 0);
            assert_eq!(header.gid().unwrap(), 0);
        }
        assert_eq!(
            entries,
            vec![
                ("studio".into(), 0o755, 0, vec![]),
                ("studio/bin".into(), 0o755, 0, vec![]),
                ("studio/bin/app".into(), 0o755, 0, b"executable".to_vec()),
                ("studio/share".into(), 0o755, 0, vec![]),
                ("studio/share/data.txt".into(), 0o644, 0, b"data".to_vec()),
            ]
        );
    }
}
