use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use luxury_spec::{
    ENTRYPOINT_SCHEMA_VERSION, FORMAT_VERSION, InstallPolicy, LICENSE_SCHEMA_VERSION,
    MAX_PAYLOAD_BYTES, MAX_PAYLOAD_FILE_BYTES, MAX_PAYLOAD_FILES, Manifest, OperatingSystem,
    Package, PackagePath, SHORTCUT_SCHEMA_VERSION, SpecError, Target,
};
use tempfile::{NamedTempFile, TempDir, tempdir_in};

use super::{
    CompilerError, MAX_IMPORT_SOURCES, NEVER_CANCELLED, PROJECT_FILE, ProjectConfig, Result,
    SAMPLE_FILE, SAMPLE_PAYLOAD, canonicalize, check_cancelled, ensure_within,
    existing_file_matches, io_error, link_metadata, portable_path, prepare_project_source,
    read_project_config, reject_link, validate_directory_path, validate_executables,
    validate_regular_file,
};

#[derive(Clone, Debug)]
pub struct ProjectUpdate {
    pub package: Package,
    pub target: Target,
    pub install: InstallPolicy,
    pub executable: Option<Vec<PackagePath>>,
}

pub fn update_project(project_root: impl AsRef<Path>, update: ProjectUpdate) -> Result<Manifest> {
    update_project_cancellable(project_root, update, &NEVER_CANCELLED)
}

pub fn update_project_cancellable(
    project_root: impl AsRef<Path>,
    update: ProjectUpdate,
    cancelled: &AtomicBool,
) -> Result<Manifest> {
    check_cancelled(cancelled)?;
    let project_input = project_root.as_ref();
    validate_directory_path(project_input)?;
    let project_root = canonicalize(project_input, "resolving project directory")?;
    let config_path = project_root.join(PROJECT_FILE);
    validate_regular_file(&config_path)?;
    let source = read_project_config(&config_path, cancelled)?;
    let mut config: ProjectConfig = toml::from_str(&source)?;
    if config.format_version != FORMAT_VERSION || config.publisher_rotation.is_some() {
        return Err(CompilerError::ProjectNotEditable);
    }

    let previous_entrypoint = config.install.entrypoint.clone();
    config.schema_version = schema_version(&update.package, &update.install);
    config.package = update.package;
    config.target = update.target;
    config.install = update.install;
    if let Some(executable) = update.executable {
        config.payload.executable = executable;
    } else {
        let previous_entrypoint_missing = previous_entrypoint.as_ref().is_some_and(|path| {
            matches!(
                fs::symlink_metadata(
                    project_root
                        .join(config.payload.directory.to_native_path())
                        .join(path.to_native_path())
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound
            )
        });
        if previous_entrypoint.as_ref() != config.install.entrypoint.as_ref()
            && previous_entrypoint_missing
        {
            config
                .payload
                .executable
                .retain(|path| Some(path) != previous_entrypoint.as_ref());
        }
        if config.target.os != OperatingSystem::Windows
            && let Some(entrypoint) = config.install.entrypoint.as_ref()
            && !config.payload.executable.contains(entrypoint)
        {
            config.payload.executable.push(entrypoint.clone());
        }
    }
    let candidate = toml::to_string_pretty(&config).map_err(|_| {
        CompilerError::InvalidConfig("project settings could not be serialized".into())
    })?;
    let (_, manifest) = prepare_project_source(&project_root, &candidate, None, None, cancelled)?;
    replace_project_config(&config_path, source.as_bytes(), candidate.as_bytes())?;
    Ok(manifest)
}

pub fn import_payload(
    project_root: impl AsRef<Path>,
    source_paths: &[PathBuf],
) -> Result<Manifest> {
    import_payload_cancellable(project_root, source_paths, &NEVER_CANCELLED)
}

pub fn import_payload_cancellable(
    project_root: impl AsRef<Path>,
    source_paths: &[PathBuf],
    cancelled: &AtomicBool,
) -> Result<Manifest> {
    if source_paths.is_empty() || source_paths.len() > MAX_IMPORT_SOURCES {
        return Err(CompilerError::InvalidImportCount);
    }
    check_cancelled(cancelled)?;
    let project_input = project_root.as_ref();
    validate_directory_path(project_input)?;
    let project_root = canonicalize(project_input, "resolving project directory")?;
    let config_path = project_root.join(PROJECT_FILE);
    validate_regular_file(&config_path)?;
    let source = read_project_config(&config_path, cancelled)?;
    let mut config: ProjectConfig = toml::from_str(&source)?;
    if config.format_version != FORMAT_VERSION || config.publisher_rotation.is_some() {
        return Err(CompilerError::ProjectNotEditable);
    }
    let (payload_root, current) =
        prepare_project_source(&project_root, &source, None, None, cancelled)?;
    let possible_starter = current.files.len() == 1
        && current.files[0].path.as_str() == SAMPLE_FILE
        && !current.files[0].executable
        && current.files[0].size == SAMPLE_PAYLOAD.len() as u64;
    let remove_starter =
        possible_starter && existing_file_matches(&payload_root.join(SAMPLE_FILE), SAMPLE_PAYLOAD)?;
    let mut budget = ImportBudget {
        files: current.files.len() - usize::from(remove_starter),
        bytes: current.payload_size()
            - if remove_starter {
                SAMPLE_PAYLOAD.len() as u64
            } else {
                0
            },
        imported_files: 0,
    };

    let staging = tempdir_in(&project_root).map_err(|error| {
        io_error(
            "creating payload import staging directory",
            &project_root,
            error,
        )
    })?;
    let incoming = staging.path().join("incoming");
    fs::create_dir(&incoming).map_err(|error| {
        io_error(
            "creating payload import staging directory",
            &incoming,
            error,
        )
    })?;
    let mut imported_executables = Vec::new();
    for source_path in source_paths {
        stage_import_source(
            &payload_root,
            source_path,
            &incoming,
            remove_starter,
            &mut imported_executables,
            &mut budget,
            cancelled,
        )?;
    }
    if budget.imported_files == 0 {
        return Err(CompilerError::EmptyImport);
    }
    imported_executables.sort_unstable();

    let config_changed = !imported_executables.is_empty();
    config.payload.executable.extend(imported_executables);
    validate_executables(&config.payload.executable)?;
    let candidate = if config_changed {
        toml::to_string_pretty(&config).map_err(|_| {
            CompilerError::InvalidConfig("project settings could not be serialized".into())
        })?
    } else {
        source.clone()
    };

    let starter = move_starter_payload(&payload_root, staging.path(), remove_starter)?;
    let mut published = Vec::new();
    let result = (|| {
        publish_staged(&incoming, &payload_root, &mut published, cancelled)?;
        let (_, manifest) =
            prepare_project_source(&project_root, &candidate, None, None, cancelled)?;
        if config_changed {
            replace_project_config(&config_path, source.as_bytes(), candidate.as_bytes())?;
        } else if !existing_file_matches(&config_path, source.as_bytes())? {
            return Err(CompilerError::ProjectChanged);
        }
        Ok(manifest)
    })();

    match result {
        Ok(manifest) => Ok(manifest),
        Err(error) => {
            let rollback = rollback_import(&published);
            let restore = restore_starter_payload(starter.as_ref());
            restore.and(rollback).and(Err(error))
        }
    }
}

/// Replaces the complete payload with the contents of one external directory.
/// The existing payload remains untouched until the replacement has been copied
/// and validated, and is restored if validation or config publication fails.
pub fn replace_payload(
    project_root: impl AsRef<Path>,
    source_directory: impl AsRef<Path>,
) -> Result<Manifest> {
    replace_payload_cancellable(project_root, source_directory, &NEVER_CANCELLED)
}

pub fn replace_payload_cancellable(
    project_root: impl AsRef<Path>,
    source_directory: impl AsRef<Path>,
    cancelled: &AtomicBool,
) -> Result<Manifest> {
    check_cancelled(cancelled)?;
    let project_input = project_root.as_ref();
    validate_directory_path(project_input)?;
    let project_root = canonicalize(project_input, "resolving project directory")?;
    let config_path = project_root.join(PROJECT_FILE);
    validate_regular_file(&config_path)?;
    let source = read_project_config(&config_path, cancelled)?;
    let mut config: ProjectConfig = toml::from_str(&source)?;
    if config.format_version != FORMAT_VERSION || config.publisher_rotation.is_some() {
        return Err(CompilerError::ProjectNotEditable);
    }
    let (payload_root, current) =
        prepare_project_source(&project_root, &source, None, None, cancelled)?;

    let staging = tempdir_in(&project_root).map_err(|error| {
        io_error(
            "creating payload replacement staging directory",
            &project_root,
            error,
        )
    })?;
    let incoming = staging.path().join("incoming");
    fs::create_dir(&incoming).map_err(|error| {
        io_error(
            "creating payload replacement staging directory",
            &incoming,
            error,
        )
    })?;
    let mut imported_executables = Vec::new();
    let mut imported_files = Vec::new();
    let mut budget = ImportBudget {
        files: 0,
        bytes: 0,
        imported_files: 0,
    };
    stage_replacement_directory(
        &payload_root,
        source_directory.as_ref(),
        &incoming,
        &mut imported_executables,
        &mut imported_files,
        &mut budget,
        cancelled,
    )?;
    if budget.imported_files == 0 {
        return Err(CompilerError::EmptyImport);
    }
    imported_executables.sort_unstable();
    imported_files.sort_unstable();
    validate_executables(&imported_executables)?;
    config.payload.executable = imported_executables;

    if let Some(entrypoint) = config.install.entrypoint.as_ref() {
        let keep_entrypoint = imported_files.binary_search(entrypoint).is_ok()
            && (config.target.os == OperatingSystem::Windows
                || config.payload.executable.contains(entrypoint));
        if !keep_entrypoint {
            config.install.entrypoint = None;
            config.install.shortcuts = luxury_spec::ShortcutPolicy::default();
        }
    }
    config.schema_version = schema_version(&config.package, &config.install);
    let candidate = toml::to_string_pretty(&config).map_err(|_| {
        CompilerError::InvalidConfig("project settings could not be serialized".into())
    })?;
    if !existing_file_matches(&config_path, source.as_bytes())? {
        return Err(CompilerError::ProjectChanged);
    }
    let (_, latest) = prepare_project_source(&project_root, &source, None, None, cancelled)?;
    if latest != current {
        return Err(CompilerError::ProjectChanged);
    }

    let previous = staging.path().join("previous");
    fs::rename(&payload_root, &previous)
        .map_err(|error| io_error("staging previous project payload", &payload_root, error))?;
    if let Err(error) = fs::rename(&incoming, &payload_root) {
        let cause = io_error(
            "publishing replacement project payload",
            &payload_root,
            error,
        );
        return restore_previous_payload(&previous, &payload_root, staging).and(Err(cause));
    }

    let result = (|| {
        let (_, manifest) =
            prepare_project_source(&project_root, &candidate, None, None, cancelled)?;
        replace_project_config(&config_path, source.as_bytes(), candidate.as_bytes())?;
        Ok(manifest)
    })();
    match result {
        Ok(manifest) => Ok(manifest),
        Err(error) => rollback_payload_replacement(&payload_root, &previous, &incoming, staging)
            .and(Err(error)),
    }
}

pub fn resolve_payload_file(
    project_root: impl AsRef<Path>,
    selected_path: impl AsRef<Path>,
) -> Result<PackagePath> {
    let project_input = project_root.as_ref();
    validate_directory_path(project_input)?;
    let project_root = canonicalize(project_input, "resolving project directory")?;
    let config_path = project_root.join(PROJECT_FILE);
    validate_regular_file(&config_path)?;
    let source = read_project_config(&config_path, &NEVER_CANCELLED)?;
    let config: ProjectConfig = toml::from_str(&source)?;
    if config.format_version != FORMAT_VERSION || config.publisher_rotation.is_some() {
        return Err(CompilerError::ProjectNotEditable);
    }
    let payload_candidate = project_root.join(config.payload.directory.to_native_path());
    validate_directory_path(&payload_candidate)?;
    let payload_root = canonicalize(&payload_candidate, "resolving payload directory")?;
    ensure_within(&payload_root, &project_root)?;

    let selected_path = selected_path.as_ref();
    if !selected_path.is_absolute() {
        return Err(CompilerError::InvalidImportSource(
            selected_path.to_path_buf(),
        ));
    }
    let metadata = link_metadata(selected_path)?;
    reject_link(selected_path, &metadata)?;
    if !metadata.is_file() {
        return Err(CompilerError::SpecialEntry(selected_path.to_path_buf()));
    }
    let resolved = canonicalize(selected_path, "resolving selected payload file")?;
    ensure_within(&resolved, &payload_root)?;
    let relative =
        resolved
            .strip_prefix(&payload_root)
            .map_err(|_| CompilerError::OutsideRoot {
                path: resolved.clone(),
                root: payload_root,
            })?;
    portable_path(relative)
}

#[derive(Debug)]
struct PublishedEntry {
    path: PathBuf,
    directory: bool,
}

#[derive(Debug)]
struct StarterBackup {
    original: PathBuf,
    backup: PathBuf,
}

struct ImportBudget {
    files: usize,
    bytes: u64,
    imported_files: usize,
}

struct ImportCopy<'a> {
    incoming: &'a Path,
    executables: &'a mut Vec<PackagePath>,
    files: Option<&'a mut Vec<PackagePath>>,
    budget: &'a mut ImportBudget,
    cancelled: &'a AtomicBool,
}

impl ImportBudget {
    fn add(&mut self, path: &PackagePath, size: u64) -> Result<()> {
        if size > MAX_PAYLOAD_FILE_BYTES {
            return Err(SpecError::FileTooLarge {
                path: path.to_string(),
                size,
            }
            .into());
        }
        self.files = self
            .files
            .checked_add(1)
            .ok_or(SpecError::TooManyFiles(usize::MAX))?;
        if self.files > MAX_PAYLOAD_FILES {
            return Err(SpecError::TooManyFiles(self.files).into());
        }
        self.bytes = self
            .bytes
            .checked_add(size)
            .ok_or(SpecError::PayloadTooLarge)?;
        if self.bytes > MAX_PAYLOAD_BYTES {
            return Err(SpecError::PayloadTooLarge.into());
        }
        self.imported_files += 1;
        Ok(())
    }
}

fn stage_import_source(
    payload_root: &Path,
    source: &Path,
    incoming: &Path,
    replace_starter: bool,
    executables: &mut Vec<PackagePath>,
    budget: &mut ImportBudget,
    cancelled: &AtomicBool,
) -> Result<()> {
    check_cancelled(cancelled)?;
    if !source.is_absolute() {
        return Err(CompilerError::InvalidImportSource(source.to_path_buf()));
    }
    let metadata = link_metadata(source)?;
    reject_link(source, &metadata)?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(CompilerError::SpecialEntry(source.to_path_buf()));
    }
    let resolved = canonicalize(source, "resolving payload import source")?;
    if resolved.starts_with(payload_root) || payload_root.starts_with(&resolved) {
        return Err(CompilerError::InvalidImportSource(source.to_path_buf()));
    }
    let name = resolved
        .file_name()
        .ok_or_else(|| CompilerError::InvalidImportSource(source.to_path_buf()))?;
    portable_path(Path::new(name))?;
    let destination = payload_root.join(name);
    match fs::symlink_metadata(&destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) if replace_starter && name == SAMPLE_FILE => {}
        Ok(_) => return Err(CompilerError::ImportConflict(destination)),
        Err(error) => {
            return Err(io_error(
                "inspecting payload destination",
                &destination,
                error,
            ));
        }
    }
    let mut copy = ImportCopy {
        incoming,
        executables,
        budget,
        cancelled,
        files: None,
    };
    copy_import_entry(&resolved, &resolved, &incoming.join(name), &mut copy)
}

fn stage_replacement_directory(
    payload_root: &Path,
    source: &Path,
    incoming: &Path,
    executables: &mut Vec<PackagePath>,
    files: &mut Vec<PackagePath>,
    budget: &mut ImportBudget,
    cancelled: &AtomicBool,
) -> Result<()> {
    check_cancelled(cancelled)?;
    if !source.is_absolute() {
        return Err(CompilerError::InvalidImportSource(source.to_path_buf()));
    }
    let metadata = link_metadata(source)?;
    reject_link(source, &metadata)?;
    if !metadata.is_dir() {
        return Err(CompilerError::InvalidImportSource(source.to_path_buf()));
    }
    let resolved = canonicalize(source, "resolving payload replacement source")?;
    if resolved.starts_with(payload_root) || payload_root.starts_with(&resolved) {
        return Err(CompilerError::InvalidImportSource(source.to_path_buf()));
    }
    let mut copy = ImportCopy {
        incoming,
        executables,
        files: Some(files),
        budget,
        cancelled,
    };
    for entry in fs::read_dir(&resolved)
        .map_err(|error| io_error("reading payload replacement directory", &resolved, error))?
    {
        check_cancelled(cancelled)?;
        let entry = entry
            .map_err(|error| io_error("reading payload replacement entry", &resolved, error))?;
        copy_import_entry(
            &resolved,
            &entry.path(),
            &incoming.join(entry.file_name()),
            &mut copy,
        )?;
    }
    Ok(())
}

fn copy_import_entry(
    source_root: &Path,
    source: &Path,
    destination: &Path,
    copy: &mut ImportCopy<'_>,
) -> Result<()> {
    check_cancelled(copy.cancelled)?;
    let metadata = link_metadata(source)?;
    reject_link(source, &metadata)?;
    let resolved = canonicalize(source, "resolving payload import entry")?;
    ensure_within(&resolved, source_root)?;
    if metadata.is_dir() {
        fs::create_dir(destination).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CompilerError::ImportConflict(destination.to_path_buf())
            } else {
                io_error("creating staged payload directory", destination, error)
            }
        })?;
        for entry in fs::read_dir(source)
            .map_err(|error| io_error("reading payload import directory", source, error))?
        {
            check_cancelled(copy.cancelled)?;
            let entry =
                entry.map_err(|error| io_error("reading payload import entry", source, error))?;
            copy_import_entry(
                source_root,
                &entry.path(),
                &destination.join(entry.file_name()),
                copy,
            )?;
        }
        if fs::read_dir(destination)
            .map_err(|error| io_error("reading staged payload directory", destination, error))?
            .next()
            .is_none()
        {
            fs::remove_dir(destination).map_err(|error| {
                io_error(
                    "removing empty staged payload directory",
                    destination,
                    error,
                )
            })?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(CompilerError::SpecialEntry(source.to_path_buf()));
    }

    let relative =
        destination
            .strip_prefix(copy.incoming)
            .map_err(|_| CompilerError::OutsideRoot {
                path: destination.to_path_buf(),
                root: copy.incoming.to_path_buf(),
            })?;
    let package_path = portable_path(relative)?;
    let input = File::open(source)
        .map_err(|error| io_error("opening payload import file", source, error))?;
    let opened_metadata = input
        .metadata()
        .map_err(|error| io_error("inspecting payload import file", source, error))?;
    if !opened_metadata.is_file() {
        return Err(CompilerError::SpecialEntry(source.to_path_buf()));
    }
    copy.budget.add(&package_path, opened_metadata.len())?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CompilerError::ImportConflict(destination.to_path_buf())
            } else {
                io_error("creating staged payload file", destination, error)
            }
        })?;
    let copied = copy_and_sync(input, output, source, destination, copy.cancelled)?;
    if copied != opened_metadata.len() {
        return Err(CompilerError::ImportSourceChanged(source.to_path_buf()));
    }
    if let Some(files) = copy.files.as_mut() {
        files.push(package_path.clone());
    }
    if source_is_executable(&opened_metadata) {
        copy.executables.push(package_path);
    }
    Ok(())
}

fn copy_and_sync(
    input: File,
    output: File,
    source: &Path,
    destination: &Path,
    cancelled: &AtomicBool,
) -> Result<u64> {
    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);
    let mut buffer = [0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        check_cancelled(cancelled)?;
        let read = reader
            .read(&mut buffer)
            .map_err(|error| io_error("reading payload import file", source, error))?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or(SpecError::PayloadTooLarge)?;
        writer
            .write_all(&buffer[..read])
            .map_err(|error| io_error("writing payload import file", destination, error))?;
    }
    check_cancelled(cancelled)?;
    writer
        .flush()
        .map_err(|error| io_error("flushing payload import file", destination, error))?;
    check_cancelled(cancelled)?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|error| io_error("syncing payload import file", destination, error))?;
    check_cancelled(cancelled)?;
    Ok(copied)
}

fn publish_staged(
    incoming: &Path,
    payload_root: &Path,
    published: &mut Vec<PublishedEntry>,
    cancelled: &AtomicBool,
) -> Result<()> {
    for entry in fs::read_dir(incoming)
        .map_err(|error| io_error("reading staged payload", incoming, error))?
    {
        check_cancelled(cancelled)?;
        let entry = entry.map_err(|error| io_error("reading staged payload", incoming, error))?;
        publish_entry(
            &entry.path(),
            &payload_root.join(entry.file_name()),
            published,
            cancelled,
        )?;
    }
    Ok(())
}

fn publish_entry(
    staged: &Path,
    destination: &Path,
    published: &mut Vec<PublishedEntry>,
    cancelled: &AtomicBool,
) -> Result<()> {
    check_cancelled(cancelled)?;
    let metadata = link_metadata(staged)?;
    if metadata.is_dir() {
        fs::create_dir(destination).map_err(|error| publish_error(destination, error))?;
        published.push(PublishedEntry {
            path: destination.to_path_buf(),
            directory: true,
        });
        for entry in fs::read_dir(staged)
            .map_err(|error| io_error("reading staged payload directory", staged, error))?
        {
            let entry =
                entry.map_err(|error| io_error("reading staged payload entry", staged, error))?;
            publish_entry(
                &entry.path(),
                &destination.join(entry.file_name()),
                published,
                cancelled,
            )?;
        }
    } else if metadata.is_file() {
        let input = File::open(staged)
            .map_err(|error| io_error("opening staged payload file", staged, error))?;
        let expected = input
            .metadata()
            .map_err(|error| io_error("inspecting staged payload file", staged, error))?
            .len();
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|error| publish_error(destination, error))?;
        let copied = match copy_and_sync(input, output, staged, destination, cancelled) {
            Ok(copied) => copied,
            Err(error) => return rollback_new_import_file(destination, error),
        };
        if copied != expected {
            return rollback_new_import_file(
                destination,
                CompilerError::ImportSourceChanged(staged.to_path_buf()),
            );
        }
        published.push(PublishedEntry {
            path: destination.to_path_buf(),
            directory: false,
        });
    } else {
        return Err(CompilerError::SpecialEntry(staged.to_path_buf()));
    }
    Ok(())
}

fn publish_error(path: &Path, error: io::Error) -> CompilerError {
    if error.kind() == io::ErrorKind::AlreadyExists {
        CompilerError::ImportConflict(path.to_path_buf())
    } else {
        io_error("publishing payload import", path, error)
    }
}

fn rollback_new_import_file(path: &Path, cause: CompilerError) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Err(cause),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(cause),
        Err(error) => Err(io_error("rolling back payload import", path, error)),
    }
}

fn move_starter_payload(
    payload_root: &Path,
    staging: &Path,
    possible_starter: bool,
) -> Result<Option<StarterBackup>> {
    let original = payload_root.join(SAMPLE_FILE);
    if !possible_starter {
        return Ok(None);
    }
    let mut entries = fs::read_dir(payload_root)
        .map_err(|error| io_error("reading starter payload directory", payload_root, error))?;
    let only_starter = match entries.next() {
        Some(Ok(entry)) => entry.file_name() == SAMPLE_FILE && entries.next().is_none(),
        Some(Err(error)) => {
            return Err(io_error(
                "reading starter payload directory",
                payload_root,
                error,
            ));
        }
        None => false,
    };
    if !only_starter || !existing_file_matches(&original, SAMPLE_PAYLOAD)? {
        return Ok(None);
    }
    let backup = staging.join("starter-backup");
    fs::rename(&original, &backup)
        .map_err(|error| io_error("backing up starter payload", &original, error))?;
    Ok(Some(StarterBackup { original, backup }))
}

fn rollback_import(published: &[PublishedEntry]) -> Result<()> {
    for entry in published.iter().rev() {
        let result = if entry.directory {
            fs::remove_dir(&entry.path)
        } else {
            fs::remove_file(&entry.path)
        };
        if let Err(error) = result
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(io_error("rolling back payload import", &entry.path, error));
        }
    }
    Ok(())
}

fn restore_starter_payload(starter: Option<&StarterBackup>) -> Result<()> {
    let Some(starter) = starter else {
        return Ok(());
    };
    match fs::symlink_metadata(&starter.original) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::rename(&starter.backup, &starter.original)
                .map_err(|error| io_error("restoring starter payload", &starter.original, error))
        }
        Err(error) => Err(io_error(
            "inspecting starter payload restore path",
            &starter.original,
            error,
        )),
        Ok(_) => Err(CompilerError::ImportConflict(starter.original.clone())),
    }
}

fn rollback_payload_replacement(
    payload: &Path,
    previous: &Path,
    incoming: &Path,
    staging: TempDir,
) -> Result<()> {
    if let Err(error) = fs::rename(payload, incoming) {
        let _ = staging.keep();
        return Err(io_error(
            "rolling back replacement project payload",
            payload,
            error,
        ));
    }
    restore_previous_payload(previous, payload, staging)
}

fn restore_previous_payload(previous: &Path, payload: &Path, staging: TempDir) -> Result<()> {
    if let Err(error) = fs::rename(previous, payload) {
        let _ = staging.keep();
        return Err(io_error(
            "restoring previous project payload",
            previous,
            error,
        ));
    }
    Ok(())
}

fn schema_version(package: &Package, install: &InstallPolicy) -> u32 {
    if install.shortcuts.enabled() {
        SHORTCUT_SCHEMA_VERSION
    } else if package.license.is_some() {
        LICENSE_SCHEMA_VERSION
    } else if install.entrypoint.is_some() {
        ENTRYPOINT_SCHEMA_VERSION
    } else {
        1
    }
}

#[cfg(unix)]
fn source_is_executable(metadata: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn source_is_executable(_: &Metadata) -> bool {
    false
}

fn replace_project_config(path: &Path, expected: &[u8], contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| CompilerError::InvalidOutput(path.to_path_buf()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|source| io_error("creating temporary project configuration", path, source))?;
    temporary
        .write_all(contents)
        .map_err(|source| io_error("writing project configuration", path, source))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| io_error("syncing project configuration", path, source))?;
    if !existing_file_matches(path, expected)? {
        return Err(CompilerError::ProjectChanged);
    }
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|error| io_error("publishing project configuration", path, error.error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_authoring_selects_schema_four() {
        let package = Package {
            id: luxury_spec::PackageId::parse("dev.luxury.demo").unwrap(),
            name: "Luxury Demo".into(),
            version: "1.0.0".parse().unwrap(),
            publisher: "Luxury Software".into(),
            description: None,
            license: None,
        };
        let install = InstallPolicy {
            scope: luxury_spec::InstallScope::User,
            directory: luxury_spec::InstallDirectory::parse("Luxury Demo").unwrap(),
            allow_downgrade: false,
            entrypoint: Some(PackagePath::parse("bin/demo.exe").unwrap()),
            show_install_log: false,
            finish_links: Vec::new(),
            shortcuts: luxury_spec::ShortcutPolicy {
                application_menu: true,
                desktop: false,
            },
        };

        assert_eq!(schema_version(&package, &install), SHORTCUT_SCHEMA_VERSION);
    }

    #[test]
    fn studio_import_applies_manifest_limits_before_copying_more_files() {
        let path = PackagePath::parse("extra.bin").unwrap();
        let mut too_many = ImportBudget {
            files: MAX_PAYLOAD_FILES,
            bytes: 0,
            imported_files: 0,
        };
        assert!(matches!(
            too_many.add(&path, 1),
            Err(CompilerError::InvalidManifest(SpecError::TooManyFiles(_)))
        ));

        let mut too_large = ImportBudget {
            files: 0,
            bytes: 0,
            imported_files: 0,
        };
        assert!(matches!(
            too_large.add(&path, MAX_PAYLOAD_FILE_BYTES + 1),
            Err(CompilerError::InvalidManifest(
                SpecError::FileTooLarge { .. }
            ))
        ));
    }
}
