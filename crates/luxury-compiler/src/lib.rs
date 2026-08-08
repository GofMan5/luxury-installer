//! Turns a project directory into a verified `.luxpkg` without rebuilding a runner.

use std::{
    collections::{BTreeSet, HashSet},
    fmt::Write as _,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use luxury_spec::{
    FORMAT_VERSION, FileEntry, InstallPolicy, Manifest, PUBLISHER_ROTATION_FORMAT_VERSION, Package,
    PackagePath, PublisherRotation, SIGNED_FORMAT_VERSION, Sha256Digest, SpecError, Target,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;

mod authoring;

pub use authoring::{
    ProjectUpdate, import_payload, import_payload_cancellable, replace_payload,
    replace_payload_cancellable, resolve_payload_file, update_project, update_project_cancellable,
};

const PROJECT_FILE: &str = "luxury.toml";
const SAMPLE_FILE: &str = "hello.txt";
const SAMPLE_PAYLOAD: &[u8] = b"Hello from Luxury Installer.\n";
const MAX_PROJECT_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_IMPORT_SOURCES: usize = 1_024;
static NEVER_CANCELLED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Error)]
pub enum CompilerError {
    #[error("operation cancelled")]
    Cancelled,
    #[error("project configuration exceeds {limit} bytes")]
    ConfigTooLarge { limit: u64 },
    #[error("project configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error(transparent)]
    InvalidManifest(#[from] SpecError),
    #[error("{action} `{path}` failed: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("payload entry `{0}` is a symlink or reparse point")]
    Link(PathBuf),
    #[error("filesystem entry `{0}` is not a regular file or directory")]
    SpecialEntry(PathBuf),
    #[error("path `{path}` resolves outside `{root}`")]
    OutsideRoot { path: PathBuf, root: PathBuf },
    #[error("payload path `{0}` is not valid UTF-8")]
    NonUtf8Path(PathBuf),
    #[error("executable list contains duplicate or case-colliding path `{0}`")]
    DuplicateExecutable(String),
    #[error("configured executable `{0}` is not a regular payload file with that exact path")]
    MissingExecutable(String),
    #[error("bundle output `{0}` must not be inside the payload directory")]
    OutputInsidePayload(PathBuf),
    #[error("bundle output path `{0}` has no file name")]
    InvalidOutput(PathBuf),
    #[error("existing bundle output `{0}` is not a regular file")]
    OutputNotRegular(PathBuf),
    #[error("only unsigned format 1 projects can be edited in Studio")]
    ProjectNotEditable,
    #[error("project configuration changed while Studio was saving it")]
    ProjectChanged,
    #[error("payload import requires between 1 and {MAX_IMPORT_SOURCES} source paths")]
    InvalidImportCount,
    #[error("payload import contains no regular files")]
    EmptyImport,
    #[error("payload import source `{0}` overlaps the project payload")]
    InvalidImportSource(PathBuf),
    #[error("payload import source `{0}` changed while it was copied")]
    ImportSourceChanged(PathBuf),
    #[error("payload destination `{0}` already exists")]
    ImportConflict(PathBuf),
    #[error("unsigned builds require project format 1, found {found}")]
    UnsignedBuildFormat { found: u32 },
    #[error("signed builds require project format 2 or 3, found {found}")]
    SignedBuildFormat { found: u32 },
    #[error("bundle creation failed: {0}")]
    Bundle(#[source] luxury_bundle::BundleError),
}

impl From<luxury_bundle::BundleError> for CompilerError {
    fn from(error: luxury_bundle::BundleError) -> Self {
        match error {
            luxury_bundle::BundleError::Cancelled => Self::Cancelled,
            error => Self::Bundle(error),
        }
    }
}

impl From<toml::de::Error> for CompilerError {
    fn from(mut error: toml::de::Error) -> Self {
        error.set_input(None);
        Self::InvalidConfig(error.to_string().trim().to_owned())
    }
}

pub type Result<T> = std::result::Result<T, CompilerError>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectConfig {
    format_version: u32,
    #[serde(default = "legacy_schema_version")]
    schema_version: u32,
    package: Package,
    target: Target,
    install: InstallPolicy,
    #[serde(default)]
    publisher_rotation: Option<PublisherRotation>,
    payload: PayloadConfig,
}

const fn legacy_schema_version() -> u32 {
    1
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadConfig {
    directory: PackagePath,
    executable: Vec<PackagePath>,
}

/// Creates a minimal project without replacing an existing config or sample payload.
pub fn init_project(path: impl AsRef<Path>) -> Result<()> {
    let project_root = path.as_ref();
    create_dir_all(project_root)?;
    validate_directory_path(project_root)?;

    let config_path = project_root.join(PROJECT_FILE);
    let config = sample_config();
    require_missing_or_same(&config_path, config.as_bytes())?;

    let payload_root = project_root.join("payload");
    create_dir_all(&payload_root)?;
    validate_directory_path(&payload_root)?;

    let sample_path = payload_root.join(SAMPLE_FILE);
    require_missing_or_same(&sample_path, SAMPLE_PAYLOAD)?;
    write_new(&sample_path, SAMPLE_PAYLOAD)?;
    write_new(&config_path, config.as_bytes())?;

    Ok(())
}

/// Compiles `luxury.toml` and its payload into an unsigned deterministic bundle.
pub fn compile_project(
    project_root: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<Manifest> {
    compile_project_with_key(
        project_root.as_ref(),
        output.as_ref(),
        None,
        &NEVER_CANCELLED,
    )
}

pub fn compile_project_cancellable(
    project_root: impl AsRef<Path>,
    output: impl AsRef<Path>,
    cancelled: &AtomicBool,
) -> Result<Manifest> {
    compile_project_with_key(project_root.as_ref(), output.as_ref(), None, cancelled)
}

/// Compiles `luxury.toml` and its payload into a signed deterministic v2/v3 bundle.
pub fn compile_signed_project(
    project_root: impl AsRef<Path>,
    output: impl AsRef<Path>,
    signing_key: &luxury_bundle::PackageSigningKey,
) -> Result<Manifest> {
    compile_project_with_key(
        project_root.as_ref(),
        output.as_ref(),
        Some(signing_key),
        &NEVER_CANCELLED,
    )
}

/// Validates `luxury.toml` and hashes its v1, v2 or v3 payload without writing a bundle.
pub fn validate_project(project_root: impl AsRef<Path>) -> Result<Manifest> {
    validate_project_cancellable(project_root, &NEVER_CANCELLED)
}

pub fn validate_project_cancellable(
    project_root: impl AsRef<Path>,
    cancelled: &AtomicBool,
) -> Result<Manifest> {
    prepare_project(project_root.as_ref(), None, None, cancelled).map(|(_, manifest)| manifest)
}

fn compile_project_with_key(
    project_root: &Path,
    output: &Path,
    signing_key: Option<&luxury_bundle::PackageSigningKey>,
    cancelled: &AtomicBool,
) -> Result<Manifest> {
    check_cancelled(cancelled)?;
    let (payload_root, manifest) = prepare_project(
        project_root,
        Some(signing_key.is_some()),
        Some(output),
        cancelled,
    )?;
    write_bundle(output, &payload_root, &manifest, signing_key, cancelled)?;

    Ok(manifest)
}

fn prepare_project(
    project_root: &Path,
    signed_build: Option<bool>,
    output: Option<&Path>,
    cancelled: &AtomicBool,
) -> Result<(PathBuf, Manifest)> {
    check_cancelled(cancelled)?;
    let project_input = project_root;
    validate_directory_path(project_input)?;
    let project_root = canonicalize(project_input, "resolving project directory")?;
    let config_path = project_root.join(PROJECT_FILE);
    validate_regular_file(&config_path)?;
    let source = read_project_config(&config_path, cancelled)?;
    prepare_project_source(&project_root, &source, signed_build, output, cancelled)
}

fn prepare_project_source(
    project_root: &Path,
    source: &str,
    signed_build: Option<bool>,
    output: Option<&Path>,
    cancelled: &AtomicBool,
) -> Result<(PathBuf, Manifest)> {
    let config: ProjectConfig = toml::from_str(source)?;
    check_cancelled(cancelled)?;

    if let Some(signed_build) = signed_build
        && !matches!(
            (signed_build, config.format_version),
            (false, FORMAT_VERSION)
                | (
                    true,
                    SIGNED_FORMAT_VERSION | PUBLISHER_ROTATION_FORMAT_VERSION
                )
        )
    {
        return Err(if signed_build {
            CompilerError::SignedBuildFormat {
                found: config.format_version,
            }
        } else {
            CompilerError::UnsignedBuildFormat {
                found: config.format_version,
            }
        });
    }

    let payload_candidate = project_root.join(config.payload.directory.to_native_path());
    validate_directory_path(&payload_candidate)?;

    let payload_root = canonicalize(&payload_candidate, "resolving payload directory")?;
    ensure_within(&payload_root, project_root)?;
    if let Some(output) = output {
        reject_output_inside_payload(output, &payload_root)?;
    }

    let executables = validate_executables(&config.payload.executable)?;
    let mut files = Vec::new();
    scan_directory(
        &payload_root,
        &payload_root,
        &executables,
        &mut files,
        cancelled,
    )?;
    files.sort_unstable_by(|left, right| left.path.cmp(&right.path));

    let found = files
        .iter()
        .filter(|file| file.executable)
        .map(|file| file.path.as_str())
        .collect::<HashSet<_>>();
    if let Some(missing) = executables
        .iter()
        .find(|path| !found.contains(path.as_str()))
    {
        return Err(CompilerError::MissingExecutable(missing.clone()));
    }

    let manifest = Manifest {
        format_version: config.format_version,
        schema_version: config.schema_version,
        package: config.package,
        target: config.target,
        install: config.install,
        publisher_rotation: config.publisher_rotation,
        files,
    };
    manifest.validate()?;
    check_cancelled(cancelled)?;

    Ok((payload_root, manifest))
}

fn read_project_config(path: &Path, cancelled: &AtomicBool) -> Result<String> {
    check_cancelled(cancelled)?;
    let file = File::open(path)
        .map_err(|source| io_error("opening project configuration", path, source))?;
    let size = file
        .metadata()
        .map_err(|source| io_error("reading project configuration metadata", path, source))?
        .len();
    if size > MAX_PROJECT_CONFIG_BYTES {
        return Err(CompilerError::ConfigTooLarge {
            limit: MAX_PROJECT_CONFIG_BYTES,
        });
    }

    let mut reader = BufReader::new(file);
    let mut bytes = Vec::with_capacity(size as usize);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        check_cancelled(cancelled)?;
        let read = reader
            .read(&mut buffer)
            .map_err(|source| io_error("reading project configuration", path, source))?;
        check_cancelled(cancelled)?;
        if read == 0 {
            break;
        }
        if bytes.len() + read > MAX_PROJECT_CONFIG_BYTES as usize {
            return Err(CompilerError::ConfigTooLarge {
                limit: MAX_PROJECT_CONFIG_BYTES,
            });
        }
        bytes.extend_from_slice(&buffer[..read]);
    }

    String::from_utf8(bytes).map_err(|source| {
        io_error(
            "reading project configuration",
            path,
            io::Error::new(io::ErrorKind::InvalidData, source),
        )
    })
}

fn scan_directory(
    payload_root: &Path,
    directory: &Path,
    executables: &BTreeSet<String>,
    files: &mut Vec<FileEntry>,
    cancelled: &AtomicBool,
) -> Result<()> {
    check_cancelled(cancelled)?;
    let entries = fs::read_dir(directory)
        .map_err(|source| io_error("reading payload directory", directory, source))?;

    for entry in entries {
        check_cancelled(cancelled)?;
        let entry = entry
            .map_err(|source| io_error("reading payload directory entry", directory, source))?;
        check_cancelled(cancelled)?;
        let path = entry.path();
        let metadata = link_metadata(&path)?;
        reject_link(&path, &metadata)?;

        let resolved = canonicalize(&path, "resolving payload entry")?;
        ensure_within(&resolved, payload_root)?;

        if metadata.is_dir() {
            scan_directory(payload_root, &path, executables, files, cancelled)?;
        } else if metadata.is_file() {
            let relative =
                path.strip_prefix(payload_root)
                    .map_err(|_| CompilerError::OutsideRoot {
                        path: path.clone(),
                        root: payload_root.to_path_buf(),
                    })?;
            let package_path = portable_path(relative)?;
            let (size, sha256) = hash_file(&path, cancelled)?;
            let executable = executables.contains(package_path.as_str());
            files.push(FileEntry {
                path: package_path,
                size,
                sha256,
                executable,
            });
        } else {
            return Err(CompilerError::SpecialEntry(path));
        }
    }

    Ok(())
}

fn portable_path(relative: &Path) -> Result<PackagePath> {
    let mut path = String::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(CompilerError::OutsideRoot {
                path: relative.to_path_buf(),
                root: PathBuf::new(),
            });
        };
        let component = component
            .to_str()
            .ok_or_else(|| CompilerError::NonUtf8Path(relative.to_path_buf()))?;
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(component);
    }
    PackagePath::parse(path).map_err(Into::into)
}

fn hash_file(path: &Path, cancelled: &AtomicBool) -> Result<(u64, Sha256Digest)> {
    let file = File::open(path).map_err(|source| io_error("opening payload file", path, source))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        check_cancelled(cancelled)?;
        let read = reader
            .read(&mut buffer)
            .map_err(|source| io_error("hashing payload file", path, source))?;
        check_cancelled(cancelled)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(CompilerError::InvalidManifest(SpecError::PayloadTooLarge))?;
        hasher.update(&buffer[..read]);
    }

    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut digest, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok((size, Sha256Digest::parse(digest)?))
}

fn validate_executables(paths: &[PackagePath]) -> Result<BTreeSet<String>> {
    let mut aliases = HashSet::with_capacity(paths.len());
    let mut exact = BTreeSet::new();
    for path in paths {
        if !aliases.insert(path.collision_key()) {
            return Err(CompilerError::DuplicateExecutable(path.to_string()));
        }
        exact.insert(path.as_str().to_owned());
    }
    Ok(exact)
}

fn reject_output_inside_payload(output: &Path, payload_root: &Path) -> Result<()> {
    let absolute = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| io_error("resolving current directory", output, source))?
            .join(output)
    };
    let parent = absolute.parent().unwrap_or_else(|| Path::new("."));
    if let Ok(parent) = fs::canonicalize(parent)
        && parent
            .join(absolute.file_name().unwrap_or_default())
            .starts_with(payload_root)
    {
        return Err(CompilerError::OutputInsidePayload(output.to_path_buf()));
    }
    Ok(())
}

fn write_bundle(
    output: &Path,
    payload_root: &Path,
    manifest: &Manifest,
    signing_key: Option<&luxury_bundle::PackageSigningKey>,
    cancelled: &AtomicBool,
) -> Result<()> {
    check_cancelled(cancelled)?;
    let mut temporary = create_temporary_output(output)?;
    let temporary_path = temporary.path().to_path_buf();
    let mut writer = BufWriter::new(temporary.as_file_mut());
    let result: Result<()> = (|| {
        match signing_key {
            Some(signing_key) => luxury_bundle::create_signed_bundle(
                &mut writer,
                payload_root,
                manifest,
                signing_key,
            )?,
            None => luxury_bundle::create_unsigned_bundle_cancellable(
                &mut writer,
                payload_root,
                manifest,
                cancelled,
            )?,
        }
        check_cancelled(cancelled)?;
        writer
            .flush()
            .map_err(|source| io_error("flushing bundle output", &temporary_path, source))?;
        check_cancelled(cancelled)?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|source| io_error("syncing bundle output", &temporary_path, source))?;
        check_cancelled(cancelled)?;
        Ok(())
    })();
    drop(writer);

    result?;
    check_cancelled(cancelled)?;
    replace_output(temporary, output)
}

fn create_temporary_output(output: &Path) -> Result<NamedTempFile> {
    output
        .file_name()
        .ok_or_else(|| CompilerError::InvalidOutput(output.to_path_buf()))?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    NamedTempFile::new_in(parent)
        .map_err(|source| io_error("creating temporary bundle output", output, source))
}

fn replace_output(temporary: NamedTempFile, output: &Path) -> Result<()> {
    match fs::symlink_metadata(output) {
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return fs::rename(temporary, output)
                .map_err(|source| io_error("publishing bundle output", output, source));
        }
        Err(source) => return Err(io_error("inspecting bundle output", output, source)),
        Ok(metadata)
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || is_reparse_point(&metadata) =>
        {
            return Err(CompilerError::OutputNotRegular(output.to_path_buf()));
        }
        Ok(_) => {}
    }
    temporary
        .persist(output)
        .map(|_| ())
        .map_err(|error| io_error("publishing bundle output", output, error.error))
}

fn ensure_within(path: &Path, root: &Path) -> Result<()> {
    if path.starts_with(root) {
        Ok(())
    } else {
        Err(CompilerError::OutsideRoot {
            path: path.to_path_buf(),
            root: root.to_path_buf(),
        })
    }
}

fn link_metadata(path: &Path) -> Result<Metadata> {
    fs::symlink_metadata(path)
        .map_err(|source| io_error("inspecting filesystem entry", path, source))
}

fn reject_link(path: &Path, metadata: &Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || is_reparse_point(metadata) {
        Err(CompilerError::Link(path.to_path_buf()))
    } else {
        Ok(())
    }
}

fn validate_directory_path(path: &Path) -> Result<()> {
    reject_links_in_path(path)?;
    let metadata = link_metadata(path)?;
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(CompilerError::SpecialEntry(path.to_path_buf()))
    }
}

fn validate_regular_file(path: &Path) -> Result<()> {
    reject_links_in_path(path)?;
    let metadata = link_metadata(path)?;
    if metadata.is_file() {
        Ok(())
    } else {
        Err(CompilerError::SpecialEntry(path.to_path_buf()))
    }
}

fn reject_links_in_path(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| io_error("resolving current directory", path, source))?
            .join(path)
    };
    let mut ancestors = absolute.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = link_metadata(ancestor)?;
        reject_link(ancestor, &metadata)?;
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_: &Metadata) -> bool {
    false
}

fn canonicalize(path: &Path, action: &'static str) -> Result<PathBuf> {
    fs::canonicalize(path).map_err(|source| io_error(action, path, source))
}

fn create_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| io_error("creating project directory", path, source))
}

fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            if existing_file_matches(path, contents)? {
                return Ok(());
            }
            return Err(io_error("creating project file", path, source));
        }
        Err(source) => return Err(io_error("creating project file", path, source)),
    };
    file.write_all(contents)
        .map_err(|source| io_error("writing project file", path, source))
}

fn require_missing_or_same(path: &Path, contents: &[u8]) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspecting project file", path, source)),
        Ok(_) if existing_file_matches(path, contents)? => Ok(()),
        Ok(_) => Err(io_error(
            "creating project file",
            path,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "project file already exists with different contents",
            ),
        )),
    }
}

fn existing_file_matches(path: &Path, contents: &[u8]) -> Result<bool> {
    validate_regular_file(path)?;
    let file = File::open(path)
        .map_err(|source| io_error("opening existing project file", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("reading existing project file metadata", path, source))?;
    if !metadata.is_file() {
        return Err(CompilerError::SpecialEntry(path.to_path_buf()));
    }
    let size = metadata.len();
    if size != contents.len() as u64 {
        return Ok(false);
    }
    let mut existing = Vec::with_capacity(contents.len());
    file.take(size.saturating_add(1))
        .read_to_end(&mut existing)
        .map_err(|source| io_error("reading existing project file", path, source))?;
    Ok(existing == contents)
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> CompilerError {
    CompilerError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        Err(CompilerError::Cancelled)
    } else {
        Ok(())
    }
}

fn sample_config() -> String {
    let target = Target::host();
    format!(
        r#"format_version = {FORMAT_VERSION}

[package]
id = "dev.luxury.demo"
name = "Luxury Demo"
version = "1.0.0"
publisher = "Luxury Software"

[target]
os = "{}"
arch = "{}"

[install]
scope = "user"
directory = "Luxury Demo"
# show_install_log = true
# [install.shortcuts]
# application_menu = true
# desktop = false
# [[install.finish_links]]
# label = "Документация"
# url = "https://example.com/docs"

[payload]
directory = "payload"
executable = []
"#,
        target.os, target.arch
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use luxury_bundle::{PackageSigningKey, PackageTrust, open_bundle};
    use luxury_spec::{ENTRYPOINT_SCHEMA_VERSION, LICENSE_SCHEMA_VERSION, PackageId};
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::*;

    // Public deterministic fixtures; never use these keys for a real package.
    const TEST_SIGNING_KEY_PEM: &str = concat!(
        "-----BEGIN PRIVATE ",
        "KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE ",
        "KEY-----\n"
    );
    const TEST_TRUSTED_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";
    const NEXT_SIGNING_KEY_PEM: &str = concat!(
        "-----BEGIN PRIVATE ",
        "KEY-----\nMC4CAQAwBQYDK2VwBCIEIEzNCJso/5banbbDRuwRTg9bijGfNaumJNqM9u1PuKb7\n-----END PRIVATE ",
        "KEY-----\n"
    );

    fn configure_rotation(project: &Path, rotation: &PublisherRotation) {
        let config = project.join(PROJECT_FILE);
        let source = fs::read_to_string(&config).unwrap().replacen(
            "format_version = 1",
            "format_version = 3",
            1,
        );
        fs::write(
            config,
            format!(
                "{source}\n[publisher_rotation]\nnext_public_key = \"{}\"\nproof = \"{}\"\n",
                rotation.next_public_key, rotation.proof
            ),
        )
        .unwrap();
    }

    #[test]
    fn initializes_and_compiles_a_deterministic_project() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();

        let output = temp.path().join("demo.luxpkg");
        let manifest = compile_project(&project, &output).unwrap();
        assert_eq!(manifest.schema_version, 1);
        assert!(manifest.install.entrypoint.is_none());
        assert!(
            !fs::read_to_string(project.join(PROJECT_FILE))
                .unwrap()
                .contains("schema_version")
        );
        let first_bundle = fs::read(&output).unwrap();
        compile_project(&project, &output).unwrap();
        assert_eq!(fs::read(&output).unwrap(), first_bundle);
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].path.as_str(), SAMPLE_FILE);
        assert_eq!(manifest.files[0].size, SAMPLE_PAYLOAD.len() as u64);
        assert!(!manifest.files[0].executable);

        let expected = Sha256::digest(SAMPLE_PAYLOAD);
        let expected = expected
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(manifest.files[0].sha256.as_str(), expected);

        let bundle = open_bundle(File::open(&output).unwrap(), None).unwrap();
        assert_eq!(bundle.manifest(), &manifest);
    }

    #[test]
    fn compiles_optional_install_log_and_finish_links() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let config = project.join(PROJECT_FILE);
        let source = fs::read_to_string(&config).unwrap().replace(
            "directory = \"Luxury Demo\"",
            "directory = \"Luxury Demo\"\nshow_install_log = true\n\n[[install.finish_links]]\nlabel = \"Документация\"\nurl = \"https://example.com/docs\"",
        );
        fs::write(config, source).unwrap();

        let manifest = validate_project(&project).unwrap();
        assert!(manifest.install.show_install_log);
        assert_eq!(manifest.install.finish_links.len(), 1);
        assert_eq!(manifest.install.finish_links[0].label, "Документация");
    }

    #[test]
    fn studio_update_is_validated_and_atomically_replaces_only_unsigned_config() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let config = project.join(PROJECT_FILE);
        let original = validate_project(&project).unwrap();
        let mut package = original.package.clone();
        package.name = "Human App".into();
        package.version = "2.1.0".parse().unwrap();
        package.license = Some("Read these terms before installing.".into());
        let mut install = original.install.clone();
        install.directory = luxury_spec::InstallDirectory::parse("Human App").unwrap();
        install.show_install_log = true;
        install.finish_links = vec![luxury_spec::FinishLink {
            label: "Документация".into(),
            url: "https://example.com/docs".into(),
        }];

        let updated = update_project(
            &project,
            ProjectUpdate {
                package,
                target: original.target,
                install,
                executable: Some(Vec::new()),
            },
        )
        .unwrap();
        assert_eq!(updated.schema_version, LICENSE_SCHEMA_VERSION);
        assert_eq!(updated.package.name, "Human App");
        assert!(updated.install.show_install_log);
        assert_eq!(validate_project(&project).unwrap(), updated);

        let before_invalid = fs::read(&config).unwrap();
        let mut invalid_install = updated.install.clone();
        invalid_install.finish_links[0].url = "http://example.com".into();
        let error = update_project(
            &project,
            ProjectUpdate {
                package: updated.package.clone(),
                target: updated.target,
                install: invalid_install,
                executable: Some(Vec::new()),
            },
        )
        .unwrap_err();
        assert!(matches!(error, CompilerError::InvalidManifest(_)));
        assert_eq!(fs::read(&config).unwrap(), before_invalid);

        let signed = String::from_utf8(before_invalid).unwrap().replacen(
            "format_version = 1",
            "format_version = 2",
            1,
        );
        fs::write(&config, signed.as_bytes()).unwrap();
        let error = update_project(
            &project,
            ProjectUpdate {
                package: updated.package,
                target: updated.target,
                install: updated.install,
                executable: Some(Vec::new()),
            },
        )
        .unwrap_err();
        assert!(matches!(error, CompilerError::ProjectNotEditable));
        assert_eq!(fs::read(&config).unwrap(), signed.as_bytes());
    }

    #[test]
    fn studio_update_preserves_executables_and_replaces_its_unix_entrypoint_intent() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        fs::create_dir_all(project.join("payload/bin")).unwrap();
        for path in ["old", "new", "helper"] {
            fs::write(project.join("payload/bin").join(path), path.as_bytes()).unwrap();
        }
        let config = project.join(PROJECT_FILE);
        let source = fs::read_to_string(&config)
            .unwrap()
            .replacen(
                "format_version = 1",
                "format_version = 1\nschema_version = 2",
                1,
            )
            .replace(&format!("os = \"{}\"", Target::host().os), "os = \"linux\"")
            .replace(
                "directory = \"Luxury Demo\"",
                "directory = \"Luxury Demo\"\nentrypoint = \"bin/old\"",
            )
            .replace(
                "executable = []",
                "executable = [\"bin/old\", \"bin/helper\"]",
            );
        fs::write(&config, source).unwrap();
        let current = validate_project(&project).unwrap();
        fs::remove_file(project.join("payload/bin/old")).unwrap();
        let mut install = current.install.clone();
        install.entrypoint = Some(PackagePath::parse("bin/new").unwrap());
        let updated = update_project(
            &project,
            ProjectUpdate {
                package: current.package,
                target: current.target,
                install,
                executable: None,
            },
        )
        .unwrap();
        let executable = updated
            .files
            .iter()
            .filter(|file| file.executable)
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(executable, ["bin/helper", "bin/new"]);
    }

    #[test]
    fn studio_import_replaces_only_the_starter_and_never_overwrites_payload() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let sources = temp.path().join("sources");
        fs::create_dir_all(sources.join("assets")).unwrap();
        let app = sources.join("app.bin");
        fs::write(&app, b"application").unwrap();
        fs::write(sources.join("assets/config.json"), b"{}").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&app, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let imported = import_payload(&project, &[app.clone(), sources.join("assets")]).unwrap();
        assert_eq!(
            imported
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            ["app.bin", "assets/config.json"]
        );
        assert!(!project.join("payload").join(SAMPLE_FILE).exists());
        assert_eq!(
            fs::read(project.join("payload/app.bin")).unwrap(),
            b"application"
        );
        assert_eq!(
            resolve_payload_file(&project, project.join("payload/app.bin"))
                .unwrap()
                .as_str(),
            "app.bin"
        );
        assert!(matches!(
            resolve_payload_file(&project, &app),
            Err(CompilerError::OutsideRoot { .. })
        ));
        #[cfg(unix)]
        assert!(imported.files[0].executable);
        #[cfg(not(unix))]
        assert!(!imported.files[0].executable);

        let new_source = sources.join("a-new.bin");
        let conflicting = sources.join("app.bin");
        fs::write(&new_source, b"new").unwrap();
        fs::write(&conflicting, b"replacement").unwrap();
        let error = import_payload(&project, &[new_source, conflicting]).unwrap_err();
        assert!(matches!(error, CompilerError::ImportConflict(_)));
        assert!(!project.join("payload/a-new.bin").exists());
        assert_eq!(
            fs::read(project.join("payload/app.bin")).unwrap(),
            b"application"
        );
        assert_eq!(validate_project(&project).unwrap(), imported);

        let empty = sources.join("empty");
        fs::create_dir(&empty).unwrap();
        assert!(matches!(
            import_payload(&project, &[empty]),
            Err(CompilerError::EmptyImport)
        ));
        assert_eq!(validate_project(&project).unwrap(), imported);

        let non_starter_project = temp.path().join("non-starter");
        init_project(&non_starter_project).unwrap();
        fs::write(non_starter_project.join("payload/user.txt"), b"keep").unwrap();
        let extra = sources.join("extra.bin");
        fs::write(&extra, b"extra").unwrap();
        import_payload(&non_starter_project, &[extra]).unwrap();
        assert_eq!(
            fs::read(non_starter_project.join("payload/hello.txt")).unwrap(),
            SAMPLE_PAYLOAD
        );
        assert_eq!(
            fs::read(non_starter_project.join("payload/user.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn studio_payload_replacement_swaps_the_whole_tree_and_keeps_precommit_failures_unchanged() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();

        let first_source = temp.path().join("first");
        fs::create_dir(&first_source).unwrap();
        fs::write(first_source.join("old.exe"), b"old application").unwrap();
        fs::write(first_source.join("shared.txt"), b"old shared").unwrap();
        let first = replace_payload(&project, &first_source).unwrap();
        let mut install = first.install.clone();
        install.entrypoint = Some(PackagePath::parse("old.exe").unwrap());
        install.shortcuts.application_menu = true;
        install.shortcuts.desktop = true;
        let configured = update_project(
            &project,
            ProjectUpdate {
                package: first.package,
                target: Target {
                    os: luxury_spec::OperatingSystem::Windows,
                    arch: first.target.arch,
                },
                install,
                executable: None,
            },
        )
        .unwrap();
        assert_eq!(
            configured.schema_version,
            luxury_spec::SHORTCUT_SCHEMA_VERSION
        );

        let next_source = temp.path().join("next");
        fs::create_dir_all(next_source.join("assets")).unwrap();
        fs::write(next_source.join("OLD.EXE"), b"new application").unwrap();
        fs::write(next_source.join("shared.txt"), b"new shared").unwrap();
        fs::write(next_source.join("assets/data.bin"), b"data").unwrap();
        let replaced = replace_payload(&project, &next_source).unwrap();
        assert_eq!(replaced.schema_version, 1);
        assert!(replaced.install.entrypoint.is_none());
        assert!(!replaced.install.shortcuts.enabled());
        assert_eq!(
            replaced
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            ["OLD.EXE", "assets/data.bin", "shared.txt"]
        );
        assert_eq!(
            fs::read(project.join("payload/shared.txt")).unwrap(),
            b"new shared"
        );

        let empty = temp.path().join("empty");
        fs::create_dir(&empty).unwrap();
        assert!(matches!(
            replace_payload(&project, &empty),
            Err(CompilerError::EmptyImport)
        ));
        assert_eq!(validate_project(&project).unwrap(), replaced);

        assert!(matches!(
            replace_payload(&project, next_source.join("OLD.EXE")),
            Err(CompilerError::InvalidImportSource(_))
        ));
        assert_eq!(validate_project(&project).unwrap(), replaced);

        let cancelled = AtomicBool::new(true);
        assert!(matches!(
            replace_payload_cancellable(&project, &first_source, &cancelled),
            Err(CompilerError::Cancelled)
        ));
        assert_eq!(validate_project(&project).unwrap(), replaced);
    }

    #[test]
    fn atomic_output_replacement_preserves_unrelated_legacy_backup_names() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let output = temp.path().join("demo.luxpkg");
        compile_project(&project, &output).unwrap();
        let previous = fs::read(&output).unwrap();

        let legacy_backups = (0..100)
            .map(|attempt| {
                temp.path()
                    .join(format!(".demo.luxpkg.{}-old-{attempt}", std::process::id()))
            })
            .collect::<Vec<_>>();
        for backup in &legacy_backups {
            fs::write(backup, b"foreign").unwrap();
        }
        fs::write(project.join("payload").join(SAMPLE_FILE), b"updated").unwrap();

        compile_project(&project, &output).unwrap();
        assert_ne!(fs::read(&output).unwrap(), previous);
        for backup in legacy_backups {
            assert_eq!(fs::read(backup).unwrap(), b"foreign");
        }
    }

    #[test]
    fn validates_and_compiles_a_deterministic_schema_two_entrypoint() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();

        let (entrypoint, executable) = match Target::host().os {
            luxury_spec::OperatingSystem::Windows => ("bin/app.EXE", "executable = []"),
            luxury_spec::OperatingSystem::Linux | luxury_spec::OperatingSystem::Macos => {
                ("bin/app", "executable = [\"bin/app\"]")
            }
        };
        let entrypoint_path = project
            .join("payload")
            .join(entrypoint.replace('/', std::path::MAIN_SEPARATOR_STR));
        fs::create_dir_all(entrypoint_path.parent().unwrap()).unwrap();
        fs::write(&entrypoint_path, b"entrypoint").unwrap();

        let config = project.join(PROJECT_FILE);
        let source = fs::read_to_string(&config)
            .unwrap()
            .replacen(
                "format_version = 1",
                &format!("format_version = 1\nschema_version = {ENTRYPOINT_SCHEMA_VERSION}"),
                1,
            )
            .replacen(
                "directory = \"Luxury Demo\"",
                &format!("directory = \"Luxury Demo\"\nentrypoint = \"{entrypoint}\""),
                1,
            )
            .replacen("executable = []", executable, 1);
        fs::write(&config, source).unwrap();

        let validated = validate_project(&project).unwrap();
        assert_eq!(validated.schema_version, ENTRYPOINT_SCHEMA_VERSION);
        assert_eq!(
            validated.install.entrypoint.as_ref().unwrap().as_str(),
            entrypoint
        );

        let output = temp.path().join("entrypoint.luxpkg");
        let compiled = compile_project(&project, &output).unwrap();
        let first_bundle = fs::read(&output).unwrap();
        compile_project(&project, &output).unwrap();
        assert_eq!(fs::read(&output).unwrap(), first_bundle);
        assert_eq!(compiled, validated);
        assert_eq!(
            open_bundle(File::open(output).unwrap(), None)
                .unwrap()
                .manifest(),
            &compiled
        );
    }

    #[test]
    fn validates_and_compiles_schema_four_shortcut_intent() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let (entrypoint, executable) = match Target::host().os {
            luxury_spec::OperatingSystem::Windows => ("bin/app.exe", "executable = []"),
            luxury_spec::OperatingSystem::Linux | luxury_spec::OperatingSystem::Macos => {
                ("bin/app", "executable = [\"bin/app\"]")
            }
        };
        let entrypoint_path = project
            .join("payload")
            .join(entrypoint.replace('/', std::path::MAIN_SEPARATOR_STR));
        fs::create_dir_all(entrypoint_path.parent().unwrap()).unwrap();
        fs::write(&entrypoint_path, b"entrypoint").unwrap();

        let config = project.join(PROJECT_FILE);
        let source = fs::read_to_string(&config)
            .unwrap()
            .replacen(
                "format_version = 1",
                &format!(
                    "format_version = 1\nschema_version = {}",
                    luxury_spec::SHORTCUT_SCHEMA_VERSION
                ),
                1,
            )
            .replacen(
                "directory = \"Luxury Demo\"",
                &format!(
                    "directory = \"Luxury Demo\"\nentrypoint = \"{entrypoint}\"\n\n[install.shortcuts]\napplication_menu = true\ndesktop = true"
                ),
                1,
            )
            .replacen("executable = []", executable, 1);
        fs::write(&config, source).unwrap();

        let validated = validate_project(&project).unwrap();
        assert_eq!(
            validated.schema_version,
            luxury_spec::SHORTCUT_SCHEMA_VERSION
        );
        assert!(validated.install.shortcuts.application_menu);
        assert!(validated.install.shortcuts.desktop);

        let output = temp.path().join("shortcuts.luxpkg");
        assert_eq!(compile_project(&project, &output).unwrap(), validated);
        assert_eq!(
            open_bundle(File::open(output).unwrap(), None)
                .unwrap()
                .manifest()
                .install
                .shortcuts,
            validated.install.shortcuts
        );
    }

    #[test]
    fn compiles_a_deterministic_signed_v2_project() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let config = project.join(PROJECT_FILE);
        fs::write(
            &config,
            fs::read_to_string(&config).unwrap().replacen(
                "format_version = 1",
                "format_version = 2",
                1,
            ),
        )
        .unwrap();
        let signing_key = PackageSigningKey::from_pkcs8_pem(TEST_SIGNING_KEY_PEM).unwrap();
        let output = temp.path().join("signed.luxpkg");

        let manifest = compile_signed_project(&project, &output, &signing_key).unwrap();
        let first_bundle = fs::read(&output).unwrap();
        compile_signed_project(&project, &output, &signing_key).unwrap();

        assert_eq!(manifest.format_version, SIGNED_FORMAT_VERSION);
        assert_eq!(fs::read(&output).unwrap(), first_bundle);
        let trusted_key =
            luxury_bundle::TrustedPublisherKey::from_public_key_pem(TEST_TRUSTED_KEY_PEM).unwrap();
        let bundle = open_bundle(File::open(output).unwrap(), Some(&trusted_key)).unwrap();
        assert_eq!(bundle.manifest(), &manifest);
        assert_eq!(
            bundle.trust(),
            PackageTrust::TrustedPublisher {
                key_id: signing_key.key_id()
            }
        );
    }

    #[test]
    fn compiles_a_deterministic_v3_rotation_without_private_key_material() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let current = PackageSigningKey::from_pkcs8_pem(TEST_SIGNING_KEY_PEM).unwrap();
        let next = PackageSigningKey::from_pkcs8_pem(NEXT_SIGNING_KEY_PEM).unwrap();
        let package_id = PackageId::parse("dev.luxury.demo").unwrap();
        let version = validate_project(&project).unwrap().package.version;
        let rotation = next
            .create_publisher_rotation(&package_id, &version, current.key_id())
            .unwrap();
        configure_rotation(&project, &rotation);
        let output = temp.path().join("rotation.luxpkg");
        let validated = validate_project(&project).unwrap();
        assert_eq!(validated.format_version, PUBLISHER_ROTATION_FORMAT_VERSION);
        assert_eq!(validated.publisher_rotation.as_ref(), Some(&rotation));

        assert!(matches!(
            compile_project(&project, temp.path().join("unsigned-v3.luxpkg")),
            Err(CompilerError::UnsignedBuildFormat {
                found: PUBLISHER_ROTATION_FORMAT_VERSION
            })
        ));

        let manifest = compile_signed_project(&project, &output, &current).unwrap();
        let first_bundle = fs::read(&output).unwrap();
        compile_signed_project(&project, &output, &current).unwrap();

        assert_eq!(manifest.format_version, PUBLISHER_ROTATION_FORMAT_VERSION);
        assert_eq!(manifest.publisher_rotation.as_ref(), Some(&rotation));
        assert_eq!(fs::read(&output).unwrap(), first_bundle);
        assert!(
            !first_bundle
                .windows(TEST_SIGNING_KEY_PEM.len())
                .any(|bytes| bytes == TEST_SIGNING_KEY_PEM.as_bytes())
        );
        assert!(
            !first_bundle
                .windows(NEXT_SIGNING_KEY_PEM.len())
                .any(|bytes| bytes == NEXT_SIGNING_KEY_PEM.as_bytes())
        );

        let trusted_key =
            luxury_bundle::TrustedPublisherKey::from_public_key_pem(TEST_TRUSTED_KEY_PEM).unwrap();
        let bundle = open_bundle(File::open(output).unwrap(), Some(&trusted_key)).unwrap();
        let verified = bundle.publisher_rotation().unwrap();
        assert_eq!(verified.from_key_id, current.key_id());
        assert_eq!(verified.to_key_id, next.key_id());
    }

    #[test]
    fn signed_v3_build_rejects_an_invalid_rotation_proof_without_output() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let current = PackageSigningKey::from_pkcs8_pem(TEST_SIGNING_KEY_PEM).unwrap();
        let next = PackageSigningKey::from_pkcs8_pem(NEXT_SIGNING_KEY_PEM).unwrap();
        let version = validate_project(&project).unwrap().package.version;
        let mut rotation = next
            .create_publisher_rotation(
                &PackageId::parse("dev.luxury.demo").unwrap(),
                &version,
                current.key_id(),
            )
            .unwrap();
        rotation.proof = luxury_spec::PublisherRotationProof::from_bytes([0; 64]);
        configure_rotation(&project, &rotation);
        let output = temp.path().join("invalid-rotation.luxpkg");

        assert!(matches!(
            compile_signed_project(&project, &output, &current),
            Err(CompilerError::Bundle(
                luxury_bundle::BundleError::InvalidPublisherRotationProof
            ))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn malformed_rotation_config_does_not_echo_rejected_secret_material() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let config = project.join(PROJECT_FILE);
        let secret = concat!("-----BEGIN PRIVATE ", "KEY-----SECRET-MARKER");
        let source = fs::read_to_string(&config).unwrap().replacen(
            "format_version = 1",
            "format_version = 3",
            1,
        );
        fs::write(
            config,
            format!(
                "{source}\n[publisher_rotation]\nnext_public_key = \"{secret}\"\nproof = \"{}\"\n",
                "0".repeat(128)
            ),
        )
        .unwrap();

        let error = validate_project(&project).unwrap_err();
        let rendered = format!("{error}\n{error:?}");
        assert!(error.to_string().contains("invalid publisher public key"));
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("PRIVATE KEY"));
    }

    #[test]
    fn validates_v1_and_v2_projects_without_writing_a_bundle() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let output = temp.path().join("validation-must-not-write.luxpkg");
        init_project(&project).unwrap();

        let v1 = validate_project(&project).unwrap();
        assert_eq!(v1.format_version, FORMAT_VERSION);
        assert_eq!(v1.files.len(), 1);
        assert!(!output.exists());

        let config = project.join(PROJECT_FILE);
        fs::write(
            &config,
            fs::read_to_string(&config).unwrap().replacen(
                "format_version = 1",
                "format_version = 2",
                1,
            ),
        )
        .unwrap();
        let v2 = validate_project(&project).unwrap();
        assert_eq!(v2.format_version, SIGNED_FORMAT_VERSION);
        assert_eq!(v2.files, v1.files);
        assert!(!output.exists());
    }

    #[test]
    fn pre_cancelled_compile_does_not_create_output() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let output = temp.path().join("cancelled.luxpkg");
        init_project(&project).unwrap();
        let cancelled = AtomicBool::new(true);

        assert!(matches!(
            compile_project_cancellable(&project, &output, &cancelled),
            Err(CompilerError::Cancelled)
        ));
        assert!(!output.exists());
    }

    #[test]
    fn rejects_oversized_project_configuration() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        fs::write(
            project.join(PROJECT_FILE),
            vec![b' '; MAX_PROJECT_CONFIG_BYTES as usize + 1],
        )
        .unwrap();

        assert!(matches!(
            validate_project(&project),
            Err(CompilerError::ConfigTooLarge {
                limit: MAX_PROJECT_CONFIG_BYTES
            })
        ));
    }

    #[test]
    fn unsigned_and_signed_compilers_reject_the_other_format() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let signing_key = PackageSigningKey::from_pkcs8_pem(TEST_SIGNING_KEY_PEM).unwrap();

        assert!(matches!(
            compile_signed_project(
                &project,
                temp.path().join("not-signed.luxpkg"),
                &signing_key
            ),
            Err(CompilerError::SignedBuildFormat {
                found: FORMAT_VERSION
            })
        ));

        let config = project.join(PROJECT_FILE);
        fs::write(
            &config,
            fs::read_to_string(&config).unwrap().replacen(
                "format_version = 1",
                "format_version = 2",
                1,
            ),
        )
        .unwrap();
        assert!(matches!(
            compile_project(&project, temp.path().join("not-unsigned.luxpkg")),
            Err(CompilerError::UnsignedBuildFormat {
                found: SIGNED_FORMAT_VERSION
            })
        ));
    }

    #[test]
    fn sorts_files_and_requires_exact_executable_paths() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        fs::create_dir_all(project.join("payload/bin")).unwrap();
        fs::write(project.join("payload/z.txt"), b"z").unwrap();
        fs::write(project.join("payload/bin/app"), b"app").unwrap();
        fs::write(
            project.join(PROJECT_FILE),
            sample_config().replace("executable = []", "executable = [\"bin/app\"]"),
        )
        .unwrap();

        let manifest = compile_project(&project, temp.path().join("ok.luxpkg")).unwrap();
        assert_eq!(
            manifest
                .files
                .iter()
                .map(|file| (file.path.as_str(), file.executable))
                .collect::<Vec<_>>(),
            [("bin/app", true), ("z.txt", false)]
        );

        let config = fs::read_to_string(project.join(PROJECT_FILE)).unwrap();
        fs::write(
            project.join(PROJECT_FILE),
            config.replace("bin/app", "BIN/app"),
        )
        .unwrap();
        assert!(matches!(
            compile_project(&project, temp.path().join("bad.luxpkg")),
            Err(CompilerError::MissingExecutable(path)) if path == "BIN/app"
        ));

        fs::write(
            project.join(PROJECT_FILE),
            sample_config().replace("executable = []", "executable = [\"bin/app\", \"BIN/app\"]"),
        )
        .unwrap();
        assert!(matches!(
            compile_project(&project, temp.path().join("duplicate.luxpkg")),
            Err(CompilerError::DuplicateExecutable(path)) if path == "BIN/app"
        ));
    }

    #[test]
    fn rejects_unknown_fields_and_links() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();

        let config = project.join(PROJECT_FILE);
        fs::write(
            &config,
            fs::read_to_string(&config).unwrap() + "\nfiles = []\n",
        )
        .unwrap();
        assert!(matches!(
            compile_project(&project, temp.path().join("bad.luxpkg")),
            Err(CompilerError::InvalidConfig(_))
        ));

        fs::write(&config, sample_config()).unwrap();
        let link = create_link(
            &project.join("payload/link"),
            &project.join("payload/hello.txt"),
        );
        #[cfg(windows)]
        if link
            .as_ref()
            .is_err_and(|error| error.raw_os_error() == Some(1314))
        {
            return;
        }
        link.unwrap();
        assert!(matches!(
            compile_project(&project, temp.path().join("link.luxpkg")),
            Err(CompilerError::Link(_))
        ));
    }

    #[test]
    fn init_never_overwrites_existing_files() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        init_project(&project).unwrap();

        let config = project.join(PROJECT_FILE);
        fs::write(&config, "keep me").unwrap();

        assert!(init_project(&project).is_err());
        assert_eq!(fs::read_to_string(config).unwrap(), "keep me");
        assert_eq!(
            fs::read(project.join("payload").join(SAMPLE_FILE)).unwrap(),
            SAMPLE_PAYLOAD
        );

        let conflict = temp.path().join("conflict");
        fs::create_dir_all(&conflict).unwrap();
        fs::write(conflict.join(PROJECT_FILE), "keep me").unwrap();
        assert!(init_project(&conflict).is_err());
        assert!(!conflict.join("payload").exists());
    }

    #[cfg(unix)]
    fn create_link(link: &Path, target: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_link(link: &Path, target: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }
}
