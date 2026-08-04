use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write, copy},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    HostLayout, ShellFlavor, assemble_into, bounded_output, exact_object, is_link_or_reparse,
    patch_setup_template_binding,
    probe::{
        probe_authenticated_container_runner, probe_authenticated_runner, probe_backend,
        probe_container_runner, probe_runner,
    },
    require_setup_template_binding, required_hash, required_string, required_u64, sha256_hex,
    staging::{
        WorkDirectory, checked_input, copy_file, ensure_real_directory, publish_file_no_clobber,
        require_missing, require_only_file, require_regular_file, retry_transient_io, sha256_file,
    },
    validate_portable_bundle,
};

const NSIS_LOCK: &str = include_str!("../../../packaging/windows/nsis.lock.json");
const NSIS_SCRIPT: &[u8] = include_bytes!("../../../packaging/windows/portable.nsi");
const SETUP_FILENAME: &str = "LuxuryInstallerSetup.dev.exe";
const SIGN_ME_FILENAME: &str = "LuxuryInstallerSetup.sign-me.exe";
const PROVENANCE_FILENAME: &str = "provenance.json";

struct PreparedNsis {
    root: PathBuf,
    makensis: PathBuf,
    private_temp: PathBuf,
    directories: WindowsDirectories,
    tree_sha256: String,
}

#[derive(Debug, PartialEq, Eq)]
struct NsisPin {
    version: String,
    url: String,
    archive_name: String,
    archive_size: u64,
    archive_sha256: String,
    archive_root: String,
    makensis_path: String,
    version_output: String,
}

pub(super) fn build(package: &Path, nsis_archive: &Path) -> Result<(), String> {
    if env::consts::OS != "windows" || env::consts::ARCH != "x86_64" {
        return Err("windows-setup requires a native Windows x86_64 host".into());
    }

    let root = crate::workspace_root();
    let target = super::resolve_target_dir(&root, env::var_os("CARGO_TARGET_DIR").as_deref());
    ensure_real_directory(&target)?;
    let output = target.join("windows-setup");
    ensure_real_directory(&output)?;
    let pin = parse_pin(NSIS_LOCK)?;
    let package = checked_input(package, "Windows Setup payload")?;
    let nsis_archive = checked_input(nsis_archive, "pinned NSIS archive")?;

    let work = WorkDirectory::new(&output)?;
    let result = build_in_work(&output, &work.path, &package, &nsis_archive, &pin);
    match result {
        Ok(artifact) => {
            work.cleanup().map_err(|error| {
                format!(
                    "verified Windows Setup was published at `{}`, but {error}",
                    artifact.display()
                )
            })?;
            println!(
                "verified unsigned Windows development Setup: {}",
                artifact.display()
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub(super) fn build_project(project: &Path, destination: &Path) -> Result<(), String> {
    if env::consts::OS != "windows" || env::consts::ARCH != "x86_64" {
        return Err("Windows Setup.exe project builds require native Windows x86_64".into());
    }
    let parent = validate_project_output(project, destination)?;
    ensure_real_directory(parent)?;
    require_missing(destination, "Windows Setup.exe output")?;

    let root = crate::workspace_root();
    let target = super::resolve_target_dir(&root, env::var_os("CARGO_TARGET_DIR").as_deref());
    fs::create_dir_all(&target)
        .map_err(|error| format!("could not create target directory: {error}"))?;
    ensure_real_directory(&target)?;
    let pin = parse_pin(NSIS_LOCK)?;
    let nsis_archive = cached_nsis_archive(&target, &pin)?;

    let work = WorkDirectory::new(parent)?;
    let package = work.path.join("internal-package.luxpkg");
    luxury_compiler::compile_project(project, &package)
        .map_err(|error| format!("could not compile installer project: {error}"))?;
    let package = checked_input(&package, "internal Windows Setup payload")?;

    let output = work.path.join("container-output");
    let container_work = work.path.join("container-work");
    fs::create_dir(&output)
        .map_err(|error| format!("could not create container output directory: {error}"))?;
    fs::create_dir(&container_work)
        .map_err(|error| format!("could not create container work directory: {error}"))?;
    let artifact = build_in_work(&output, &container_work, &package, &nsis_archive, &pin)?;
    let setup = artifact.join(SETUP_FILENAME);
    publish_file_no_clobber(&setup, destination)?;
    work.cleanup().map_err(|error| {
        format!(
            "verified Windows Setup.exe was published at `{}`, but {error}",
            destination.display()
        )
    })?;
    println!(
        "verified unsigned Windows development Setup.exe: {}",
        destination.display()
    );
    Ok(())
}

pub(super) fn build_packaged_project(
    project: &Path,
    destination: &Path,
    resources: &Path,
) -> Result<(), String> {
    if env::consts::OS != "windows" || env::consts::ARCH != "x86_64" {
        return Err("packaged Windows project builds require native Windows x86_64".into());
    }
    let parent = validate_project_output(project, destination)?;
    ensure_real_directory(parent)?;
    require_missing(destination, "Windows Setup.exe output")?;

    let host = HostLayout::new("windows", "x86_64")?;
    let template = resources.join("templates").join("windows-x86_64");
    validate_portable_bundle(&template, host, ShellFlavor::SetupTemplate, None)?;
    require_setup_template_binding(&host.launcher(&template))?;
    let nsis_archive = resources.join("tools").join("nsis-3.12.zip");
    let pin = parse_pin(NSIS_LOCK)?;
    verify_pinned_archive(&nsis_archive, &pin)?;

    let work = WorkDirectory::new(parent)?;
    let package = work.path.join("internal-package.luxpkg");
    luxury_compiler::compile_project(project, &package)
        .map_err(|error| format!("could not compile installer project: {error}"))?;
    let package = checked_input(&package, "internal Windows Setup payload")?;
    let template_backend = host
        .resources_directory(&template)
        .join("backend")
        .join(host.backend_name);
    let fingerprint = probe_backend(&template_backend, &package, host)?;

    let runner_name = super::artifact_name(host, &fingerprint)?;
    let runner = work.path.join(runner_name);
    copy_tree(&template, &runner)?;
    let launcher = host.launcher(&runner);
    patch_setup_template_binding(&launcher, &fingerprint)?;
    let payload = host
        .resources_directory(&runner)
        .join("payload")
        .join("package.luxpkg");
    fs::create_dir(
        payload
            .parent()
            .ok_or_else(|| "packaged Windows payload has no parent".to_owned())?,
    )
    .map_err(|error| format!("could not create packaged Windows payload directory: {error}"))?;
    copy_file(&package, &payload)?;
    validate_portable_bundle(&runner, host, ShellFlavor::Setup, None)?;
    let backend = host
        .resources_directory(&runner)
        .join("backend")
        .join(host.backend_name);
    if probe_backend(&backend, &payload, host)? != fingerprint {
        return Err("packaged Windows template inspected a different payload".into());
    }
    probe_runner(&launcher)?;

    let nsis = prepare_nsis(&work.path, &nsis_archive, &pin)?;
    let output = work.path.join("container-output");
    fs::create_dir(&output)
        .map_err(|error| format!("could not create container output directory: {error}"))?;
    let artifact = wrap_runner(
        &output,
        &work.path,
        &runner,
        &super::artifact_name(host, &fingerprint)?,
        &sha256_hex(sha256_file(&package)?),
        None,
        &nsis,
        &pin,
    )?;
    publish_file_no_clobber(&artifact.join(SETUP_FILENAME), destination)?;
    work.cleanup().map_err(|error| {
        format!(
            "verified Windows Setup.exe was published at `{}`, but {error}",
            destination.display()
        )
    })?;
    println!(
        "verified unsigned Windows development Setup.exe: {}",
        destination.display()
    );
    Ok(())
}

fn validate_project_output<'a>(project: &Path, destination: &'a Path) -> Result<&'a Path, String> {
    if !project.is_absolute() || !destination.is_absolute() {
        return Err("project-installer paths must be absolute".into());
    }
    if !destination
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
    {
        return Err("Windows project-installer output must end in .exe".into());
    }
    destination
        .parent()
        .ok_or_else(|| "Windows Setup.exe output has no parent directory".to_owned())
}

fn cached_nsis_archive(target: &Path, pin: &NsisPin) -> Result<PathBuf, String> {
    let cache = target.join("tool-cache");
    fs::create_dir_all(&cache)
        .map_err(|error| format!("could not create tool cache directory: {error}"))?;
    ensure_real_directory(&cache)?;
    let archive = cache.join(&pin.archive_name);
    if archive.exists() {
        verify_pinned_archive(&archive, pin)?;
        return Ok(archive);
    }

    let work = WorkDirectory::new(&cache)?;
    let downloaded = work.path.join(&pin.archive_name);
    let status = Command::new("curl.exe")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--ssl-revoke-best-effort",
            "--http1.1",
            "--retry",
            "3",
            "--retry-all-errors",
            "--output",
        ])
        .arg(&downloaded)
        .arg(&pin.url)
        .status()
        .map_err(|error| format!("could not start the built-in Windows curl client: {error}"))?;
    if !status.success()
        && let Err(verification) = verify_pinned_archive(&downloaded, pin)
    {
        return Err(format!(
            "pinned NSIS download exited with {status}; {verification}"
        ));
    }
    verify_pinned_archive(&downloaded, pin)?;
    if let Err(error) = copy_file(&downloaded, &archive)
        && (!archive.exists() || verify_pinned_archive(&archive, pin).is_err())
    {
        return Err(error);
    }
    verify_pinned_archive(&archive, pin)?;
    work.cleanup()?;
    Ok(archive)
}

pub(super) fn cached_studio_nsis(target: &Path) -> Result<PathBuf, String> {
    cached_nsis_archive(target, &parse_pin(NSIS_LOCK)?)
}

pub(super) fn build_signed_runner(runner: &Path, nsis_archive: &Path) -> Result<(), String> {
    if env::consts::OS != "windows" || env::consts::ARCH != "x86_64" {
        return Err("windows-release-setup requires a native Windows x86_64 host".into());
    }
    let root = crate::workspace_root();
    let target = super::resolve_target_dir(&root, env::var_os("CARGO_TARGET_DIR").as_deref());
    ensure_real_directory(&target)?;
    let output = target.join("windows-release-setup");
    ensure_real_directory(&output)?;
    let runner = checked_runner(runner)?;
    let nsis_archive = checked_input(nsis_archive, "pinned NSIS archive")?;
    let pin = parse_pin(NSIS_LOCK)?;
    let work = WorkDirectory::new(&output)?;
    let result = build_signed_in_work(&output, &work.path, &runner, &nsis_archive, &pin);
    match result {
        Ok(artifact) => {
            work.cleanup().map_err(|error| {
                format!(
                    "signing-ready Windows Setup was published at `{}`, but {error}",
                    artifact.display()
                )
            })?;
            println!(
                "verified Windows Setup with signed inner runner; sign outer container next: {}",
                artifact.display()
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub(super) fn verify_signed_setup(setup: &Path) -> Result<(), String> {
    if env::consts::OS != "windows" || env::consts::ARCH != "x86_64" {
        return Err("verify-windows-release must run on Windows x86_64".into());
    }
    let setup = checked_input(setup, "signed Windows Setup")?;
    require_pe(&setup)?;
    let guard = open_read_guard(&setup)?;
    let signer = luxury_windows_trust::verify_authenticode_signer(&setup)
        .map_err(|error| error.to_string())?;
    let before = sha256_file(&setup)?;
    let root = crate::workspace_root();
    let target = super::resolve_target_dir(&root, env::var_os("CARGO_TARGET_DIR").as_deref());
    ensure_real_directory(&target)?;
    let verification = target.join("windows-release-verification");
    ensure_real_directory(&verification)?;
    let work = WorkDirectory::new(&verification)?;
    let result = (|| {
        probe_authenticated_container_runner(&setup, &work.path)?;
        require_argument_rejection(&setup, &work.path)?;
        require_empty_directory(&work.path, "signed Setup probe temp")?;
        if sha256_file(&setup)? != before {
            return Err("signed Windows Setup changed during final verification".into());
        }
        Ok(())
    })();
    drop(guard);
    match (result, work.cleanup()) {
        (Ok(()), Ok(())) => {
            println!(
                "verified final signed Windows Setup and signer-bound inner runner: {}",
                sha256_hex(signer.certificate_sha256())
            );
            Ok(())
        }
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}

fn build_in_work(
    output: &Path,
    work: &Path,
    package: &Path,
    nsis_archive: &Path,
    pin: &NsisPin,
) -> Result<PathBuf, String> {
    let inputs = work.join("inputs");
    fs::create_dir(&inputs)
        .map_err(|error| format!("could not create container input directory: {error}"))?;
    let package = stage_package(package, &inputs.join("package.luxpkg"))?;
    let package_sha256 = sha256_hex(sha256_file(&package.path)?);
    let nsis = prepare_nsis(work, nsis_archive, pin)?;

    let runner_output = work.join("runner-output");
    let assembled = assemble_into(&package.path, &runner_output)?;
    let bundle = assembled.path;
    let runner_artifact = artifact_name(&bundle)?;
    wrap_runner(
        output,
        work,
        &bundle,
        &runner_artifact,
        &package_sha256,
        None,
        &nsis,
        pin,
    )
}

fn build_signed_in_work(
    output: &Path,
    work: &Path,
    source_runner: &Path,
    nsis_archive: &Path,
    pin: &NsisPin,
) -> Result<PathBuf, String> {
    let host = HostLayout::new("windows", "x86_64")?;
    validate_portable_bundle(source_runner, host, ShellFlavor::Setup, None)?;
    let runner_artifact = artifact_name(source_runner)?;
    let launcher = host.launcher(source_runner);
    let resources = host.resources_directory(source_runner);
    let backend = resources.join("backend").join(host.backend_name);
    let payload = resources.join("payload").join("package.luxpkg");
    let signer = luxury_windows_trust::verify_same_authenticode_signer(&launcher, &backend)
        .map_err(|error| error.to_string())?;
    let before = hash_tree(source_runner)?;
    probe_runner(&launcher)?;
    probe_authenticated_runner(&launcher)?;
    if hash_tree(source_runner)? != before {
        return Err("signed Windows runner changed during authenticated verification".into());
    }
    let fingerprint = probe_backend(&backend, &payload, host)?;
    if !runner_artifact.ends_with(&fingerprint[..12]) {
        return Err("signed Windows runner name does not match its bound package".into());
    }
    let package_sha256 = sha256_hex(sha256_file(&payload)?);
    let staged = work.join("signed-runner-input");
    copy_tree(source_runner, &staged)?;
    if hash_tree(&staged)? != before {
        return Err("signed Windows runner changed while staging for NSIS".into());
    }
    let nsis = prepare_nsis(work, nsis_archive, pin)?;
    wrap_runner(
        output,
        work,
        &staged,
        &runner_artifact,
        &package_sha256,
        Some(sha256_hex(signer.certificate_sha256())),
        &nsis,
        pin,
    )
}

fn prepare_nsis(work: &Path, archive: &Path, pin: &NsisPin) -> Result<PreparedNsis, String> {
    let staged = stage_pinned_archive(archive, &work.join(&pin.archive_name), pin)?;
    let extract = work.join("nsis");
    let private_temp = work.join("tool-temp");
    fs::create_dir(&extract)
        .map_err(|error| format!("could not create NSIS extraction directory: {error}"))?;
    fs::create_dir(&private_temp)
        .map_err(|error| format!("could not create private tool temp directory: {error}"))?;
    let directories = windows_directories()?;
    extract_archive(&staged.path, &extract, &private_temp, &directories)?;
    verify_pinned_archive(&staged.path, pin)?;
    let root = extract.join(&pin.archive_root);
    require_single_directory(&extract, &pin.archive_root)?;
    let tree_sha256 = hash_tree(&root)?;
    let makensis = extract.join(path_from_forward_slashes(&pin.makensis_path)?);
    require_regular_file(&makensis, "pinned makensis launcher")?;
    verify_makensis(
        &makensis,
        &root,
        &private_temp,
        &directories,
        &pin.version_output,
    )?;
    Ok(PreparedNsis {
        root,
        makensis,
        private_temp,
        directories,
        tree_sha256,
    })
}

#[allow(clippy::too_many_arguments)]
fn wrap_runner(
    output: &Path,
    work: &Path,
    bundle: &Path,
    runner_artifact: &str,
    package_sha256: &str,
    inner_signer: Option<String>,
    nsis: &PreparedNsis,
    pin: &NsisPin,
) -> Result<PathBuf, String> {
    let build = work.join("container-build");
    fs::create_dir(&build)
        .map_err(|error| format!("could not create container build directory: {error}"))?;
    let runner = build.join("runner");
    retry_transient_io(|| fs::rename(bundle, &runner))
        .map_err(|error| format!("could not stage verified runner for NSIS: {error}"))?;
    let runner_tree_sha256 = hash_tree(&runner)?;
    let packaged_payload = runner.join("payload").join("package.luxpkg");
    require_regular_file(&packaged_payload, "packaged Setup payload")?;
    let packaged_payload_sha256 = sha256_hex(sha256_file(&packaged_payload)?);
    if packaged_payload_sha256 != package_sha256 {
        return Err("packaged Setup payload changed after input staging".into());
    }

    let script = build.join("portable.nsi");
    let script_sha256 = sha256_hex(Sha256::digest(NSIS_SCRIPT).into());
    write_new(&script, NSIS_SCRIPT)?;
    if sha256_hex(sha256_file(&script)?) != script_sha256 {
        return Err("staged NSIS script does not match the embedded script".into());
    }
    let container_output = build.join("container-output");
    fs::create_dir(&container_output)
        .map_err(|error| format!("could not create NSIS output directory: {error}"))?;
    run_makensis(
        &nsis.makensis,
        &nsis.root,
        &nsis.private_temp,
        &nsis.directories,
        &build,
    )?;
    if hash_tree(&nsis.root)? != nsis.tree_sha256 {
        return Err("pinned NSIS tool tree changed during compilation".into());
    }
    if sha256_hex(sha256_file(&script)?) != script_sha256 {
        return Err("NSIS script changed during compilation".into());
    }
    require_only_file(&container_output, SETUP_FILENAME)?;

    let setup = container_output.join(SETUP_FILENAME);
    require_pe(&setup)?;
    let setup_guard = open_read_guard(&setup)?;
    let setup_sha256 = sha256_hex(sha256_file(&setup)?);
    let setup_probe_temp = work.join("setup-probe-temp");
    fs::create_dir(&setup_probe_temp)
        .map_err(|error| format!("could not create Setup probe temp directory: {error}"))?;
    if hash_tree(&runner)? != runner_tree_sha256 {
        return Err("NSIS compilation changed the verified runner tree".into());
    }
    probe_container_runner(&setup, &setup_probe_temp)?;
    require_argument_rejection(&setup, &setup_probe_temp)?;
    require_empty_directory(&setup_probe_temp, "Setup probe temp")?;
    if sha256_hex(sha256_file(&setup)?) != setup_sha256 {
        return Err("Windows Setup changed after its runtime probes".into());
    }

    let lock_sha256 = sha256_hex(Sha256::digest(NSIS_LOCK.as_bytes()).into());
    let signed_runner = inner_signer.is_some();
    let artifact_kind = if signed_runner {
        "unsignedWindowsContainerWithSignedRunner"
    } else {
        "unsignedWindowsPortableDevelopment"
    };
    let published_filename = if signed_runner {
        SIGN_ME_FILENAME
    } else {
        SETUP_FILENAME
    };
    let suffix = if signed_runner {
        "setup-sign-me"
    } else {
        "setup-dev"
    };
    let artifact_name = format!("{runner_artifact}-{suffix}");
    let final_artifact = output.join(&artifact_name);
    require_missing(&final_artifact, "Windows Setup artifact")?;

    let publish = work.join("publish");
    fs::create_dir(&publish)
        .map_err(|error| format!("could not create Setup publication directory: {error}"))?;
    let published_setup = publish.join(published_filename);
    copy_file(&setup, &published_setup)?;
    if sha256_hex(sha256_file(&setup)?) != setup_sha256 {
        return Err("verified Setup source changed during publication".into());
    }
    drop(setup_guard);
    let published_setup_guard = open_read_guard(&published_setup)?;
    if sha256_hex(sha256_file(&published_setup)?) != setup_sha256 {
        return Err("published Setup bytes changed after verification".into());
    }
    drop(published_setup_guard);

    let provenance = json!({
        "schemaVersion": 1,
        "artifactKind": artifact_kind,
        "artifactName": artifact_name,
        "target": {
            "os": "windows",
            "arch": "x86_64"
        },
        "package": {
            "sha256": packaged_payload_sha256
        },
        "runner": {
            "treeSha256": runner_tree_sha256,
            "signed": signed_runner,
            "certificateSha256": inner_signer
        },
        "nsis": {
            "version": pin.version,
            "url": pin.url,
            "archiveName": pin.archive_name,
            "archiveSize": pin.archive_size,
            "archiveSha256": pin.archive_sha256,
            "extractedTreeSha256": nsis.tree_sha256,
            "lockSha256": lock_sha256,
            "scriptSha256": script_sha256
        },
        "setup": {
            "file": published_filename,
            "sha256": setup_sha256,
            "signed": false
        },
        "productionReady": false,
        "publishable": false
    });
    let mut provenance = serde_json::to_vec_pretty(&provenance)
        .map_err(|error| format!("could not serialize Setup provenance: {error}"))?;
    provenance.push(b'\n');
    write_new(&publish.join(PROVENANCE_FILENAME), &provenance)?;
    require_publication_layout(&publish, published_filename)?;

    retry_transient_io(|| fs::rename(&publish, &final_artifact)).map_err(|error| {
        format!(
            "could not atomically publish Windows Setup `{}`: {error}",
            final_artifact.display()
        )
    })?;
    let final_setup = final_artifact.join(published_filename);
    let final_setup_guard = open_read_guard(&final_setup)?;
    if sha256_hex(sha256_file(&final_setup)?) != setup_sha256 {
        return Err("published Setup bytes changed during atomic publication".into());
    }
    drop(final_setup_guard);
    Ok(final_artifact)
}

fn parse_pin(source: &str) -> Result<NsisPin, String> {
    let value: Value = serde_json::from_str(source)
        .map_err(|error| format!("could not parse pinned NSIS lock: {error}"))?;
    let object = exact_object(
        &value,
        "NSIS lock",
        &[
            "schemaVersion",
            "version",
            "url",
            "archiveName",
            "archiveSize",
            "archiveSha256",
            "archiveRoot",
            "makensisPath",
            "versionOutput",
        ],
    )?;
    if required_u64(object, "schemaVersion")? != 1 {
        return Err("unsupported NSIS lock schema".into());
    }
    let version = required_string(object, "version")?;
    if version.is_empty()
        || version.len() > 16
        || version
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("NSIS lock version is invalid".into());
    }
    let archive_name = format!("nsis-{version}.zip");
    let archive_root = format!("nsis-{version}");
    let expected_url = format!(
        "https://sourceforge.net/projects/nsis/files/NSIS%203/{version}/{archive_name}/download"
    );
    let makensis_path = format!("{archive_root}/makensis.exe");
    let version_output = format!("v{version}");
    if required_string(object, "url")? != expected_url
        || required_string(object, "archiveName")? != archive_name
        || required_string(object, "archiveRoot")? != archive_root
        || required_string(object, "makensisPath")? != makensis_path
        || required_string(object, "versionOutput")? != version_output
    {
        return Err("NSIS lock fields are not internally consistent".into());
    }
    let archive_size = required_u64(object, "archiveSize")?;
    if !(1_000_000..=32 * 1024 * 1024).contains(&archive_size) {
        return Err("NSIS archive size is outside the allowed range".into());
    }
    Ok(NsisPin {
        version: version.to_owned(),
        url: expected_url,
        archive_name,
        archive_size,
        archive_sha256: required_hash(object, "archiveSha256")?,
        archive_root,
        makensis_path,
        version_output,
    })
}

struct HeldFile {
    path: PathBuf,
    _guard: File,
}

fn stage_package(source: &Path, destination: &Path) -> Result<HeldFile, String> {
    super::staging::copy_file(source, destination)?;
    let guard = open_read_guard(destination)?;
    require_regular_file(destination, "staged Setup payload")?;
    Ok(HeldFile {
        path: destination.to_path_buf(),
        _guard: guard,
    })
}

fn stage_pinned_archive(
    source: &Path,
    destination: &Path,
    pin: &NsisPin,
) -> Result<HeldFile, String> {
    require_regular_file(source, "pinned NSIS archive")?;
    let source = File::open(source)
        .map_err(|error| format!("could not open pinned NSIS archive: {error}"))?;
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| format!("could not stage pinned NSIS archive: {error}"))?;
    let copied = copy(
        &mut source.take(pin.archive_size + 1),
        &mut destination_file,
    )
    .map_err(|error| format!("could not copy pinned NSIS archive: {error}"))?;
    destination_file
        .sync_all()
        .map_err(|error| format!("could not sync staged NSIS archive: {error}"))?;
    drop(destination_file);
    if copied != pin.archive_size {
        return Err(format!(
            "NSIS archive size mismatch: expected {}, copied {copied}",
            pin.archive_size
        ));
    }
    let guard = open_read_guard(destination)?;
    verify_pinned_archive(destination, pin)?;
    Ok(HeldFile {
        path: destination.to_path_buf(),
        _guard: guard,
    })
}

#[cfg(windows)]
fn open_read_guard(path: &Path) -> Result<File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|error| format!("could not guard staged input `{}`: {error}", path.display()))
}

#[cfg(not(windows))]
fn open_read_guard(path: &Path) -> Result<File, String> {
    File::open(path)
        .map_err(|error| format!("could not guard staged input `{}`: {error}", path.display()))
}

fn verify_pinned_archive(path: &Path, pin: &NsisPin) -> Result<(), String> {
    require_regular_file(path, "pinned NSIS archive")?;
    let size = fs::metadata(path)
        .map_err(|error| format!("could not inspect pinned NSIS archive: {error}"))?
        .len();
    if size != pin.archive_size {
        return Err(format!(
            "NSIS archive size mismatch: expected {}, found {size}",
            pin.archive_size
        ));
    }
    let found = sha256_hex(sha256_file(path)?);
    if found != pin.archive_sha256 {
        return Err(format!(
            "NSIS archive SHA-256 mismatch: expected {}, found {found}",
            pin.archive_sha256
        ));
    }
    Ok(())
}

fn extract_archive(
    archive: &Path,
    output: &Path,
    private_temp: &Path,
    directories: &WindowsDirectories,
) -> Result<(), String> {
    let tar = checked_input(&directories.system.join("tar.exe"), "Windows tar")?;
    println!("> verified Windows tar -xf pinned NSIS archive");
    let mut command = isolated_command(&tar, directories, private_temp);
    let result = command
        .args(["-xf"])
        .arg(archive)
        .arg("-C")
        .arg(output)
        .current_dir(output)
        .output()
        .map_err(|error| format!("could not start Windows tar: {error}"))?;
    if !result.status.success() {
        return Err(format!(
            "Windows tar failed to extract pinned NSIS: {}",
            bounded_output(&result.stderr)
        ));
    }
    Ok(())
}

fn verify_makensis(
    makensis: &Path,
    nsis_root: &Path,
    private_temp: &Path,
    directories: &WindowsDirectories,
    expected: &str,
) -> Result<(), String> {
    let mut command = isolated_command(makensis, directories, private_temp);
    let output = command
        .env("NSISDIR", nsis_root)
        .arg("/VERSION")
        .current_dir(nsis_root)
        .output()
        .map_err(|error| format!("could not query pinned makensis version: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "pinned makensis /VERSION failed: {}",
            bounded_output(&output.stderr)
        ));
    }
    let version = std::str::from_utf8(&output.stdout)
        .map_err(|_| "pinned makensis returned a non-UTF-8 version".to_owned())?
        .trim();
    if version != expected {
        return Err(format!(
            "pinned makensis version mismatch: expected `{expected}`, found `{version}`"
        ));
    }
    Ok(())
}

fn run_makensis(
    makensis: &Path,
    nsis_root: &Path,
    private_temp: &Path,
    directories: &WindowsDirectories,
    build: &Path,
) -> Result<(), String> {
    println!("> pinned makensis /NOCONFIG /WX portable.nsi");
    let mut command = isolated_command(makensis, directories, private_temp);
    let output = command
        .env("NSISDIR", nsis_root)
        .args(["/NOCONFIG", "/WX", "portable.nsi"])
        .current_dir(build)
        .output()
        .map_err(|error| format!("could not start pinned makensis: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "pinned makensis failed; stdout: {}; stderr: {}",
            bounded_output(&output.stdout),
            bounded_output(&output.stderr),
        ));
    }
    Ok(())
}

fn isolated_command(
    executable: &Path,
    directories: &WindowsDirectories,
    private_temp: &Path,
) -> Command {
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("SystemRoot", &directories.windows)
        .env("WINDIR", &directories.windows)
        .env("TEMP", private_temp)
        .env("TMP", private_temp);
    command
}

struct WindowsDirectories {
    windows: PathBuf,
    system: PathBuf,
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_directories() -> Result<WindowsDirectories, String> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemDirectoryW, GetWindowsDirectoryW,
    };

    const CAPACITY: usize = 32_768;
    let mut windows = vec![0_u16; CAPACITY];
    let mut system = vec![0_u16; CAPACITY];
    // SAFETY: both APIs receive writable buffers with their exact u32 capacities.
    let windows_length = unsafe { GetWindowsDirectoryW(windows.as_mut_ptr(), CAPACITY as u32) };
    // SAFETY: both APIs receive writable buffers with their exact u32 capacities.
    let system_length = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), CAPACITY as u32) };
    if windows_length == 0
        || system_length == 0
        || windows_length as usize >= CAPACITY
        || system_length as usize >= CAPACITY
    {
        return Err("Windows did not return bounded native directories".into());
    }
    let windows = fs::canonicalize(PathBuf::from(OsString::from_wide(
        &windows[..windows_length as usize],
    )))
    .map_err(|error| format!("could not resolve native Windows directory: {error}"))?;
    let system = fs::canonicalize(PathBuf::from(OsString::from_wide(
        &system[..system_length as usize],
    )))
    .map_err(|error| format!("could not resolve native Windows system directory: {error}"))?;
    if !system.starts_with(&windows) {
        return Err("native Windows system directory is outside the Windows directory".into());
    }
    Ok(WindowsDirectories { windows, system })
}

#[cfg(not(windows))]
fn windows_directories() -> Result<WindowsDirectories, String> {
    Err("native Windows directories are unavailable on this host".into())
}

fn path_from_forward_slashes(value: &str) -> Result<PathBuf, String> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | "..") || part.contains(':'))
    {
        return Err("pinned NSIS relative path is invalid".into());
    }
    Ok(value.split('/').collect())
}

fn require_single_directory(directory: &Path, name: &str) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("could not inspect extracted NSIS directory: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("could not inspect extracted NSIS entry: {error}"))?;
    if entries.len() != 1 || entries[0].file_name() != name {
        return Err("pinned NSIS archive has an unexpected top-level layout".into());
    }
    let metadata = fs::symlink_metadata(entries[0].path())
        .map_err(|error| format!("could not inspect extracted NSIS root: {error}"))?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err("pinned NSIS archive root is not a real directory".into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TreeEntry {
    relative: String,
    path: PathBuf,
    directory: bool,
}

fn hash_tree(root: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("could not inspect tree root `{}`: {error}", root.display()))?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(format!(
            "tree root `{}` is not a real directory",
            root.display()
        ));
    }
    let mut entries = Vec::new();
    collect_tree(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));

    let mut hasher = Sha256::new();
    hasher.update(b"luxury-runner-tree-v1\0");
    for entry in entries {
        hasher.update([if entry.directory { b'd' } else { b'f' }]);
        let relative = entry.relative.as_bytes();
        hasher.update((relative.len() as u64).to_le_bytes());
        hasher.update(relative);
        if !entry.directory {
            let before = fs::symlink_metadata(&entry.path)
                .map_err(|error| format!("could not inspect tree file: {error}"))?;
            if is_link_or_reparse(&before) || !before.is_file() {
                return Err(format!(
                    "tree file `{}` is not a regular file",
                    entry.path.display()
                ));
            }
            let digest = sha256_file(&entry.path)?;
            let after = fs::symlink_metadata(&entry.path)
                .map_err(|error| format!("could not re-inspect tree file: {error}"))?;
            if before.len() != after.len() || is_link_or_reparse(&after) || !after.is_file() {
                return Err(format!(
                    "tree file `{}` changed while hashing",
                    entry.path.display()
                ));
            }
            hasher.update(after.len().to_le_bytes());
            hasher.update(digest);
        }
    }
    Ok(sha256_hex(hasher.finalize().into()))
}

fn collect_tree(root: &Path, directory: &Path, entries: &mut Vec<TreeEntry>) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("could not read tree `{}`: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("could not read a tree entry: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!("could not inspect tree entry `{}`: {error}", path.display())
        })?;
        if is_link_or_reparse(&metadata) {
            return Err(format!(
                "tree entry `{}` is a link or reparse point",
                path.display()
            ));
        }
        let relative = path
            .strip_prefix(root)
            .ok()
            .and_then(Path::to_str)
            .map(|value| value.replace('\\', "/"))
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
            .ok_or_else(|| {
                format!(
                    "tree entry `{}` has an invalid relative path",
                    path.display()
                )
            })?;
        if metadata.is_dir() {
            entries.push(TreeEntry {
                relative,
                path: path.clone(),
                directory: true,
            });
            collect_tree(root, &path, entries)?;
        } else if metadata.is_file() {
            entries.push(TreeEntry {
                relative,
                path,
                directory: false,
            });
        } else {
            return Err(format!(
                "tree entry `{}` is not a regular file or directory",
                path.display()
            ));
        }
    }
    Ok(())
}

fn checked_runner(path: &Path) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect signed Windows runner: {error}"))?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err("signed Windows runner must be one real directory".into());
    }
    fs::canonicalize(path)
        .map_err(|error| format!("could not resolve signed Windows runner: {error}"))
}

fn artifact_name(path: &Path) -> Result<String, String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| {
            !name.is_empty()
                && !matches!(*name, "." | "..")
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .map(str::to_owned)
        .ok_or_else(|| "Windows runner has an invalid artifact name".to_owned())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    require_missing(destination, "staged signed runner")?;
    fs::create_dir(destination)
        .map_err(|error| format!("could not create signed runner staging root: {error}"))?;
    let mut entries = Vec::new();
    collect_tree(source, source, &mut entries)?;
    for entry in entries {
        let target = destination.join(path_from_forward_slashes(&entry.relative)?);
        if entry.directory {
            fs::create_dir(&target)
                .map_err(|error| format!("could not create signed runner directory: {error}"))?;
        } else {
            copy_file(&entry.path, &target)?;
        }
    }
    Ok(())
}

fn require_pe(path: &Path) -> Result<(), String> {
    require_regular_file(path, "Windows Setup")?;
    let mut magic = [0_u8; 2];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .map_err(|error| format!("could not read Windows Setup header: {error}"))?;
    if magic != *b"MZ" {
        return Err("Windows Setup does not have a PE header".into());
    }
    Ok(())
}

fn require_argument_rejection(setup: &Path, private_temp: &Path) -> Result<(), String> {
    let mut command = Command::new(setup);
    command
        .arg("--unexpected-argument")
        .env("TEMP", private_temp)
        .env("TMP", private_temp)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let (mut child, mut containment) =
        super::containment::ChildContainment::spawn(&mut command, Duration::from_secs(10))
            .map_err(|error| {
                format!("could not run Windows Setup argument rejection probe: {error}")
            })?;
    containment
        .wait_for_primary_exit(&child)
        .map_err(|error| format!("could not wait for Setup argument rejection probe: {error}"))?;
    let status = child
        .wait()
        .map_err(|error| format!("could not reap Setup argument rejection probe: {error}"))?;
    let timed_out = containment.timed_out();
    containment.disarm();
    if timed_out {
        return Err("Windows Setup argument rejection probe timed out".into());
    }
    if status.code() != Some(64) {
        return Err(format!(
            "Windows Setup accepted an unexpected argument or returned {status}"
        ));
    }
    Ok(())
}

fn require_empty_directory(directory: &Path, label: &str) -> Result<(), String> {
    let mut entries =
        fs::read_dir(directory).map_err(|error| format!("could not inspect {label}: {error}"))?;
    match entries.next() {
        None => Ok(()),
        Some(Ok(entry)) => Err(format!(
            "{label} retained unexpected entry `{}`",
            entry.file_name().to_string_lossy()
        )),
        Some(Err(error)) => Err(format!("could not inspect {label} entry: {error}")),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "could not create `{}` without overwriting it: {error}",
                path.display()
            )
        })?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("could not write `{}`: {error}", path.display()))
}

fn require_publication_layout(directory: &Path, setup_filename: &str) -> Result<(), String> {
    let mut names = fs::read_dir(directory)
        .map_err(|error| format!("could not inspect Setup publication: {error}"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("could not inspect Setup publication entry: {error}"))?;
    names.sort();
    if names != [setup_filename, PROVENANCE_FILENAME] {
        return Err("Setup publication has an unexpected layout".into());
    }
    require_regular_file(&directory.join(setup_filename), "published Windows Setup")?;
    require_regular_file(&directory.join(PROVENANCE_FILENAME), "Setup provenance")
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn committed_nsis_pin_is_strict_and_self_consistent() {
        let pin = parse_pin(NSIS_LOCK).unwrap();
        assert_eq!(pin.version, "3.12");
        assert_eq!(pin.archive_size, 2_362_938);
        assert_eq!(pin.version_output, "v3.12");

        let unknown = NSIS_LOCK.replacen("\n}", ",\n  \"unknown\": true\n}", 1);
        assert!(parse_pin(&unknown).is_err());
    }

    #[test]
    fn project_output_is_an_absolute_setup_executable() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let output = temp.path().join("Demo-Setup.EXE");
        assert_eq!(
            validate_project_output(&project, &output).unwrap(),
            temp.path()
        );
        assert!(validate_project_output(&project, &temp.path().join("demo.luxpkg")).is_err());
        assert!(validate_project_output(Path::new("demo"), Path::new("Demo-Setup.exe")).is_err());
    }

    #[test]
    fn nsis_authenticated_mode_binds_inner_runner_to_container_parent() {
        let source = std::str::from_utf8(NSIS_SCRIPT).unwrap();
        assert!(source.contains("--verify-authenticated-transport"));
        assert!(source.contains(
            "--verify-runner --verify-authenticated-transport --verify-container-parent"
        ));
        assert_eq!(source.matches("--verify-container-parent").count(), 1);
    }

    #[test]
    fn nsis_forwards_public_arguments_to_the_strict_bound_runner() {
        let source = std::str::from_utf8(NSIS_SCRIPT).unwrap();
        assert!(source.contains("normal_with_parameters:"));
        assert!(source.contains("Luxury Installer.exe\" $Parameters"));
        assert!(!source.contains("invalid_parameters:"));
    }

    #[test]
    fn tree_hash_binds_paths_and_bytes() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("tree");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/one"), b"one").unwrap();
        let first = hash_tree(&root).unwrap();
        assert_eq!(hash_tree(&root).unwrap(), first);

        fs::write(root.join("nested/one"), b"two").unwrap();
        assert_ne!(hash_tree(&root).unwrap(), first);
    }

    #[test]
    fn wrong_nsis_archive_is_rejected_before_execution() {
        let temp = tempdir().unwrap();
        let archive = temp.path().join("nsis.zip");
        fs::write(&archive, b"not the pinned archive").unwrap();
        let error = verify_pinned_archive(&archive, &parse_pin(NSIS_LOCK).unwrap()).unwrap_err();
        assert!(error.contains("size mismatch"));
    }

    #[test]
    fn publication_layout_accepts_only_setup_and_provenance() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join(SETUP_FILENAME), b"setup").unwrap();
        fs::write(temp.path().join(PROVENANCE_FILENAME), b"receipt").unwrap();
        require_publication_layout(temp.path(), SETUP_FILENAME).unwrap();

        fs::remove_file(temp.path().join(SETUP_FILENAME)).unwrap();
        fs::write(temp.path().join(SIGN_ME_FILENAME), b"setup").unwrap();
        require_publication_layout(temp.path(), SIGN_ME_FILENAME).unwrap();

        fs::write(temp.path().join("extra"), b"unexpected").unwrap();
        assert!(require_publication_layout(temp.path(), SIGN_ME_FILENAME).is_err());
    }
}
