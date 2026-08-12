use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
use std::io::Read as _;

use super::{
    APP_NAME, HostLayout, LINUX_POLICY_BYTES, ShellFlavor, TAURI_BINARY_NAME, assemble_into,
    bounded_output, resolve_target_dir, rustc_host_triple, sha256_hex,
    staging::{
        WorkDirectory, checked_input, copy_file, ensure_real_directory,
        publish_directory_no_clobber, require_executable, require_missing, require_only_entries,
        require_regular_file, sha256_file,
    },
    validate_portable_bundle,
};

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
use super::{
    LINUX_ICON_BYTES, patch_setup_template_binding,
    probe::{probe_backend, probe_runner},
    require_setup_template_binding,
    staging::set_runner_permissions,
};

const TAURI_CLI_VERSION: &str = "2.11.4";
const TAURI_BUNDLE_MARKER: &[u8] = b"__TAURI_BUNDLE_TYPE_VAR_UNK";
const TAURI_DEB_MARKER: &[u8] = b"__TAURI_BUNDLE_TYPE_VAR_DEB";
const TAURI_RPM_MARKER: &[u8] = b"__TAURI_BUNDLE_TYPE_VAR_RPM";
const PACKAGE_NAME: &str = "luxury-installer";
const PUBLISHER: &str = "Luxury Installer Contributors <opensource@luxury.software>";
const PROVENANCE_FILENAME: &str = "provenance.json";
const MAX_PACKAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 128;
const MAX_TREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
// ponytail: rpm 0.16 buffers package inputs; raise this only with a streaming RPM writer.
#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
const MAX_STANDALONE_INPUT_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
const MAX_STANDALONE_CONTAINER_BYTES: u64 = 384 * 1024 * 1024;

const LAUNCHER_PATH: &str = "usr/bin/luxury-installer";
const BACKEND_PATH: &str = "usr/lib/Luxury Installer/backend/luxury";
const PAYLOAD_PATH: &str = "usr/lib/Luxury Installer/payload/package.luxpkg";
const HELPER_PATH: &str = "usr/libexec/luxury-installer-helper";
const POLICY_PATH: &str = "usr/share/polkit-1/actions/software.luxury.installer.policy";
const DESKTOP_PATH: &str = "usr/share/applications/Luxury Installer.desktop";
const ICON_PATH: &str = "usr/share/icons/hicolor/512x512/apps/luxury-installer.png";

#[derive(Clone, Copy)]
struct ExpectedFile {
    sha256: Option<[u8; 32]>,
    executable: bool,
}

struct RunnerInput<'a> {
    path: &'a Path,
    fingerprint: &'a str,
    icon: &'a Path,
}

pub(super) fn build(package: &Path) -> Result<(), String> {
    if env::consts::OS != "linux" || !matches!(env::consts::ARCH, "x86_64" | "aarch64") {
        return Err("linux-packages requires a native Linux x86_64 or aarch64 host".into());
    }

    let root = crate::workspace_root();
    let host = HostLayout::new(env::consts::OS, env::consts::ARCH)?;
    let target = resolve_target_dir(&root, env::var_os("CARGO_TARGET_DIR").as_deref());
    ensure_real_directory(&target)?;
    let output = target.join("linux-packages");
    ensure_real_directory(&output)?;
    let package = checked_input(package, "Linux package payload")?;
    let work = WorkDirectory::new(&output)?;
    let result = build_in_work(&output, &work.path, &root, host, &package);

    match (result, work.cleanup()) {
        (Ok(artifact), Ok(())) => {
            println!(
                "verified unsigned Linux development packages: {}",
                artifact.display()
            );
            Ok(())
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(artifact), Err(cleanup)) => Err(format!(
            "verified Linux packages were published at `{}`, but {cleanup}",
            artifact.display()
        )),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}

pub(super) fn build_project(
    project: &Path,
    destination: &Path,
    managed_work: Option<&Path>,
) -> Result<(), String> {
    if env::consts::OS != "linux" || !matches!(env::consts::ARCH, "x86_64" | "aarch64") {
        return Err("Linux project builds require a native Linux x86_64 or aarch64 host".into());
    }
    if !project.is_absolute() || !destination.is_absolute() {
        return Err("project-installer paths must be absolute".into());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "Linux installer output has no parent directory".to_owned())?;
    ensure_real_directory(parent)?;
    require_missing(destination, "Linux installer output")?;

    let root = crate::workspace_root();
    let host = HostLayout::new(env::consts::OS, env::consts::ARCH)?;
    let work = WorkDirectory::project(parent, managed_work)?;
    let package = work.path.join("internal-package.luxpkg");
    luxury_compiler::compile_project(project, &package)
        .map_err(|error| format!("could not compile installer project: {error}"))?;
    let package = checked_input(&package, "internal Linux installer payload")?;
    let output = work.path.join("native-output");
    let container_work = work.path.join("native-work");
    fs::create_dir(&output)
        .map_err(|error| format!("could not create Linux output staging: {error}"))?;
    fs::create_dir(&container_work)
        .map_err(|error| format!("could not create Linux work staging: {error}"))?;
    let artifact = build_in_work(&output, &container_work, &root, host, &package)?;
    publish_directory_no_clobber(&artifact, destination)?;
    work.cleanup().map_err(|error| {
        format!(
            "verified Linux installers were published at `{}`, but {error}",
            destination.display()
        )
    })?;
    println!(
        "verified unsigned Linux .deb and .rpm installers: {}",
        destination.display()
    );
    Ok(())
}

pub(super) fn build_packaged_project(
    project: &Path,
    destination: &Path,
    resources: &Path,
    managed_work: Option<&Path>,
) -> Result<(), String> {
    #[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
    {
        build_packaged_project_native(project, destination, resources, managed_work)
    }
    #[cfg(all(target_os = "linux", not(feature = "standalone-linux-packager")))]
    {
        let _ = (project, destination, resources, managed_work);
        Err("packaged Linux Studio is missing its embedded native bundler".into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (project, destination, resources, managed_work);
        Err("packaged Linux project builds require a native Linux host".into())
    }
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
fn build_packaged_project_native(
    project: &Path,
    destination: &Path,
    resources: &Path,
    managed_work: Option<&Path>,
) -> Result<(), String> {
    if !matches!(env::consts::ARCH, "x86_64" | "aarch64") {
        return Err("Linux project builds require x86_64 or aarch64".into());
    }
    if !project.is_absolute() || !destination.is_absolute() {
        return Err("project-installer paths must be absolute".into());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "Linux installer output has no parent directory".to_owned())?;
    ensure_real_directory(parent)?;
    require_missing(destination, "Linux installer output")?;

    let host = HostLayout::new("linux", env::consts::ARCH)?;
    let template = resources
        .join("templates")
        .join(format!("linux-{}", host.rust_arch));
    validate_portable_bundle(&template, host, ShellFlavor::SetupTemplate, None)?;
    require_setup_template_binding(&host.launcher(&template))?;
    let icon = resources.join("icon.png");
    require_regular_file(&icon, "packaged Linux icon")?;
    if fs::read(&icon).map_err(|error| format!("could not read packaged Linux icon: {error}"))?
        != LINUX_ICON_BYTES
    {
        return Err("packaged Linux icon bytes changed".into());
    }

    let work = WorkDirectory::project(parent, managed_work)?;
    let package = work.path.join("internal-package.luxpkg");
    luxury_compiler::compile_project(project, &package)
        .map_err(|error| format!("could not compile installer project: {error}"))?;
    let package = checked_input(&package, "internal Linux installer payload")?;
    let template_backend = host
        .resources_directory(&template)
        .join("backend")
        .join(host.backend_name);
    let fingerprint = probe_backend(&template_backend, &package, host)?;

    let runner = work.path.join(super::artifact_name(host, &fingerprint)?);
    let resources = host.resources_directory(&runner);
    let launcher = host.launcher(&runner);
    let backend = resources.join("backend").join(host.backend_name);
    let payload = resources.join("payload").join("package.luxpkg");
    for path in [&launcher, &backend, &payload] {
        fs::create_dir_all(
            path.parent()
                .ok_or_else(|| "packaged Linux runner path has no parent".to_owned())?,
        )
        .map_err(|error| format!("could not create packaged Linux runner directory: {error}"))?;
    }
    copy_file(&host.launcher(&template), &launcher)?;
    copy_file(&template_backend, &backend)?;
    copy_file(&package, &payload)?;
    patch_setup_template_binding(&launcher, &fingerprint)?;
    set_runner_permissions(&launcher, &backend, Some(&payload))?;
    super::stage_linux_privilege_integration(&runner, host, &backend)?;
    validate_portable_bundle(&runner, host, ShellFlavor::Setup, None)?;
    if probe_backend(&backend, &payload, host)? != fingerprint {
        return Err("packaged Linux template inspected a different payload".into());
    }
    probe_runner(&launcher)?;

    let output = work.path.join("native-output");
    let package_work = work.path.join("native-work");
    fs::create_dir(&output)
        .map_err(|error| format!("could not create Linux output staging: {error}"))?;
    fs::create_dir(&package_work)
        .map_err(|error| format!("could not create Linux work staging: {error}"))?;
    let artifact = build_runner_in_work(
        &output,
        &package_work,
        host,
        &package,
        RunnerInput {
            path: &runner,
            fingerprint: &fingerprint,
            icon: &icon,
        },
        None,
    )?;
    publish_directory_no_clobber(&artifact, destination)?;
    work.cleanup().map_err(|error| {
        format!(
            "verified Linux installers were published at `{}`, but {error}",
            destination.display()
        )
    })?;
    println!(
        "verified standalone unsigned Linux .deb and .rpm installers: {}",
        destination.display()
    );
    Ok(())
}

fn build_in_work(
    output: &Path,
    work: &Path,
    root: &Path,
    host: HostLayout,
    package: &Path,
) -> Result<PathBuf, String> {
    let runner = assemble_into(package, &work.join("runner-output"))?;
    let icon = checked_input(
        &root
            .join("apps")
            .join("luxury-installer")
            .join("src-tauri")
            .join("icons")
            .join("icon.png"),
        "Linux package icon",
    )?;
    build_runner_in_work(
        output,
        work,
        host,
        package,
        RunnerInput {
            path: &runner.path,
            fingerprint: &runner.package_fingerprint,
            icon: &icon,
        },
        Some(root),
    )
}

fn build_runner_in_work(
    output: &Path,
    work: &Path,
    host: HostLayout,
    package: &Path,
    runner: RunnerInput<'_>,
    workspace_root: Option<&Path>,
) -> Result<PathBuf, String> {
    validate_portable_bundle(runner.path, host, ShellFlavor::Setup, None)?;
    let runner_name = safe_name(runner.path, "assembled Linux runner")?;
    let fingerprint = runner.fingerprint;
    let icon = runner.icon;
    let fingerprint_prefix = fingerprint
        .get(..12)
        .filter(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        .ok_or_else(|| "assembled Linux runner has an invalid fingerprint".to_owned())?;

    let resources = host.resources_directory(runner.path);
    let launcher = host.launcher(runner.path);
    let backend = resources.join("backend").join(host.backend_name);
    let payload = resources.join("payload").join("package.luxpkg");
    let helper = runner
        .path
        .join("usr")
        .join("libexec")
        .join("luxury-installer-helper");
    let policy = runner
        .path
        .join("usr")
        .join("share")
        .join("polkit-1")
        .join("actions")
        .join("software.luxury.installer.policy");
    for (path, label) in [
        (&launcher, "verified Linux launcher"),
        (&backend, "verified Linux backend"),
        (&payload, "verified Linux payload"),
        (&helper, "verified Linux privilege helper"),
        (&policy, "reviewed Linux polkit policy"),
    ] {
        require_regular_file(path, label)?;
    }
    require_executable(&launcher, "verified Linux launcher")?;
    require_executable(&backend, "verified Linux backend")?;
    require_executable(&helper, "verified Linux privilege helper")?;
    if fs::read(&policy).map_err(|error| format!("could not read staged Linux policy: {error}"))?
        != LINUX_POLICY_BYTES
    {
        return Err("staged Linux policy no longer matches the reviewed bytes".into());
    }
    if sha256_file(package)? != sha256_file(&payload)? {
        return Err("bound Linux payload changed before native packaging".into());
    }
    if sha256_file(&backend)? != sha256_file(&helper)? {
        return Err("Linux package helper no longer matches the verified backend".into());
    }

    let expected = expected_files(&launcher, &backend, &payload, &helper, &policy, icon)?;
    let triple = match workspace_root {
        Some(root) => rustc_host_triple(root)?,
        None => match host.rust_arch {
            "x86_64" => "x86_64-unknown-linux-gnu".into(),
            "aarch64" => "aarch64-unknown-linux-gnu".into(),
            _ => return Err("unsupported embedded Linux target".into()),
        },
    };
    let isolated_target = work.join("tauri-target");
    let release = isolated_target.join(&triple).join("release");
    fs::create_dir_all(&release)
        .map_err(|error| format!("could not create isolated Tauri bundle target: {error}"))?;
    let bundled_binary = release.join(TAURI_BINARY_NAME);
    copy_file(&launcher, &bundled_binary)?;
    set_executable(&bundled_binary)?;
    if sha256_file(&bundled_binary)? != sha256_file(&launcher)? {
        return Err("isolated Tauri bundle binary differs from the verified launcher".into());
    }

    match workspace_root {
        Some(root) => {
            let config = bundle_config(
                &backend,
                &payload,
                &helper,
                &policy,
                icon,
                fingerprint_prefix,
            )?;
            let config_path = work.join("tauri.linux-package.conf.json");
            write_json(&config_path, &config)?;
            run_tauri_bundle(root, &triple, &isolated_target, &config_path)?;
        }
        None => {
            #[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
            run_embedded_linux_bundle(
                &release,
                EmbeddedRunnerFiles {
                    launcher: &bundled_binary,
                    backend: &backend,
                    payload: &payload,
                    helper: &helper,
                    policy: &policy,
                    icon,
                },
                fingerprint_prefix,
            )?;
            #[cfg(not(all(target_os = "linux", feature = "standalone-linux-packager")))]
            return Err("embedded Linux package support is unavailable".into());
        }
    }
    if sha256_file(&bundled_binary)? != sha256_file(&launcher)? {
        return Err("Tauri bundling changed the verified Setup executable".into());
    }

    let bundle_root = release.join("bundle");
    let deb = single_bundle(&bundle_root.join("deb"), "deb")?;
    let rpm = single_bundle(&bundle_root.join("rpm"), "rpm")?;
    let deb_hash = sha256_file(&deb)?;
    let rpm_hash = sha256_file(&rpm)?;
    if workspace_root.is_some() {
        let deb_launcher_hash = tauri_patched_launcher_hash(&bundled_binary, TAURI_DEB_MARKER)?;
        let rpm_launcher_hash = tauri_patched_launcher_hash(&bundled_binary, TAURI_RPM_MARKER)?;
        let mut deb_expected = expected.clone();
        deb_expected
            .get_mut(LAUNCHER_PATH)
            .expect("the launcher expectation is always present")
            .sha256 = Some(deb_launcher_hash);
        let mut rpm_expected = expected.clone();
        rpm_expected
            .get_mut(LAUNCHER_PATH)
            .expect("the launcher expectation is always present")
            .sha256 = Some(rpm_launcher_hash);
        verify_deb(&deb, work, host, &deb_expected)?;
        verify_rpm(&rpm, work, host, fingerprint_prefix, &rpm_expected)?;
    } else {
        #[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
        {
            verify_deb_embedded(&deb, host, &expected)?;
            verify_rpm_embedded(&rpm, host, fingerprint_prefix, &expected)?;
        }
        #[cfg(not(all(target_os = "linux", feature = "standalone-linux-packager")))]
        return Err("embedded Linux package verification is unavailable".into());
    }
    if sha256_file(&deb)? != deb_hash || sha256_file(&rpm)? != rpm_hash {
        return Err("Linux native package bytes changed during verification".into());
    }

    let artifact_name = format!("{runner_name}-linux-packages-dev");
    let artifact = output.join(&artifact_name);
    require_missing(&artifact, "Linux package artifact")?;
    let publish = work.join("publish");
    fs::create_dir(&publish)
        .map_err(|error| format!("could not create Linux package publication: {error}"))?;
    let deb_name = format!(
        "luxury-installer-{}-linux-{}-{fingerprint_prefix}.deb",
        env!("CARGO_PKG_VERSION"),
        host.rust_arch
    );
    let rpm_name = format!(
        "luxury-installer-{}-linux-{}-{fingerprint_prefix}.rpm",
        env!("CARGO_PKG_VERSION"),
        host.rust_arch
    );
    let published_deb = publish.join(&deb_name);
    let published_rpm = publish.join(&rpm_name);
    copy_file(&deb, &published_deb)?;
    copy_file(&rpm, &published_rpm)?;

    let provenance = json!({
        "schemaVersion": 1,
        "artifactKind": "unsignedLinuxNativeDevelopment",
        "artifactName": artifact_name,
        "target": {
            "os": "linux",
            "arch": host.rust_arch,
            "triple": triple
        },
        "package": {
            "fingerprint": fingerprint,
            "sha256": sha256_hex(sha256_file(package)?)
        },
        "runner": {
            "launcherSha256": sha256_hex(sha256_file(&launcher)?),
            "backendSha256": sha256_hex(sha256_file(&backend)?),
            "helperSha256": sha256_hex(sha256_file(&helper)?),
            "policySha256": sha256_hex(sha256_file(&policy)?)
        },
        "bundler": {
            "kind": if workspace_root.is_some() { "tauri-cli" } else { "rust-native" },
            "version": if workspace_root.is_some() { TAURI_CLI_VERSION } else { env!("CARGO_PKG_VERSION") },
            "formats": ["deb", "rpm"]
        },
        "deb": {
            "file": deb_name,
            "sha256": sha256_hex(deb_hash),
            "signed": false
        },
        "rpm": {
            "file": rpm_name,
            "sha256": sha256_hex(rpm_hash),
            "signed": false
        },
        "reproducibilityVerified": false,
        "nativeLifecycleVerified": false,
        "productionReady": false,
        "publishable": false
    });
    write_json(&publish.join(PROVENANCE_FILENAME), &provenance)?;
    require_only_entries(
        &publish,
        &[&deb_name, &rpm_name, PROVENANCE_FILENAME],
        "Linux package publication",
    )?;
    if sha256_file(&published_deb)? != deb_hash || sha256_file(&published_rpm)? != rpm_hash {
        return Err("published Linux package bytes differ from the verified packages".into());
    }

    publish_directory_no_clobber(&publish, &artifact)?;
    if sha256_file(&artifact.join(&deb_name))? != deb_hash
        || sha256_file(&artifact.join(&rpm_name))? != rpm_hash
    {
        return Err("Linux package bytes changed during atomic publication".into());
    }
    Ok(artifact)
}

fn bundle_config(
    backend: &Path,
    payload: &Path,
    helper: &Path,
    policy: &Path,
    icon: &Path,
    fingerprint_prefix: &str,
) -> Result<Value, String> {
    let mut resources = Map::new();
    resources.insert(path_text(backend)?, Value::String("backend/luxury".into()));
    resources.insert(
        path_text(payload)?,
        Value::String("payload/package.luxpkg".into()),
    );

    let mut files = Map::new();
    files.insert(
        "/usr/libexec/luxury-installer-helper".into(),
        Value::String(path_text(helper)?),
    );
    files.insert(
        "/usr/share/polkit-1/actions/software.luxury.installer.policy".into(),
        Value::String(path_text(policy)?),
    );

    Ok(json!({
        "productName": APP_NAME,
        "mainBinaryName": TAURI_BINARY_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "identifier": "software.luxury.installer",
        "bundle": {
            "active": true,
            "targets": ["deb", "rpm"],
            "publisher": PUBLISHER,
            "icon": [path_text(icon)?],
            "resources": resources,
            "license": "MIT OR Apache-2.0",
            "category": "DeveloperTool",
            "shortDescription": "Secure, transactional setup powered by Rust",
            "longDescription": "A bound Luxury Installer Setup with verified payload, rollback, ownership receipts, and native least-privilege system integration.",
            "linux": {
                "deb": {
                    "depends": ["policykit-1"],
                    "files": files,
                    "section": "utils",
                    "priority": "optional"
                },
                "rpm": {
                    "depends": ["polkit"],
                    "files": files,
                    "release": format!("1.{fingerprint_prefix}")
                }
            }
        }
    }))
}

fn run_tauri_bundle(root: &Path, triple: &str, target: &Path, config: &Path) -> Result<(), String> {
    let app = root.join("apps").join("luxury-installer");
    let pnpm = env::var_os("PNPM").unwrap_or_else(|| OsString::from("pnpm"));
    let version = Command::new(&pnpm)
        .args(["exec", "tauri", "--version"])
        .current_dir(&app)
        .env("CI", "true")
        .output()
        .map_err(|error| format!("could not query the pinned Tauri CLI: {error}"))?;
    if !version.status.success()
        || String::from_utf8_lossy(&version.stdout).trim()
            != format!("tauri-cli {TAURI_CLI_VERSION}")
    {
        return Err(format!(
            "Tauri CLI must be exactly {TAURI_CLI_VERSION}; stdout: {}; stderr: {}",
            bounded_output(&version.stdout),
            bounded_output(&version.stderr)
        ));
    }

    println!("> tauri bundle --bundles deb,rpm --features setup --target {triple}");
    let mut command = Command::new(pnpm);
    command
        .args(["exec", "tauri", "bundle", "--bundles", "deb,rpm"])
        .args(["--features", "setup", "--target", triple, "--config"])
        .arg(config)
        .args(["--ci", "--no-sign"])
        .current_dir(&app);
    configure_tauri_bundle_environment(&mut command, target);
    let output = command
        .output()
        .map_err(|error| format!("could not start the pinned Tauri bundler: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "pinned Tauri Linux bundler failed; stdout: {}; stderr: {}",
            bounded_output(&output.stdout),
            bounded_output(&output.stderr)
        ))
    }
}

fn configure_tauri_bundle_environment(command: &mut Command, target: &Path) {
    command
        .env("CARGO_TARGET_DIR", target)
        .env("CI", "true")
        .env_remove("LUXURY_BOUND_PACKAGE_FINGERPRINT")
        .env_remove("TAURI_SIGNING_PRIVATE_KEY")
        .env_remove("TAURI_SIGNING_PRIVATE_KEY_PASSWORD")
        .env_remove("TAURI_SIGNING_RPM_KEY")
        .env_remove("TAURI_SIGNING_RPM_KEY_PASSPHRASE");
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
struct EmbeddedPackageFile<'a> {
    path: &'static str,
    source: &'a Path,
    mode: u32,
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
struct EmbeddedRunnerFiles<'a> {
    launcher: &'a Path,
    backend: &'a Path,
    payload: &'a Path,
    helper: &'a Path,
    policy: &'a Path,
    icon: &'a Path,
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
fn run_embedded_linux_bundle(
    release: &Path,
    runner: EmbeddedRunnerFiles<'_>,
    fingerprint_prefix: &str,
) -> Result<(), String> {
    let desktop = release.join("luxury-installer.desktop");
    let mut desktop_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&desktop)
        .map_err(|error| format!("could not create embedded Linux desktop entry: {error}"))?;
    desktop_file
        .write_all(desktop_entry_bytes())
        .and_then(|()| desktop_file.sync_all())
        .map_err(|error| format!("could not persist embedded Linux desktop entry: {error}"))?;
    let files = [
        EmbeddedPackageFile {
            path: LAUNCHER_PATH,
            source: runner.launcher,
            mode: 0o755,
        },
        EmbeddedPackageFile {
            path: BACKEND_PATH,
            source: runner.backend,
            mode: 0o755,
        },
        EmbeddedPackageFile {
            path: PAYLOAD_PATH,
            source: runner.payload,
            mode: 0o644,
        },
        EmbeddedPackageFile {
            path: HELPER_PATH,
            source: runner.helper,
            mode: 0o755,
        },
        EmbeddedPackageFile {
            path: POLICY_PATH,
            source: runner.policy,
            mode: 0o644,
        },
        EmbeddedPackageFile {
            path: DESKTOP_PATH,
            source: &desktop,
            mode: 0o644,
        },
        EmbeddedPackageFile {
            path: ICON_PATH,
            source: runner.icon,
            mode: 0o644,
        },
    ];
    let mut input_bytes = 0_u64;
    for file in &files {
        input_bytes = input_bytes
            .checked_add(
                fs::metadata(file.source)
                    .map_err(|error| format!("could not inspect standalone Linux input: {error}"))?
                    .len(),
            )
            .filter(|total| *total <= MAX_STANDALONE_INPUT_BYTES)
            .ok_or_else(|| {
                "standalone Linux package inputs exceed the 256 MiB memory-safe limit".to_owned()
            })?;
    }
    let deb = release.join("bundle").join("deb");
    let rpm = release.join("bundle").join("rpm");
    fs::create_dir_all(&deb)
        .map_err(|error| format!("could not create embedded Debian output: {error}"))?;
    fs::create_dir_all(&rpm)
        .map_err(|error| format!("could not create embedded RPM output: {error}"))?;
    build_embedded_deb(&deb, &files)?;
    build_embedded_rpm(&rpm, &files, fingerprint_prefix)?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
fn build_embedded_deb(output: &Path, files: &[EmbeddedPackageFile<'_>]) -> Result<(), String> {
    use md5::Md5;

    let mut data = Vec::with_capacity(files.len());
    let mut md5sums = String::new();
    let mut installed_bytes = 0_u64;
    for file in files {
        let bytes = fs::read(file.source)
            .map_err(|error| format!("could not read Debian input `{}`: {error}", file.path))?;
        installed_bytes = installed_bytes
            .checked_add(bytes.len() as u64)
            .filter(|total| *total <= MAX_TREE_BYTES)
            .ok_or_else(|| "embedded Debian inputs are too large".to_owned())?;
        use std::fmt::Write as _;
        let mut hasher = Md5::default();
        md5::Digest::update(&mut hasher, &bytes);
        writeln!(
            &mut md5sums,
            "{:x}  {}",
            md5::Digest::finalize(hasher),
            file.path
        )
        .map_err(|_| "could not format Debian md5sums".to_owned())?;
        data.push((file.path.to_owned(), bytes, file.mode));
    }
    let control = format!(
        "Package: {PACKAGE_NAME}\nVersion: {}\nArchitecture: {}\nInstalled-Size: {}\nMaintainer: {PUBLISHER}\nSection: utils\nPriority: optional\nDepends: policykit-1, libwebkit2gtk-4.1-0, libgtk-3-0\nDescription: Secure, transactional setup powered by Rust\n A bound Luxury Installer Setup with verified rollback and ownership receipts.\n",
        env!("CARGO_PKG_VERSION"),
        match env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => return Err("unsupported embedded Debian architecture".into()),
        },
        installed_bytes.div_ceil(1024),
    );
    let control = tar_gz_bytes(&[
        ("control".into(), control.into_bytes(), 0o644),
        ("md5sums".into(), md5sums.into_bytes(), 0o644),
    ])?;
    let data = tar_gz_bytes(&data)?;
    let destination = output.join(format!(
        "{PACKAGE_NAME}_{}_{}.deb",
        env!("CARGO_PKG_VERSION"),
        if env::consts::ARCH == "x86_64" {
            "amd64"
        } else {
            "arm64"
        }
    ));
    require_missing(&destination, "embedded Debian package")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| format!("could not create embedded Debian package: {error}"))?;
    {
        let mut archive = ar::Builder::new(&mut file);
        for (name, bytes) in [
            ("debian-binary", b"2.0\n".as_slice()),
            ("control.tar.gz", control.as_slice()),
            ("data.tar.gz", data.as_slice()),
        ] {
            let mut header = ar::Header::new(name.as_bytes().to_vec(), bytes.len() as u64);
            header.set_mode(0o100644);
            archive
                .append(&header, std::io::Cursor::new(bytes))
                .map_err(|error| format!("could not write Debian archive: {error}"))?;
        }
        archive
            .into_inner()
            .map_err(|error| format!("could not finish Debian archive: {error}"))?;
    }
    file.sync_all()
        .map_err(|error| format!("could not sync embedded Debian package: {error}"))
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
fn tar_gz_bytes(entries: &[(String, Vec<u8>, u32)]) -> Result<Vec<u8>, String> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    let mut archive = tar::Builder::new(encoder);
    let mut directories = BTreeSet::new();
    for (path, _, _) in entries {
        let mut parent = Path::new(path).parent();
        while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
            directories.insert(portable_path(path)?);
            parent = path.parent();
        }
    }
    for directory in directories {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o755);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, directory, std::io::empty())
            .map_err(|error| format!("could not write Linux package directory: {error}"))?;
    }
    for (path, bytes, mode) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(*mode);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, path, std::io::Cursor::new(bytes))
            .map_err(|error| format!("could not write Linux package file: {error}"))?;
    }
    archive
        .into_inner()
        .map_err(|error| format!("could not finish Linux package tar: {error}"))?
        .finish()
        .map_err(|error| format!("could not finish Linux package gzip: {error}"))
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
fn build_embedded_rpm(
    output: &Path,
    files: &[EmbeddedPackageFile<'_>],
    fingerprint_prefix: &str,
) -> Result<(), String> {
    let arch = match env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => return Err("unsupported embedded RPM architecture".into()),
    };
    let mut package = rpm::PackageBuilder::new(
        PACKAGE_NAME,
        env!("CARGO_PKG_VERSION"),
        "MIT OR Apache-2.0",
        arch,
        "Secure, transactional setup powered by Rust",
    )
    .release(format!("1.{fingerprint_prefix}"))
    .description(
        "A bound Luxury Installer Setup with verified payload, rollback, ownership receipts, and native least-privilege system integration.",
    )
    .vendor(PUBLISHER)
    .compression(rpm::CompressionWithLevel::Gzip(9))
    .requires(rpm::Dependency::any("polkit"))
    .requires(rpm::Dependency::any("libwebkit2gtk-4.1.so.0()(64bit)"))
    .requires(rpm::Dependency::any("libgtk-3.so.0()(64bit)"));
    for file in files {
        package = package
            .with_file(
                file.source,
                rpm::FileOptions::new(format!("/{}", file.path))
                    .mode(rpm::FileMode::regular(file.mode as u16)),
            )
            .map_err(|error| format!("could not add `{}` to RPM: {error}", file.path))?;
    }
    let destination = output.join(format!(
        "{PACKAGE_NAME}-{}-1.{fingerprint_prefix}.{arch}.rpm",
        env!("CARGO_PKG_VERSION")
    ));
    require_missing(&destination, "embedded RPM package")?;
    package
        .build()
        .map_err(|error| format!("could not build embedded RPM: {error}"))?
        .write_file(&destination)
        .map_err(|error| format!("could not write embedded RPM: {error}"))?;
    fs::File::open(&destination)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("could not sync embedded RPM: {error}"))
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
fn desktop_entry_bytes() -> &'static [u8] {
    b"[Desktop Entry]\nCategories=Development;\nComment=Secure, transactional setup powered by Rust\nExec=luxury-installer\nStartupWMClass=luxury-installer\nIcon=luxury-installer\nName=Luxury Installer\nTerminal=false\nType=Application\n"
}

fn expected_files(
    launcher: &Path,
    backend: &Path,
    payload: &Path,
    helper: &Path,
    policy: &Path,
    icon: &Path,
) -> Result<BTreeMap<String, ExpectedFile>, String> {
    let mut expected = BTreeMap::new();
    for (relative, path, executable) in [
        (LAUNCHER_PATH, launcher, true),
        (BACKEND_PATH, backend, true),
        (PAYLOAD_PATH, payload, false),
        (HELPER_PATH, helper, true),
        (POLICY_PATH, policy, false),
        (ICON_PATH, icon, false),
    ] {
        expected.insert(
            relative.to_owned(),
            ExpectedFile {
                sha256: Some(sha256_file(path)?),
                executable,
            },
        );
    }
    expected.insert(
        DESKTOP_PATH.into(),
        ExpectedFile {
            sha256: None,
            executable: false,
        },
    );
    Ok(expected)
}

fn tauri_patched_launcher_hash(path: &Path, replacement: &[u8]) -> Result<[u8; 32], String> {
    if replacement.len() != TAURI_BUNDLE_MARKER.len() {
        return Err("Tauri bundle marker length changed".into());
    }
    let mut bytes = fs::read(path)
        .map_err(|error| format!("could not read the verified Tauri launcher: {error}"))?;
    let mut matches = bytes
        .windows(TAURI_BUNDLE_MARKER.len())
        .enumerate()
        .filter_map(|(index, window)| (window == TAURI_BUNDLE_MARKER).then_some(index));
    let index = matches
        .next()
        .ok_or_else(|| "verified Tauri launcher has no bundle marker".to_owned())?;
    if matches.next().is_some() {
        return Err("verified Tauri launcher has multiple bundle markers".into());
    }
    bytes[index..index + replacement.len()].copy_from_slice(replacement);
    Ok(Sha256::digest(&bytes).into())
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
fn verify_deb_embedded(
    package: &Path,
    host: HostLayout,
    expected: &BTreeMap<String, ExpectedFile>,
) -> Result<(), String> {
    require_regular_file(package, "embedded Debian package")?;
    if fs::metadata(package)
        .map_err(|error| format!("could not inspect Debian package size: {error}"))?
        .len()
        > MAX_STANDALONE_CONTAINER_BYTES
    {
        return Err("Debian package exceeds its size limit".into());
    }
    let mut archive = ar::Archive::new(
        fs::File::open(package)
            .map_err(|error| format!("could not open Debian package: {error}"))?,
    );
    let mut members = BTreeMap::new();
    while let Some(entry) = archive.next_entry() {
        let mut entry = entry.map_err(|error| format!("invalid Debian archive: {error}"))?;
        let name = std::str::from_utf8(entry.header().identifier())
            .map_err(|_| "Debian archive member name is not UTF-8".to_owned())?
            .trim_end_matches('/')
            .to_owned();
        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(MAX_STANDALONE_CONTAINER_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("could not read Debian archive member: {error}"))?;
        if bytes.len() as u64 > MAX_STANDALONE_CONTAINER_BYTES
            || members.insert(name, bytes).is_some()
        {
            return Err("Debian archive contains an oversized or duplicate member".into());
        }
    }
    if members.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["control.tar.gz", "data.tar.gz", "debian-binary"])
        || members.get("debian-binary").map(Vec::as_slice) != Some(b"2.0\n")
    {
        return Err("Debian archive layout is not exact".into());
    }
    verify_deb_control(
        members
            .get("control.tar.gz")
            .ok_or_else(|| "Debian control archive is missing".to_owned())?,
        host,
    )?;
    verify_deb_data(
        members
            .get("data.tar.gz")
            .ok_or_else(|| "Debian data archive is missing".to_owned())?,
        expected,
    )
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
fn verify_deb_control(bytes: &[u8], host: HostLayout) -> Result<(), String> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut files = BTreeMap::new();
    for entry in archive
        .entries()
        .map_err(|error| format!("invalid Debian control archive: {error}"))?
    {
        let entry = entry.map_err(|error| format!("invalid Debian control entry: {error}"))?;
        if !entry.header().entry_type().is_file()
            || entry.header().uid().ok() != Some(0)
            || entry.header().gid().ok() != Some(0)
        {
            return Err("Debian control archive contains a non-root regular entry".into());
        }
        let name = entry
            .path()
            .map_err(|error| format!("invalid Debian control path: {error}"))?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_owned();
        if !matches!(name.as_str(), "control" | "md5sums") {
            return Err("Debian control archive contains an unexpected entry".into());
        }
        let mut data = Vec::new();
        entry
            .take(64 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|error| format!("could not read Debian control entry: {error}"))?;
        if data.len() > 64 * 1024 || files.insert(name, data).is_some() {
            return Err("Debian control archive is oversized or duplicated".into());
        }
    }
    if files.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["control", "md5sums"])
    {
        return Err("Debian control archive is incomplete".into());
    }
    let source = std::str::from_utf8(
        files
            .get("control")
            .ok_or_else(|| "Debian control file is missing".to_owned())?,
    )
    .map_err(|_| "Debian control file is not UTF-8".to_owned())?;
    let mut fields = BTreeMap::new();
    for line in source.lines().filter(|line| !line.starts_with(' ')) {
        let (name, value) = line
            .split_once(": ")
            .ok_or_else(|| "Debian control file contains an invalid field".to_owned())?;
        if fields.insert(name, value).is_some() {
            return Err("Debian control file contains a duplicate field".into());
        }
    }
    for (name, value) in [
        ("Package", PACKAGE_NAME),
        ("Version", env!("CARGO_PKG_VERSION")),
        ("Architecture", deb_arch(host)?),
        ("Maintainer", PUBLISHER),
        ("Section", "utils"),
        ("Priority", "optional"),
    ] {
        if fields.get(name).copied() != Some(value) {
            return Err(format!("Debian control field `{name}` is invalid"));
        }
    }
    let dependencies = fields
        .get("Depends")
        .ok_or_else(|| "Debian package has no dependencies".to_owned())?;
    for dependency in ["policykit-1", "libwebkit2gtk-4.1-0", "libgtk-3-0"] {
        if !dependencies
            .split(',')
            .map(str::trim)
            .any(|value| value == dependency || value.starts_with(&format!("{dependency} ")))
        {
            return Err(format!(
                "Debian package is missing dependency `{dependency}`"
            ));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
fn verify_deb_data(bytes: &[u8], expected: &BTreeMap<String, ExpectedFile>) -> Result<(), String> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut files = BTreeSet::new();
    let mut total = 0_u64;
    for entry in archive
        .entries()
        .map_err(|error| format!("invalid Debian data archive: {error}"))?
    {
        let entry = entry.map_err(|error| format!("invalid Debian data entry: {error}"))?;
        if entry.header().uid().ok() != Some(0) || entry.header().gid().ok() != Some(0) {
            return Err("Debian data archive contains a non-root-owned entry".into());
        }
        let raw = entry
            .path()
            .map_err(|error| format!("invalid Debian data path: {error}"))?;
        let relative = portable_path(Path::new(raw.to_string_lossy().trim_start_matches("./")))?;
        if entry.header().entry_type().is_dir() {
            if !expected
                .keys()
                .any(|path| path.starts_with(&format!("{relative}/")))
            {
                return Err("Debian package contains an unexpected directory".into());
            }
            continue;
        }
        if !entry.header().entry_type().is_file() || !files.insert(relative.clone()) {
            return Err("Debian package contains a link, special, or duplicate entry".into());
        }
        let mode = entry
            .header()
            .mode()
            .map_err(|error| format!("invalid Debian data mode: {error}"))?
            & 0o777;
        let mut data = Vec::new();
        entry
            .take(MAX_TREE_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|error| format!("could not read Debian data entry: {error}"))?;
        if data.len() as u64 > MAX_TREE_BYTES {
            return Err("Debian data entry exceeds its size limit".into());
        }
        total = total
            .checked_add(data.len() as u64)
            .filter(|total| *total <= MAX_STANDALONE_INPUT_BYTES)
            .ok_or_else(|| "Debian package expands beyond the standalone limit".to_owned())?;
        if files.len() > MAX_TREE_ENTRIES {
            return Err("Debian package contains too many files".into());
        }
        verify_embedded_file(&relative, mode, &data, expected)?;
    }
    if files == expected.keys().cloned().collect() {
        Ok(())
    } else {
        Err("Debian package is missing expected files".into())
    }
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
fn verify_rpm_embedded(
    path: &Path,
    host: HostLayout,
    fingerprint_prefix: &str,
    expected: &BTreeMap<String, ExpectedFile>,
) -> Result<(), String> {
    require_regular_file(path, "embedded RPM package")?;
    if fs::metadata(path)
        .map_err(|error| format!("could not inspect RPM package size: {error}"))?
        .len()
        > MAX_STANDALONE_CONTAINER_BYTES
    {
        return Err("RPM package exceeds its size limit".into());
    }
    let package = rpm::Package::open(path).map_err(|error| format!("invalid RPM: {error}"))?;
    package
        .verify_digests()
        .map_err(|error| format!("RPM digest verification failed: {error}"))?;
    let metadata = &package.metadata;
    let expected_release = format!("1.{fingerprint_prefix}");
    if metadata.get_name().ok() != Some(PACKAGE_NAME)
        || metadata.get_version().ok() != Some(env!("CARGO_PKG_VERSION"))
        || metadata.get_release().ok() != Some(expected_release.as_str())
        || metadata.get_arch().ok() != Some(rpm_arch(host)?)
        || metadata.get_license().ok() != Some("MIT OR Apache-2.0")
        || metadata.get_vendor().ok() != Some(PUBLISHER)
    {
        return Err("RPM metadata does not match the verified runner".into());
    }
    let dependencies = metadata
        .get_requires()
        .map_err(|error| format!("could not read RPM dependencies: {error}"))?
        .into_iter()
        .map(|dependency| dependency.name)
        .collect::<BTreeSet<_>>();
    for dependency in [
        "polkit",
        "libwebkit2gtk-4.1.so.0()(64bit)",
        "libgtk-3.so.0()(64bit)",
    ] {
        if !dependencies.contains(dependency) {
            return Err(format!("RPM package is missing dependency `{dependency}`"));
        }
    }
    for script in [
        metadata.get_pre_install_script(),
        metadata.get_post_install_script(),
        metadata.get_pre_uninstall_script(),
        metadata.get_post_uninstall_script(),
        metadata.get_pre_trans_script(),
        metadata.get_post_trans_script(),
        metadata.get_pre_untrans_script(),
        metadata.get_post_untrans_script(),
    ] {
        if !matches!(script, Err(rpm::Error::TagNotFound(_))) {
            return Err("RPM package unexpectedly contains a script".into());
        }
    }
    let mut header_files = BTreeSet::new();
    for entry in metadata
        .get_file_entries()
        .map_err(|error| format!("could not read RPM file metadata: {error}"))?
    {
        let relative = portable_path(
            entry
                .path
                .strip_prefix("/")
                .map_err(|_| "RPM contains a non-absolute file path".to_owned())?,
        )?;
        let expectation = expected
            .get(&relative)
            .ok_or_else(|| "RPM contains an unexpected file".to_owned())?;
        let permissions = match entry.mode {
            rpm::FileMode::Regular { permissions } => permissions,
            _ => return Err("RPM contains a link or special entry".into()),
        };
        if entry.ownership.user != "root"
            || entry.ownership.group != "root"
            || !entry.linkto.is_empty()
            || permissions != if expectation.executable { 0o755 } else { 0o644 }
        {
            return Err("RPM file ownership or mode is invalid".into());
        }
        if let Some(hash) = expectation.sha256 {
            let digest = entry
                .digest
                .ok_or_else(|| "RPM file is missing its digest".to_owned())?;
            if digest.algorithm() != rpm::DigestAlgorithm::Sha2_256
                || digest.as_hex() != sha256_hex(hash)
            {
                return Err("RPM file digest differs from verified bytes".into());
            }
        }
        if !header_files.insert(relative) {
            return Err("RPM contains duplicate file metadata".into());
        }
    }
    if header_files != expected.keys().cloned().collect() {
        return Err("RPM file metadata is incomplete".into());
    }

    let mut input = flate2::read::GzDecoder::new(std::io::Cursor::new(package.content.as_slice()));
    let mut payload_files = BTreeSet::new();
    let mut total = 0_u64;
    loop {
        let mut entry = cpio::NewcReader::new(input)
            .map_err(|error| format!("invalid RPM CPIO payload: {error}"))?;
        if entry.entry().is_trailer() {
            input = entry
                .finish()
                .map_err(|error| format!("invalid RPM CPIO trailer: {error}"))?;
            let mut trailing = [0_u8; 1];
            if input
                .read(&mut trailing)
                .map_err(|error| format!("could not finish RPM payload: {error}"))?
                != 0
            {
                return Err("RPM payload contains trailing data".into());
            }
            break;
        }
        let relative = portable_path(Path::new(entry.entry().name().trim_start_matches("./")))?;
        if entry.entry().uid() != 0
            || entry.entry().gid() != 0
            || entry.entry().mode() & 0o170000 != 0o100000
            || !payload_files.insert(relative.clone())
        {
            return Err("RPM payload contains an invalid or duplicate entry".into());
        }
        let mode = entry.entry().mode() & 0o777;
        let mut data = Vec::new();
        entry
            .by_ref()
            .take(MAX_TREE_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|error| format!("could not read RPM payload entry: {error}"))?;
        if data.len() as u64 > MAX_TREE_BYTES {
            return Err("RPM payload entry exceeds its size limit".into());
        }
        total = total
            .checked_add(data.len() as u64)
            .filter(|total| *total <= MAX_STANDALONE_INPUT_BYTES)
            .ok_or_else(|| "RPM payload expands beyond the standalone limit".to_owned())?;
        if payload_files.len() > MAX_TREE_ENTRIES {
            return Err("RPM payload contains too many files".into());
        }
        verify_embedded_file(&relative, mode, &data, expected)?;
        input = entry
            .finish()
            .map_err(|error| format!("invalid RPM payload padding: {error}"))?;
    }
    if payload_files == expected.keys().cloned().collect() {
        Ok(())
    } else {
        Err("RPM payload is missing expected files".into())
    }
}

#[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
fn verify_embedded_file(
    relative: &str,
    mode: u32,
    data: &[u8],
    expected: &BTreeMap<String, ExpectedFile>,
) -> Result<(), String> {
    let expectation = expected
        .get(relative)
        .ok_or_else(|| format!("native Linux package contains unexpected file `{relative}`"))?;
    if mode != if expectation.executable { 0o755 } else { 0o644 } {
        return Err(format!(
            "native Linux package mode is invalid for `{relative}`"
        ));
    }
    if let Some(hash) = expectation.sha256 {
        if <[u8; 32]>::from(Sha256::digest(data)) != hash {
            return Err(format!("native Linux package changed `{relative}`"));
        }
    } else if relative == DESKTOP_PATH {
        validate_desktop_entry_bytes(data)?;
    } else {
        return Err("native Linux package has an unverified generated file".into());
    }
    Ok(())
}

fn verify_deb(
    package: &Path,
    work: &Path,
    host: HostLayout,
    expected: &BTreeMap<String, ExpectedFile>,
) -> Result<(), String> {
    require_field(package, "Package", PACKAGE_NAME, "dpkg-deb")?;
    require_field(package, "Version", env!("CARGO_PKG_VERSION"), "dpkg-deb")?;
    require_field(package, "Architecture", deb_arch(host)?, "dpkg-deb")?;
    require_field(package, "Maintainer", PUBLISHER, "dpkg-deb")?;
    require_field(package, "Section", "utils", "dpkg-deb")?;
    let dependencies = deb_field(package, "Depends")?;
    for dependency in ["policykit-1", "libwebkit2gtk-4.1-0", "libgtk-3-0"] {
        if !dependencies
            .split(',')
            .map(str::trim)
            .any(|value| value == dependency || value.starts_with(&format!("{dependency} ")))
        {
            return Err(format!(
                "Debian package is missing dependency `{dependency}`"
            ));
        }
    }

    let listing = tool_output(
        "dpkg-deb",
        &[OsStr::new("--contents"), package.as_os_str()],
        None,
    )?;
    let mut listed = Vec::new();
    for line in listing.lines().filter(|line| !line.trim().is_empty()) {
        let (mode, path) = parse_dpkg_contents_line(line)?;
        listed.push((path.to_owned(), entry_kind(mode)?));
    }
    validate_archive_listing(&listed, expected)?;

    let control = work.join("deb-control");
    require_missing(&control, "Debian control extraction")?;
    run_tool(
        "dpkg-deb",
        &[
            OsStr::new("--control"),
            package.as_os_str(),
            control.as_os_str(),
        ],
        None,
    )?;
    require_only_entries(&control, &["control", "md5sums"], "Debian control archive")?;
    require_regular_file(&control.join("control"), "Debian control file")?;
    require_regular_file(&control.join("md5sums"), "Debian md5sums file")?;

    let extracted = work.join("deb-extracted");
    require_missing(&extracted, "Debian package extraction")?;
    run_tool(
        "dpkg-deb",
        &[
            OsStr::new("--extract"),
            package.as_os_str(),
            extracted.as_os_str(),
        ],
        None,
    )?;
    validate_extracted_tree(&extracted, expected)
}

fn parse_dpkg_contents_line(line: &str) -> Result<(&str, &str), String> {
    let mut rest = line;
    let mode = take_listing_field(&mut rest)?;
    let owner = take_listing_field(&mut rest)?;
    let size = take_listing_field(&mut rest)?;
    let _date = take_listing_field(&mut rest)?;
    let _time = take_listing_field(&mut rest)?;
    let path = rest.trim_start();
    if !matches!(owner, "root/root" | "0/0") {
        return Err("Debian package contains a non-root-owned entry".into());
    }
    if size.parse::<u64>().is_err() || path.is_empty() {
        return Err("dpkg-deb returned an invalid contents line".into());
    }
    Ok((mode, path))
}

fn take_listing_field<'a>(input: &mut &'a str) -> Result<&'a str, String> {
    *input = input.trim_start();
    let end = input
        .find(char::is_whitespace)
        .ok_or_else(|| "dpkg-deb returned an invalid contents line".to_owned())?;
    let field = &input[..end];
    *input = &input[end..];
    Ok(field)
}

fn verify_rpm(
    package: &Path,
    work: &Path,
    host: HostLayout,
    fingerprint_prefix: &str,
    expected: &BTreeMap<String, ExpectedFile>,
) -> Result<(), String> {
    run_tool(
        "rpm",
        &[
            OsStr::new("--checksig"),
            OsStr::new("--verbose"),
            package.as_os_str(),
        ],
        None,
    )?;
    let query = tool_output(
        "rpm",
        &[
            OsStr::new("-qp"),
            OsStr::new("--queryformat"),
            OsStr::new("%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n[%{REQUIRENAME}\n]"),
            package.as_os_str(),
        ],
        None,
    )?;
    let mut lines = query.lines();
    if lines.next() != Some(PACKAGE_NAME)
        || lines.next() != Some(env!("CARGO_PKG_VERSION"))
        || lines.next() != Some(&format!("1.{fingerprint_prefix}"))
        || lines.next() != Some(rpm_arch(host)?)
    {
        return Err("RPM package metadata does not match the verified runner".into());
    }
    let dependencies = lines.collect::<BTreeSet<_>>();
    for dependency in [
        "polkit",
        "libwebkit2gtk-4.1.so.0()(64bit)",
        "libgtk-3.so.0()(64bit)",
    ] {
        if !dependencies.contains(dependency) {
            return Err(format!("RPM package is missing dependency `{dependency}`"));
        }
    }

    let scripts = tool_output(
        "rpm",
        &[
            OsStr::new("-qp"),
            OsStr::new("--scripts"),
            package.as_os_str(),
        ],
        None,
    )?;
    if !scripts.trim().is_empty() {
        return Err("RPM package unexpectedly contains install scripts".into());
    }
    let listing = tool_output(
        "rpm",
        &[
            OsStr::new("-qp"),
            OsStr::new("--queryformat"),
            OsStr::new("[%{FILEMODES:perms}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILENAMES}\n]"),
            package.as_os_str(),
        ],
        None,
    )?;
    let mut listed = Vec::new();
    for line in listing.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.splitn(4, '\t');
        let mode = fields
            .next()
            .ok_or_else(|| "rpm returned an invalid file mode".to_owned())?;
        if fields.next() != Some("root") || fields.next() != Some("root") {
            return Err("RPM package contains a non-root-owned entry".into());
        }
        let path = fields
            .next()
            .ok_or_else(|| "rpm returned an invalid file path".to_owned())?;
        listed.push((path.to_owned(), entry_kind(mode)?));
    }
    validate_archive_listing(&listed, expected)?;

    let extracted = work.join("rpm-extracted");
    extract_rpm(package, &extracted)?;
    validate_extracted_tree(&extracted, expected)
}

fn extract_rpm(package: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir(destination)
        .map_err(|error| format!("could not create RPM extraction directory: {error}"))?;
    let mut decoder = Command::new("rpm2cpio")
        .arg(package)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start rpm2cpio: {error}"))?;
    let decoded = decoder
        .stdout
        .take()
        .ok_or_else(|| "rpm2cpio did not expose its output".to_owned())?;
    let extraction = Command::new("cpio")
        .args([
            "--extract",
            "--make-directories",
            "--no-absolute-filenames",
            "--quiet",
        ])
        .current_dir(destination)
        .env("LC_ALL", "C")
        .stdin(decoded)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("could not start cpio for RPM verification: {error}"))?;
    let decoded = decoder
        .wait_with_output()
        .map_err(|error| format!("could not finish rpm2cpio: {error}"))?;
    if !rpm2cpio_output_is_complete(
        decoded.status.code(),
        &decoded.stderr,
        extraction.status.success(),
    ) {
        return Err(format!(
            "RPM extraction failed; rpm2cpio code {:?}: {}; cpio code {:?}: {}",
            decoded.status.code(),
            bounded_output(&decoded.stderr),
            extraction.status.code(),
            bounded_output(&extraction.stderr)
        ));
    }
    Ok(())
}

fn rpm2cpio_output_is_complete(
    decoder_code: Option<i32>,
    decoder_stderr: &[u8],
    extraction_succeeded: bool,
) -> bool {
    // Ubuntu rpm2cpio 4.18 can emit a complete stream and return 1 without diagnostics.
    // The caller still validates the extracted tree byte-for-byte before publication.
    extraction_succeeded
        && (decoder_code == Some(0) || (decoder_code == Some(1) && decoder_stderr.is_empty()))
}

fn validate_extracted_tree(
    root: &Path,
    expected: &BTreeMap<String, ExpectedFile>,
) -> Result<(), String> {
    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    collect_tree(root, root, &mut files, &mut total)?;
    let actual = files.keys().cloned().collect::<BTreeSet<_>>();
    let expected_names = expected.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected_names {
        return Err("native Linux package does not contain exactly the expected files".into());
    }

    for (relative, expectation) in expected {
        let path = files
            .get(relative)
            .ok_or_else(|| format!("native Linux package is missing `{relative}`"))?;
        if let Some(hash) = expectation.sha256
            && sha256_file(path)? != hash
        {
            return Err(format!(
                "native Linux package changed verified bytes at `{relative}`"
            ));
        }
        require_mode(path, expectation.executable, relative)?;
    }
    validate_desktop_entry(
        files
            .get(DESKTOP_PATH)
            .ok_or_else(|| "native Linux package has no desktop entry".to_owned())?,
    )
}

fn validate_archive_listing(
    entries: &[(String, bool)],
    expected: &BTreeMap<String, ExpectedFile>,
) -> Result<(), String> {
    let mut files = BTreeSet::new();
    for (raw, directory) in entries {
        let relative = raw
            .strip_prefix("./")
            .or_else(|| raw.strip_prefix('/'))
            .unwrap_or(raw)
            .trim_end_matches('/');
        if relative.is_empty() {
            if *directory {
                continue;
            }
            return Err("native Linux package listing contains an empty file path".into());
        }
        let relative = portable_path(Path::new(relative))?;
        if *directory {
            let prefix = format!("{relative}/");
            if !expected.keys().any(|path| path.starts_with(&prefix)) {
                return Err(format!(
                    "native Linux package contains unexpected directory `{relative}`"
                ));
            }
        } else if !expected.contains_key(&relative) || !files.insert(relative) {
            return Err("native Linux package contains an unexpected or duplicate file".into());
        }
    }
    if files == expected.keys().cloned().collect() {
        Ok(())
    } else {
        Err("native Linux package listing is missing expected files".into())
    }
}

fn entry_kind(mode: &str) -> Result<bool, String> {
    match mode.as_bytes().first().copied() {
        Some(b'd') => Ok(true),
        Some(b'-') => Ok(false),
        _ => Err("native Linux package contains a link or special entry".into()),
    }
}

fn collect_tree(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, PathBuf>,
    total: &mut u64,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("could not read extracted Linux package: {error}"))?
    {
        let entry = entry.map_err(|error| format!("could not read package entry: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("could not inspect extracted package entry: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("native Linux package contains a symbolic link".into());
        }
        if metadata.is_dir() {
            collect_tree(root, &path, files, total)?;
            continue;
        }
        if !metadata.is_file() || metadata.len() == 0 {
            return Err("native Linux package contains an empty or special file".into());
        }
        *total = total
            .checked_add(metadata.len())
            .filter(|value| *value <= MAX_TREE_BYTES)
            .ok_or_else(|| "native Linux package extraction is too large".to_owned())?;
        let relative = portable_path(
            path.strip_prefix(root)
                .map_err(|_| "extracted package entry escaped its root".to_owned())?,
        )?;
        if files.insert(relative, path).is_some() || files.len() > MAX_TREE_ENTRIES {
            return Err("native Linux package has duplicate or too many files".into());
        }
    }
    Ok(())
}

fn validate_desktop_entry(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("could not read generated Linux desktop entry: {error}"))?;
    validate_desktop_entry_bytes(&bytes)
}

fn validate_desktop_entry_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 4_096 {
        return Err("generated Linux desktop entry is too large".into());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "generated Linux desktop entry is not UTF-8".to_owned())?;
    let mut lines = text.lines();
    if lines.next() != Some("[Desktop Entry]") {
        return Err("generated Linux desktop entry has an invalid header".into());
    }
    let mut fields = BTreeMap::new();
    for line in lines {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| "generated Linux desktop entry has an invalid line".to_owned())?;
        if name.is_empty()
            || value.is_empty()
            || !matches!(
                name,
                "Categories"
                    | "Comment"
                    | "Exec"
                    | "StartupWMClass"
                    | "Icon"
                    | "Name"
                    | "Terminal"
                    | "Type"
            )
            || fields.insert(name, value).is_some()
        {
            return Err("generated Linux desktop entry has unexpected fields".into());
        }
    }
    for (name, value) in [
        ("Exec", TAURI_BINARY_NAME),
        ("StartupWMClass", TAURI_BINARY_NAME),
        ("Icon", TAURI_BINARY_NAME),
        ("Name", APP_NAME),
        ("Terminal", "false"),
        ("Type", "Application"),
    ] {
        if fields.get(name).copied() != Some(value) {
            return Err(format!("generated Linux desktop field `{name}` is invalid"));
        }
    }
    if fields.len() != 8
        || fields.get("Categories").copied() != Some("Development;")
        || fields.get("Comment").copied() != Some("Secure, transactional setup powered by Rust")
    {
        return Err("generated Linux desktop entry metadata is invalid".into());
    }
    Ok(())
}

fn require_field(package: &Path, field: &str, expected: &str, tool: &str) -> Result<(), String> {
    let actual = deb_field(package, field)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{tool} field `{field}` must be `{expected}`, found `{actual}`"
        ))
    }
}

fn deb_field(package: &Path, field: &str) -> Result<String, String> {
    Ok(tool_output(
        "dpkg-deb",
        &[
            OsStr::new("--field"),
            package.as_os_str(),
            OsStr::new(field),
        ],
        None,
    )?
    .trim()
    .to_owned())
}

fn tool_output(program: &str, args: &[&OsStr], cwd: Option<&Path>) -> Result<String, String> {
    let mut command = Command::new(program);
    command.args(args).env("LC_ALL", "C");
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command
        .output()
        .map_err(|error| format!("could not start `{program}`: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{program}` failed; stdout: {}; stderr: {}",
            bounded_output(&output.stdout),
            bounded_output(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| format!("`{program}` returned non-UTF-8 output"))
}

fn run_tool(program: &str, args: &[&OsStr], cwd: Option<&Path>) -> Result<(), String> {
    tool_output(program, args, cwd).map(|_| ())
}

fn single_bundle(directory: &Path, extension: &str) -> Result<PathBuf, String> {
    let mut matches = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "could not read Tauri `{extension}` bundle output `{}`: {error}",
            directory.display()
        )
    })? {
        let path = entry
            .map_err(|error| format!("could not read Tauri bundle entry: {error}"))?
            .path();
        if path.extension() == Some(OsStr::new(extension)) {
            matches.push(path);
        }
    }
    if matches.len() != 1 {
        return Err(format!(
            "Tauri bundler must produce exactly one `.{extension}` file"
        ));
    }
    let path = matches.pop().expect("one package was checked");
    require_regular_file(&path, "Tauri Linux native package")?;
    let bytes = fs::metadata(&path)
        .map_err(|error| format!("could not inspect Tauri package size: {error}"))?
        .len();
    if bytes > MAX_PACKAGE_BYTES {
        return Err("Tauri Linux native package exceeds its size limit".into());
    }
    Ok(path)
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not serialize Linux package metadata: {error}"))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "could not create Linux package metadata `{}`: {error}",
                path.display()
            )
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("could not persist Linux package metadata: {error}"))
}

fn path_text(path: &Path) -> Result<String, String> {
    let path = fs::canonicalize(path)
        .map_err(|error| format!("could not resolve Linux bundle input: {error}"))?;
    if !path.is_absolute() {
        return Err("Linux bundle input must resolve to an absolute path".into());
    }
    path.to_str()
        .filter(|value| !value.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(|| "Linux bundle input path must be safe UTF-8".to_owned())
}

fn portable_path(path: &Path) -> Result<String, String> {
    let mut value = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err("native Linux package contains a non-portable path".into());
        };
        let component = component
            .to_str()
            .filter(|part| !part.is_empty() && !part.chars().any(char::is_control))
            .ok_or_else(|| "native Linux package path is not safe UTF-8".to_owned())?;
        if !value.is_empty() {
            value.push('/');
        }
        value.push_str(component);
    }
    if value.is_empty() || value.len() > 4_096 {
        Err("native Linux package contains an invalid path".into())
    } else {
        Ok(value)
    }
}

fn safe_name(path: &Path, label: &str) -> Result<String, String> {
    path.file_name()
        .and_then(OsStr::to_str)
        .filter(|name| {
            !name.is_empty()
                && !matches!(*name, "." | "..")
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .map(str::to_owned)
        .ok_or_else(|| format!("{label} has an invalid artifact name"))
}

fn deb_arch(host: HostLayout) -> Result<&'static str, String> {
    match host.rust_arch {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        _ => Err("unsupported Debian architecture".into()),
    }
}

fn rpm_arch(host: HostLayout) -> Result<&'static str, String> {
    match host.rust_arch {
        "x86_64" => Ok("x86_64"),
        "aarch64" => Ok("aarch64"),
        _ => Err("unsupported RPM architecture".into()),
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("could not set isolated Tauri binary permissions: {error}"))
}

#[cfg(not(unix))]
fn set_executable(_: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn require_mode(path: &Path, executable: bool, relative: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let actual = fs::metadata(path)
        .map_err(|error| format!("could not inspect packaged mode for `{relative}`: {error}"))?
        .permissions()
        .mode()
        & 0o777;
    let expected = if executable { 0o755 } else { 0o644 };
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "native Linux package mode for `{relative}` must be {expected:o}, found {actual:o}"
        ))
    }
}

#[cfg(not(unix))]
fn require_mode(_: &Path, _: bool, _: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_entry_accepts_only_pathless_tauri_launch() {
        let temp = tempfile::tempdir().unwrap();
        let desktop = temp.path().join("app.desktop");
        fs::write(
            &desktop,
            "[Desktop Entry]\nCategories=Development;\nComment=Secure, transactional setup powered by Rust\nExec=luxury-installer\nStartupWMClass=luxury-installer\nIcon=luxury-installer\nName=Luxury Installer\nTerminal=false\nType=Application\n",
        )
        .unwrap();
        validate_desktop_entry(&desktop).unwrap();

        fs::write(
            &desktop,
            "[Desktop Entry]\nCategories=Development;\nComment=Secure, transactional setup powered by Rust\nExec=luxury-installer %U\nStartupWMClass=luxury-installer\nIcon=luxury-installer\nName=Luxury Installer\nTerminal=false\nType=Application\n",
        )
        .unwrap();
        assert!(validate_desktop_entry(&desktop).is_err());
    }

    #[test]
    fn bundle_config_contains_only_fixed_system_destinations() {
        let temp = tempfile::tempdir().unwrap();
        let paths =
            ["backend", "payload", "helper", "policy", "icon"].map(|name| temp.path().join(name));
        for path in &paths {
            fs::write(path, b"fixture").unwrap();
        }
        let value = bundle_config(
            &paths[0],
            &paths[1],
            &paths[2],
            &paths[3],
            &paths[4],
            "0123456789ab",
        )
        .unwrap();
        assert_eq!(value["bundle"]["targets"], json!(["deb", "rpm"]));
        assert_eq!(
            value["bundle"]["linux"]["deb"]["files"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "/usr/libexec/luxury-installer-helper".into(),
                "/usr/share/polkit-1/actions/software.luxury.installer.policy".into(),
            ])
        );
        assert!(value.to_string().find("preInstallScript").is_none());
        assert!(value.to_string().find("TAURI_SIGNING").is_none());
    }

    #[test]
    fn artifact_names_reject_path_syntax() {
        assert_eq!(
            safe_name(Path::new("/tmp/luxury-installer-linux-x86_64"), "runner").unwrap(),
            "luxury-installer-linux-x86_64"
        );
        assert!(safe_name(Path::new("/tmp/not safe"), "runner").is_err());
    }

    #[test]
    fn dpkg_contents_accepts_named_or_numeric_root_and_preserves_spaces() {
        for (line, expected) in [
            (
                "-rwxr-xr-x root/root 42 2026-08-04 15:46 ./usr/lib/Luxury Installer/backend/luxury",
                "./usr/lib/Luxury Installer/backend/luxury",
            ),
            (
                "-rwxr-xr-x 0/0 42 1970-01-01 03:00 usr/lib/Luxury  Installer/backend/luxury",
                "usr/lib/Luxury  Installer/backend/luxury",
            ),
        ] {
            let (mode, path) = parse_dpkg_contents_line(line).unwrap();
            assert_eq!(mode, "-rwxr-xr-x");
            assert_eq!(path, expected);
        }
        assert!(parse_dpkg_contents_line("-rw-r--r-- user/user 1 now now usr/file").is_err());
        assert!(parse_dpkg_contents_line("-rw-r--r-- 0/0 nope now now usr/file").is_err());
        assert!(parse_dpkg_contents_line("-rw-r--r-- 0/0 1 now now").is_err());
    }

    #[test]
    fn tauri_bundler_receives_only_the_isolated_target_without_credentials() {
        let mut command = Command::new("pnpm");
        let target = Path::new("isolated-target");
        configure_tauri_bundle_environment(&mut command, target);

        let env = |name: &str| {
            command
                .get_envs()
                .find(|(key, _)| *key == OsStr::new(name))
                .map(|(_, value)| value)
        };
        assert_eq!(env("LUXURY_BOUND_PACKAGE_FINGERPRINT"), Some(None));
        assert_eq!(env("CARGO_TARGET_DIR"), Some(Some(target.as_os_str())));
        assert_eq!(env("TAURI_SIGNING_PRIVATE_KEY"), Some(None));
    }

    #[test]
    fn tauri_launcher_hash_allows_only_its_single_exact_bundle_marker_patch() {
        let temp = tempfile::tempdir().unwrap();
        let launcher = temp.path().join("luxury-installer");
        let mut original = b"prefix".to_vec();
        original.extend_from_slice(TAURI_BUNDLE_MARKER);
        original.extend_from_slice(b"suffix");
        fs::write(&launcher, &original).unwrap();

        for replacement in [TAURI_DEB_MARKER, TAURI_RPM_MARKER] {
            let mut patched = original.clone();
            let start = b"prefix".len();
            patched[start..start + replacement.len()].copy_from_slice(replacement);
            assert_eq!(
                tauri_patched_launcher_hash(&launcher, replacement).unwrap(),
                <[u8; 32]>::from(Sha256::digest(&patched))
            );
        }

        fs::write(&launcher, b"no marker").unwrap();
        assert!(tauri_patched_launcher_hash(&launcher, TAURI_DEB_MARKER).is_err());
        fs::write(
            &launcher,
            [TAURI_BUNDLE_MARKER, TAURI_BUNDLE_MARKER].concat(),
        )
        .unwrap();
        assert!(tauri_patched_launcher_hash(&launcher, TAURI_DEB_MARKER).is_err());
        assert!(tauri_patched_launcher_hash(&launcher, b"short").is_err());
    }

    #[test]
    fn rpm2cpio_exit_one_is_usable_only_after_a_clean_complete_extraction() {
        assert!(rpm2cpio_output_is_complete(Some(0), b"", true));
        assert!(rpm2cpio_output_is_complete(Some(1), b"", true));
        assert!(!rpm2cpio_output_is_complete(Some(1), b"warning", true));
        assert!(!rpm2cpio_output_is_complete(Some(1), b"", false));
        assert!(!rpm2cpio_output_is_complete(Some(2), b"", true));
        assert!(!rpm2cpio_output_is_complete(None, b"", true));
    }

    #[test]
    fn archive_listing_is_exact_and_rejects_links() {
        let expected = BTreeMap::from([(
            "usr/bin/luxury-installer".into(),
            ExpectedFile {
                sha256: None,
                executable: true,
            },
        )]);
        validate_archive_listing(
            &[
                ("./usr/".into(), true),
                ("./usr/bin/".into(), true),
                ("./usr/bin/luxury-installer".into(), false),
            ],
            &expected,
        )
        .unwrap();
        assert!(
            validate_archive_listing(&[("./usr/bin/not-luxury".into(), false)], &expected).is_err()
        );
        assert!(entry_kind("lrwxrwxrwx").is_err());
    }

    #[cfg(all(target_os = "linux", feature = "standalone-linux-packager"))]
    #[test]
    fn standalone_rust_containers_round_trip_without_system_package_tools() {
        let temp = tempfile::tempdir().unwrap();
        let release = temp.path().join("release");
        fs::create_dir(&release).unwrap();
        let [launcher, backend, payload, helper, policy, icon] =
            ["launcher", "backend", "payload", "helper", "policy", "icon"]
                .map(|name| temp.path().join(name));
        for (path, bytes) in [
            (&launcher, b"launcher".as_slice()),
            (&backend, b"backend".as_slice()),
            (&payload, b"payload".as_slice()),
            (&helper, b"backend".as_slice()),
            (&policy, LINUX_POLICY_BYTES),
            (&icon, b"icon".as_slice()),
        ] {
            fs::write(path, bytes).unwrap();
        }
        run_embedded_linux_bundle(
            &release,
            EmbeddedRunnerFiles {
                launcher: &launcher,
                backend: &backend,
                payload: &payload,
                helper: &helper,
                policy: &policy,
                icon: &icon,
            },
            "0123456789ab",
        )
        .unwrap();

        let expected =
            expected_files(&launcher, &backend, &payload, &helper, &policy, &icon).unwrap();
        let bundle = release.join("bundle");
        let deb = single_bundle(&bundle.join("deb"), "deb").unwrap();
        let rpm = single_bundle(&bundle.join("rpm"), "rpm").unwrap();
        let host = HostLayout::new("linux", env::consts::ARCH).unwrap();
        verify_deb_embedded(&deb, host, &expected).unwrap();
        verify_rpm_embedded(&rpm, host, "0123456789ab", &expected).unwrap();
    }
}
