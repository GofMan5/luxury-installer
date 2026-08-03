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

const TAURI_CLI_VERSION: &str = "2.11.4";
const PACKAGE_NAME: &str = "luxury-installer";
const PUBLISHER: &str = "Luxury Installer Contributors <opensource@luxury.software>";
const PROVENANCE_FILENAME: &str = "provenance.json";
const MAX_PACKAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 128;
const MAX_TREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

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

fn build_in_work(
    output: &Path,
    work: &Path,
    root: &Path,
    host: HostLayout,
    package: &Path,
) -> Result<PathBuf, String> {
    let runner = assemble_into(package, &work.join("runner-output"))?;
    validate_portable_bundle(&runner.path, host, ShellFlavor::Setup, None)?;
    let runner_name = safe_name(&runner.path, "assembled Linux runner")?;
    let fingerprint = &runner.package_fingerprint;
    let fingerprint_prefix = fingerprint
        .get(..12)
        .filter(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        .ok_or_else(|| "assembled Linux runner has an invalid fingerprint".to_owned())?;

    let resources = host.resources_directory(&runner.path);
    let launcher = host.launcher(&runner.path);
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
    let icon = checked_input(
        &root
            .join("apps")
            .join("luxury-installer")
            .join("src-tauri")
            .join("icons")
            .join("icon.png"),
        "Linux package icon",
    )?;

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

    let expected = expected_files(&launcher, &backend, &payload, &helper, &policy, &icon)?;
    let triple = rustc_host_triple(root)?;
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

    let config = bundle_config(
        &backend,
        &payload,
        &helper,
        &policy,
        &icon,
        fingerprint_prefix,
    )?;
    let config_path = work.join("tauri.linux-package.conf.json");
    write_json(&config_path, &config)?;
    run_tauri_bundle(root, &triple, &isolated_target, &config_path)?;
    if sha256_file(&bundled_binary)? != sha256_file(&launcher)? {
        return Err("Tauri bundling changed the verified Setup executable".into());
    }

    let bundle_root = release.join("bundle");
    let deb = single_bundle(&bundle_root.join("deb"), "deb")?;
    let rpm = single_bundle(&bundle_root.join("rpm"), "rpm")?;
    let deb_hash = sha256_file(&deb)?;
    let rpm_hash = sha256_file(&rpm)?;
    verify_deb(&deb, work, host, &expected)?;
    verify_rpm(&rpm, work, host, fingerprint_prefix, &expected)?;
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
            "kind": "tauri",
            "cliVersion": TAURI_CLI_VERSION,
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
    let output = Command::new(pnpm)
        .args(["exec", "tauri", "bundle", "--bundles", "deb,rpm"])
        .args(["--features", "setup", "--target", triple, "--config"])
        .arg(config)
        .args(["--ci", "--no-sign"])
        .current_dir(&app)
        .env("CARGO_TARGET_DIR", target)
        .env("CI", "true")
        .env_remove("LUXURY_BOUND_PACKAGE_FINGERPRINT")
        .env_remove("TAURI_SIGNING_PRIVATE_KEY")
        .env_remove("TAURI_SIGNING_PRIVATE_KEY_PASSWORD")
        .env_remove("TAURI_SIGNING_RPM_KEY")
        .env_remove("TAURI_SIGNING_RPM_KEY_PASSPHRASE")
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
        let marker = line
            .find(" ./")
            .ok_or_else(|| "dpkg-deb returned an invalid contents path".to_owned())?;
        let mut fields = line[..marker].split_whitespace();
        let mode = fields
            .next()
            .ok_or_else(|| "dpkg-deb returned an invalid contents line".to_owned())?;
        if fields.next() != Some("root/root") {
            return Err("Debian package contains a non-root-owned entry".into());
        }
        listed.push((line[marker + 1..].to_owned(), entry_kind(mode)?));
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
    if !decoded.status.success() || !extraction.status.success() {
        return Err(format!(
            "RPM extraction failed; rpm2cpio: {}; cpio: {}",
            bounded_output(&decoded.stderr),
            bounded_output(&extraction.stderr)
        ));
    }
    Ok(())
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
    if bytes.len() > 4_096 {
        return Err("generated Linux desktop entry is too large".into());
    }
    let text = std::str::from_utf8(&bytes)
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
}
