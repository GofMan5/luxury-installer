use std::path::Path;

#[cfg(target_os = "macos")]
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::Command,
};

#[cfg(target_os = "macos")]
use serde_json::json;

#[cfg(target_os = "macos")]
use super::{
    APP_ID, APP_NAME, HostLayout, MACOS_HELPER_PLIST_BYTES, MACOS_ICON_BYTES, bounded_output,
    macos_info_plist_bytes,
    probe::{probe_backend, probe_runner},
    resolve_target_dir, sha256_hex,
    staging::{
        WorkDirectory, copy_file, ensure_real_directory, publish_directory_no_clobber,
        require_executable, require_missing, require_only_entries, require_only_file,
        require_regular_file, sha256_file,
    },
};

#[cfg(target_os = "macos")]
const DMG_FILENAME: &str = "LuxuryInstallerSetup.dev.dmg";
#[cfg(target_os = "macos")]
const PROVENANCE_FILENAME: &str = "provenance.json";
#[cfg(target_os = "macos")]
const MAX_DMG_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct AppIdentity {
    fingerprint: String,
    launcher_sha256: [u8; 32],
    backend_sha256: [u8; 32],
    payload_sha256: [u8; 32],
    helper_sha256: [u8; 32],
    icon_sha256: [u8; 32],
    code_resources_sha256: [u8; 32],
}

#[cfg(target_os = "macos")]
struct VerifiedApp {
    path: PathBuf,
    identity: AppIdentity,
}

pub(super) fn verify_release_app(app: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let app = inspect_release_app(app)?;
        println!(
            "verified signed, Gatekeeper-accepted, stapled macOS Setup app ({})",
            app.identity.fingerprint
        );
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        Err("verify-macos-release must run on macOS".into())
    }
}

pub(super) fn build_dmg(app: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        build_dmg_native(app)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        Err("macos-dmg must run on macOS".into())
    }
}

pub(super) fn verify_release_dmg(dmg: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let root = crate::workspace_root();
        let target = resolve_target_dir(&root, std::env::var_os("CARGO_TARGET_DIR").as_deref());
        ensure_real_directory(&target)?;
        let verification = target.join("macos-dmg-verification");
        ensure_real_directory(&verification)?;
        let work = WorkDirectory::new(&verification)?;
        let result = inspect_dmg(dmg, &work.path, true);
        match (result, work.cleanup()) {
            (Ok(app), Ok(())) => {
                println!(
                    "verified signed, Gatekeeper-accepted, stapled macOS DMG ({})",
                    app.identity.fingerprint
                );
                Ok(())
            }
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = dmg;
        Err("verify-macos-dmg must run on macOS".into())
    }
}

#[cfg(target_os = "macos")]
fn build_dmg_native(app: &Path) -> Result<(), String> {
    let source = inspect_release_app(app)?;
    let root = crate::workspace_root();
    let host = HostLayout::new(std::env::consts::OS, std::env::consts::ARCH)?;
    let target = resolve_target_dir(&root, std::env::var_os("CARGO_TARGET_DIR").as_deref());
    ensure_real_directory(&target)?;
    let output = target.join("macos-dmg");
    ensure_real_directory(&output)?;
    let work = WorkDirectory::new(&output)?;
    let result = build_dmg_in_work(&source, host, &output, &work.path);

    match (result, work.cleanup()) {
        (Ok(artifact), Ok(())) => {
            println!(
                "verified unsigned macOS development DMG: {}",
                artifact.display()
            );
            Ok(())
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(artifact), Err(cleanup)) => Err(format!(
            "verified macOS DMG was published at `{}`, but {cleanup}",
            artifact.display()
        )),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}

#[cfg(target_os = "macos")]
fn build_dmg_in_work(
    source: &VerifiedApp,
    host: HostLayout,
    output: &Path,
    work: &Path,
) -> Result<PathBuf, String> {
    let image_root = work.join("image-root");
    fs::create_dir(&image_root)
        .map_err(|error| format!("could not create macOS image staging: {error}"))?;
    let staged_app = image_root.join(format!("{APP_NAME}.app"));
    run_tool(
        "/usr/bin/ditto",
        &[
            OsStr::new("--rsrc"),
            OsStr::new("--extattr"),
            OsStr::new("--acl"),
            OsStr::new("--noqtn"),
            source.path.as_os_str(),
            staged_app.as_os_str(),
        ],
    )?;
    symlink("/Applications", image_root.join("Applications"))
        .map_err(|error| format!("could not create Applications link: {error}"))?;
    let staged = inspect_release_app(&staged_app)?;
    if staged.identity != source.identity {
        return Err("staged macOS app identity differs from the verified source".into());
    }

    let dmg = work.join(DMG_FILENAME);
    require_missing(&dmg, "macOS development DMG")?;
    run_tool(
        "/usr/bin/hdiutil",
        &[
            OsStr::new("create"),
            OsStr::new("-quiet"),
            OsStr::new("-fs"),
            OsStr::new("HFS+"),
            OsStr::new("-format"),
            OsStr::new("UDZO"),
            OsStr::new("-imagekey"),
            OsStr::new("zlib-level=9"),
            OsStr::new("-volname"),
            OsStr::new(APP_NAME),
            OsStr::new("-srcfolder"),
            image_root.as_os_str(),
            dmg.as_os_str(),
        ],
    )?;
    require_regular_file(&dmg, "macOS development DMG")?;
    sync_file(&dmg)?;
    let dmg_sha256 = sha256_file(&dmg)?;
    let mounted = inspect_dmg(&dmg, &work.join("dmg-check"), false)?;
    if mounted.identity != source.identity || sha256_file(&dmg)? != dmg_sha256 {
        return Err("macOS DMG changed the verified app or image bytes".into());
    }

    let prefix = source
        .identity
        .fingerprint
        .get(..12)
        .ok_or_else(|| "verified macOS package fingerprint is too short".to_owned())?;
    let artifact_name = format!(
        "luxury-installer-{}-macos-{}-{prefix}-dmg-dev",
        env!("CARGO_PKG_VERSION"),
        host.rust_arch
    );
    let artifact = output.join(&artifact_name);
    require_missing(&artifact, "macOS DMG artifact")?;
    let publish = work.join("publish");
    fs::create_dir(&publish)
        .map_err(|error| format!("could not create macOS DMG publication: {error}"))?;
    let published_dmg = publish.join(DMG_FILENAME);
    copy_file(&dmg, &published_dmg)?;
    if sha256_file(&published_dmg)? != dmg_sha256 {
        return Err("published macOS DMG differs from the verified image".into());
    }
    let provenance = json!({
        "schemaVersion": 1,
        "artifactKind": "unsignedMacosDmgDevelopment",
        "artifactName": artifact_name,
        "target": {
            "os": "macos",
            "arch": host.rust_arch
        },
        "package": {
            "fingerprint": source.identity.fingerprint,
            "payloadSha256": sha256_hex(source.identity.payload_sha256)
        },
        "app": {
            "launcherSha256": sha256_hex(source.identity.launcher_sha256),
            "backendSha256": sha256_hex(source.identity.backend_sha256),
            "helperSha256": sha256_hex(source.identity.helper_sha256),
            "iconSha256": sha256_hex(source.identity.icon_sha256),
            "codeResourcesSha256": sha256_hex(source.identity.code_resources_sha256),
            "signed": true,
            "notarizationStapled": true
        },
        "dmg": {
            "file": DMG_FILENAME,
            "sha256": sha256_hex(dmg_sha256),
            "signed": false,
            "notarizationStapled": false
        },
        "reproducibilityVerified": false,
        "nativeLifecycleVerified": false,
        "productionReady": false,
        "publishable": false
    });
    write_json(&publish.join(PROVENANCE_FILENAME), &provenance)?;
    require_only_entries(
        &publish,
        &[DMG_FILENAME, PROVENANCE_FILENAME],
        "macOS DMG publication",
    )?;
    publish_directory_no_clobber(&publish, &artifact)?;
    if sha256_file(&artifact.join(DMG_FILENAME))? != dmg_sha256 {
        return Err("macOS DMG changed during atomic publication".into());
    }
    Ok(artifact)
}

#[cfg(target_os = "macos")]
fn inspect_release_app(app: &Path) -> Result<VerifiedApp, String> {
    let metadata = fs::symlink_metadata(app)
        .map_err(|error| format!("could not inspect macOS app bundle: {error}"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || app.extension() != Some(OsStr::new("app"))
    {
        return Err("macOS release input must be one real .app directory".into());
    }
    let app = fs::canonicalize(app)
        .map_err(|error| format!("could not resolve macOS app bundle: {error}"))?;
    let contents = app.join("Contents");
    let resources = contents.join("Resources");
    let launcher = contents.join("MacOS").join(APP_NAME);
    let backend = resources.join("backend").join("luxury");
    let payload = resources.join("payload").join("package.luxpkg");
    let helper = resources.join("luxury-installer-helper");
    let icon = resources.join("icon.icns");
    let helper_plist = contents
        .join("Library")
        .join("LaunchDaemons")
        .join("software.luxury.installer.helper.plist");
    let info_plist = contents.join("Info.plist");
    let code_resources = contents.join("_CodeSignature").join("CodeResources");

    require_only_entries(&app, &["Contents"], "signed macOS application bundle")?;
    require_signed_contents(&contents)?;
    require_only_entries(
        &contents.join("Library"),
        &["LaunchDaemons"],
        "macOS Library",
    )?;
    require_only_file(
        &contents.join("Library").join("LaunchDaemons"),
        "software.luxury.installer.helper.plist",
    )?;
    require_only_file(&contents.join("MacOS"), APP_NAME)?;
    require_only_entries(
        &resources,
        &["backend", "icon.icns", "luxury-installer-helper", "payload"],
        "signed macOS resources",
    )?;
    require_only_file(&resources.join("backend"), "luxury")?;
    require_only_file(&resources.join("payload"), "package.luxpkg")?;
    require_only_file(&contents.join("_CodeSignature"), "CodeResources")?;

    for (path, label) in [
        (&launcher, "signed macOS launcher"),
        (&backend, "signed macOS backend"),
        (&payload, "signed macOS payload"),
        (&helper, "signed macOS helper"),
        (&icon, "signed macOS icon"),
        (&helper_plist, "signed macOS helper plist"),
        (&info_plist, "signed macOS Info.plist"),
        (&code_resources, "signed macOS CodeResources"),
    ] {
        require_regular_file(path, label)?;
    }
    for (path, label) in [
        (&launcher, "signed macOS launcher"),
        (&backend, "signed macOS backend"),
        (&helper, "signed macOS helper"),
    ] {
        require_executable(path, label)?;
        require_mode(path, 0o755, label)?;
    }
    for (path, label) in [
        (&payload, "signed macOS payload"),
        (&icon, "signed macOS icon"),
        (&helper_plist, "signed macOS helper plist"),
        (&info_plist, "signed macOS Info.plist"),
        (&code_resources, "signed macOS CodeResources"),
    ] {
        require_mode(path, 0o644, label)?;
    }
    if fs::read(&helper_plist)
        .map_err(|error| format!("could not read macOS helper plist: {error}"))?
        != MACOS_HELPER_PLIST_BYTES
    {
        return Err("macOS release helper plist does not match the reviewed bytes".into());
    }
    if fs::read(&icon).map_err(|error| format!("could not read macOS icon: {error}"))?
        != MACOS_ICON_BYTES
    {
        return Err("macOS release icon does not match the branded source".into());
    }
    let expected_info = macos_info_plist_bytes(
        APP_NAME,
        APP_ID,
        APP_NAME,
        APP_NAME,
        env!("CARGO_PKG_VERSION"),
    )?;
    if fs::read(&info_plist).map_err(|error| format!("could not read macOS Info.plist: {error}"))?
        != expected_info
    {
        return Err("macOS release Info.plist differs from the exact build contract".into());
    }
    let before = app_hashes(
        &launcher,
        &backend,
        &payload,
        &helper,
        &icon,
        &code_resources,
    )?;
    luxury_macos_trust::verify_path(&app, luxury_macos_trust::CodeRole::App)
        .map_err(|error| error.to_string())?;
    luxury_macos_trust::verify_path(&helper, luxury_macos_trust::CodeRole::Helper)
        .map_err(|error| error.to_string())?;
    run_tool(
        "/usr/bin/codesign",
        &[
            OsStr::new("--verify"),
            OsStr::new("--deep"),
            OsStr::new("--strict"),
            OsStr::new("--verbose=4"),
            app.as_os_str(),
        ],
    )?;
    run_tool(
        "/usr/sbin/spctl",
        &[
            OsStr::new("--assess"),
            OsStr::new("--type"),
            OsStr::new("execute"),
            OsStr::new("--verbose=4"),
            app.as_os_str(),
        ],
    )?;
    run_tool(
        "/usr/bin/xcrun",
        &[
            OsStr::new("stapler"),
            OsStr::new("validate"),
            app.as_os_str(),
        ],
    )?;
    let host = HostLayout::new("macos", std::env::consts::ARCH)?;
    let fingerprint = probe_backend(&backend, &payload, host)?;
    probe_runner(&launcher)?;
    run_tool(
        "/usr/bin/codesign",
        &[
            OsStr::new("--verify"),
            OsStr::new("--deep"),
            OsStr::new("--strict"),
            OsStr::new("--verbose=4"),
            app.as_os_str(),
        ],
    )?;
    run_tool(
        "/usr/bin/xcrun",
        &[
            OsStr::new("stapler"),
            OsStr::new("validate"),
            app.as_os_str(),
        ],
    )?;
    let after = app_hashes(
        &launcher,
        &backend,
        &payload,
        &helper,
        &icon,
        &code_resources,
    )?;
    if before != after {
        return Err("macOS release app changed during verification".into());
    }
    Ok(VerifiedApp {
        path: app,
        identity: AppIdentity {
            fingerprint,
            launcher_sha256: after[0],
            backend_sha256: after[1],
            payload_sha256: after[2],
            helper_sha256: after[3],
            icon_sha256: after[4],
            code_resources_sha256: after[5],
        },
    })
}

#[cfg(target_os = "macos")]
fn require_signed_contents(contents: &Path) -> Result<(), String> {
    let required = BTreeSet::from(
        [
            "Info.plist",
            "Library",
            "MacOS",
            "Resources",
            "_CodeSignature",
        ]
        .map(str::to_owned),
    );
    let mut found = BTreeSet::new();
    for entry in fs::read_dir(contents)
        .map_err(|error| format!("could not read signed macOS Contents: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("could not read macOS Contents entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "signed macOS Contents contains a non-UTF-8 name".to_owned())?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("could not inspect macOS Contents entry: {error}"))?;
        if name == "CodeResources" {
            if metadata.file_type().is_symlink() {
                if fs::read_link(entry.path())
                    .map_err(|error| format!("could not read CodeResources link: {error}"))?
                    != Path::new("_CodeSignature/CodeResources")
                {
                    return Err("macOS CodeResources link has an unexpected target".into());
                }
            } else if !metadata.is_file() || metadata.len() == 0 {
                return Err("macOS stapled CodeResources must be a non-empty regular file".into());
            }
            continue;
        }
        if !required.contains(&name) || metadata.file_type().is_symlink() {
            return Err("signed macOS Contents has an unexpected entry".into());
        }
        found.insert(name);
    }
    if found == required {
        Ok(())
    } else {
        Err("signed macOS Contents is missing a required entry".into())
    }
}

#[cfg(target_os = "macos")]
fn inspect_dmg(dmg: &Path, work: &Path, require_signed: bool) -> Result<VerifiedApp, String> {
    let metadata = fs::symlink_metadata(dmg)
        .map_err(|error| format!("could not inspect macOS DMG: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_DMG_BYTES
        || dmg.extension() != Some(OsStr::new("dmg"))
    {
        return Err("macOS DMG must be one bounded regular .dmg file".into());
    }
    let dmg =
        fs::canonicalize(dmg).map_err(|error| format!("could not resolve macOS DMG: {error}"))?;
    let image_sha256 = sha256_file(&dmg)?;
    run_tool(
        "/usr/bin/hdiutil",
        &[OsStr::new("verify"), OsStr::new("-quiet"), dmg.as_os_str()],
    )?;
    if require_signed {
        run_tool(
            "/usr/bin/codesign",
            &[
                OsStr::new("--verify"),
                OsStr::new("--strict"),
                OsStr::new("--verbose=4"),
                dmg.as_os_str(),
            ],
        )?;
        run_tool(
            "/usr/sbin/spctl",
            &[
                OsStr::new("--assess"),
                OsStr::new("--type"),
                OsStr::new("open"),
                OsStr::new("--context"),
                OsStr::new("context:primary-signature"),
                OsStr::new("--verbose=4"),
                dmg.as_os_str(),
            ],
        )?;
        run_tool(
            "/usr/bin/xcrun",
            &[
                OsStr::new("stapler"),
                OsStr::new("validate"),
                dmg.as_os_str(),
            ],
        )?;
    }

    fs::create_dir_all(work)
        .map_err(|error| format!("could not create DMG verification work directory: {error}"))?;
    let mount = work.join("mount");
    fs::create_dir(&mount).map_err(|error| format!("could not create DMG mount point: {error}"))?;
    run_tool(
        "/usr/bin/hdiutil",
        &[
            OsStr::new("attach"),
            OsStr::new("-quiet"),
            OsStr::new("-readonly"),
            OsStr::new("-nobrowse"),
            OsStr::new("-noautoopen"),
            OsStr::new("-mountpoint"),
            mount.as_os_str(),
            dmg.as_os_str(),
        ],
    )?;
    let verification = (|| {
        require_dmg_root(&mount)?;
        inspect_release_app(&mount.join(format!("{APP_NAME}.app")))
    })();
    let detach = detach_dmg(&mount);
    match (verification, detach) {
        (Ok(app), Ok(())) if sha256_file(&dmg)? == image_sha256 => Ok(app),
        (Ok(_), Ok(())) => Err("macOS DMG changed during mounted verification".into()),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(detach)) => Err(format!("{error}; {detach}")),
    }
}

#[cfg(target_os = "macos")]
fn detach_dmg(mount: &Path) -> Result<(), String> {
    let normal = run_tool(
        "/usr/bin/hdiutil",
        &[
            OsStr::new("detach"),
            OsStr::new("-quiet"),
            mount.as_os_str(),
        ],
    );
    if normal.is_ok() {
        return Ok(());
    }
    let forced = run_tool(
        "/usr/bin/hdiutil",
        &[
            OsStr::new("detach"),
            OsStr::new("-quiet"),
            OsStr::new("-force"),
            mount.as_os_str(),
        ],
    );
    match (normal, forced) {
        (Err(error), Ok(())) => Err(format!(
            "{error}; the read-only QA image required forced detach"
        )),
        (Err(error), Err(forced)) => Err(format!("{error}; forced detach also failed: {forced}")),
        _ => unreachable!("successful normal detach returned above"),
    }
}

#[cfg(target_os = "macos")]
fn require_dmg_root(mount: &Path) -> Result<(), String> {
    let mut names = fs::read_dir(mount)
        .map_err(|error| format!("could not read mounted macOS DMG: {error}"))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| format!("could not read mounted DMG entry: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    let mut expected = vec![
        OsStr::new("Applications").to_os_string(),
        OsStr::new(&format!("{APP_NAME}.app")).to_os_string(),
    ];
    expected.sort();
    if names != expected {
        return Err("macOS DMG must contain only the Setup app and Applications link".into());
    }
    let applications = mount.join("Applications");
    let metadata = fs::symlink_metadata(&applications)
        .map_err(|error| format!("could not inspect Applications link: {error}"))?;
    if !metadata.file_type().is_symlink()
        || fs::read_link(&applications)
            .map_err(|error| format!("could not read Applications link: {error}"))?
            != Path::new("/Applications")
    {
        return Err("macOS DMG Applications entry must link exactly to /Applications".into());
    }
    let app = mount.join(format!("{APP_NAME}.app"));
    let metadata = fs::symlink_metadata(&app)
        .map_err(|error| format!("could not inspect mounted Setup app: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("macOS DMG Setup app must be one real directory".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn app_hashes(
    launcher: &Path,
    backend: &Path,
    payload: &Path,
    helper: &Path,
    icon: &Path,
    code_resources: &Path,
) -> Result<[[u8; 32]; 6], String> {
    Ok([
        sha256_file(launcher)?,
        sha256_file(backend)?,
        sha256_file(payload)?,
        sha256_file(helper)?,
        sha256_file(icon)?,
        sha256_file(code_resources)?,
    ])
}

#[cfg(target_os = "macos")]
fn require_mode(path: &Path, expected: u32, label: &str) -> Result<(), String> {
    let actual = fs::metadata(path)
        .map_err(|error| format!("could not inspect {label} mode: {error}"))?
        .permissions()
        .mode()
        & 0o777;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} mode must be {expected:o}, found {actual:o}"
        ))
    }
}

#[cfg(target_os = "macos")]
fn run_tool(executable: &str, args: &[&OsStr]) -> Result<(), String> {
    let output = Command::new(executable)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|error| format!("could not start macOS release tool `{executable}`: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "macOS release tool `{executable}` failed; stdout: {}; stderr: {}",
            bounded_output(&output.stdout),
            bounded_output(&output.stderr)
        ))
    }
}

#[cfg(target_os = "macos")]
fn sync_file(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("could not sync macOS DMG: {error}"))
}

#[cfg(target_os = "macos")]
fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not serialize macOS DMG provenance: {error}"))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("could not create macOS DMG provenance: {error}"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("could not persist macOS DMG provenance: {error}"))
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn macos_release_commands_fail_before_touching_inputs_off_platform() {
        let missing = Path::new("missing.app");
        assert_eq!(
            build_dmg(missing).unwrap_err(),
            "macos-dmg must run on macOS"
        );
        assert_eq!(
            verify_release_app(missing).unwrap_err(),
            "verify-macos-release must run on macOS"
        );
        assert_eq!(
            verify_release_dmg(Path::new("missing.dmg")).unwrap_err(),
            "verify-macos-dmg must run on macOS"
        );
    }
}
