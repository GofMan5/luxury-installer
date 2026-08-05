use std::{
    collections::BTreeSet,
    env,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::{Value, json};

use crate::{gui_check, workspace_root};

#[cfg(unix)]
mod archive;
mod linux_container;
mod macos_container;
mod probe;
mod staging;
mod windows_container;

use probe::{
    LifecycleProbe, StressExpectation, StressPackage, probe_backend, probe_crash_recovery,
    probe_install_cancellation, probe_launch, probe_lifecycle, probe_runner, probe_studio,
    probe_uninstall_precommit_crash_recovery, probe_upgrade_crash_recovery,
};
use staging::{
    WorkDirectory, checked_input, copy_file, ensure_real_directory, hash_frontend_tree,
    publish_directory_no_clobber, require_executable, require_missing, require_only_entries,
    require_only_file, require_regular_file, retry_transient_io, set_runner_permissions,
    sha256_file,
};

const APP_NAME: &str = "Luxury Installer";
const APP_ID: &str = "software.luxury.installer";
const TAURI_BINARY_NAME: &str = "luxury-installer";
const TAURI_SHELL_KIND: &str = "tauri";
const TAURI_SHELL_VERSION: &str = "2.11.5";
const LINUX_POLICY_BYTES: &[u8] =
    include_bytes!("../../packaging/linux/software.luxury.installer.policy");
const LINUX_ICON_BYTES: &[u8] =
    include_bytes!("../../apps/luxury-installer/src-tauri/icons/icon.png");
const MACOS_HELPER_PLIST_BYTES: &[u8] =
    include_bytes!("../../packaging/macos/software.luxury.installer.helper.plist");
const MACOS_ICON_BYTES: &[u8] =
    include_bytes!("../../apps/luxury-installer/src-tauri/icons/icon.icns");
const EVIDENCE_SCHEMA_VERSION: u32 = 2;
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024;
const SMOKE_HELLO: &[u8] = b"Hello from Luxury Installer.\n";
const SMOKE_LICENSE: &str = "Luxury Installer smoke license.\nAcceptance is required.";
const SMOKE_INSTALLED_FILES: u64 = 1;
const LAUNCH_MARKER_FILE: &str = "launch-probe.ok";
const LAUNCH_MARKER_TEMP_FILE: &str = "launch-probe.tmp";
const LAUNCH_MARKER_MAGIC: &str = "luxury-launch-proof-v1";
const LAUNCH_EXIT_ACK: &[u8] = b"launch-helper-exiting\n";
const CANCELLATION_LARGE_BYTES: u64 = 16 * 1024 * 1024;
const CANCELLATION_MARKER_FILES: u64 = 768;
const EXPECTED_EVIDENCE: [(&str, &str, &str); 3] = [
    ("linux-x86_64.json", "linux", "x86_64"),
    ("windows-x86_64.json", "windows", "x86_64"),
    ("macos-aarch64.json", "macos", "aarch64"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunnerEvidence {
    schema_version: u32,
    target: EvidenceTarget,
    shell: EvidenceShell,
    package: EvidencePackage,
    artifacts: EvidenceArtifacts,
    lifecycle: EvidenceLifecycle,
    checks: EvidenceChecks,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EvidenceShell {
    kind: String,
    version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EvidenceTarget {
    triple: String,
    os: String,
    arch: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EvidencePackage {
    id: String,
    version: String,
    fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EvidenceArtifacts {
    backend_sha256: String,
    payload_sha256: String,
    frontend_tree_sha256: String,
    launcher_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EvidenceLifecycle {
    installed_files: u64,
    installed_bytes: u64,
    removed_files: u64,
    missing_files: u64,
    preserved_modified_files: u64,
    install_progress_events: u64,
    uninstall_progress_events: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EvidenceChecks {
    backend_inspect: bool,
    backend_install: bool,
    installed_bytes_verified: bool,
    foreign_preserved: bool,
    uninstall: bool,
    receipt_cleanup: bool,
    transaction_cleanup: bool,
    tauri_entrypoint: bool,
    temp_cleanup: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostLayout {
    rust_os: &'static str,
    rust_arch: &'static str,
    backend_name: &'static str,
    shell_name: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShellFlavor {
    Setup,
    SetupTemplate,
    Studio,
}

impl ShellFlavor {
    fn cargo_feature_args(self) -> &'static [&'static str] {
        match self {
            Self::Setup | Self::SetupTemplate => &["--no-default-features", "--features", "setup"],
            Self::Studio => &["--features", "studio"],
        }
    }
}

pub(super) struct AssembledRunner {
    pub(super) path: PathBuf,
    pub(super) frontend_tree_sha256: [u8; 32],
    pub(super) package_fingerprint: String,
}

impl HostLayout {
    fn new(os: &str, arch: &str) -> Result<Self, String> {
        let (rust_os, backend_name, shell_name) = match os {
            "windows" => ("windows", "luxury.exe", "luxury-installer.exe"),
            "linux" => ("linux", "luxury", TAURI_BINARY_NAME),
            "macos" => ("macos", "luxury", TAURI_BINARY_NAME),
            other => {
                return Err(format!(
                    "native runner assembly does not support host OS `{other}`"
                ));
            }
        };
        let rust_arch = match arch {
            "x86_64" => "x86_64",
            "aarch64" => "aarch64",
            other => {
                return Err(format!(
                    "native runner assembly does not support host architecture `{other}`"
                ));
            }
        };
        Ok(Self {
            rust_os,
            rust_arch,
            backend_name,
            shell_name,
        })
    }

    fn resources_directory(self, bundle: &Path) -> PathBuf {
        match self.rust_os {
            "windows" => bundle.to_path_buf(),
            "linux" => bundle.join("usr").join("lib").join(APP_NAME),
            "macos" => bundle
                .join(format!("{APP_NAME}.app"))
                .join("Contents")
                .join("Resources"),
            _ => unreachable!("HostLayout rejects unsupported operating systems"),
        }
    }

    fn launcher(self, bundle: &Path) -> PathBuf {
        match self.rust_os {
            "macos" => bundle
                .join(format!("{APP_NAME}.app"))
                .join("Contents")
                .join("MacOS")
                .join(APP_NAME),
            "windows" => bundle.join(format!("{APP_NAME}.exe")),
            "linux" => bundle.join("usr").join("bin").join("luxury-installer"),
            _ => unreachable!("HostLayout rejects unsupported operating systems"),
        }
    }

    fn launch_probe_entrypoint(self) -> &'static str {
        if self.rust_os == "windows" {
            "launch-probe.exe"
        } else {
            "launch-probe"
        }
    }
}

fn macos_info_plist_bytes(
    executable: &str,
    identifier: &str,
    name: &str,
    display_name: &str,
    version: &str,
) -> Result<Vec<u8>, String> {
    if !valid_bundle_identifier(identifier) {
        return Err("macOS bundle identifier is invalid".into());
    }
    if !valid_apple_bundle_version(version) {
        return Err("macOS bundle version must contain one to three numeric components".into());
    }
    let executable = escape_plist_text(executable, "CFBundleExecutable")?;
    let identifier = escape_plist_text(identifier, "CFBundleIdentifier")?;
    let name = escape_plist_text(name, "CFBundleName")?;
    let display_name = escape_plist_text(display_name, "CFBundleDisplayName")?;
    let version = escape_plist_text(version, "bundle version")?;
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"https://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
  <key>CFBundleDisplayName</key>\n\
  <string>{display_name}</string>\n\
  <key>CFBundleExecutable</key>\n\
  <string>{executable}</string>\n\
  <key>CFBundleIdentifier</key>\n\
  <string>{identifier}</string>\n\
  <key>CFBundleInfoDictionaryVersion</key>\n\
  <string>6.0</string>\n\
  <key>CFBundleIconFile</key>\n\
  <string>icon.icns</string>\n\
  <key>CFBundleName</key>\n\
  <string>{name}</string>\n\
  <key>CFBundlePackageType</key>\n\
  <string>APPL</string>\n\
  <key>CFBundleShortVersionString</key>\n\
  <string>{version}</string>\n\
  <key>CFBundleVersion</key>\n\
  <string>{version}</string>\n\
  <key>LSMinimumSystemVersion</key>\n\
  <string>13.0</string>\n\
</dict>\n\
</plist>\n"
    )
    .into_bytes())
}

fn escape_plist_text(value: &str, label: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
        return Err(format!("{label} is not safe plist text"));
    }
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            character => escaped.push(character),
        }
    }
    Ok(escaped)
}

fn valid_bundle_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.split('.').count() >= 2
        && value.split('.').all(|component| {
            !component.is_empty()
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_apple_bundle_version(value: &str) -> bool {
    let components = value.split('.').collect::<Vec<_>>();
    (1..=3).contains(&components.len())
        && components.iter().all(|component| {
            !component.is_empty()
                && component.len() <= 4
                && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn write_macos_info_plist(bundle: &Path) -> Result<Vec<u8>, String> {
    let bytes = macos_info_plist_bytes(
        APP_NAME,
        APP_ID,
        APP_NAME,
        APP_NAME,
        env!("CARGO_PKG_VERSION"),
    )?;
    let path = bundle
        .join(format!("{APP_NAME}.app"))
        .join("Contents")
        .join("Info.plist");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("could not create macOS Info.plist: {error}"))?;
    file.write_all(&bytes)
        .map_err(|error| format!("could not write macOS Info.plist: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("could not sync macOS Info.plist: {error}"))?;
    drop(file);
    Ok(bytes)
}

fn validate_macos_bundle(
    bundle: &Path,
    host: HostLayout,
    flavor: ShellFlavor,
    expected_info_plist: &[u8],
) -> Result<(), String> {
    if host.rust_os != "macos" {
        return Err("macOS bundle validation requires a macOS host layout".into());
    }
    let app_name = format!("{APP_NAME}.app");
    let app = bundle.join(&app_name);
    require_only_entries(bundle, &[&app_name], "portable macOS runner")?;
    validate_macos_app(&app, host, flavor, expected_info_plist)
}

fn validate_macos_app(
    app: &Path,
    host: HostLayout,
    flavor: ShellFlavor,
    expected_info_plist: &[u8],
) -> Result<(), String> {
    let contents = app.join("Contents");
    let executables = contents.join("MacOS");
    let resources = contents.join("Resources");
    let backend = resources.join("backend");
    let payload = resources.join("payload");
    let helper = resources.join("luxury-installer-helper");
    let icon = resources.join("icon.icns");
    let launch_daemons = contents.join("Library").join("LaunchDaemons");
    let helper_plist = launch_daemons.join("software.luxury.installer.helper.plist");
    let info_plist = contents.join("Info.plist");

    require_only_entries(app, &["Contents"], "macOS application bundle")?;
    require_only_entries(
        &contents,
        &["Info.plist", "Library", "MacOS", "Resources"],
        "macOS bundle Contents",
    )?;
    require_only_entries(
        &contents.join("Library"),
        &["LaunchDaemons"],
        "macOS Library",
    )?;
    require_only_file(&launch_daemons, "software.luxury.installer.helper.plist")?;
    require_only_file(&executables, APP_NAME)?;
    let resource_entries: &[&str] = match flavor {
        ShellFlavor::Setup => &["backend", "icon.icns", "luxury-installer-helper", "payload"],
        ShellFlavor::SetupTemplate => &["backend", "icon.icns", "luxury-installer-helper"],
        ShellFlavor::Studio => &[
            "backend",
            "icon.icns",
            "luxury-installer-helper",
            "packager",
            "templates",
        ],
    };
    require_only_entries(&resources, resource_entries, "macOS bundle Resources")?;
    require_only_file(&backend, host.backend_name)?;
    require_regular_file(&helper, "macOS privilege helper")?;
    require_executable(&helper, "macOS privilege helper")?;
    if sha256_file(&helper)? != sha256_file(&backend.join(host.backend_name))? {
        return Err("macOS privilege helper does not match the verified backend".into());
    }
    if fs::read(&helper_plist)
        .map_err(|error| format!("could not read macOS helper plist: {error}"))?
        != MACOS_HELPER_PLIST_BYTES
    {
        return Err("macOS helper plist bytes changed after staging".into());
    }
    if fs::read(&icon).map_err(|error| format!("could not read macOS icon: {error}"))?
        != MACOS_ICON_BYTES
    {
        return Err("macOS icon bytes changed after staging".into());
    }
    match flavor {
        ShellFlavor::Setup => require_only_file(&payload, "package.luxpkg")?,
        ShellFlavor::SetupTemplate | ShellFlavor::Studio => {
            require_missing(&payload, "payload-free resource")?
        }
    }
    require_regular_file(&info_plist, "macOS Info.plist")?;
    let metadata = fs::metadata(&info_plist)
        .map_err(|error| format!("could not inspect macOS Info.plist size: {error}"))?;
    if metadata.len() != expected_info_plist.len() as u64 {
        return Err("macOS Info.plist size changed after generation".into());
    }
    let actual = fs::read(&info_plist)
        .map_err(|error| format!("could not read macOS Info.plist: {error}"))?;
    if actual != expected_info_plist {
        return Err("macOS Info.plist bytes changed after generation".into());
    }
    Ok(())
}

fn validate_portable_bundle(
    bundle: &Path,
    host: HostLayout,
    flavor: ShellFlavor,
    expected_info_plist: Option<&[u8]>,
) -> Result<(), String> {
    let resources = host.resources_directory(bundle);
    let launcher = host.launcher(bundle);
    let backend = resources.join("backend").join(host.backend_name);
    require_regular_file(&launcher, "portable Tauri Studio launcher")?;
    require_executable(&launcher, "portable Tauri Studio launcher")?;
    require_regular_file(&backend, "portable Studio backend")?;
    require_executable(&backend, "portable Studio backend")?;

    match host.rust_os {
        "windows" => {
            if expected_info_plist.is_some() {
                return Err("Windows Studio must not contain a macOS Info.plist".into());
            }
            let entries: &[&str] = match flavor {
                ShellFlavor::SetupTemplate => &["Luxury Installer.exe", "backend"],
                ShellFlavor::Studio => &[
                    "Luxury Installer.exe",
                    "backend",
                    "packager",
                    "templates",
                    "tools",
                ],
                ShellFlavor::Setup => &["Luxury Installer.exe", "backend", "payload"],
            };
            require_only_entries(bundle, entries, "portable Windows application")?;
            require_only_file(&resources.join("backend"), host.backend_name)?;
        }
        "linux" => {
            if expected_info_plist.is_some() {
                return Err("Linux Studio must not contain a macOS Info.plist".into());
            }
            let usr = bundle.join("usr");
            let bin = usr.join("bin");
            let lib = usr.join("lib");
            let helper = usr.join("libexec").join("luxury-installer-helper");
            let policy_directory = usr.join("share").join("polkit-1").join("actions");
            let policy = policy_directory.join("software.luxury.installer.policy");
            require_only_entries(bundle, &["usr"], "portable Linux Studio")?;
            require_only_entries(
                &usr,
                &["bin", "lib", "libexec", "share"],
                "portable Linux Studio usr",
            )?;
            require_only_file(&bin, "luxury-installer")?;
            require_only_entries(&lib, &[APP_NAME], "portable Linux Studio lib")?;
            require_only_file(&usr.join("libexec"), "luxury-installer-helper")?;
            require_only_entries(&usr.join("share"), &["polkit-1"], "Linux share")?;
            require_only_entries(
                &usr.join("share").join("polkit-1"),
                &["actions"],
                "Linux polkit share",
            )?;
            require_only_file(&policy_directory, "software.luxury.installer.policy")?;
            require_regular_file(&helper, "installed Linux privilege helper")?;
            require_executable(&helper, "installed Linux privilege helper")?;
            if sha256_file(&helper)? != sha256_file(&backend)? {
                return Err("Linux privilege helper does not match the verified backend".into());
            }
            if fs::read(&policy)
                .map_err(|error| format!("could not read Linux polkit policy: {error}"))?
                != LINUX_POLICY_BYTES
            {
                return Err("Linux polkit policy bytes changed after staging".into());
            }
            let entries: &[&str] = match flavor {
                ShellFlavor::SetupTemplate => &["backend"],
                ShellFlavor::Studio => &["backend", "icon.png", "packager", "templates"],
                ShellFlavor::Setup => &["backend", "payload"],
            };
            require_only_entries(&resources, entries, "portable Linux application resources")?;
            require_only_file(&resources.join("backend"), host.backend_name)?;
            if flavor == ShellFlavor::Studio
                && fs::read(resources.join("icon.png"))
                    .map_err(|error| format!("could not read Linux Studio icon: {error}"))?
                    != LINUX_ICON_BYTES
            {
                return Err("portable Linux Studio icon bytes changed during staging".into());
            }
        }
        "macos" => {
            let expected = expected_info_plist
                .ok_or_else(|| "macOS Studio is missing expected Info.plist bytes".to_owned())?;
            validate_macos_bundle(bundle, host, flavor, expected)?;
        }
        _ => unreachable!("HostLayout rejects unsupported operating systems"),
    }
    let payload = resources.join("payload");
    match flavor {
        ShellFlavor::SetupTemplate | ShellFlavor::Studio => {
            require_missing(&payload, "payload-free resource")?
        }
        ShellFlavor::Setup => require_only_file(&payload, "package.luxpkg")?,
    }
    if flavor == ShellFlavor::Studio {
        let packager = resources
            .join("packager")
            .join(packaged_packager_name(host));
        require_only_file(&resources.join("packager"), packaged_packager_name(host))?;
        require_regular_file(&packager, "Studio native packager")?;
        require_executable(&packager, "Studio native packager")?;

        let template_name = format!("{}-{}", host.rust_os, host.rust_arch);
        let templates = resources.join("templates");
        require_only_entries(&templates, &[&template_name], "Studio Setup templates")?;
        let template = templates.join(template_name);
        validate_portable_bundle(
            &template,
            host,
            ShellFlavor::SetupTemplate,
            expected_info_plist,
        )?;
        require_setup_template_binding(&host.launcher(&template))?;

        let tools = resources.join("tools");
        if host.rust_os == "windows" {
            require_only_file(&tools, "nsis-3.12.zip")?;
        } else {
            require_missing(&tools, "non-Windows Studio tool directory")?;
        }
    }
    Ok(())
}

pub(super) fn assemble(package: &Path) -> Result<(), String> {
    let runner = assemble_into(package, &workspace_root().join("dist"))?;
    println!("verified portable Tauri runner: {}", runner.path.display());
    #[cfg(unix)]
    println!(
        "verified portable Tauri runner archive: {}",
        archive::create(&runner.path)?.display()
    );
    Ok(())
}

pub(super) fn studio_assemble() -> Result<(), String> {
    let studio = assemble_studio_into(&workspace_root().join("dist"))?;
    println!("verified portable Tauri Studio: {}", studio.display());
    #[cfg(unix)]
    println!(
        "verified portable Tauri Studio archive: {}",
        archive::create(&studio)?.display()
    );
    Ok(())
}

pub(super) fn project_installer(project: &Path, output: &Path) -> Result<(), String> {
    let packaged_resources = packaged_studio_resources()?;
    match env::consts::OS {
        "windows" => match packaged_resources {
            Some(resources) => {
                windows_container::build_packaged_project(project, output, &resources)
            }
            None => windows_container::build_project(project, output),
        },
        "linux" => match packaged_resources {
            Some(resources) => linux_container::build_packaged_project(project, output, &resources),
            None => linux_container::build_project(project, output),
        },
        "macos" => match packaged_resources {
            Some(resources) => macos_container::build_packaged_project(project, output, &resources),
            None => macos_container::build_project(project, output),
        },
        _ => unreachable!("HostLayout rejects unsupported operating systems"),
    }
}

fn packaged_studio_resources() -> Result<Option<PathBuf>, String> {
    let host = HostLayout::new(env::consts::OS, env::consts::ARCH)?;
    let executable = env::current_exe()
        .map_err(|error| format!("could not resolve native packager executable: {error}"))?;
    if executable.file_name() != Some(OsStr::new(packaged_packager_name(host))) {
        return Ok(None);
    }
    let packager = executable
        .parent()
        .ok_or_else(|| "native packager executable has no parent".to_owned())?;
    if packager.file_name() != Some(OsStr::new("packager")) {
        return Err("packaged native packager is outside its fixed resource directory".into());
    }
    let resources = packager
        .parent()
        .ok_or_else(|| "native packager resource directory has no parent".to_owned())?;
    ensure_real_directory(resources)?;
    Ok(Some(resources.to_path_buf()))
}

pub(super) fn windows_setup(package: &Path, nsis_archive: &Path) -> Result<(), String> {
    windows_container::build(package, nsis_archive)
}

pub(super) fn windows_release_setup(runner: &Path, nsis_archive: &Path) -> Result<(), String> {
    windows_container::build_signed_runner(runner, nsis_archive)
}

pub(super) fn verify_windows_release(setup: &Path) -> Result<(), String> {
    windows_container::verify_signed_setup(setup)
}

pub(super) fn linux_packages(package: &Path) -> Result<(), String> {
    linux_container::build(package)
}

pub(super) fn macos_dmg(app: &Path) -> Result<(), String> {
    macos_container::build_dmg(app)
}

pub(super) fn verify_macos_release(app: &Path) -> Result<(), String> {
    macos_container::verify_release_app(app)
}

pub(super) fn verify_macos_dmg(dmg: &Path) -> Result<(), String> {
    macos_container::verify_release_dmg(dmg)
}

pub(super) fn smoke() -> Result<(), String> {
    let root = workspace_root();
    let host = HostLayout::new(env::consts::OS, env::consts::ARCH)?;
    let evidence_path = evidence_path(&root, host)?;
    remove_stale_evidence(&evidence_path)?;
    let work = WorkDirectory::new(&root.join("target"))?;
    let result = (|| {
        let work_root = fs::canonicalize(&work.path)
            .map_err(|error| format!("could not resolve runner smoke directory: {error}"))?;
        let source_backend = build_backend(&root, host)?;
        let project = work_root.join("project");
        let package = work_root.join("runner-smoke.luxpkg");
        let cancellation_project = work_root.join("cancellation-project");
        let cancellation_package = work_root.join("runner-cancellation.luxpkg");
        let upgrade_project = work_root.join("upgrade-project");
        let upgrade_package = work_root.join("runner-upgrade.luxpkg");
        let barrier_project = work_root.join("barrier-project");
        let barrier_package = work_root.join("runner-barrier.luxpkg");
        let launch_project = work_root.join("launch-project");
        let launch_package = work_root.join("runner-launch.luxpkg");

        run_luxury(&source_backend, "init", &[&project])?;
        set_project_license(&project)?;
        run_luxury(&source_backend, "build", &[&project, &package])?;
        build_stress_package(
            &source_backend,
            &cancellation_project,
            &cancellation_package,
            "1.0.0",
            0,
            cfg!(unix),
        )?;
        build_stress_package(
            &source_backend,
            &upgrade_project,
            &upgrade_package,
            "2.0.0",
            1,
            false,
        )?;
        run_luxury(&source_backend, "init", &[&barrier_project])?;
        set_project_version(&barrier_project, "0.9.0")?;
        run_luxury(
            &source_backend,
            "build",
            &[&barrier_project, &barrier_package],
        )?;
        build_launch_package(&source_backend, &launch_project, &launch_package, host)?;

        let package = checked_input(&package, "runner smoke payload")?;
        let cancellation_package =
            checked_input(&cancellation_package, "runner cancellation payload")?;
        let upgrade_package = checked_input(&upgrade_package, "runner upgrade payload")?;
        let barrier_package = checked_input(&barrier_package, "runner recovery barrier payload")?;
        let runner = assemble_checked_into(
            &package,
            &work_root.join("dist"),
            &root,
            host,
            &source_backend,
        )?;
        probe_bound_package_drift(&runner.path, &barrier_package, host)?;
        collect_smoke_evidence(
            &root,
            host,
            &runner,
            &project,
            StressPackage {
                package: &cancellation_package,
                source_payload: &cancellation_project.join("payload"),
                expected: StressExpectation {
                    files: CANCELLATION_MARKER_FILES + 2,
                    bytes: CANCELLATION_LARGE_BYTES
                        + CANCELLATION_MARKER_FILES
                        + SMOKE_HELLO.len() as u64,
                    applied_bytes: CANCELLATION_LARGE_BYTES,
                    action: "install",
                    executable: cfg!(unix),
                },
            },
            StressPackage {
                package: &upgrade_package,
                source_payload: &upgrade_project.join("payload"),
                expected: StressExpectation {
                    files: CANCELLATION_MARKER_FILES + 2,
                    bytes: CANCELLATION_LARGE_BYTES
                        + CANCELLATION_MARKER_FILES
                        + SMOKE_HELLO.len() as u64,
                    applied_bytes: CANCELLATION_LARGE_BYTES,
                    action: "update",
                    executable: false,
                },
            },
            StressPackage {
                package: &barrier_package,
                source_payload: &barrier_project.join("payload"),
                expected: StressExpectation {
                    files: 1,
                    bytes: SMOKE_HELLO.len() as u64,
                    applied_bytes: SMOKE_HELLO.len() as u64,
                    action: "downgrade",
                    executable: false,
                },
            },
        )
    })();
    let cleanup = work.cleanup();

    match (result, cleanup) {
        (Ok(mut evidence), Ok(())) => {
            evidence.checks.temp_cleanup = true;
            publish_evidence(&evidence_path, &evidence)?;
            println!("verified host-native packaged runner smoke");
            Ok(())
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}

fn probe_bound_package_drift(
    runner: &Path,
    replacement: &Path,
    host: HostLayout,
) -> Result<(), String> {
    let payload = host
        .resources_directory(runner)
        .join("payload")
        .join("package.luxpkg");
    let launcher = host.launcher(runner);
    let backup = payload.with_extension("binding-original");
    require_regular_file(&payload, "bound runner payload")?;
    require_regular_file(replacement, "binding drift payload")?;
    require_missing(&backup, "binding drift backup")?;
    let original_hash = sha256_file(&payload)?;
    fs::rename(&payload, &backup)
        .map_err(|error| format!("could not stage the bound payload for drift QA: {error}"))?;

    let probe = (|| {
        copy_file(replacement, &payload)?;
        let error = match probe_runner(&launcher) {
            Ok(()) => return Err("Setup accepted a package outside its compiled binding".into()),
            Err(error) => error,
        };
        if !error.contains("[invalid_bound_package]") {
            return Err(format!(
                "package-binding drift failed for the wrong reason: {error}"
            ));
        }
        Ok(())
    })();

    let remove = if payload.exists() {
        fs::remove_file(&payload)
            .map_err(|error| format!("could not remove binding drift payload: {error}"))
    } else {
        Ok(())
    };
    let restore = fs::rename(&backup, &payload)
        .map_err(|error| format!("could not restore the bound payload after drift QA: {error}"));
    let cleanup = match (remove, restore) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(remove), Err(restore)) => Err(format!("{remove}; {restore}")),
    };
    match (probe, cleanup) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
        (Err(probe), Err(cleanup)) => return Err(format!("{probe}; {cleanup}")),
    }
    if sha256_file(&payload)? != original_hash {
        return Err("bound payload bytes changed during drift QA".into());
    }
    Ok(())
}

fn build_stress_package(
    backend: &Path,
    project: &Path,
    package: &Path,
    version: &str,
    salt: u8,
    executable: bool,
) -> Result<(), String> {
    run_luxury(backend, "init", &[project])?;
    set_project_version(project, version)?;
    if executable {
        let config = project.join("luxury.toml");
        let source = fs::read_to_string(&config)
            .map_err(|error| format!("could not read stress project config: {error}"))?;
        const EMPTY_EXECUTABLES: &str = "executable = []";
        if source.matches(EMPTY_EXECUTABLES).count() != 1 {
            return Err("stress project config has an unexpected executable field".into());
        }
        fs::write(
            config,
            source.replacen(EMPTY_EXECUTABLES, "executable = [\"000-large.bin\"]", 1),
        )
        .map_err(|error| format!("could not update stress project executable: {error}"))?;
    }
    let large_path = project.join("payload/000-large.bin");
    let mut large = File::create(&large_path)
        .map_err(|error| format!("could not create stress payload: {error}"))?;
    large
        .set_len(CANCELLATION_LARGE_BYTES)
        .and_then(|_| large.write_all(&[salt]))
        .map_err(|error| format!("could not populate stress payload: {error}"))?;
    drop(large);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(
            &large_path,
            fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
        )
        .map_err(|error| format!("could not set stress payload permissions: {error}"))?;
    }
    for index in 0..CANCELLATION_MARKER_FILES {
        fs::write(
            project
                .join("payload")
                .join(format!("marker-{index:04}.bin")),
            [(index as u8).wrapping_add(salt)],
        )
        .map_err(|error| format!("could not create stress marker: {error}"))?;
    }
    run_luxury(backend, "build", &[project, package])
}

fn build_launch_package(
    backend: &Path,
    project: &Path,
    package: &Path,
    host: HostLayout,
) -> Result<(), String> {
    run_luxury(backend, "init", &[project])?;
    let entrypoint = host.launch_probe_entrypoint();
    let payload = project.join("payload");
    fs::remove_file(payload.join("hello.txt"))
        .map_err(|error| format!("could not remove launch fixture placeholder: {error}"))?;

    let build_directory = project.join(".launch-build");
    fs::create_dir(&build_directory)
        .map_err(|error| format!("could not create launch probe build directory: {error}"))?;
    let source_path = build_directory.join("launch-probe.rs");
    fs::write(&source_path, launch_probe_source())
        .map_err(|error| format!("could not write launch probe source: {error}"))?;
    let compiled_executable = build_directory.join(entrypoint);
    let executable = payload.join(entrypoint);
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let output = Command::new(rustc)
        .arg("--edition=2024")
        .arg("-C")
        .arg("debuginfo=0")
        .arg("-C")
        .arg("opt-level=s")
        .arg(&source_path)
        .arg("-o")
        .arg(&compiled_executable)
        .output()
        .map_err(|error| format!("could not compile launch probe: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "launch probe compilation failed: {}",
            bounded_output(&output.stderr)
        ));
    }
    require_executable(&compiled_executable, "compiled launch probe executable")?;
    retry_transient_io(|| fs::rename(&compiled_executable, &executable)).map_err(|error| {
        format!("could not publish launch probe executable into its payload: {error}")
    })?;
    require_executable(&executable, "launch probe executable")?;

    let config = project.join("luxury.toml");
    let source = fs::read_to_string(&config)
        .map_err(|error| format!("could not read launch project config: {error}"))?;
    for required in [
        "format_version = 1",
        "directory = \"Luxury Demo\"",
        "executable = []",
    ] {
        if source.matches(required).count() != 1 {
            return Err("launch project config has an unexpected generated shape".into());
        }
    }
    let executable_policy = if host.rust_os == "windows" {
        "executable = []".to_owned()
    } else {
        format!("executable = [\"{entrypoint}\"]")
    };
    let source = source
        .replacen(
            "format_version = 1",
            "format_version = 1\nschema_version = 2",
            1,
        )
        .replacen(
            "directory = \"Luxury Demo\"",
            &format!("directory = \"Luxury Demo\"\nentrypoint = \"{entrypoint}\""),
            1,
        )
        .replacen("executable = []", &executable_policy, 1);
    fs::write(config, source)
        .map_err(|error| format!("could not update launch project config: {error}"))?;
    run_luxury(backend, "build", &[project, package])
}

fn launch_probe_source() -> String {
    format!(
        r#"use std::{{
    fs::{{self, OpenOptions}},
    io::{{self, Read, Write}},
    net::{{Shutdown, TcpListener}},
    thread,
    time::{{Duration, Instant}},
}};

fn run() -> io::Result<()> {{
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let token = format!("{{:08x}}{{:04x}}", std::process::id(), port);
    let marker_bytes = format!("{{}}\n{{}}\n{{}}\n", {LAUNCH_MARKER_MAGIC:?}, port, token);
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open({LAUNCH_MARKER_TEMP_FILE:?})?;
    marker.write_all(marker_bytes.as_bytes())?;
    marker.sync_all()?;
    drop(marker);
    fs::rename({LAUNCH_MARKER_TEMP_FILE:?}, {LAUNCH_MARKER_FILE:?})?;

    let deadline = Instant::now() + Duration::from_secs(15);
    let (mut stream, peer) = loop {{
        match listener.accept() {{
            Ok(connection) => break connection,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {{
                thread::sleep(Duration::from_millis(10));
            }}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {{
                return Err(io::Error::new(io::ErrorKind::TimedOut, "launch proof timed out"));
            }}
            Err(error) => return Err(error),
        }}
    }};
    if !peer.ip().is_loopback() {{
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "launch proof peer is not loopback",
        ));
    }}
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut received = vec![0_u8; token.len()];
    stream.read_exact(&mut received)?;
    if received != token.as_bytes() {{
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launch proof token did not match",
        ));
    }}
    stream.write_all(&{LAUNCH_EXIT_ACK:?})?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Write);
    Ok(())
}}

fn main() {{
    if std::env::args_os().count() != 1 {{
        std::process::exit(2);
    }}
    if run().is_err() {{
        std::process::exit(3);
    }}
}}
"#
    )
}

fn set_project_version(project: &Path, version: &str) -> Result<(), String> {
    if version != "1.0.0" {
        let config = project.join("luxury.toml");
        let source = fs::read_to_string(&config)
            .map_err(|error| format!("could not read stress project config: {error}"))?;
        const DEFAULT_VERSION: &str = "version = \"1.0.0\"";
        if source.matches(DEFAULT_VERSION).count() != 1 {
            return Err("stress project config has an unexpected version field".into());
        }
        fs::write(
            config,
            source.replacen(DEFAULT_VERSION, &format!("version = \"{version}\""), 1),
        )
        .map_err(|error| format!("could not update stress project version: {error}"))?;
    }
    Ok(())
}

fn set_project_license(project: &Path) -> Result<(), String> {
    let config = project.join("luxury.toml");
    let source = fs::read_to_string(&config)
        .map_err(|error| format!("could not read lifecycle project config: {error}"))?;
    const FORMAT: &str = "format_version = 1";
    const PUBLISHER: &str = "publisher = \"Luxury Software\"";
    if source.matches(FORMAT).count() != 1 || source.matches(PUBLISHER).count() != 1 {
        return Err("lifecycle project config has an unexpected generated shape".into());
    }
    let license = serde_json::to_string(SMOKE_LICENSE)
        .map_err(|error| format!("could not encode lifecycle license: {error}"))?;
    let source = source
        .replacen(FORMAT, "format_version = 1\nschema_version = 3", 1)
        .replacen(PUBLISHER, &format!("{PUBLISHER}\nlicense = {license}"), 1);
    fs::write(config, source)
        .map_err(|error| format!("could not update lifecycle project license: {error}"))
}

pub(super) fn verify_evidence_set(directory: &Path) -> Result<(), String> {
    require_evidence_directory(directory)?;
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "could not read evidence set `{}`: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| format!("could not read evidence entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "evidence set contains a non-Unicode filename".to_owned())?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("could not inspect evidence `{name}`: {error}"))?;
        if is_link_or_reparse(&metadata) || !metadata.is_file() {
            return Err(format!(
                "evidence `{name}` must be a regular file, not a link"
            ));
        }
        actual.insert(name);
    }
    let expected = EXPECTED_EVIDENCE
        .iter()
        .map(|(name, _, _)| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "evidence set must contain exactly {}; found {}",
            expected.into_iter().collect::<Vec<_>>().join(", "),
            actual.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    let mut package_identity: Option<(String, String)> = None;
    for (name, os, arch) in EXPECTED_EVIDENCE {
        let evidence = read_evidence_file(&directory.join(name), os, arch)?;
        let identity = (
            evidence.package.id.clone(),
            evidence.package.version.clone(),
        );
        if let Some(expected) = &package_identity {
            if &identity != expected {
                return Err(format!(
                    "evidence `{name}` describes package {} {}, expected {} {}",
                    identity.0, identity.1, expected.0, expected.1
                ));
            }
        } else {
            package_identity = Some(identity);
        }
    }
    Ok(())
}

fn collect_smoke_evidence(
    root: &Path,
    host: HostLayout,
    runner: &AssembledRunner,
    project: &Path,
    base_stress: StressPackage<'_>,
    upgrade_stress: StressPackage<'_>,
    barrier_stress: StressPackage<'_>,
) -> Result<RunnerEvidence, String> {
    let bundle = &runner.path;
    let resources = host.resources_directory(bundle);
    let backend = resources.join("backend").join(host.backend_name);
    let payload = resources.join("payload").join("package.luxpkg");
    let launcher = host.launcher(bundle);
    let work_root = project
        .parent()
        .ok_or_else(|| "runner smoke project has no work directory".to_owned())?;
    let launch_package = checked_input(
        &work_root.join("runner-launch.luxpkg"),
        "runner launch payload",
    )?;
    let probe_root = work_root.join("lifecycle");
    fs::create_dir(&probe_root)
        .map_err(|error| format!("could not create lifecycle probe directory: {error}"))?;
    let expected_hello = fs::read(project.join("payload").join("hello.txt"))
        .map_err(|error| format!("could not read runner smoke payload bytes: {error}"))?;
    if expected_hello != SMOKE_HELLO {
        return Err("runner smoke payload does not match the schema-v2 fixture".into());
    }
    let upgrade_recovery_root = work_root.join("upgrade-recovery");
    fs::create_dir(&upgrade_recovery_root)
        .map_err(|error| format!("could not create upgrade recovery probe directory: {error}"))?;
    println!("> runner smoke: upgrade crash recovery");
    probe_upgrade_crash_recovery(
        &backend,
        base_stress,
        upgrade_stress,
        barrier_stress,
        host,
        &upgrade_recovery_root,
    )?;
    let recovery_root = work_root.join("recovery");
    fs::create_dir(&recovery_root)
        .map_err(|error| format!("could not create recovery probe directory: {error}"))?;
    println!("> runner smoke: initial-install crash recovery");
    probe_crash_recovery(&backend, base_stress, host, &recovery_root)?;
    let uninstall_recovery_root = work_root.join("uninstall-recovery");
    fs::create_dir(&uninstall_recovery_root)
        .map_err(|error| format!("could not create uninstall recovery probe directory: {error}"))?;
    println!("> runner smoke: uninstall crash recovery");
    probe_uninstall_precommit_crash_recovery(
        &backend,
        base_stress,
        barrier_stress,
        host,
        &uninstall_recovery_root,
    )?;
    let cancellation_root = work_root.join("cancellation");
    fs::create_dir(&cancellation_root)
        .map_err(|error| format!("could not create cancellation probe directory: {error}"))?;
    println!("> runner smoke: cancellation rollback");
    probe_install_cancellation(
        &backend,
        base_stress.package,
        host,
        &cancellation_root,
        base_stress.expected,
    )?;
    let launch_root = work_root.join("launch");
    fs::create_dir(&launch_root)
        .map_err(|error| format!("could not create launch probe directory: {error}"))?;
    println!("> runner smoke: receipt-owned launch");
    probe_launch(
        &backend,
        &launch_package,
        host,
        &launch_root,
        host.launch_probe_entrypoint(),
    )?;
    println!("> runner smoke: normal lifecycle");
    let lifecycle = probe_lifecycle(&backend, &payload, host, &probe_root, &expected_hello)?;
    let frontend = root
        .join("apps")
        .join("luxury-installer")
        .join("out")
        .join("renderer");
    if hash_frontend_tree(&frontend)? != runner.frontend_tree_sha256 {
        return Err("frontend build output no longer matches the assembled Tauri shell".into());
    }
    let target_triple = rustc_host_triple(root)?;
    let artifacts = EvidenceArtifacts {
        backend_sha256: sha256_hex(sha256_file(&backend)?),
        payload_sha256: sha256_hex(sha256_file(&payload)?),
        frontend_tree_sha256: sha256_hex(runner.frontend_tree_sha256),
        launcher_sha256: sha256_hex(sha256_file(&launcher)?),
    };
    build_evidence(host, target_triple, artifacts, lifecycle)
}

fn build_evidence(
    host: HostLayout,
    target_triple: String,
    artifacts: EvidenceArtifacts,
    lifecycle: LifecycleProbe,
) -> Result<RunnerEvidence, String> {
    if lifecycle.install_directory.is_empty() {
        return Err("lifecycle probe returned an empty install directory".into());
    }
    let install_progress_events = u64::try_from(lifecycle.install_progress_events)
        .map_err(|_| "install progress count does not fit evidence schema".to_owned())?;
    let uninstall_progress_events = u64::try_from(lifecycle.uninstall_progress_events)
        .map_err(|_| "uninstall progress count does not fit evidence schema".to_owned())?;
    Ok(RunnerEvidence {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        target: EvidenceTarget {
            triple: target_triple,
            os: host.rust_os.to_owned(),
            arch: host.rust_arch.to_owned(),
        },
        shell: EvidenceShell {
            kind: TAURI_SHELL_KIND.to_owned(),
            version: TAURI_SHELL_VERSION.to_owned(),
        },
        package: EvidencePackage {
            id: lifecycle.package_id,
            version: lifecycle.package_version,
            fingerprint: lifecycle.package_fingerprint,
        },
        artifacts,
        lifecycle: EvidenceLifecycle {
            installed_files: lifecycle.installed_files,
            installed_bytes: lifecycle.installed_bytes,
            removed_files: lifecycle.removed_files,
            missing_files: lifecycle.missing_files,
            preserved_modified_files: lifecycle.preserved_modified_files,
            install_progress_events,
            uninstall_progress_events,
        },
        checks: EvidenceChecks {
            backend_inspect: true,
            backend_install: true,
            installed_bytes_verified: lifecycle.hello_verified
                && lifecycle.installed_files == SMOKE_INSTALLED_FILES
                && lifecycle.installed_bytes == SMOKE_HELLO.len() as u64,
            foreign_preserved: lifecycle.foreign_preserved,
            uninstall: lifecycle.owned_removed,
            receipt_cleanup: lifecycle.state_clean,
            transaction_cleanup: lifecycle.state_clean,
            tauri_entrypoint: true,
            temp_cleanup: false,
        },
    })
}

fn evidence_path(root: &Path, host: HostLayout) -> Result<PathBuf, String> {
    let target = root.join("target");
    ensure_real_directory(&target)?;
    let directory = target.join("runner-evidence");
    ensure_real_directory(&directory)?;
    Ok(directory.join(format!("{}-{}.json", host.rust_os, host.rust_arch)))
}

fn remove_stale_evidence(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not inspect stale runner evidence `{}`: {error}",
            path.display()
        )),
        Ok(metadata) if metadata.is_file() && !is_link_or_reparse(&metadata) => {
            fs::remove_file(path).map_err(|error| {
                format!(
                    "could not remove stale runner evidence `{}`: {error}",
                    path.display()
                )
            })
        }
        Ok(_) => Err(format!(
            "runner evidence `{}` is not a regular file; refusing to remove it",
            path.display()
        )),
    }
}

fn publish_evidence(path: &Path, evidence: &RunnerEvidence) -> Result<(), String> {
    validate_evidence(evidence)?;
    let parent = path
        .parent()
        .ok_or_else(|| "runner evidence path has no parent".to_owned())?;
    ensure_real_directory(parent)?;
    let filename = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| "runner evidence filename is not valid Unicode".to_owned())?;
    let temporary = parent.join(format!(".{filename}.{}.tmp", std::process::id()));
    let mut created = false;
    let mut published = false;
    let result: Result<(), String> = (|| {
        let bytes = evidence_bytes(evidence)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("could not create runner evidence temp file: {error}"))?;
        created = true;
        file.write_all(&bytes)
            .map_err(|error| format!("could not write runner evidence: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("could not sync runner evidence: {error}"))?;
        drop(file);
        fs::hard_link(&temporary, path).map_err(|error| {
            format!("could not atomically publish runner evidence without overwriting: {error}")
        })?;
        published = true;
        fs::remove_file(&temporary)
            .map_err(|error| format!("could not remove published runner evidence temp: {error}"))?;
        created = false;
        Ok(())
    })();
    if let Err(error) = result {
        let mut cleanup = Vec::new();
        if published && let Err(source) = fs::remove_file(path) {
            cleanup.push(format!("removing published evidence failed: {source}"));
        }
        if created && let Err(source) = fs::remove_file(&temporary) {
            cleanup.push(format!("removing evidence temp failed: {source}"));
        }
        return if cleanup.is_empty() {
            Err(error)
        } else {
            Err(format!("{error}; {}", cleanup.join("; ")))
        };
    }
    Ok(())
}

fn evidence_bytes(evidence: &RunnerEvidence) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(&evidence_value(evidence))
        .map_err(|error| format!("could not serialize runner evidence: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn evidence_value(evidence: &RunnerEvidence) -> Value {
    json!({
        "schemaVersion": evidence.schema_version,
        "target": {
            "triple": &evidence.target.triple,
            "os": &evidence.target.os,
            "arch": &evidence.target.arch,
        },
        "shell": {
            "kind": &evidence.shell.kind,
            "version": &evidence.shell.version,
        },
        "package": {
            "id": &evidence.package.id,
            "version": &evidence.package.version,
            "fingerprint": &evidence.package.fingerprint,
        },
        "artifacts": {
            "backendSha256": &evidence.artifacts.backend_sha256,
            "payloadSha256": &evidence.artifacts.payload_sha256,
            "frontendTreeSha256": &evidence.artifacts.frontend_tree_sha256,
            "launcherSha256": &evidence.artifacts.launcher_sha256,
        },
        "lifecycle": {
            "installedFiles": evidence.lifecycle.installed_files,
            "installedBytes": evidence.lifecycle.installed_bytes,
            "removedFiles": evidence.lifecycle.removed_files,
            "missingFiles": evidence.lifecycle.missing_files,
            "preservedModifiedFiles": evidence.lifecycle.preserved_modified_files,
            "installProgressEvents": evidence.lifecycle.install_progress_events,
            "uninstallProgressEvents": evidence.lifecycle.uninstall_progress_events,
        },
        "checks": {
            "backendInspect": evidence.checks.backend_inspect,
            "backendInstall": evidence.checks.backend_install,
            "installedBytesVerified": evidence.checks.installed_bytes_verified,
            "foreignPreserved": evidence.checks.foreign_preserved,
            "uninstall": evidence.checks.uninstall,
            "receiptCleanup": evidence.checks.receipt_cleanup,
            "transactionCleanup": evidence.checks.transaction_cleanup,
            "tauriEntrypoint": evidence.checks.tauri_entrypoint,
            "tempCleanup": evidence.checks.temp_cleanup,
        },
    })
}

fn validate_evidence(evidence: &RunnerEvidence) -> Result<(), String> {
    if evidence.schema_version != EVIDENCE_SCHEMA_VERSION
        || evidence.target.triple.is_empty()
        || evidence.target.os.is_empty()
        || evidence.target.arch.is_empty()
        || evidence.shell.kind != TAURI_SHELL_KIND
        || evidence.shell.version != TAURI_SHELL_VERSION
        || evidence.package.id.is_empty()
        || evidence.package.version.is_empty()
        || !is_lower_hex_64(&evidence.package.fingerprint)
        || evidence.lifecycle.installed_files != SMOKE_INSTALLED_FILES
        || evidence.lifecycle.installed_bytes != SMOKE_HELLO.len() as u64
        || evidence.lifecycle.removed_files != evidence.lifecycle.installed_files
        || evidence.lifecycle.missing_files != 0
        || evidence.lifecycle.preserved_modified_files != 0
        || evidence.lifecycle.install_progress_events == 0
        || evidence.lifecycle.uninstall_progress_events == 0
    {
        return Err("runner evidence is incomplete".into());
    }
    for hash in [
        &evidence.artifacts.backend_sha256,
        &evidence.artifacts.payload_sha256,
        &evidence.artifacts.frontend_tree_sha256,
        &evidence.artifacts.launcher_sha256,
    ] {
        if !is_lower_hex_64(hash) {
            return Err("runner evidence contains an invalid artifact SHA-256".into());
        }
    }
    if !evidence.checks.backend_inspect
        || !evidence.checks.backend_install
        || !evidence.checks.installed_bytes_verified
        || !evidence.checks.foreign_preserved
        || !evidence.checks.uninstall
        || !evidence.checks.receipt_cleanup
        || !evidence.checks.transaction_cleanup
        || !evidence.checks.tauri_entrypoint
        || !evidence.checks.temp_cleanup
    {
        return Err("runner evidence contains an unverified lifecycle check".into());
    }
    Ok(())
}

fn require_evidence_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "could not inspect evidence directory `{}`: {error}",
            path.display()
        )
    })?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(format!(
            "evidence set `{}` must be a real directory",
            path.display()
        ));
    }
    Ok(())
}

fn read_evidence_file(
    path: &Path,
    expected_os: &str,
    expected_arch: &str,
) -> Result<RunnerEvidence, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect evidence `{}`: {error}", path.display()))?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "evidence `{}` must be a non-empty regular file, not a link",
            path.display()
        ));
    }
    if metadata.len() > MAX_EVIDENCE_BYTES {
        return Err(format!(
            "evidence `{}` exceeds {MAX_EVIDENCE_BYTES} bytes",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|error| format!("could not open evidence `{}`: {error}", path.display()))?
        .take(MAX_EVIDENCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read evidence `{}`: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_EVIDENCE_BYTES {
        return Err(format!(
            "evidence `{}` exceeds {MAX_EVIDENCE_BYTES} bytes",
            path.display()
        ));
    }
    let source = std::str::from_utf8(&bytes)
        .map_err(|_| format!("evidence `{}` is not valid UTF-8", path.display()))?;
    parse_evidence(source, expected_os, expected_arch)
        .map_err(|error| format!("invalid evidence `{}`: {error}", path.display()))
}

fn parse_evidence(
    source: &str,
    expected_os: &str,
    expected_arch: &str,
) -> Result<RunnerEvidence, String> {
    let value: Value = serde_json::from_str(source)
        .map_err(|error| format!("could not parse schema-v2 JSON: {error}"))?;
    let root = exact_object(
        &value,
        "root",
        &[
            "schemaVersion",
            "target",
            "shell",
            "package",
            "artifacts",
            "lifecycle",
            "checks",
        ],
    )?;
    if root.get("schemaVersion").and_then(Value::as_u64) != Some(u64::from(EVIDENCE_SCHEMA_VERSION))
    {
        return Err("schemaVersion must be 2".into());
    }

    let target = exact_object(
        required(root, "target")?,
        "target",
        &["triple", "os", "arch"],
    )?;
    let triple = bounded_text(required_string(target, "triple")?, 128, "target.triple")?;
    let os = bounded_text(required_string(target, "os")?, 16, "target.os")?;
    let arch = bounded_text(required_string(target, "arch")?, 16, "target.arch")?;
    if os != expected_os || arch != expected_arch || !triple_matches_target(&triple, &os, &arch) {
        return Err(format!(
            "target {triple} ({os}/{arch}) does not match {expected_os}/{expected_arch}"
        ));
    }
    let shell = exact_object(required(root, "shell")?, "shell", &["kind", "version"])?;
    let shell_kind = bounded_text(required_string(shell, "kind")?, 16, "shell.kind")?;
    let shell_version = bounded_text(required_string(shell, "version")?, 64, "shell.version")?;
    if shell_kind != TAURI_SHELL_KIND || shell_version != TAURI_SHELL_VERSION {
        return Err(format!(
            "shell must be {TAURI_SHELL_KIND} {TAURI_SHELL_VERSION}"
        ));
    }

    let package = exact_object(
        required(root, "package")?,
        "package",
        &["id", "version", "fingerprint"],
    )?;
    let package_id = bounded_text(required_string(package, "id")?, 128, "package.id")?;
    if !valid_package_id(&package_id) {
        return Err("package.id is invalid".into());
    }
    let package_version =
        bounded_text(required_string(package, "version")?, 128, "package.version")?;
    let package_fingerprint = required_string(package, "fingerprint")?.to_owned();
    if !is_lower_hex_64(&package_fingerprint) {
        return Err("package.fingerprint must be lowercase SHA-256".into());
    }

    let artifacts = exact_object(
        required(root, "artifacts")?,
        "artifacts",
        &[
            "backendSha256",
            "payloadSha256",
            "frontendTreeSha256",
            "launcherSha256",
        ],
    )?;
    let artifacts = EvidenceArtifacts {
        backend_sha256: required_hash(artifacts, "backendSha256")?,
        payload_sha256: required_hash(artifacts, "payloadSha256")?,
        frontend_tree_sha256: required_hash(artifacts, "frontendTreeSha256")?,
        launcher_sha256: required_hash(artifacts, "launcherSha256")?,
    };

    let lifecycle = exact_object(
        required(root, "lifecycle")?,
        "lifecycle",
        &[
            "installedFiles",
            "installedBytes",
            "removedFiles",
            "missingFiles",
            "preservedModifiedFiles",
            "installProgressEvents",
            "uninstallProgressEvents",
        ],
    )?;
    let lifecycle = EvidenceLifecycle {
        installed_files: required_u64(lifecycle, "installedFiles")?,
        installed_bytes: required_u64(lifecycle, "installedBytes")?,
        removed_files: required_u64(lifecycle, "removedFiles")?,
        missing_files: required_u64(lifecycle, "missingFiles")?,
        preserved_modified_files: required_u64(lifecycle, "preservedModifiedFiles")?,
        install_progress_events: required_u64(lifecycle, "installProgressEvents")?,
        uninstall_progress_events: required_u64(lifecycle, "uninstallProgressEvents")?,
    };

    let checks = exact_object(
        required(root, "checks")?,
        "checks",
        &[
            "backendInspect",
            "backendInstall",
            "installedBytesVerified",
            "foreignPreserved",
            "uninstall",
            "receiptCleanup",
            "transactionCleanup",
            "tauriEntrypoint",
            "tempCleanup",
        ],
    )?;
    for name in [
        "backendInspect",
        "backendInstall",
        "installedBytesVerified",
        "foreignPreserved",
        "uninstall",
        "receiptCleanup",
        "transactionCleanup",
        "tauriEntrypoint",
        "tempCleanup",
    ] {
        if checks.get(name).and_then(Value::as_bool) != Some(true) {
            return Err(format!("checks.{name} must be true"));
        }
    }
    let evidence = RunnerEvidence {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        target: EvidenceTarget { triple, os, arch },
        shell: EvidenceShell {
            kind: shell_kind,
            version: shell_version,
        },
        package: EvidencePackage {
            id: package_id,
            version: package_version,
            fingerprint: package_fingerprint,
        },
        artifacts,
        lifecycle,
        checks: EvidenceChecks {
            backend_inspect: true,
            backend_install: true,
            installed_bytes_verified: true,
            foreign_preserved: true,
            uninstall: true,
            receipt_cleanup: true,
            transaction_cleanup: true,
            tauri_entrypoint: true,
            temp_cleanup: true,
        },
    };
    validate_evidence(&evidence)?;
    Ok(evidence)
}

fn exact_object<'a>(
    value: &'a Value,
    label: &str,
    keys: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(format!("{label} has unexpected or missing fields"));
    }
    Ok(object)
}

fn required<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a Value, String> {
    object
        .get(name)
        .ok_or_else(|| format!("missing field `{name}`"))
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, String> {
    required(object, name)?
        .as_str()
        .ok_or_else(|| format!("field `{name}` must be a string"))
}

fn required_u64(object: &serde_json::Map<String, Value>, name: &str) -> Result<u64, String> {
    required(object, name)?
        .as_u64()
        .ok_or_else(|| format!("field `{name}` must be an unsigned integer"))
}

fn required_hash(object: &serde_json::Map<String, Value>, name: &str) -> Result<String, String> {
    let value = required_string(object, name)?;
    if is_lower_hex_64(value) {
        Ok(value.to_owned())
    } else {
        Err(format!("field `{name}` must be lowercase SHA-256"))
    }
}

fn bounded_text(value: &str, max_bytes: usize, label: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        Err(format!("{label} must contain 1..={max_bytes} safe bytes"))
    } else {
        Ok(value.to_owned())
    }
}

fn valid_package_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.contains('.')
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.split('.').all(|part| {
            !part.is_empty()
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn triple_matches_target(triple: &str, os: &str, arch: &str) -> bool {
    if !triple.starts_with(&format!("{arch}-"))
        || !triple
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return false;
    }
    let components = triple.split('-').collect::<Vec<_>>();
    match os {
        "linux" => components.contains(&"linux"),
        "windows" => components.contains(&"windows"),
        "macos" => components.contains(&"darwin"),
        _ => false,
    }
}

fn sha256_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
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

fn assemble_into(package: &Path, output: &Path) -> Result<AssembledRunner, String> {
    let root = workspace_root();
    let host = HostLayout::new(env::consts::OS, env::consts::ARCH)?;
    let package = checked_input(package, "installer payload")?;
    let source_backend = build_backend(&root, host)?;
    assemble_checked_into(&package, output, &root, host, &source_backend)
}

fn assemble_studio_into(output: &Path) -> Result<PathBuf, String> {
    let root = workspace_root();
    let host = HostLayout::new(env::consts::OS, env::consts::ARCH)?;
    let source_backend = build_backend(&root, host)?;
    require_regular_file(&source_backend, "built Rust backend")?;
    require_executable(&source_backend, "built Rust backend")?;
    let backend_hash = sha256_file(&source_backend)?;
    let source_packager = build_packager(&root, host)?;
    let packager_hash = sha256_file(&source_packager)?;

    ensure_real_directory(output)?;
    let artifact = output.join(studio_artifact_name(host));
    require_missing(&artifact, "portable Studio artifact")?;
    let work = WorkDirectory::new(output)?;

    gui_check()?;
    let frontend = root
        .join("apps")
        .join("luxury-installer")
        .join("out")
        .join("renderer");
    let frontend_hash = hash_frontend_tree(&frontend)?;
    let built_studio_shell = build_tauri_shell(&root, host, ShellFlavor::Studio, None)?;
    let source_shell = work.path.join(if host.rust_os == "windows" {
        "studio-shell.exe"
    } else {
        "studio-shell"
    });
    copy_file(&built_studio_shell, &source_shell)?;
    let shell_hash = sha256_file(&source_shell)?;
    let template_binding = std::str::from_utf8(&luxury_spec::SETUP_BINDING_TEMPLATE)
        .expect("the Setup template marker is ASCII");
    let built_template_shell = build_tauri_shell(
        &root,
        host,
        ShellFlavor::SetupTemplate,
        Some(template_binding),
    )?;
    let source_template_shell = work.path.join(if host.rust_os == "windows" {
        "setup-template-shell.exe"
    } else {
        "setup-template-shell"
    });
    copy_file(&built_template_shell, &source_template_shell)?;
    require_setup_template_binding(&source_template_shell)?;
    let template_shell_hash = sha256_file(&source_template_shell)?;
    let source_nsis = if host.rust_os == "windows" {
        let target = resolve_target_dir(&root, env::var_os("CARGO_TARGET_DIR").as_deref());
        Some(windows_container::cached_studio_nsis(&target)?)
    } else {
        None
    };
    if hash_frontend_tree(&frontend)? != frontend_hash {
        return Err("frontend build output changed while Tauri Studio was built".into());
    }

    let bundle = work.path.join("portable-studio");
    let resources = host.resources_directory(&bundle);
    let launcher = host.launcher(&bundle);
    let packaged_backend_dir = resources.join("backend");
    let packaged_backend = packaged_backend_dir.join(host.backend_name);
    let packaged_packager_dir = resources.join("packager");
    let packaged_packager = packaged_packager_dir.join(packaged_packager_name(host));
    let template = resources
        .join("templates")
        .join(format!("{}-{}", host.rust_os, host.rust_arch));
    fs::create_dir_all(
        launcher
            .parent()
            .ok_or_else(|| "portable Tauri Studio launcher has no parent".to_owned())?,
    )
    .map_err(|error| format!("could not create portable Studio launcher directory: {error}"))?;
    fs::create_dir_all(&packaged_backend_dir)
        .map_err(|error| format!("could not create portable Studio backend directory: {error}"))?;
    fs::create_dir_all(&packaged_packager_dir)
        .map_err(|error| format!("could not create native packager directory: {error}"))?;
    if host.rust_os == "linux" {
        let icon = resources.join("icon.png");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&icon)
            .map_err(|error| format!("could not create Linux Studio icon: {error}"))?;
        file.write_all(LINUX_ICON_BYTES)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("could not persist Linux Studio icon: {error}"))?;
        #[cfg(unix)]
        fs::set_permissions(&icon, std::os::unix::fs::PermissionsExt::from_mode(0o644))
            .map_err(|error| format!("could not set Linux Studio icon permissions: {error}"))?;
    }
    let macos_info_plist = (host.rust_os == "macos")
        .then(|| write_macos_info_plist(&bundle))
        .transpose()?;
    copy_file(&source_shell, &launcher)?;
    copy_file(&source_backend, &packaged_backend)?;
    copy_file(&source_packager, &packaged_packager)?;
    set_packager_permissions(&packaged_packager)?;
    set_runner_permissions(&launcher, &packaged_backend, None)?;
    stage_linux_privilege_integration(&bundle, host, &source_backend)?;
    stage_macos_privilege_integration(&bundle, host, &source_backend)?;
    stage_setup_template(&template, host, &source_template_shell, &source_backend)?;
    if let Some(source_nsis) = &source_nsis {
        let tools = resources.join("tools");
        fs::create_dir(&tools)
            .map_err(|error| format!("could not create Studio tool directory: {error}"))?;
        copy_file(source_nsis, &tools.join("nsis-3.12.zip"))?;
    }
    validate_portable_bundle(
        &bundle,
        host,
        ShellFlavor::Studio,
        macos_info_plist.as_deref(),
    )?;

    if sha256_file(&launcher)? != shell_hash {
        return Err("portable Studio launcher bytes do not match the locked Tauri build".into());
    }
    if sha256_file(&packaged_backend)? != backend_hash {
        return Err("portable Studio backend bytes do not match the dist build".into());
    }
    if sha256_file(&packaged_packager)? != packager_hash
        || sha256_file(&host.launcher(&template))? != template_shell_hash
    {
        return Err("portable Studio packager resources changed during staging".into());
    }
    if let Some(source_nsis) = &source_nsis
        && sha256_file(&resources.join("tools").join("nsis-3.12.zip"))? != sha256_file(source_nsis)?
    {
        return Err("portable Studio NSIS bytes changed during staging".into());
    }
    probe_studio(&launcher)?;
    if hash_frontend_tree(&frontend)? != frontend_hash {
        return Err("frontend build output changed during Tauri Studio verification".into());
    }
    validate_portable_bundle(
        &bundle,
        host,
        ShellFlavor::Studio,
        macos_info_plist.as_deref(),
    )?;
    if sha256_file(&launcher)? != shell_hash
        || sha256_file(&packaged_backend)? != backend_hash
        || sha256_file(&packaged_packager)? != packager_hash
        || sha256_file(&host.launcher(&template))? != template_shell_hash
    {
        return Err("portable Studio bytes changed during runtime verification".into());
    }

    publish_directory_no_clobber(&bundle, &artifact)?;
    work.cleanup().map_err(|error| {
        format!(
            "verified portable Tauri Studio was published at `{}`, but {error}",
            artifact.display()
        )
    })?;
    Ok(artifact)
}

fn stage_setup_template(
    template: &Path,
    host: HostLayout,
    source_shell: &Path,
    source_backend: &Path,
) -> Result<(), String> {
    let resources = host.resources_directory(template);
    let launcher = host.launcher(template);
    let backend = resources.join("backend").join(host.backend_name);
    fs::create_dir_all(
        launcher
            .parent()
            .ok_or_else(|| "Setup template launcher has no parent".to_owned())?,
    )
    .map_err(|error| format!("could not create Setup template launcher directory: {error}"))?;
    fs::create_dir_all(
        backend
            .parent()
            .ok_or_else(|| "Setup template backend has no parent".to_owned())?,
    )
    .map_err(|error| format!("could not create Setup template backend directory: {error}"))?;
    let macos_info_plist = (host.rust_os == "macos")
        .then(|| write_macos_info_plist(template))
        .transpose()?;
    copy_file(source_shell, &launcher)?;
    copy_file(source_backend, &backend)?;
    set_runner_permissions(&launcher, &backend, None)?;
    stage_linux_privilege_integration(template, host, source_backend)?;
    stage_macos_privilege_integration(template, host, source_backend)?;
    validate_portable_bundle(
        template,
        host,
        ShellFlavor::SetupTemplate,
        macos_info_plist.as_deref(),
    )?;
    require_setup_template_binding(&launcher)
}

fn assemble_checked_into(
    package: &Path,
    output: &Path,
    root: &Path,
    host: HostLayout,
    source_backend: &Path,
) -> Result<AssembledRunner, String> {
    require_regular_file(source_backend, "built Rust backend")?;
    require_executable(source_backend, "built Rust backend")?;

    let identity = probe_backend(source_backend, package, host)?;
    let backend_hash = sha256_file(source_backend)?;
    let package_hash = sha256_file(package)?;
    let artifact_name = artifact_name(host, &identity)?;
    ensure_real_directory(output)?;
    let artifact = output.join(artifact_name);
    require_missing(&artifact, "native runner artifact")?;

    gui_check()?;
    let frontend = root
        .join("apps")
        .join("luxury-installer")
        .join("out")
        .join("renderer");
    let frontend_hash = hash_frontend_tree(&frontend)?;
    let source_shell = build_tauri_shell(root, host, ShellFlavor::Setup, Some(&identity))?;
    let shell_hash = sha256_file(&source_shell)?;
    if hash_frontend_tree(&frontend)? != frontend_hash {
        return Err("frontend build output changed while the Tauri shell was built".into());
    }

    let work = WorkDirectory::new(output)?;
    let bundle = work.path.join("portable-runner");
    let resources = host.resources_directory(&bundle);
    let launcher = host.launcher(&bundle);
    let packaged_backend_dir = resources.join("backend");
    let packaged_payload_dir = resources.join("payload");
    let packaged_trust_dir = resources.join("trust");
    let packaged_backend = packaged_backend_dir.join(host.backend_name);
    let packaged_payload = packaged_payload_dir.join("package.luxpkg");

    fs::create_dir_all(
        launcher
            .parent()
            .ok_or_else(|| "portable Tauri launcher has no parent".to_owned())?,
    )
    .map_err(|error| format!("could not create portable Tauri launcher directory: {error}"))?;
    fs::create_dir_all(&packaged_backend_dir)
        .map_err(|error| format!("could not create portable backend directory: {error}"))?;
    fs::create_dir_all(&packaged_payload_dir)
        .map_err(|error| format!("could not create portable payload directory: {error}"))?;
    let macos_info_plist = (host.rust_os == "macos")
        .then(|| write_macos_info_plist(&bundle))
        .transpose()?;
    copy_file(&source_shell, &launcher)?;
    copy_file(source_backend, &packaged_backend)?;
    copy_file(package, &packaged_payload)?;
    set_runner_permissions(&launcher, &packaged_backend, Some(&packaged_payload))?;
    stage_linux_privilege_integration(&bundle, host, source_backend)?;
    stage_macos_privilege_integration(&bundle, host, source_backend)?;

    require_regular_file(&launcher, "packaged Tauri launcher")?;
    require_executable(&launcher, "packaged Tauri launcher")?;
    require_only_file(&packaged_backend_dir, host.backend_name)?;
    require_only_file(&packaged_payload_dir, "package.luxpkg")?;
    require_missing(&packaged_trust_dir, "packaged trust resource")?;
    require_executable(&packaged_backend, "packaged Rust backend")?;
    validate_portable_bundle(
        &bundle,
        host,
        ShellFlavor::Setup,
        macos_info_plist.as_deref(),
    )?;

    if sha256_file(&launcher)? != shell_hash {
        return Err("packaged Tauri launcher bytes do not match the locked release build".into());
    }
    if sha256_file(&packaged_backend)? != backend_hash {
        return Err("packaged Rust backend bytes do not match the dist build".into());
    }
    if sha256_file(&packaged_payload)? != package_hash {
        return Err("packaged payload bytes do not match the selected package".into());
    }
    if probe_backend(&packaged_backend, &packaged_payload, host)? != identity {
        return Err("packaged backend inspected a different payload identity".into());
    }
    probe_runner(&launcher)?;
    if hash_frontend_tree(&frontend)? != frontend_hash {
        return Err("frontend build output changed during Tauri runner verification".into());
    }
    validate_portable_bundle(
        &bundle,
        host,
        ShellFlavor::Setup,
        macos_info_plist.as_deref(),
    )?;
    if sha256_file(&launcher)? != shell_hash
        || sha256_file(&packaged_backend)? != backend_hash
        || sha256_file(&packaged_payload)? != package_hash
    {
        return Err("portable Setup bytes changed during runtime verification".into());
    }

    publish_directory_no_clobber(&bundle, &artifact)?;

    work.cleanup().map_err(|error| {
        format!(
            "verified portable Tauri runner was published at `{}`, but {error}",
            artifact.display()
        )
    })?;

    Ok(AssembledRunner {
        path: artifact,
        frontend_tree_sha256: frontend_hash,
        package_fingerprint: identity,
    })
}

fn stage_linux_privilege_integration(
    bundle: &Path,
    host: HostLayout,
    source_backend: &Path,
) -> Result<(), String> {
    if host.rust_os != "linux" {
        return Ok(());
    }
    let usr = bundle.join("usr");
    let helper = usr.join("libexec").join("luxury-installer-helper");
    let policy = usr
        .join("share")
        .join("polkit-1")
        .join("actions")
        .join("software.luxury.installer.policy");
    fs::create_dir_all(
        helper
            .parent()
            .ok_or_else(|| "Linux privilege helper has no parent".to_owned())?,
    )
    .map_err(|error| format!("could not create Linux helper directory: {error}"))?;
    fs::create_dir_all(
        policy
            .parent()
            .ok_or_else(|| "Linux polkit policy has no parent".to_owned())?,
    )
    .map_err(|error| format!("could not create Linux polkit directory: {error}"))?;
    copy_file(source_backend, &helper)?;
    let mut policy_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&policy)
        .map_err(|error| format!("could not create Linux polkit policy: {error}"))?;
    policy_file
        .write_all(LINUX_POLICY_BYTES)
        .and_then(|()| policy_file.sync_all())
        .map_err(|error| format!("could not persist Linux polkit policy: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("could not set Linux helper permissions: {error}"))?;
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("could not set Linux policy permissions: {error}"))?;
    }
    Ok(())
}

fn stage_macos_privilege_integration(
    bundle: &Path,
    host: HostLayout,
    source_backend: &Path,
) -> Result<(), String> {
    if host.rust_os != "macos" {
        return Ok(());
    }
    let contents = bundle.join(format!("{APP_NAME}.app")).join("Contents");
    let helper = contents.join("Resources").join("luxury-installer-helper");
    let icon = contents.join("Resources").join("icon.icns");
    let plist = contents
        .join("Library")
        .join("LaunchDaemons")
        .join("software.luxury.installer.helper.plist");
    fs::create_dir_all(
        helper
            .parent()
            .ok_or_else(|| "macOS privilege helper has no parent".to_owned())?,
    )
    .map_err(|error| format!("could not create macOS helper directory: {error}"))?;
    fs::create_dir_all(
        plist
            .parent()
            .ok_or_else(|| "macOS helper plist has no parent".to_owned())?,
    )
    .map_err(|error| format!("could not create macOS LaunchDaemons directory: {error}"))?;
    copy_file(source_backend, &helper)?;
    let mut icon_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&icon)
        .map_err(|error| format!("could not create macOS icon: {error}"))?;
    icon_file
        .write_all(MACOS_ICON_BYTES)
        .and_then(|()| icon_file.sync_all())
        .map_err(|error| format!("could not persist macOS icon: {error}"))?;
    let mut plist_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&plist)
        .map_err(|error| format!("could not create macOS helper plist: {error}"))?;
    plist_file
        .write_all(MACOS_HELPER_PLIST_BYTES)
        .and_then(|()| plist_file.sync_all())
        .map_err(|error| format!("could not persist macOS helper plist: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("could not set macOS helper permissions: {error}"))?;
        fs::set_permissions(&icon, fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("could not set macOS icon permissions: {error}"))?;
        fs::set_permissions(&plist, fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("could not set macOS helper plist permissions: {error}"))?;
    }
    Ok(())
}

fn resolve_target_dir(root: &Path, configured: Option<&OsStr>) -> PathBuf {
    match configured {
        Some(path) if Path::new(path).is_absolute() => PathBuf::from(path),
        Some(path) => root.join(path),
        None => root.join("target"),
    }
}

fn rustc_host_triple(root: &Path) -> Result<String, String> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let output = Command::new(rustc)
        .arg("-vV")
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not start rustc: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "rustc -vV failed: {}",
            bounded_output(&output.stderr)
        ));
    }
    let output = std::str::from_utf8(&output.stdout)
        .map_err(|_| "rustc -vV returned non-UTF-8 output".to_owned())?;
    output
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .filter(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
        .map(str::to_owned)
        .ok_or_else(|| "rustc -vV did not return a valid host triple".to_owned())
}

fn build_backend(root: &Path, host: HostLayout) -> Result<PathBuf, String> {
    let host_triple = rustc_host_triple(root)?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    println!("> cargo build --locked --profile dist -p luxury --target {host_triple}");
    let status = Command::new(cargo)
        .args([
            "build",
            "--locked",
            "--profile",
            "dist",
            "-p",
            "luxury",
            "--target",
        ])
        .arg(&host_triple)
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not start cargo: {error}"))?;
    if status.success() {
        let target_dir = resolve_target_dir(root, env::var_os("CARGO_TARGET_DIR").as_deref());
        let backend = target_dir
            .join(host_triple)
            .join("dist")
            .join(host.backend_name);
        require_regular_file(&backend, "built Rust backend")?;
        require_executable(&backend, "built Rust backend")?;
        Ok(backend)
    } else {
        Err(format!("host Rust backend build exited with {status}"))
    }
}

fn build_packager(root: &Path, host: HostLayout) -> Result<PathBuf, String> {
    let host_triple = rustc_host_triple(root)?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let feature = if host.rust_os == "linux" {
        " --features standalone-linux-packager"
    } else {
        ""
    };
    println!("> cargo build --locked --profile dist -p xtask --target {host_triple}{feature}");
    let mut command = Command::new(cargo);
    command.args([
        "build",
        "--locked",
        "--profile",
        "dist",
        "-p",
        "xtask",
        "--target",
    ]);
    command.arg(&host_triple);
    if host.rust_os == "linux" {
        command.args(["--features", "standalone-linux-packager"]);
    }
    let status = command
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not start packager build: {error}"))?;
    if !status.success() {
        return Err(format!("host Rust packager build exited with {status}"));
    }
    let target_dir = resolve_target_dir(root, env::var_os("CARGO_TARGET_DIR").as_deref());
    let packager = target_dir
        .join(host_triple)
        .join("dist")
        .join(if host.rust_os == "windows" {
            "xtask.exe"
        } else {
            "xtask"
        });
    require_regular_file(&packager, "built Rust native packager")?;
    require_executable(&packager, "built Rust native packager")?;
    Ok(packager)
}

fn packaged_packager_name(host: HostLayout) -> &'static str {
    if host.rust_os == "windows" {
        "luxury-packager.exe"
    } else {
        "luxury-packager"
    }
}

fn set_packager_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("could not set native packager permissions: {error}"))?;
    }
    let _ = path;
    Ok(())
}

fn build_tauri_shell(
    root: &Path,
    host: HostLayout,
    flavor: ShellFlavor,
    bound_package_fingerprint: Option<&str>,
) -> Result<PathBuf, String> {
    match (flavor, bound_package_fingerprint) {
        (ShellFlavor::Studio, None) => {}
        (ShellFlavor::Setup, Some(value)) if is_lower_hex_64(value) => {}
        (ShellFlavor::SetupTemplate, Some(value))
            if value.as_bytes() == luxury_spec::SETUP_BINDING_TEMPLATE => {}
        _ => return Err("Tauri shell flavor and package binding do not match".into()),
    }
    let host_triple = rustc_host_triple(root)?;
    let tauri_directory = root.join("apps").join("luxury-installer").join("src-tauri");
    let manifest = tauri_directory.join("Cargo.toml");
    require_tauri_version_pin(&manifest)?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    println!(
        "> cargo build --locked --release --manifest-path {} --target {host_triple} {}",
        manifest.display(),
        flavor.cargo_feature_args().join(" ")
    );
    let mut command = Command::new(cargo);
    command
        .args(["build", "--locked", "--release", "--manifest-path"])
        .arg(&manifest)
        .arg("--target")
        .arg(&host_triple)
        .args(flavor.cargo_feature_args())
        .env_remove("LUXURY_BOUND_PACKAGE_FINGERPRINT")
        .current_dir(&tauri_directory);
    if let Some(fingerprint) = bound_package_fingerprint {
        command.env("LUXURY_BOUND_PACKAGE_FINGERPRINT", fingerprint);
    }
    let status = command
        .status()
        .map_err(|error| format!("could not start the Tauri shell build: {error}"))?;
    if !status.success() {
        return Err(format!(
            "locked Tauri {:?} release build exited with {status}",
            flavor
        ));
    }

    let target_dir =
        resolve_target_dir(&tauri_directory, env::var_os("CARGO_TARGET_DIR").as_deref());
    let shell = target_dir
        .join(host_triple)
        .join("release")
        .join(host.shell_name);
    require_regular_file(&shell, "built Tauri release shell")?;
    require_executable(&shell, "built Tauri release shell")?;
    Ok(shell)
}

fn require_tauri_version_pin(manifest: &Path) -> Result<(), String> {
    let source = fs::read_to_string(manifest).map_err(|error| {
        format!(
            "could not read Tauri manifest `{}`: {error}",
            manifest.display()
        )
    })?;
    let expected = format!("version = \"={TAURI_SHELL_VERSION}\"");
    if source.lines().any(|line| {
        let line = line.trim();
        line.starts_with("tauri =") && line.contains(&expected)
    }) {
        Ok(())
    } else {
        Err(format!(
            "Tauri manifest must pin tauri exactly to {TAURI_SHELL_VERSION} before evidence can be emitted"
        ))
    }
}

fn run_luxury(executable: &Path, command: &str, paths: &[&Path]) -> Result<(), String> {
    println!("> {} {command}", executable.display());
    let status = Command::new(executable)
        .arg(command)
        .args(paths.iter().map(|path| path.as_os_str()))
        .status()
        .map_err(|error| format!("could not start `luxury {command}`: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("luxury {command} exited with {status}"))
    }
}

fn artifact_name(host: HostLayout, fingerprint: &str) -> Result<String, String> {
    let prefix = fingerprint
        .get(..12)
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| "package fingerprint cannot name the native artifact".to_owned())?;
    Ok(format!(
        "luxury-installer-{}-{}-{}-{prefix}",
        env!("CARGO_PKG_VERSION"),
        host.rust_os,
        host.rust_arch
    ))
}

fn require_setup_template_binding(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("could not read Setup template binding: {error}"))?;
    binding_offset(&bytes, &luxury_spec::SETUP_BINDING_TEMPLATE).map(|_| ())
}

fn patch_setup_template_binding(path: &Path, fingerprint: &str) -> Result<(), String> {
    if !is_lower_hex_64(fingerprint) {
        return Err("Setup template fingerprint must be exact lower hex".into());
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("could not read Setup template binding: {error}"))?;
    let offset = binding_offset(&bytes, &luxury_spec::SETUP_BINDING_TEMPLATE)?
        + luxury_spec::SETUP_BINDING_PREFIX.len();
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| format!("could not open Setup template for binding: {error}"))?;
    file.seek(SeekFrom::Start(offset as u64))
        .map_err(|error| format!("could not seek to Setup template binding: {error}"))?;
    file.write_all(fingerprint.as_bytes())
        .map_err(|error| format!("could not write Setup template binding: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("could not sync Setup template binding: {error}"))?;
    drop(file);

    let patched = fs::read(path)
        .map_err(|error| format!("could not verify Setup template binding: {error}"))?;
    binding_offset(&patched, fingerprint.as_bytes())?;
    if binding_offset(&patched, &luxury_spec::SETUP_BINDING_TEMPLATE).is_ok() {
        return Err("Setup template placeholder remained after binding".into());
    }
    Ok(())
}

fn binding_offset(bytes: &[u8], fingerprint: &[u8]) -> Result<usize, String> {
    if fingerprint.len() != 64 {
        return Err("Setup binding fingerprint length is invalid".into());
    }
    let width = luxury_spec::SETUP_BINDING_PREFIX.len()
        + fingerprint.len()
        + luxury_spec::SETUP_BINDING_SUFFIX.len();
    let mut found = None;
    for (offset, window) in bytes.windows(width).enumerate() {
        if window.starts_with(&luxury_spec::SETUP_BINDING_PREFIX)
            && window[luxury_spec::SETUP_BINDING_PREFIX.len()
                ..luxury_spec::SETUP_BINDING_PREFIX.len() + fingerprint.len()]
                == *fingerprint
            && window.ends_with(&luxury_spec::SETUP_BINDING_SUFFIX)
            && found.replace(offset).is_some()
        {
            return Err("Setup binary contains multiple matching bindings".into());
        }
    }
    found.ok_or_else(|| "Setup binary does not contain the expected binding".into())
}

fn studio_artifact_name(host: HostLayout) -> String {
    format!(
        "luxury-installer-studio-{}-{}-{}",
        env!("CARGO_PKG_VERSION"),
        host.rust_os,
        host.rust_arch
    )
}

fn bounded_output(bytes: &[u8]) -> String {
    let mut output = String::new();
    for character in String::from_utf8_lossy(bytes).chars().take(1_024) {
        match character {
            '\n' | '\t' => output.push(character),
            character if character.is_control() => output.push('\u{fffd}'),
            character => output.push(character),
        }
    }
    if bytes.len() > output.len() {
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evidence() -> RunnerEvidence {
        RunnerEvidence {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            target: EvidenceTarget {
                triple: "x86_64-pc-windows-msvc".into(),
                os: "windows".into(),
                arch: "x86_64".into(),
            },
            shell: EvidenceShell {
                kind: TAURI_SHELL_KIND.into(),
                version: TAURI_SHELL_VERSION.into(),
            },
            package: EvidencePackage {
                id: "dev.luxury.demo".into(),
                version: "1.0.0".into(),
                fingerprint: "a".repeat(64),
            },
            artifacts: EvidenceArtifacts {
                backend_sha256: "b".repeat(64),
                payload_sha256: "c".repeat(64),
                frontend_tree_sha256: "d".repeat(64),
                launcher_sha256: "e".repeat(64),
            },
            lifecycle: EvidenceLifecycle {
                installed_files: 1,
                installed_bytes: 29,
                removed_files: 1,
                missing_files: 0,
                preserved_modified_files: 0,
                install_progress_events: 2,
                uninstall_progress_events: 2,
            },
            checks: EvidenceChecks {
                backend_inspect: true,
                backend_install: true,
                installed_bytes_verified: true,
                foreign_preserved: true,
                uninstall: true,
                receipt_cleanup: true,
                transaction_cleanup: true,
                tauri_entrypoint: true,
                temp_cleanup: true,
            },
        }
    }

    fn platform_evidence(os: &str) -> RunnerEvidence {
        let mut evidence = sample_evidence();
        let (triple, arch, marker) = match os {
            "linux" => ("x86_64-unknown-linux-gnu", "x86_64", '1'),
            "windows" => ("x86_64-pc-windows-msvc", "x86_64", '2'),
            "macos" => ("aarch64-apple-darwin", "aarch64", '3'),
            other => panic!("unsupported test OS {other}"),
        };
        evidence.target.triple = triple.into();
        evidence.target.os = os.into();
        evidence.target.arch = arch.into();
        evidence.package.fingerprint = marker.to_string().repeat(64);
        evidence.artifacts.payload_sha256 = marker.to_string().repeat(64);
        evidence
    }

    #[test]
    fn launch_probe_source_publishes_synced_marker_and_holds_stream_until_exit() {
        let source = launch_probe_source();
        assert!(source.contains("args_os().count() != 1"));
        assert!(source.contains(LAUNCH_MARKER_FILE));
        assert!(source.contains(LAUNCH_MARKER_TEMP_FILE));
        assert!(source.contains(LAUNCH_MARKER_MAGIC));
        assert!(source.contains("create_new(true)"));
        assert!(source.contains("TcpListener::bind((\"127.0.0.1\", 0))"));
        assert!(!source.contains("stream.read(&mut extra)"));
        let sync = source.find("marker.sync_all()").unwrap();
        let publish = source.find("fs::rename").unwrap();
        let accept = source.find("listener.accept()").unwrap();
        let acknowledge = source.find("stream.write_all").unwrap();
        let shutdown = source.find("stream.shutdown(Shutdown::Write)").unwrap();
        let success = source.find("Ok(())").unwrap();
        assert!(
            sync < publish
                && publish < accept
                && accept < acknowledge
                && acknowledge < shutdown
                && shutdown < success
        );
        assert!(!source.contains("std::process::exit(0)"));
        assert!(!source.contains("Command::new"));
    }

    fn write_evidence_set(directory: &Path) {
        for (name, os, _) in EXPECTED_EVIDENCE {
            fs::write(
                directory.join(name),
                evidence_bytes(&platform_evidence(os)).unwrap(),
            )
            .unwrap();
        }
    }

    fn assert_no_path_fields(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(fields) => {
                for (name, value) in fields {
                    let name = name.to_ascii_lowercase();
                    assert!(!name.contains("path"));
                    assert!(!name.contains("timestamp"));
                    assert_no_path_fields(value);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    assert_no_path_fields(value);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn evidence_serialization_is_deterministic_and_contains_no_path_fields() {
        let evidence = sample_evidence();
        let first = evidence_bytes(&evidence).unwrap();
        let second = evidence_bytes(&evidence.clone()).unwrap();
        assert_eq!(first, second);
        assert!(first.ends_with(b"\n"));
        let value: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(value["schemaVersion"], EVIDENCE_SCHEMA_VERSION);
        assert_eq!(value["shell"]["kind"], TAURI_SHELL_KIND);
        assert_eq!(value["shell"]["version"], TAURI_SHELL_VERSION);
        assert!(value.get("electronVersion").is_none());
        assert!(value["artifacts"].get("appAsarSha256").is_none());
        assert!(value["artifacts"].get("frontendTreeSha256").is_some());
        assert_no_path_fields(&value);
    }

    #[test]
    fn evidence_parser_rejects_shell_drift_and_legacy_electron_fields() {
        let evidence = platform_evidence("windows");
        let mut value = evidence_value(&evidence);
        value["shell"]["version"] = Value::String("2.11.4".into());
        assert!(
            parse_evidence(&value.to_string(), "windows", "x86_64")
                .unwrap_err()
                .contains("shell must be")
        );

        let mut value = evidence_value(&evidence);
        value["electronVersion"] = Value::String("43.2.0".into());
        assert!(parse_evidence(&value.to_string(), "windows", "x86_64").is_err());
    }

    #[test]
    fn stale_evidence_removal_refuses_non_files() {
        let work = WorkDirectory::new(&env::temp_dir()).unwrap();
        let host = HostLayout::new("windows", "x86_64").unwrap();
        let path = evidence_path(&work.path, host).unwrap();
        fs::write(&path, b"stale").unwrap();
        remove_stale_evidence(&path).unwrap();
        assert!(!path.exists());

        fs::create_dir(&path).unwrap();
        assert!(remove_stale_evidence(&path).is_err());
        assert!(path.is_dir());
    }

    #[test]
    fn evidence_publication_is_atomic_and_never_overwrites() {
        let work = WorkDirectory::new(&env::temp_dir()).unwrap();
        let host = HostLayout::new("linux", "aarch64").unwrap();
        let path = evidence_path(&work.path, host).unwrap();
        let evidence = sample_evidence();
        let expected = evidence_bytes(&evidence).unwrap();

        publish_evidence(&path, &evidence).unwrap();
        assert_eq!(fs::read(&path).unwrap(), expected);
        assert!(publish_evidence(&path, &evidence).is_err());
        assert_eq!(fs::read(&path).unwrap(), expected);
        let parent = path.parent().unwrap();
        let entries = fs::read_dir(parent)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path(), path);

        remove_stale_evidence(&path).unwrap();
        let mut incomplete = evidence;
        incomplete.checks.temp_cleanup = false;
        assert!(publish_evidence(&path, &incomplete).is_err());
        assert!(!path.exists());
        assert_eq!(fs::read_dir(parent).unwrap().count(), 0);
    }

    #[test]
    fn evidence_set_accepts_target_specific_fingerprints_and_payload_hashes() {
        let work = WorkDirectory::new(&env::temp_dir()).unwrap();
        write_evidence_set(&work.path);
        verify_evidence_set(&work.path).unwrap();
    }

    #[test]
    fn evidence_set_rejects_missing_file() {
        let work = WorkDirectory::new(&env::temp_dir()).unwrap();
        write_evidence_set(&work.path);
        fs::remove_file(work.path.join("macos-aarch64.json")).unwrap();
        assert!(verify_evidence_set(&work.path).is_err());
    }

    #[test]
    fn evidence_set_rejects_extra_file() {
        let work = WorkDirectory::new(&env::temp_dir()).unwrap();
        write_evidence_set(&work.path);
        fs::write(work.path.join("extra.json"), b"{}").unwrap();
        assert!(verify_evidence_set(&work.path).is_err());
    }

    #[test]
    fn evidence_set_rejects_tampered_checks() {
        let work = WorkDirectory::new(&env::temp_dir()).unwrap();
        write_evidence_set(&work.path);
        let path = work.path.join("windows-x86_64.json");
        let mut value = evidence_value(&platform_evidence("windows"));
        value["checks"]["foreignPreserved"] = Value::Bool(false);
        let mut bytes = serde_json::to_vec_pretty(&value).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();
        assert!(verify_evidence_set(&work.path).is_err());
    }

    #[test]
    fn evidence_set_rejects_self_consistent_but_wrong_payload_counts() {
        let work = WorkDirectory::new(&env::temp_dir()).unwrap();
        write_evidence_set(&work.path);
        let path = work.path.join("linux-x86_64.json");
        let mut value = evidence_value(&platform_evidence("linux"));
        value["lifecycle"]["installedFiles"] = Value::from(2);
        value["lifecycle"]["installedBytes"] = Value::from((SMOKE_HELLO.len() * 2) as u64);
        value["lifecycle"]["removedFiles"] = Value::from(2);
        let mut bytes = serde_json::to_vec_pretty(&value).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();
        assert!(verify_evidence_set(&work.path).is_err());
    }

    #[test]
    fn evidence_set_rejects_mismatched_package_version() {
        let work = WorkDirectory::new(&env::temp_dir()).unwrap();
        write_evidence_set(&work.path);
        let path = work.path.join("macos-aarch64.json");
        let mut evidence = platform_evidence("macos");
        evidence.package.version = "2.0.0".into();
        fs::write(path, evidence_bytes(&evidence).unwrap()).unwrap();
        assert!(verify_evidence_set(&work.path).is_err());
    }

    #[test]
    fn macos_info_plist_is_deterministic_and_xml_safe() {
        let first = macos_info_plist_bytes(APP_NAME, APP_ID, APP_NAME, APP_NAME, "1.2.3").unwrap();
        assert_eq!(
            first,
            macos_info_plist_bytes(APP_NAME, APP_ID, APP_NAME, APP_NAME, "1.2.3").unwrap()
        );
        let source = std::str::from_utf8(&first).unwrap();
        for key in [
            "CFBundleExecutable",
            "CFBundleIdentifier",
            "CFBundleName",
            "CFBundleDisplayName",
            "CFBundleVersion",
            "CFBundleShortVersionString",
            "CFBundlePackageType",
            "LSMinimumSystemVersion",
        ] {
            assert!(source.contains(&format!("<key>{key}</key>")));
        }
        assert!(source.ends_with("</plist>\n"));
        assert!(source.contains("CFBundleIconFile"));
        assert!(source.contains("<string>icon.icns</string>"));
        assert_eq!(
            escape_plist_text("A&B <C> \"D\" 'E'", "test").unwrap(),
            "A&amp;B &lt;C&gt; &quot;D&quot; &apos;E&apos;"
        );
        assert!(escape_plist_text("unsafe\ntext", "test").is_err());
        assert!(macos_info_plist_bytes(APP_NAME, APP_ID, APP_NAME, APP_NAME, "1.2.3.4").is_err());
    }

    #[test]
    fn macos_bundle_layout_is_exact_and_plist_bytes_are_bound() {
        let work = WorkDirectory::new(&env::temp_dir()).unwrap();
        let bundle = work.path.join("portable");
        let host = HostLayout::new("macos", "aarch64").unwrap();
        let resources = host.resources_directory(&bundle);
        let launcher = host.launcher(&bundle);
        let backend = resources.join("backend").join(host.backend_name);
        let payload = resources.join("payload").join("package.luxpkg");
        fs::create_dir_all(launcher.parent().unwrap()).unwrap();
        fs::create_dir_all(backend.parent().unwrap()).unwrap();
        fs::create_dir_all(payload.parent().unwrap()).unwrap();
        fs::write(&launcher, b"launcher").unwrap();
        fs::write(&backend, b"backend").unwrap();
        fs::write(&payload, b"payload").unwrap();
        stage_macos_privilege_integration(&bundle, host, &backend).unwrap();
        let expected = write_macos_info_plist(&bundle).unwrap();

        validate_macos_bundle(&bundle, host, ShellFlavor::Setup, &expected).unwrap();
        let contents = bundle.join("Luxury Installer.app").join("Contents");
        let unexpected = contents.join("unexpected");
        fs::write(&unexpected, b"foreign").unwrap();
        assert!(validate_macos_bundle(&bundle, host, ShellFlavor::Setup, &expected).is_err());
        fs::remove_file(unexpected).unwrap();

        fs::write(contents.join("Info.plist"), b"changed").unwrap();
        assert!(validate_macos_bundle(&bundle, host, ShellFlavor::Setup, &expected).is_err());
    }

    #[test]
    fn shell_flavors_select_explicit_cargo_features() {
        assert_eq!(
            ShellFlavor::Setup.cargo_feature_args(),
            ["--no-default-features", "--features", "setup"]
        );
        assert_eq!(
            ShellFlavor::Studio.cargo_feature_args(),
            ["--features", "studio"]
        );
    }

    #[test]
    fn package_fingerprints_are_exact_lower_hex() {
        assert!(is_lower_hex_64(&"a".repeat(64)));
        assert!(!is_lower_hex_64(&"A".repeat(64)));
        assert!(!is_lower_hex_64(&"a".repeat(63)));
    }

    #[test]
    fn setup_template_binding_is_unique_and_exactly_patchable() {
        let temp = tempfile::tempdir().unwrap();
        let template = temp.path().join("setup-template.bin");
        let mut bytes = b"prefix".to_vec();
        bytes.extend_from_slice(&luxury_spec::SETUP_BINDING_PREFIX);
        bytes.extend_from_slice(&luxury_spec::SETUP_BINDING_TEMPLATE);
        bytes.extend_from_slice(&luxury_spec::SETUP_BINDING_SUFFIX);
        bytes.extend_from_slice(b"suffix");
        fs::write(&template, &bytes).unwrap();
        require_setup_template_binding(&template).unwrap();

        let fingerprint = "a".repeat(64);
        patch_setup_template_binding(&template, &fingerprint).unwrap();
        let patched = fs::read(&template).unwrap();
        assert!(binding_offset(&patched, fingerprint.as_bytes()).is_ok());
        assert!(binding_offset(&patched, &luxury_spec::SETUP_BINDING_TEMPLATE).is_err());

        bytes.extend_from_slice(&luxury_spec::SETUP_BINDING_PREFIX);
        bytes.extend_from_slice(&luxury_spec::SETUP_BINDING_TEMPLATE);
        bytes.extend_from_slice(&luxury_spec::SETUP_BINDING_SUFFIX);
        assert!(binding_offset(&bytes, &luxury_spec::SETUP_BINDING_TEMPLATE).is_err());
    }

    #[test]
    fn studio_layout_is_payload_free_and_exact_on_each_host() {
        let work = WorkDirectory::new(&env::temp_dir()).unwrap();
        for (os, arch) in [
            ("windows", "x86_64"),
            ("linux", "aarch64"),
            ("macos", "x86_64"),
        ] {
            let host = HostLayout::new(os, arch).unwrap();
            let bundle = work.path.join(os);
            let resources = host.resources_directory(&bundle);
            let launcher = host.launcher(&bundle);
            let backend = resources.join("backend").join(host.backend_name);
            fs::create_dir_all(launcher.parent().unwrap()).unwrap();
            fs::create_dir_all(backend.parent().unwrap()).unwrap();
            fs::write(&launcher, b"studio-launcher").unwrap();
            fs::write(&backend, b"studio-backend").unwrap();
            set_runner_permissions(&launcher, &backend, None).unwrap();
            stage_linux_privilege_integration(&bundle, host, &backend).unwrap();
            stage_macos_privilege_integration(&bundle, host, &backend).unwrap();
            let packager = resources
                .join("packager")
                .join(packaged_packager_name(host));
            fs::create_dir_all(packager.parent().unwrap()).unwrap();
            fs::write(&packager, b"native-packager").unwrap();
            set_packager_permissions(&packager).unwrap();
            if os == "linux" {
                fs::write(resources.join("icon.png"), LINUX_ICON_BYTES).unwrap();
            }
            let template_source = work.path.join(format!("template-source-{os}"));
            let mut template_bytes = b"template-prefix".to_vec();
            template_bytes.extend_from_slice(&luxury_spec::SETUP_BINDING_PREFIX);
            template_bytes.extend_from_slice(&luxury_spec::SETUP_BINDING_TEMPLATE);
            template_bytes.extend_from_slice(&luxury_spec::SETUP_BINDING_SUFFIX);
            fs::write(&template_source, template_bytes).unwrap();
            let template = resources.join("templates").join(format!("{os}-{arch}"));
            stage_setup_template(&template, host, &template_source, &backend).unwrap();
            if os == "windows" {
                let tools = resources.join("tools");
                fs::create_dir(&tools).unwrap();
                fs::write(tools.join("nsis-3.12.zip"), b"pinned in assembly").unwrap();
            }
            let info_plist = (os == "macos").then(|| write_macos_info_plist(&bundle).unwrap());

            validate_portable_bundle(&bundle, host, ShellFlavor::Studio, info_plist.as_deref())
                .unwrap();
            assert!(!resources.join("payload").exists());
            assert!(!resources.join("trust").exists());

            fs::create_dir(resources.join("payload")).unwrap();
            assert!(
                validate_portable_bundle(&bundle, host, ShellFlavor::Studio, info_plist.as_deref())
                    .is_err()
            );
        }
    }

    #[test]
    fn setup_layout_is_exact_on_each_host() {
        let work = WorkDirectory::new(&env::temp_dir()).unwrap();
        for (os, arch) in [
            ("windows", "x86_64"),
            ("linux", "aarch64"),
            ("macos", "x86_64"),
        ] {
            let host = HostLayout::new(os, arch).unwrap();
            let bundle = work.path.join(format!("setup-{os}"));
            let resources = host.resources_directory(&bundle);
            let launcher = host.launcher(&bundle);
            let backend = resources.join("backend").join(host.backend_name);
            let payload = resources.join("payload").join("package.luxpkg");
            fs::create_dir_all(launcher.parent().unwrap()).unwrap();
            fs::create_dir_all(backend.parent().unwrap()).unwrap();
            fs::create_dir_all(payload.parent().unwrap()).unwrap();
            fs::write(&launcher, b"setup-launcher").unwrap();
            fs::write(&backend, b"setup-backend").unwrap();
            fs::write(&payload, b"setup-payload").unwrap();
            set_runner_permissions(&launcher, &backend, Some(&payload)).unwrap();
            stage_linux_privilege_integration(&bundle, host, &backend).unwrap();
            stage_macos_privilege_integration(&bundle, host, &backend).unwrap();
            let info_plist = (os == "macos").then(|| write_macos_info_plist(&bundle).unwrap());

            validate_portable_bundle(&bundle, host, ShellFlavor::Setup, info_plist.as_deref())
                .unwrap();
            fs::write(bundle.join("foreign"), b"foreign").unwrap();
            assert!(
                validate_portable_bundle(&bundle, host, ShellFlavor::Setup, info_plist.as_deref())
                    .is_err()
            );
        }
    }

    #[test]
    fn studio_artifact_name_is_host_specific_and_stable() {
        assert_eq!(
            studio_artifact_name(HostLayout::new("windows", "x86_64").unwrap()),
            format!(
                "luxury-installer-studio-{}-windows-x86_64",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn host_layout_and_paths_are_explicit_and_portable() {
        let cases = [
            ("windows", "x86_64", "luxury.exe"),
            ("windows", "aarch64", "luxury.exe"),
            ("linux", "x86_64", "luxury"),
            ("linux", "aarch64", "luxury"),
            ("macos", "x86_64", "luxury"),
            ("macos", "aarch64", "luxury"),
        ];
        let bundle = Path::new("runner output ü with spaces");
        for (os, arch, backend) in cases {
            let layout = HostLayout::new(os, arch).unwrap();
            assert_eq!(layout.backend_name, backend);
            assert!(layout.resources_directory(bundle).starts_with(bundle));
            assert!(layout.launcher(bundle).starts_with(bundle));
        }
        let windows = HostLayout::new("windows", "x86_64").unwrap();
        assert_eq!(windows.resources_directory(bundle), bundle);
        assert_eq!(
            windows.launcher(bundle),
            bundle.join("Luxury Installer.exe")
        );
        let linux = HostLayout::new("linux", "x86_64").unwrap();
        assert_eq!(
            linux.resources_directory(bundle),
            bundle.join("usr").join("lib").join(APP_NAME)
        );
        assert_eq!(
            linux.launcher(bundle),
            bundle.join("usr").join("bin").join("luxury-installer")
        );
        let macos = HostLayout::new("macos", "aarch64").unwrap();
        assert_eq!(
            macos.resources_directory(bundle),
            bundle
                .join("Luxury Installer.app")
                .join("Contents")
                .join("Resources")
        );
        assert!(HostLayout::new("freebsd", "x86_64").is_err());
        assert!(HostLayout::new("windows", "riscv64").is_err());

        let root = Path::new("workspace ü with spaces");
        assert_eq!(resolve_target_dir(root, None), root.join("target"));
        assert_eq!(
            resolve_target_dir(root, Some(OsStr::new("build cache"))),
            root.join("build cache")
        );
        let absolute = env::current_dir().unwrap().join("absolute target");
        assert_eq!(
            resolve_target_dir(root, Some(absolute.as_os_str())),
            absolute
        );
    }
}
