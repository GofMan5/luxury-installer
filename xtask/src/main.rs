use std::{
    env,
    ffi::{OsStr, OsString},
    path::Path,
    path::PathBuf,
    process::{Command, ExitCode},
};

mod runner;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [command] if command == OsStr::new("ci") => {
            cargo(&["fmt", "--all", "--", "--check"])?;
            cargo(&["quick", "--locked"])?;
            gui_check()?;
        }
        [command] if command == OsStr::new("gui-check") => {
            gui_check()?;
        }
        [command] if command == OsStr::new("dist") => {
            cargo(&["full-test", "--locked"])?;
            cargo(&["build", "--locked", "--profile", "dist", "-p", "luxury"])?;
            gui_check()?;
            println!(
                "host backend and checked Tauri frontend are ready; use cargo studio-assemble or cargo assemble for a verified portable artifact"
            );
        }
        [command] if command == OsStr::new("runner-smoke") => {
            runner::smoke()?;
        }
        [command] if command == OsStr::new("studio-assemble") => {
            runner::studio_assemble()?;
        }
        [command, project, output, work]
            if command == OsStr::new("__managed-project-installer") =>
        {
            runner::managed_project_installer(
                Path::new(project),
                Path::new(output),
                Path::new(work),
            )?;
        }
        [command, project, output] if command == OsStr::new("project-installer") => {
            runner::project_installer(Path::new(project), Path::new(output))?;
        }
        [command, separator, project, output]
            if command == OsStr::new("__workspace-project-installer")
                && separator == OsStr::new("--") =>
        {
            runner::workspace_project_installer(Path::new(project), Path::new(output))?;
        }
        [command, separator, project, output]
            if command == OsStr::new("project-installer") && separator == OsStr::new("--") =>
        {
            runner::project_installer(Path::new(project), Path::new(output))?;
        }
        [command, package] if command == OsStr::new("assemble") => {
            runner::assemble(Path::new(package))?;
        }
        [command, separator, package]
            if command == OsStr::new("assemble") && separator == OsStr::new("--") =>
        {
            runner::assemble(Path::new(package))?;
        }
        [command, package] if command == OsStr::new("linux-packages") => {
            runner::linux_packages(Path::new(package))?;
        }
        [command, separator, package]
            if command == OsStr::new("linux-packages") && separator == OsStr::new("--") =>
        {
            runner::linux_packages(Path::new(package))?;
        }
        [command, app] if command == OsStr::new("macos-dmg") => {
            runner::macos_dmg(Path::new(app))?;
        }
        [command, separator, app]
            if command == OsStr::new("macos-dmg") && separator == OsStr::new("--") =>
        {
            runner::macos_dmg(Path::new(app))?;
        }
        [command, package, nsis_archive] if command == OsStr::new("windows-setup") => {
            runner::windows_setup(Path::new(package), Path::new(nsis_archive))?;
        }
        [command, separator, package, nsis_archive]
            if command == OsStr::new("windows-setup") && separator == OsStr::new("--") =>
        {
            runner::windows_setup(Path::new(package), Path::new(nsis_archive))?;
        }
        [command, runner, nsis_archive] if command == OsStr::new("windows-release-setup") => {
            runner::windows_release_setup(Path::new(runner), Path::new(nsis_archive))?;
        }
        [command, separator, runner, nsis_archive]
            if command == OsStr::new("windows-release-setup") && separator == OsStr::new("--") =>
        {
            runner::windows_release_setup(Path::new(runner), Path::new(nsis_archive))?;
        }
        [command, first, second] if command == OsStr::new("verify-authenticode-pair") => {
            verify_authenticode_pair(Path::new(first), Path::new(second))?;
        }
        [command, separator, first, second]
            if command == OsStr::new("verify-authenticode-pair")
                && separator == OsStr::new("--") =>
        {
            verify_authenticode_pair(Path::new(first), Path::new(second))?;
        }
        [command, setup] if command == OsStr::new("verify-windows-release") => {
            runner::verify_windows_release(Path::new(setup))?;
        }
        [command, separator, setup]
            if command == OsStr::new("verify-windows-release") && separator == OsStr::new("--") =>
        {
            runner::verify_windows_release(Path::new(setup))?;
        }
        [command, directory] if command == OsStr::new("verify-evidence-set") => {
            runner::verify_evidence_set(Path::new(directory))?;
            println!("verified three-platform runner evidence set");
        }
        [command, app] if command == OsStr::new("verify-macos-release") => {
            runner::verify_macos_release(Path::new(app))?;
        }
        [command, separator, app]
            if command == OsStr::new("verify-macos-release") && separator == OsStr::new("--") =>
        {
            runner::verify_macos_release(Path::new(app))?;
        }
        [command, dmg] if command == OsStr::new("verify-macos-dmg") => {
            runner::verify_macos_dmg(Path::new(dmg))?;
        }
        [command, separator, dmg]
            if command == OsStr::new("verify-macos-dmg") && separator == OsStr::new("--") =>
        {
            runner::verify_macos_dmg(Path::new(dmg))?;
        }
        [command] if matches!(command.to_str(), Some("help" | "--help" | "-h")) => {
            usage();
        }
        _ => {
            usage();
            return Err(
                "expected ci, gui-check, dist, runner-smoke, studio-assemble, project-installer <project> <output>, assemble <package.luxpkg>, linux-packages <package.luxpkg>, macos-dmg <signed.app>, windows-setup <package.luxpkg> <nsis.zip>, windows-release-setup <signed-runner> <nsis.zip>, verify-authenticode-pair <launcher.exe> <helper.exe>, verify-windows-release <signed-setup.exe>, verify-macos-release <app.bundle>, verify-macos-dmg <signed.dmg>, or verify-evidence-set <directory>".into(),
            );
        }
    }
    Ok(())
}

fn verify_authenticode_pair(first: &Path, second: &Path) -> Result<(), String> {
    let signer = luxury_windows_trust::verify_same_authenticode_signer(first, second)
        .map_err(|error| error.to_string())?;
    let mut certificate_sha256 = String::with_capacity(64);
    for byte in signer.certificate_sha256() {
        use std::fmt::Write as _;
        write!(&mut certificate_sha256, "{byte:02x}").expect("writing to a String cannot fail");
    }
    println!("verified matching Authenticode signer: {certificate_sha256}");
    Ok(())
}

fn cargo(args: &[&str]) -> Result<(), String> {
    println!("> cargo {}", args.join(" "));
    let executable = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let status = Command::new(executable)
        .args(args)
        .current_dir(workspace_root())
        .status()
        .map_err(|error| format!("could not start cargo: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo {} exited with {status}", args.join(" ")))
    }
}

pub(crate) fn gui_check() -> Result<(), String> {
    let directory = workspace_root().join("apps").join("luxury-installer");
    if !directory.join("node_modules").is_dir() {
        return Err(format!(
            "Tauri frontend dependencies are missing; run `pnpm --dir {} install --frozen-lockfile`",
            directory.display()
        ));
    }

    let executable = env::var_os("PNPM").unwrap_or_else(|| {
        #[cfg(windows)]
        {
            OsString::from("pnpm.cmd")
        }
        #[cfg(not(windows))]
        {
            OsString::from("pnpm")
        }
    });
    println!("> pnpm run check ({})", directory.display());
    let status = Command::new(executable)
        .args(["run", "check"])
        .current_dir(&directory)
        .status()
        .map_err(|error| format!("could not start pnpm: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("pnpm run check exited with {status}"))
    }
}

pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live directly under the workspace root")
        .to_path_buf()
}

fn usage() {
    eprintln!(
        "Usage:
  cargo run -p xtask -- ci
  cargo run -p xtask -- gui-check
  cargo run -p xtask -- dist
  cargo run -p xtask -- runner-smoke
  cargo run -p xtask -- studio-assemble
  cargo run -p xtask -- project-installer <project> <native-output>
  cargo run -p xtask -- assemble <package.luxpkg>
  cargo run -p xtask -- linux-packages <package.luxpkg>
  cargo run -p xtask -- macos-dmg <signed.app>
  cargo run -p xtask -- windows-setup <package.luxpkg> <pinned-nsis.zip>
  cargo run -p xtask -- windows-release-setup <signed-runner> <pinned-nsis.zip>
  cargo run -p xtask -- verify-authenticode-pair <launcher.exe> <helper.exe>
  cargo run -p xtask -- verify-windows-release <signed-setup.exe>
  cargo run -p xtask -- verify-macos-release <signed-app.bundle>
  cargo run -p xtask -- verify-macos-dmg <signed-notarized.dmg>
  cargo run -p xtask -- verify-evidence-set <directory>

ci runs formatting, one fast Rust gate, and the isolated Tauri/TypeScript check.
gui-check runs renderer contracts, TypeScript, the frontend build, and the isolated Tauri check.
dist runs the full Rust test gate and builds the host backend plus the checked Tauri frontend.
runner-smoke verifies the portable Tauri runner lifecycle and writes schema-v2 evidence after cleanup.
studio-assemble builds and verifies one payload-free portable Tauri Studio without overwriting an artifact; Unix also gets a deterministic mode-preserving tar.gz.
project-installer keeps the package container internal and publishes one host-native end-user installer without overwriting the selected output.
assemble builds one unsigned-v1 portable Tauri runner without overwriting an artifact; Unix also gets a deterministic mode-preserving tar.gz.
linux-packages uses the pinned Tauri bundler to wrap one verified bound Setup as inspected unsigned .deb and RPM development artifacts on native Linux.
macos-dmg wraps one verified signed/stapled Setup app in an inspected unsigned development DMG on native macOS.
windows-setup wraps that verified runner in one pinned, unsigned Windows x64 development Setup.exe.
windows-release-setup requires a same-signer launcher/backend pair, runs the UAC Authenticode probe, and emits an unsigned outer Setup for signing.
verify-authenticode-pair requires two valid Windows Authenticode chains and the exact same leaf certificate.
verify-windows-release binds the signed NSIS parent to its signed Tauri launcher and elevated Rust helper, then rejects unexpected arguments.
verify-macos-release requires matching designated requirements, strict nested codesign, Gatekeeper acceptance, and a stapled notarization ticket.
verify-macos-dmg requires a signed, Gatekeeper-accepted, stapled image containing exactly that verified app and an Applications link.
verify-evidence-set validates Linux/Windows x86_64 plus macOS ARM64 evidence files.
Signed-v2/v3 runner assembly stays disabled until the native container has a verified trust anchor."
    );
}
