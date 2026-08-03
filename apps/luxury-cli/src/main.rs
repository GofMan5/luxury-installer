use std::{
    env,
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};

use luxury_bundle::{PackageSigningKey, PackageTrust, TrustedPublisherKey, open_bundle_file};
use luxury_compiler::{compile_project, compile_signed_project, init_project};
use luxury_engine::{
    install::{
        InstallAction, InstallCommand, InstallEvent, InstallPrepareOutcome, install,
        prepare_install,
    },
    launch::{LaunchCommand, launch},
    uninstall::{UninstallCommand, UninstallEvent, UninstallOutcome, uninstall},
};
use luxury_platform::{LocalInstallAdapter, LocalLaunchAdapter, LocalUninstallAdapter};
use luxury_spec::{Manifest, PackageId, PublisherKeyId, PublisherRotation};
use semver::Version;
use zeroize::Zeroizing;

mod privilege;
mod stdio;

const MAX_TERMINAL_DIAGNOSTIC_CHARS: usize = 4_096;
const MAX_KEY_PEM_BYTES: usize = 16 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            print_diagnostic(format_args!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_else(|| OsString::from("luxury"));
    let Some(command) = args.next() else {
        privilege::guard_command(OsStr::new(""))?;
        print_usage(&program);
        return Ok(());
    };
    let rest = args.collect::<Vec<_>>();
    privilege::guard_command(&command)?;

    match command.to_string_lossy().as_ref() {
        "stdio" => stdio::run(&rest),
        "privilege-probe" => privilege::run_probe(&rest)?,
        "privilege-probe-elevated" => privilege::run_elevated_probe(&rest)?,
        "privilege-probe-authenticated" => privilege::run_authenticated_probe(&rest)?,
        "privilege-authorize-install" => privilege::run_install_authorization(&rest)?,
        "privilege-install-system" => privilege::run_system_install(&rest)?,
        "privilege-uninstall-system" => privilege::run_system_uninstall(&rest)?,
        "privilege-launch-system" => privilege::run_system_launch(&rest)?,
        "init" => {
            expect_len(&rest, 1, &program)?;
            init_project(path_arg(&rest, 0))?;
            println!("initialized {}", display_arg(&rest[0]));
        }
        "build" => {
            let signed = command_args(parse_build_args(&rest), &program)?;
            let manifest = if signed {
                let signing_key = read_signing_key(io::stdin().lock())?;
                compile_signed_project(path_arg(&rest, 0), path_arg(&rest, 1), &signing_key)?
            } else {
                compile_project(path_arg(&rest, 0), path_arg(&rest, 1))?
            };
            println!(
                "built {}: {} {} ({} files, {} bytes)",
                display_arg(&rest[1]),
                manifest.package.id,
                manifest.package.version,
                manifest.files.len(),
                manifest.payload_size()
            );
        }
        "publisher-key-id" => {
            expect_len(&rest, 1, &program)?;
            println!("{}", read_trusted_key(&path_arg(&rest, 0))?.key_id());
        }
        "prepare-rotation" => {
            let options = command_args(parse_publisher_rotation_args(&rest), &program)?;
            let next_key = read_signing_key(io::stdin().lock())?;
            let rotation = next_key.create_publisher_rotation(
                &options.package_id,
                &options.version,
                options.current_key_id,
            )?;
            print!("{}", publisher_rotation_toml(&rotation));
        }
        "inspect" => {
            let options = command_args(parse_package_options(&rest, 1, false), &program)?;
            let trusted_key = options
                .trusted_key
                .as_deref()
                .map(read_trusted_key)
                .transpose()?;
            let bundle = open_bundle_file(path_arg(&rest, 0), trusted_key.as_ref())?;
            print_manifest(bundle.manifest(), bundle.trust());
            if let Some(rotation) = bundle.publisher_rotation() {
                println!(
                    "rotation:  {} -> {} (verified)",
                    rotation.from_key_id, rotation.to_key_id
                );
            }
        }
        "prepare-install" => {
            let options = command_args(parse_package_options(&rest, 3, false), &program)?;
            let trusted_key = options
                .trusted_key
                .as_deref()
                .map(read_trusted_key)
                .transpose()?;
            let bundle = open_bundle_file(path_arg(&rest, 0), trusted_key.as_ref())?;
            let manifest = bundle.manifest().clone();
            let package_id = manifest.package.id.clone();
            let mut port = LocalInstallAdapter::new(bundle, path_arg(&rest, 1), path_arg(&rest, 2));
            match prepare_install(manifest, &mut port)? {
                InstallPrepareOutcome::Ready {
                    action,
                    installed_version,
                    publisher_migration_required,
                } => {
                    let installed = installed_version
                        .map_or_else(|| "none".to_owned(), |version| version.to_string());
                    let action = prepared_install_action(action)?;
                    println!(
                        "ready {} {package_id}: installed version {installed}, publisher migration required: {publisher_migration_required}",
                        action
                    );
                }
                InstallPrepareOutcome::InsufficientSpace {
                    action,
                    installed_version,
                    publisher_migration_required,
                } => {
                    let installed = installed_version
                        .map_or_else(|| "none".to_owned(), |version| version.to_string());
                    let action = prepared_install_action(action)?;
                    println!(
                        "insufficient space for {} {package_id}: installed version {installed}, publisher migration required: {publisher_migration_required}; choose another install root or free space",
                        action
                    );
                }
                InstallPrepareOutcome::RecoveryRequired => {
                    println!("recovery required for {package_id}");
                }
            }
        }
        "install" => {
            let options = command_args(parse_package_options(&rest, 3, true), &program)?;
            let trusted_key = options
                .trusted_key
                .as_deref()
                .map(read_trusted_key)
                .transpose()?;
            let bundle = open_bundle_file(path_arg(&rest, 0), trusted_key.as_ref())?;
            require_install_consent(bundle.trust(), options.allow_unsigned)?;
            let manifest = bundle.manifest().clone();
            if bundle.trust() == PackageTrust::Unsigned {
                print_diagnostic(
                    "warning: package is unsigned; integrity is verified, publisher trust is not",
                );
            }
            let mut port = LocalInstallAdapter::new(bundle, path_arg(&rest, 1), path_arg(&rest, 2));
            let outcome = install(
                InstallCommand::new(manifest)
                    .with_license_acceptance(options.accept_license)
                    .with_downgrade_approval(options.allow_downgrade)
                    .with_publisher_migration_approval(options.allow_publisher_migration),
                &mut port,
                || false,
                print_install_event,
            )?;
            println!(
                "{} {}: {} files, {} bytes",
                completed_install_action(outcome.action),
                outcome.package_id,
                outcome.installed_files,
                outcome.installed_bytes
            );
        }
        "uninstall" => {
            expect_len(&rest, 3, &program)?;
            let package_id = package_id_arg(&rest[0])?;
            let mut port = LocalUninstallAdapter::new(path_arg(&rest, 1), path_arg(&rest, 2));
            match uninstall(
                UninstallCommand::new(package_id.clone()),
                &mut port,
                || false,
                print_uninstall_event,
            )? {
                UninstallOutcome::NotInstalled => println!("{package_id} is not installed"),
                UninstallOutcome::Uninstalled {
                    removed_files,
                    missing_files,
                    preserved_modified_files,
                } => println!(
                    "uninstalled {package_id}: {removed_files} removed, {missing_files} missing, {preserved_modified_files} preserved"
                ),
            }
        }
        "launch" => {
            expect_len(&rest, 3, &program)?;
            let package_id = package_id_arg(&rest[0])?;
            let mut port = LocalLaunchAdapter::new(path_arg(&rest, 1), path_arg(&rest, 2));
            launch(LaunchCommand::new(package_id.clone()), &mut port)?;
            println!("launched {package_id}");
        }
        "help" | "--help" | "-h" => print_usage(&program),
        other => {
            print_usage(&program);
            return Err(format!("unknown command '{other}'").into());
        }
    }

    Ok(())
}

#[derive(Default)]
struct PackageOptions {
    trusted_key: Option<PathBuf>,
    allow_unsigned: bool,
    accept_license: bool,
    allow_downgrade: bool,
    allow_publisher_migration: bool,
}

struct PublisherRotationArgs {
    package_id: PackageId,
    version: Version,
    current_key_id: PublisherKeyId,
}

fn parse_build_args(args: &[OsString]) -> Result<bool, String> {
    match args {
        [_, _] => Ok(false),
        [_, _, flag] if flag == OsStr::new("--signing-key-stdin") => Ok(true),
        _ => {
            Err("build expects <project-dir> <out.luxpkg> and optional --signing-key-stdin".into())
        }
    }
}

fn parse_publisher_rotation_args(args: &[OsString]) -> Result<PublisherRotationArgs, String> {
    let [package_id, version, current_key_id, flag] = args else {
        return Err(
            "prepare-rotation expects <package-id> <version> <A-key-id> --next-signing-key-stdin"
                .into(),
        );
    };
    if flag != OsStr::new("--next-signing-key-stdin") {
        return Err(
            "prepare-rotation accepts the next private key only through --next-signing-key-stdin"
                .into(),
        );
    }
    let package_id = text_arg(package_id, "package-id")?;
    let version = text_arg(version, "version")?;
    let current_key_id = text_arg(current_key_id, "current-key-id")?;
    Ok(PublisherRotationArgs {
        package_id: PackageId::parse(package_id).map_err(|error| error.to_string())?,
        version: Version::parse(version).map_err(|error| format!("invalid version: {error}"))?,
        current_key_id: PublisherKeyId::parse(current_key_id).map_err(|error| error.to_string())?,
    })
}

fn parse_package_options(
    args: &[OsString],
    positional_count: usize,
    supports_install_consent: bool,
) -> Result<PackageOptions, String> {
    if args.len() < positional_count {
        return Err(format!(
            "expected at least {positional_count} arguments, got {}",
            args.len()
        ));
    }

    let mut options = PackageOptions::default();
    let mut index = positional_count;
    while index < args.len() {
        match args[index].as_os_str() {
            flag if flag == OsStr::new("--trusted-publisher-key") => {
                if options.trusted_key.is_some() {
                    return Err("--trusted-publisher-key may be specified only once".into());
                }
                let value = args
                    .get(index + 1)
                    .filter(|value| {
                        !value.as_os_str().is_empty()
                            && !value.to_str().is_some_and(|value| value.starts_with("--"))
                    })
                    .ok_or("--trusted-publisher-key requires a file path")?;
                options.trusted_key = Some(PathBuf::from(value));
                index += 2;
            }
            flag if flag == OsStr::new("--allow-unsigned") && supports_install_consent => {
                if options.allow_unsigned {
                    return Err("--allow-unsigned may be specified only once".into());
                }
                options.allow_unsigned = true;
                index += 1;
            }
            flag if flag == OsStr::new("--accept-license") && supports_install_consent => {
                if options.accept_license {
                    return Err("--accept-license may be specified only once".into());
                }
                options.accept_license = true;
                index += 1;
            }
            flag if flag == OsStr::new("--allow-downgrade") && supports_install_consent => {
                if options.allow_downgrade {
                    return Err("--allow-downgrade may be specified only once".into());
                }
                options.allow_downgrade = true;
                index += 1;
            }
            flag if flag == OsStr::new("--allow-publisher-migration")
                && supports_install_consent =>
            {
                if options.allow_publisher_migration {
                    return Err("--allow-publisher-migration may be specified only once".into());
                }
                options.allow_publisher_migration = true;
                index += 1;
            }
            flag => return Err(format!("unknown option `{}`", flag.to_string_lossy())),
        }
    }
    Ok(options)
}

fn command_args<T>(result: Result<T, String>, program: &OsString) -> Result<T, Box<dyn Error>> {
    result.map_err(|message| {
        print_usage(program);
        message.into()
    })
}

fn read_signing_key(reader: impl Read) -> Result<PackageSigningKey, Box<dyn Error>> {
    let mut pem = Zeroizing::new(Vec::with_capacity(MAX_KEY_PEM_BYTES + 1));
    read_bounded(reader, &mut pem, "PKCS#8 signing key from stdin")?;
    let pem = std::str::from_utf8(&pem).map_err(|_| "signing key PEM is not valid UTF-8")?;
    PackageSigningKey::from_pkcs8_pem(pem).map_err(Into::into)
}

fn read_trusted_key(path: &Path) -> Result<TrustedPublisherKey, Box<dyn Error>> {
    let file = File::open(path).map_err(|source| {
        format!(
            "opening trusted publisher key `{}` failed: {source}",
            path.display()
        )
    })?;
    if !file
        .metadata()
        .map_err(|source| {
            format!(
                "inspecting trusted publisher key `{}` failed: {source}",
                path.display()
            )
        })?
        .is_file()
    {
        return Err(format!(
            "trusted publisher key `{}` is not a regular file",
            path.display()
        )
        .into());
    }

    let mut pem = Vec::new();
    read_bounded(
        file,
        &mut pem,
        &format!("trusted publisher key `{}`", path.display()),
    )?;
    let pem =
        std::str::from_utf8(&pem).map_err(|_| "trusted publisher key PEM is not valid UTF-8")?;
    TrustedPublisherKey::from_public_key_pem(pem).map_err(Into::into)
}

fn read_bounded(
    reader: impl Read,
    output: &mut Vec<u8>,
    description: &str,
) -> Result<(), Box<dyn Error>> {
    reader
        .take((MAX_KEY_PEM_BYTES + 1) as u64)
        .read_to_end(output)
        .map_err(|source| format!("reading {description} failed: {source}"))?;
    if output.len() > MAX_KEY_PEM_BYTES {
        return Err(format!("{description} exceeds the {MAX_KEY_PEM_BYTES}-byte limit").into());
    }
    Ok(())
}

fn require_install_consent(
    trust: PackageTrust,
    allow_unsigned: bool,
) -> Result<(), Box<dyn Error>> {
    if trust == PackageTrust::Unsigned && !allow_unsigned {
        Err("unsigned package installation requires --allow-unsigned".into())
    } else {
        Ok(())
    }
}

fn expect_len(
    args: &[OsString],
    expected: usize,
    program: &OsString,
) -> Result<(), Box<dyn Error>> {
    if args.len() == expected {
        Ok(())
    } else {
        print_usage(program);
        Err(format!("expected {expected} arguments, got {}", args.len()).into())
    }
}

fn path_arg(args: &[OsString], index: usize) -> PathBuf {
    PathBuf::from(&args[index])
}

fn package_id_arg(value: &OsString) -> Result<PackageId, Box<dyn Error>> {
    PackageId::parse(value.to_string_lossy().into_owned()).map_err(Into::into)
}

fn display_arg(value: &OsString) -> String {
    Path::new(value).display().to_string()
}

fn text_arg<'a>(value: &'a OsString, name: &str) -> Result<&'a str, String> {
    value
        .to_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} must be non-empty UTF-8"))
}

fn publisher_rotation_toml(rotation: &PublisherRotation) -> String {
    format!(
        "[publisher_rotation]\nnext_public_key = \"{}\"\nproof = \"{}\"\n",
        rotation.next_public_key, rotation.proof
    )
}

fn print_manifest(manifest: &Manifest, trust: PackageTrust) {
    println!(
        "package:   {} {}",
        manifest.package.id, manifest.package.version
    );
    println!("name:      {}", manifest.package.name);
    println!("publisher: {}", manifest.package.publisher);
    if let Some(license) = &manifest.package.license {
        println!("license:\n--- begin license ---\n{license}\n--- end license ---");
    } else {
        println!("license:   none");
    }
    println!("target:    {} {}", manifest.target.os, manifest.target.arch);
    println!(
        "install:   {:?} / {}",
        manifest.install.scope, manifest.install.directory
    );
    println!("trust:     {trust:?}");
    println!(
        "payload:   {} files, {} bytes",
        manifest.files.len(),
        manifest.payload_size()
    );
    for file in &manifest.files {
        let executable = if file.executable { " executable" } else { "" };
        println!("  {} {} bytes{executable}", file.path, file.size);
    }
}

fn install_action(action: InstallAction) -> &'static str {
    match action {
        InstallAction::Install => "install",
        InstallAction::Update => "update",
        InstallAction::Repair => "repair",
        InstallAction::Downgrade => "downgrade",
    }
}

fn prepared_install_action(action: InstallAction) -> Result<&'static str, Box<dyn Error>> {
    if action == InstallAction::Downgrade {
        Err("prepare-install returned an unexpected downgrade action".into())
    } else {
        Ok(install_action(action))
    }
}

fn completed_install_action(action: InstallAction) -> &'static str {
    match action {
        InstallAction::Install => "installed",
        InstallAction::Update => "updated",
        InstallAction::Repair => "repaired",
        InstallAction::Downgrade => "downgraded",
    }
}

fn print_install_event(event: InstallEvent) {
    match event {
        InstallEvent::Phase(phase) => print_diagnostic(format_args!("install: {phase:?}")),
        InstallEvent::Action(action) => {
            print_diagnostic(format_args!("install: action {}", install_action(action)))
        }
        InstallEvent::Progress(progress) => print_diagnostic(format_args!(
            "install: {}/{} files, {}/{} bytes",
            progress.completed_files,
            progress.total_files,
            progress.completed_bytes,
            progress.total_bytes
        )),
    }
}

fn print_uninstall_event(event: UninstallEvent) {
    match event {
        UninstallEvent::Phase(phase) => print_diagnostic(format_args!("uninstall: {phase:?}")),
        UninstallEvent::Progress(progress) => {
            print_diagnostic(format_args!(
                "uninstall: {}/{} files",
                progress.processed_files, progress.total_files
            ));
        }
        UninstallEvent::PreservedModified(path) => {
            print_diagnostic(format_args!("uninstall: preserved modified {path}"))
        }
    }
}

fn print_usage(program: &OsString) {
    let program = Path::new(program).display();
    print_diagnostic(format_args!(
        "Luxury Installer CLI

Usage:
  {program} stdio [--trusted-publisher-key <absolute-public.pem>]
  {program} init <project-dir>
  {program} build <project-dir> <out.luxpkg> [--signing-key-stdin]
  {program} publisher-key-id <public.pem>
  {program} prepare-rotation <package-id> <version> <A-key-id> --next-signing-key-stdin
  {program} inspect <package.luxpkg> [--trusted-publisher-key <public.pem>]
  {program} prepare-install <package.luxpkg> <install-base> <state-root> [--trusted-publisher-key <public.pem>]
  {program} install <package.luxpkg> <install-base> <state-root> [--trusted-publisher-key <public.pem>] [--allow-unsigned] [--accept-license] [--allow-downgrade] [--allow-publisher-migration]
  {program} uninstall <package-id> <install-base> <state-root>
  {program} launch <package-id> <install-base> <state-root>

Notes:
  Signed builds require a v2/v3 project and read a bounded PKCS#8 PEM only from stdin.
  Publisher rotation reads the next private key from stdin and prints only a public TOML section.
  Signed v2/v3 packages require a matching external SPKI publisher key.
  Unsigned v1 installation requires explicit --allow-unsigned consent.
  A package license requires explicit --accept-license consent.
  Replacing a newer installed version requires explicit --allow-downgrade consent.
  Migrating legacy ownership identity or binding unsigned state to a publisher requires explicit --allow-publisher-migration consent.
  <state-root> must live outside the removable install tree."
    ));
}

fn print_diagnostic(message: impl fmt::Display) {
    eprintln!("{}", terminal_safe_diagnostic(message));
}

fn terminal_safe_diagnostic(message: impl fmt::Display) -> String {
    let message = message.to_string();
    let mut chars = message.chars();
    let mut safe = String::with_capacity(message.len().min(MAX_TERMINAL_DIAGNOSTIC_CHARS));
    for character in chars.by_ref().take(MAX_TERMINAL_DIAGNOSTIC_CHARS) {
        match character {
            '\n' | '\t' => safe.push(character),
            character if character.is_control() => safe.push('\u{fffd}'),
            character => safe.push(character),
        }
    }
    if chars.next().is_some() {
        safe.push('\u{2026}');
    }
    safe
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Cursor};

    use tempfile::tempdir;

    use super::*;

    // Public deterministic fixture; never use this key for a real package.
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

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_only_the_supported_signing_and_trust_options() {
        assert!(!parse_build_args(&args(&["project", "out.luxpkg"])).unwrap());
        assert!(
            parse_build_args(&args(&["project", "out.luxpkg", "--signing-key-stdin"])).unwrap()
        );
        assert!(
            parse_build_args(&args(&[
                "project",
                "out.luxpkg",
                "--signing-key",
                "key.pem"
            ]))
            .is_err()
        );

        let install = parse_package_options(
            &args(&[
                "package.luxpkg",
                "install",
                "state",
                "--allow-unsigned",
                "--accept-license",
                "--allow-downgrade",
                "--allow-publisher-migration",
                "--trusted-publisher-key",
                "publisher.pem",
            ]),
            3,
            true,
        )
        .unwrap();
        assert!(install.allow_unsigned);
        assert!(install.accept_license);
        assert!(install.allow_downgrade);
        assert!(install.allow_publisher_migration);
        assert_eq!(install.trusted_key, Some(PathBuf::from("publisher.pem")));
        let prepare = parse_package_options(
            &args(&[
                "package.luxpkg",
                "install",
                "state",
                "--trusted-publisher-key",
                "publisher.pem",
            ]),
            3,
            false,
        )
        .unwrap();
        assert_eq!(prepare.trusted_key, Some(PathBuf::from("publisher.pem")));
        assert!(!prepare.allow_unsigned);
        assert!(!prepare.accept_license);
        assert!(!prepare.allow_downgrade);
        assert!(!prepare.allow_publisher_migration);
        assert!(
            parse_package_options(&args(&["package.luxpkg", "--allow-unsigned"]), 1, false)
                .is_err()
        );
        assert!(
            parse_package_options(&args(&["package.luxpkg", "--allow-downgrade"]), 1, false)
                .is_err()
        );
        assert!(
            parse_package_options(&args(&["package.luxpkg", "--accept-license"]), 1, false)
                .is_err()
        );
        assert!(
            parse_package_options(
                &args(&["package.luxpkg", "--allow-publisher-migration"]),
                1,
                false,
            )
            .is_err()
        );
        assert!(
            parse_package_options(
                &args(&[
                    "package.luxpkg",
                    "install",
                    "state",
                    "--allow-downgrade",
                    "--allow-downgrade",
                ]),
                3,
                true,
            )
            .is_err()
        );
        assert!(
            parse_package_options(
                &args(&[
                    "package.luxpkg",
                    "install",
                    "state",
                    "--allow-publisher-migration",
                    "--allow-publisher-migration",
                ]),
                3,
                true,
            )
            .is_err()
        );
        assert!(
            parse_package_options(
                &args(&["package.luxpkg", "--trusted-publisher-key"]),
                1,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn signing_key_input_is_bounded_and_unsigned_install_requires_consent() {
        let signing_key = read_signing_key(Cursor::new(TEST_SIGNING_KEY_PEM)).unwrap();
        assert_eq!(signing_key.key_id().to_string().len(), 64);

        let oversized = vec![b'x'; MAX_KEY_PEM_BYTES + 1];
        let error = read_signing_key(Cursor::new(oversized)).err().unwrap();
        assert!(error.to_string().contains("exceeds"));

        assert!(require_install_consent(PackageTrust::Unsigned, false).is_err());
        assert!(require_install_consent(PackageTrust::Unsigned, true).is_ok());
        assert!(
            require_install_consent(
                PackageTrust::TrustedPublisher {
                    key_id: signing_key.key_id()
                },
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn publisher_rotation_command_parses_context_and_outputs_only_public_toml() {
        let current = PackageSigningKey::from_pkcs8_pem(TEST_SIGNING_KEY_PEM).unwrap();
        let next = PackageSigningKey::from_pkcs8_pem(NEXT_SIGNING_KEY_PEM).unwrap();
        let values = args(&[
            "dev.luxury.demo",
            "2.0.0",
            &current.key_id().to_string(),
            "--next-signing-key-stdin",
        ]);
        let parsed = parse_publisher_rotation_args(&values).unwrap();
        assert_eq!(parsed.package_id.as_str(), "dev.luxury.demo");
        assert_eq!(parsed.version, Version::new(2, 0, 0));
        assert_eq!(parsed.current_key_id, current.key_id());
        assert!(
            parse_publisher_rotation_args(&args(&[
                "dev.luxury.demo",
                "2.0.0",
                &current.key_id().to_string(),
                "--signing-key",
            ]))
            .is_err()
        );

        let rotation = next
            .create_publisher_rotation(&parsed.package_id, &parsed.version, parsed.current_key_id)
            .unwrap();
        let public_toml = publisher_rotation_toml(&rotation);
        assert!(public_toml.starts_with("[publisher_rotation]\n"));
        assert!(public_toml.contains(&rotation.next_public_key.to_string()));
        assert!(public_toml.contains(&rotation.proof.to_string()));
        assert!(!public_toml.contains("PRIVATE KEY"));
        assert!(!public_toml.contains(TEST_SIGNING_KEY_PEM));
        assert!(!public_toml.contains(NEXT_SIGNING_KEY_PEM));
    }

    #[test]
    fn publisher_key_id_reads_only_a_public_key() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("publisher.pem");
        fs::write(&path, TEST_TRUSTED_KEY_PEM).unwrap();
        let expected = PackageSigningKey::from_pkcs8_pem(TEST_SIGNING_KEY_PEM)
            .unwrap()
            .key_id();

        assert_eq!(read_trusted_key(&path).unwrap().key_id(), expected);
    }

    #[test]
    fn terminal_diagnostics_neutralize_controls_preserve_text_and_are_bounded() {
        let safe = terminal_safe_diagnostic(format!(
            "readable \u{1b}[31mtext\u{7}\n{}",
            "x".repeat(MAX_TERMINAL_DIAGNOSTIC_CHARS)
        ));

        assert!(!safe.contains(['\u{1b}', '\u{7}']));
        assert!(safe.starts_with("readable \u{fffd}[31mtext\u{fffd}\n"));
        assert_eq!(safe.chars().count(), MAX_TERMINAL_DIAGNOSTIC_CHARS + 1);
        assert!(safe.ends_with('\u{2026}'));
    }

    #[test]
    fn install_actions_have_truthful_human_words() {
        let cases = [
            (InstallAction::Install, "install", "installed"),
            (InstallAction::Update, "update", "updated"),
            (InstallAction::Repair, "repair", "repaired"),
            (InstallAction::Downgrade, "downgrade", "downgraded"),
        ];
        for (action, planned, completed) in cases {
            assert_eq!(install_action(action), planned);
            assert_eq!(completed_install_action(action), completed);
        }
        assert!(prepared_install_action(InstallAction::Downgrade).is_err());
    }
}
