use std::{
    cell::Cell,
    fs::{self, OpenOptions},
    io::{self, Cursor, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use luxury_bundle::{
    PackageSigningKey, TrustedPublisherKey, create_signed_bundle, create_unsigned_bundle,
    open_bundle,
};
use luxury_engine::{
    PortErrorKind,
    install::{
        InstallAction, InstallCommand, InstallError, InstallEvent, InstallPrepareOutcome,
        InstallPreparePort, PackageIdentity, install, prepare_install,
    },
    uninstall::{
        OwnershipReceipt, RECEIPT_FORMAT_VERSION, UninstallCommand, UninstallError,
        UninstallOutcome, UninstallPort, uninstall,
    },
};
use luxury_spec::{
    FORMAT_VERSION, FileEntry, InstallDirectory, InstallPolicy, InstallScope, Manifest,
    PUBLISHER_ROTATION_FORMAT_VERSION, Package, PackageId, PackagePath, SIGNED_FORMAT_VERSION,
    Sha256Digest, Target,
};
use semver::Version;
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

use super::capacity::{
    CAPACITY_MIN_HEADROOM_BYTES, SpaceSnapshot, check_directory_write_access, query_space,
    require_storage_capacity, round_up,
};
use super::transaction::load_recovery_for_scope;
#[cfg(windows)]
use super::transaction::set_remove_regular_matching_hook;
use super::{
    ActiveTransaction, JournalRecord, LocalInstallAdapter, LocalUninstallAdapter, Operation,
    begin_transaction, begin_transaction_with_package_lock, begin_uninstall_transaction,
    ensure_directory, hash_regular, io_error, load_recovery, lock_package, open_regular,
    read_receipt_with_hash, removed_file, same_file, staged_file, staged_receipt,
    sync_movable_regular_snapshot, transaction_paths,
};

// Public deterministic fixtures. Never use these keys for a real package.
const SIGNING_KEY_PEM: &str = concat!(
    "-----BEGIN PRIVATE ",
    "KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE ",
    "KEY-----\n"
);
const TRUSTED_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";
const NEXT_SIGNING_KEY_PEM: &str = concat!(
    "-----BEGIN PRIVATE ",
    "KEY-----\nMC4CAQAwBQYDK2VwBCIEIEzNCJso/5banbbDRuwRTg9bijGfNaumJNqM9u1PuKb7\n-----END PRIVATE ",
    "KEY-----\n"
);
const NEXT_TRUSTED_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=\n-----END PUBLIC KEY-----\n";

#[test]
fn journal_scope_mismatch_fails_before_recovery_mutation() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    ensure_directory(&install_base, None).unwrap();
    let package_lock = match lock_package(&state_root, &package_id, InstallScope::System) {
        Ok(lock) => lock,
        Err(error) if error.kind() == PortErrorKind::Permission => return,
        Err(error) => panic!("preparing system-private state failed: {error}"),
    };
    let transaction = begin_transaction_with_package_lock(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
        InstallScope::System,
        None,
        package_lock,
    )
    .unwrap();
    let paths = transaction.paths.clone();
    drop(transaction);
    let header = fs::read_to_string(&paths.journal).unwrap();
    assert!(
        header
            .lines()
            .next()
            .unwrap()
            .contains("\"scope\":\"system\"")
    );

    let install_before = tree_snapshot(&install_base);
    let state_before = tree_snapshot(&state_root);
    let error = match load_recovery_for_scope(
        &install_base,
        &state_root,
        &package_id,
        InstallScope::User,
    ) {
        Err(error) => error,
        Ok(_) => panic!("user authority recovered a system journal"),
    };
    match error.kind() {
        PortErrorKind::State => {
            assert!(error.to_string().contains("scope System"), "{error}");
        }
        #[cfg(windows)]
        PortErrorKind::Permission => {
            assert!(
                error.to_string().contains("private directory ACL"),
                "{error}"
            );
        }
        kind => panic!("unexpected journal scope mismatch error {kind:?}: {error}"),
    }
    assert_eq!(tree_snapshot(&install_base), install_before);
    assert_eq!(tree_snapshot(&state_root), state_before);
}

#[test]
fn system_receipt_is_visible_only_to_system_adapter_authority() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let files = [("app.bin", b"system".as_slice())];
    let (bundle, manifest) = system_bundle(&files);
    let package_id = manifest.package.id.clone();
    let installed = install(
        InstallCommand::for_system(manifest),
        &mut LocalInstallAdapter::for_system(bundle, &install_base, &state_root),
        || false,
        |_| {},
    );
    match installed {
        Ok(_) => {}
        Err(InstallError::Port { source, .. }) if source.kind() == PortErrorKind::Permission => {
            return;
        }
        Err(error) => panic!("system install failed unexpectedly: {error}"),
    }

    let (user_bundle, _) = system_bundle(&files);
    let mut user = LocalInstallAdapter::new(user_bundle, &install_base, &state_root);
    let error = user
        .load_receipt(&package_id)
        .expect_err("user adapter must not load a system receipt");
    assert!(error.to_string().contains("scope System"), "{error}");

    let (system_bundle, _) = system_bundle(&files);
    let receipt = LocalInstallAdapter::for_system(system_bundle, &install_base, &state_root)
        .load_receipt(&package_id)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.scope(), InstallScope::System);
}

#[test]
fn package_lock_prepares_every_fixed_state_directory() {
    let temp = tempdir().unwrap();
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();

    let _lock = lock_package(&state_root, &package_id, InstallScope::User).unwrap();

    for directory in ["locks", "transactions", "receipts"] {
        assert!(state_root.join(directory).is_dir());
    }
}

#[cfg(unix)]
#[test]
fn private_directory_creation_preserves_the_existing_parent_mode() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let nested = temp.path().join("created-parent").join("private");

    ensure_directory(&nested, Some(InstallScope::User)).unwrap();

    assert_eq!(
        fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(nested.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(nested).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[cfg(unix)]
#[test]
fn system_private_policy_requires_root_and_exact_modes() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = tempdir().unwrap();
    let state = temp.path().join("system-state");
    if rustix::process::geteuid().is_root() {
        ensure_directory(&state, Some(InstallScope::System)).unwrap();
        let receipt = state.join("receipt.json");
        fs::write(&receipt, b"{}").unwrap();
        super::set_private_file(&receipt, InstallScope::System).unwrap();
        let directory = fs::metadata(&state).unwrap();
        let file = fs::metadata(&receipt).unwrap();
        assert_eq!(directory.uid(), 0);
        assert_eq!(directory.permissions().mode() & 0o777, 0o700);
        assert_eq!(file.uid(), 0);
        assert_eq!(file.permissions().mode() & 0o777, 0o600);
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        let error = ensure_directory(&state, Some(InstallScope::System))
            .expect_err("broad existing system state must fail closed");
        assert_eq!(error.kind(), PortErrorKind::Permission);
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o755,
            "validation must not silently harden and accept pre-existing state"
        );
    } else {
        let error = ensure_directory(&state, Some(InstallScope::System))
            .expect_err("non-root authority must not create system-private state");
        assert_eq!(error.kind(), PortErrorKind::Permission);
        assert!(!state.exists());
    }
}

#[cfg(any(unix, windows))]
#[test]
fn recovery_rejects_a_dangling_state_directory_link() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    ensure_directory(&state_root, Some(InstallScope::User)).unwrap();
    ensure_directory(paths.state_dir.parent().unwrap(), Some(InstallScope::User)).unwrap();
    let missing_target = temp.path().join("missing-target");
    if let Err(error) = create_directory_link(&paths.state_dir, &missing_target) {
        #[cfg(windows)]
        if error.raw_os_error() == Some(1314) {
            return;
        }
        panic!("creating dangling transaction state link failed: {error}");
    }

    let error = load_recovery(&install_base, &state_root, &package_id)
        .err()
        .expect("a dangling transaction state link must fail closed");

    assert_eq!(error.kind(), PortErrorKind::State);
    assert!(!missing_target.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn recovery_rejects_a_dangling_destination_link_when_state_exists() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    ensure_directory(&paths.state_dir, Some(InstallScope::User)).unwrap();
    fs::create_dir_all(paths.destination_dir.parent().unwrap()).unwrap();
    let missing_target = temp.path().join("missing-target");
    if let Err(error) = create_directory_link(&paths.destination_dir, &missing_target) {
        #[cfg(windows)]
        if error.raw_os_error() == Some(1314) {
            return;
        }
        panic!("creating dangling destination link failed: {error}");
    }

    let error = load_recovery(&install_base, &state_root, &package_id)
        .err()
        .expect("a dangling destination link must fail closed");

    assert_eq!(error.kind(), PortErrorKind::State);
    assert!(paths.state_dir.is_dir());
    assert!(!missing_target.exists());
}

#[test]
fn upgrade_receipt_is_staged_on_the_state_volume() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let paths = transaction_paths(&install_base, &state_root, &package_id);

    assert_eq!(
        staged_receipt(&paths),
        paths.state_dir.join("receipt.incoming")
    );
}

#[test]
fn capacity_query_uses_the_nearest_existing_directory_without_creating_roots() {
    let temp = tempdir().unwrap();
    let missing = temp.path().join("missing").join("nested");

    let space = query_space(&missing).unwrap();

    assert!(space.allocation_unit > 0);
    assert!(!missing.exists());
    assert!(!missing.parent().unwrap().exists());
}

#[test]
fn same_volume_capacity_is_aggregated_once_and_fails_one_byte_short() {
    let required = CAPACITY_MIN_HEADROOM_BYTES + 30;
    let space = SpaceSnapshot {
        volume_id: 7,
        available_bytes: required,
        allocation_unit: 1,
    };

    require_storage_capacity(space, 10, 0, space, 20, 0).unwrap();

    let short = SpaceSnapshot {
        available_bytes: required - 1,
        ..space
    };
    let error = require_storage_capacity(short, 10, 0, short, 20, 0).unwrap_err();
    assert_eq!(error.kind(), luxury_engine::PortErrorKind::Capacity);
}

#[test]
fn separate_volume_capacity_is_checked_independently() {
    let install = SpaceSnapshot {
        volume_id: 1,
        available_bytes: CAPACITY_MIN_HEADROOM_BYTES + 10,
        allocation_unit: 1,
    };
    let state = SpaceSnapshot {
        volume_id: 2,
        available_bytes: CAPACITY_MIN_HEADROOM_BYTES + 20,
        allocation_unit: 1,
    };

    require_storage_capacity(install, 10, 0, state, 20, 0).unwrap();

    let short = SpaceSnapshot {
        available_bytes: state.available_bytes - 1,
        ..state
    };
    let error = require_storage_capacity(install, 10, 0, short, 20, 0).unwrap_err();
    assert_eq!(error.kind(), luxury_engine::PortErrorKind::Capacity);
}

#[test]
fn capacity_rejects_rounding_overflow() {
    let space = SpaceSnapshot {
        volume_id: 1,
        available_bytes: u64::MAX,
        allocation_unit: 1,
    };
    require_storage_capacity(space, 0, 2, space, 0, 2).unwrap();
    assert_eq!(
        round_up(u64::MAX, 4096).unwrap_err().kind(),
        luxury_engine::PortErrorKind::Capacity
    );
}

#[test]
fn platform_io_errors_keep_stable_kinds() {
    for kind in [io::ErrorKind::StorageFull, io::ErrorKind::QuotaExceeded] {
        let error = io_error(
            "writing transaction data",
            Path::new("payload"),
            kind.into(),
        );
        assert_eq!(error.kind(), luxury_engine::PortErrorKind::Capacity);
    }
    assert_eq!(
        io_error(
            "publishing transaction data",
            Path::new("payload"),
            io::ErrorKind::Unsupported.into(),
        )
        .kind(),
        luxury_engine::PortErrorKind::Unsupported
    );
}

#[test]
fn prepare_fresh_package_is_ready_without_creating_roots() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);

    let outcome = prepare_install(
        manifest,
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
    )
    .unwrap();

    assert_eq!(
        outcome,
        InstallPrepareOutcome::Ready {
            action: InstallAction::Install,
            installed_version: None,
            publisher_migration_required: false,
        }
    );
    assert!(!install_base.exists());
    assert!(!state_root.exists());
}

#[test]
fn shortcut_intent_fails_before_local_mutation_until_native_adapter_exists() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (discarded, mut manifest) = bundle(&[("bin/app.exe", b"owned")]);
    drop(discarded);
    manifest.schema_version = luxury_spec::SHORTCUT_SCHEMA_VERSION;
    manifest.install.entrypoint = Some(manifest.files[0].path.clone());
    manifest.files[0].executable = true;
    manifest.install.shortcuts.application_menu = true;
    let payload = tempdir().unwrap();
    let source = payload.path().join("bin").join("app.exe");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(source, b"owned").unwrap();
    let mut encoded = Vec::new();
    create_unsigned_bundle(&mut encoded, payload.path(), &manifest).unwrap();
    let bundle = open_bundle(Cursor::new(encoded), None).unwrap();

    let error = prepare_install(
        manifest,
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        luxury_engine::install::InstallError::Port {
            step: "preflight",
            source,
        } if source.kind() == luxury_engine::PortErrorKind::Unsupported
    ));
    assert!(!install_base.exists());
    assert!(!state_root.exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn prepare_rejects_a_non_writable_destination_without_mutating_it() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let install_base = temp.path().join("restricted");
    let state_root = temp.path().join("state");
    fs::create_dir(&install_base).unwrap();
    fs::set_permissions(&install_base, fs::Permissions::from_mode(0o555)).unwrap();
    if check_directory_write_access(&install_base).is_ok() {
        fs::set_permissions(&install_base, fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }
    let before = tree_snapshot(&install_base);
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let error = prepare_install(
        manifest,
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
    )
    .unwrap_err();
    fs::set_permissions(&install_base, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        error,
        InstallError::Port { source, .. } if source.kind() == PortErrorKind::Permission
    ));
    assert_eq!(tree_snapshot(&install_base), before);
    assert!(!state_root.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn prepare_rejects_non_private_existing_state_without_mutating_it() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    fs::create_dir(&state_root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let before = tree_snapshot(&state_root);
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);

    let error = prepare_install(
        manifest,
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        InstallError::Port { source, .. } if source.kind() == PortErrorKind::Permission
    ));
    assert_eq!(tree_snapshot(&state_root), before);
    assert!(!install_base.exists());
}

#[cfg(windows)]
#[test]
fn prepare_rejects_program_files_for_a_non_elevated_user_without_mutating_it() {
    let Some(install_base) = std::env::var_os("ProgramFiles").map(PathBuf::from) else {
        return;
    };
    if check_directory_write_access(&install_base).is_ok() {
        return;
    }
    let temp = tempdir().unwrap();
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let error = prepare_install(
        manifest,
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        InstallError::Port { source, .. } if source.kind() == PortErrorKind::Permission
    ));
    assert!(!state_root.exists());
}

#[test]
fn prepare_reports_pending_recovery_without_mutating_either_root() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let paths = transaction_paths(&install_base, &state_root, &manifest.package.id);
    fs::create_dir_all(&paths.state_dir).unwrap();
    fs::create_dir_all(&paths.destination_dir).unwrap();
    fs::write(paths.state_dir.join("sentinel"), b"state bytes").unwrap();
    fs::write(paths.destination_dir.join("sentinel"), b"destination bytes").unwrap();
    let install_before = tree_snapshot(&install_base);
    let state_before = tree_snapshot(&state_root);

    let outcome = prepare_install(
        manifest,
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
    )
    .unwrap();

    assert_eq!(outcome, InstallPrepareOutcome::RecoveryRequired);
    assert_eq!(tree_snapshot(&install_base), install_before);
    assert_eq!(tree_snapshot(&state_root), state_before);
}

#[test]
fn installs_with_external_receipt_and_uninstalls_only_owned_files() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("bin/app", b"app"), ("share/readme.txt", b"readme")]);
    let package_id = manifest.package.id.clone();
    let install_root = install_base.join(manifest.install.directory.as_str());

    let mut adapter = LocalInstallAdapter::new(bundle, &install_base, &state_root);
    let outcome = install(
        InstallCommand::new(manifest),
        &mut adapter,
        || false,
        |_| {},
    )
    .unwrap();
    assert_eq!(outcome.installed_files, 2);
    assert_eq!(fs::read(install_root.join("bin/app")).unwrap(), b"app");

    let paths = transaction_paths(&install_base, &state_root, &package_id);
    assert!(paths.receipt.is_file());
    let mut receipt_reader = LocalUninstallAdapter::new(&install_base, &state_root);
    assert_eq!(
        receipt_reader
            .load_receipt(&package_id)
            .unwrap()
            .unwrap()
            .package_identity(),
        Some(PackageIdentity::Unsigned)
    );
    assert!(!paths.receipt.starts_with(&install_root));
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());

    fs::write(install_root.join("user-notes.txt"), b"keep").unwrap();
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let outcome = uninstall(
        UninstallCommand::new(package_id),
        &mut adapter,
        || false,
        |_| {},
    )
    .unwrap();
    assert_eq!(
        outcome,
        UninstallOutcome::Uninstalled {
            removed_files: 2,
            missing_files: 0,
            preserved_modified_files: 0,
        }
    );
    assert!(!install_root.join("bin/app").exists());
    assert_eq!(
        fs::read(install_root.join("user-notes.txt")).unwrap(),
        b"keep"
    );
    assert!(!paths.receipt.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn signed_bundle_identity_is_persisted_in_current_receipt() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest, key_id) = signed_bundle(&[("app.bin", b"signed")]);
    let package_id = manifest.package.id.clone();

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    assert_eq!(
        adapter
            .load_receipt(&package_id)
            .unwrap()
            .unwrap()
            .package_identity(),
        Some(PackageIdentity::TrustedPublisher { key_id })
    );
}

#[test]
fn verified_rotation_persists_a_signed_payload_and_b_authorized_publisher() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest, key_a) = signed_bundle(&[("app.bin", b"a")]);
    let package_id = manifest.package.id.clone();
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    let (bundle, manifest, rotation_from, key_b) =
        rotation_bundle(Version::new(2, 0, 0), &[("app.bin", b"b")]);
    assert_eq!(rotation_from, key_a);
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    let paths = transaction_paths(&install_base, &state_root, &package_id);
    let mut receipt_reader = LocalUninstallAdapter::new(&install_base, &state_root);
    let rotated = receipt_reader.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(rotated.format_version(), RECEIPT_FORMAT_VERSION);
    assert_eq!(
        rotated.package_identity(),
        Some(PackageIdentity::TrustedPublisher { key_id: key_b })
    );
    assert_eq!(
        rotated.payload_signer(),
        Some(PackageIdentity::TrustedPublisher { key_id: key_a })
    );
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&paths.receipt).unwrap()).unwrap();
    assert_eq!(stored["format_version"], 2);
    assert_eq!(
        stored["receipt"]["authorized_publisher"]["keyId"],
        key_b.to_string()
    );
    assert_eq!(
        stored["receipt"]["payload_signer"]["keyId"],
        key_a.to_string()
    );

    let (replay, manifest, _, _) = rotation_bundle(Version::new(2, 0, 0), &[("app.bin", b"b")]);
    let error = install(
        InstallCommand::new(manifest)
            .with_downgrade_approval(true)
            .with_publisher_migration_approval(true),
        &mut LocalInstallAdapter::new(replay, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(
        error,
        InstallError::PublisherRotationDenied { .. }
    ));
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());

    let (bundle, manifest, future_key) = signed_bundle_with_keys(
        Version::new(3, 0, 0),
        &[("app.bin", b"c")],
        NEXT_SIGNING_KEY_PEM,
        NEXT_TRUSTED_KEY_PEM,
    );
    assert_eq!(future_key, key_b);
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut receipt_reader = LocalUninstallAdapter::new(&install_base, &state_root);
    let future = receipt_reader.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(
        future.package_identity(),
        Some(PackageIdentity::TrustedPublisher { key_id: key_b })
    );
    assert_eq!(future.payload_signer(), future.package_identity());
}

#[test]
fn stored_receipt_v2_reads_legacy_ownership_receipt_v1() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    fs::create_dir_all(&install_base).unwrap();
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    fs::create_dir_all(paths.receipt.parent().unwrap()).unwrap();
    let receipt = OwnershipReceipt::new(
        package_id.clone(),
        Version::new(1, 0, 0),
        InstallScope::User,
        InstallDirectory::parse("LuxuryDemo").unwrap(),
        PackageIdentity::Unsigned,
        vec![FileEntry {
            path: PackagePath::parse("app.bin").unwrap(),
            size: 3,
            sha256: digest(b"old"),
            executable: false,
        }],
    )
    .unwrap();
    write_stored_receipt(&paths.receipt, &install_base, &receipt);
    rewrite_stored_receipt_as_legacy(&paths.receipt);

    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let legacy = adapter.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(legacy.format_version(), 1);
    assert_eq!(legacy.package_identity(), None);
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(paths.receipt).unwrap()).unwrap();
    assert_eq!(stored["format_version"], 2);
}

#[test]
fn upgrade_replaces_owned_files_and_preserves_modified_obsolete_files() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle_version(
        Version::new(1, 0, 0),
        &[
            ("shared.bin", b"old"),
            ("stable.bin", b"stable"),
            ("obsolete.bin", b"remove"),
            ("keep.cfg", b"default"),
        ],
    );
    let package_id = manifest.package.id.clone();
    let install_root = install_base.join(manifest.install.directory.as_str());
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    fs::write(install_root.join("shared.bin"), b"user changed shared").unwrap();
    fs::write(install_root.join("keep.cfg"), b"user setting").unwrap();

    let (bundle, manifest) = bundle_version(
        Version::new(2, 0, 0),
        &[
            ("shared.bin", b"new"),
            ("stable.bin", b"stable"),
            ("added.bin", b"added"),
        ],
    );
    let expected_files = manifest.files.clone();
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    assert_eq!(fs::read(install_root.join("shared.bin")).unwrap(), b"new");
    assert_eq!(
        fs::read(install_root.join("stable.bin")).unwrap(),
        b"stable"
    );
    assert_eq!(fs::read(install_root.join("added.bin")).unwrap(), b"added");
    assert!(!install_root.join("obsolete.bin").exists());
    assert_eq!(
        fs::read(install_root.join("keep.cfg")).unwrap(),
        b"user setting"
    );
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(receipt.version(), &Version::new(2, 0, 0));
    assert_eq!(receipt.files(), expected_files);
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[cfg(windows)]
#[test]
fn upgrade_works_with_install_and_state_on_distinct_available_volumes() {
    let state_volume = tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let install_volume = tempfile::Builder::new()
        .prefix("luxury-cross-volume-")
        .tempdir_in(executable.parent().unwrap())
        .unwrap();
    if query_space(state_volume.path()).unwrap().volume_id
        == query_space(install_volume.path()).unwrap().volume_id
    {
        return;
    }

    let install_base = install_volume.path().join("install");
    let state_root = state_volume.path().join("state");
    let (bundle, manifest) = bundle_version(Version::new(1, 0, 0), &[("app.bin", b"old")]);
    let package_id = manifest.package.id.clone();
    let install_root = install_base.join(manifest.install.directory.as_str());
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    let (bundle, manifest) = bundle_version(Version::new(2, 0, 0), &[("app.bin", b"new")]);
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    assert_eq!(fs::read(install_root.join("app.bin")).unwrap(), b"new");
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    assert_eq!(
        adapter
            .load_receipt(&package_id)
            .unwrap()
            .unwrap()
            .version(),
        &Version::new(2, 0, 0)
    );
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[cfg(unix)]
#[test]
fn upgrade_preserves_obsolete_file_with_changed_executable_mode() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle_version(
        Version::new(1, 0, 0),
        &[("obsolete.bin", b"owned"), ("stable.bin", b"stable")],
    );
    let install_root = install_base.join(manifest.install.directory.as_str());
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let obsolete = install_root.join("obsolete.bin");
    fs::set_permissions(&obsolete, fs::Permissions::from_mode(0o755)).unwrap();

    let (bundle, manifest) = bundle_version(Version::new(2, 0, 0), &[("stable.bin", b"stable")]);
    let outcome = install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    assert_eq!(outcome.action, InstallAction::Update);
    assert_eq!(fs::read(&obsolete).unwrap(), b"owned");
    assert_ne!(
        fs::metadata(obsolete).unwrap().permissions().mode() & 0o111,
        0
    );
}

#[test]
fn approved_legacy_migration_commits_current_unsigned_identity() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle_version(Version::new(1, 0, 0), &[("app.bin", b"old")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    rewrite_stored_receipt_as_legacy(&paths.receipt);

    let (bundle, manifest) = bundle_version(Version::new(2, 0, 0), &[("app.bin", b"new")]);
    install(
        InstallCommand::new(manifest).with_publisher_migration_approval(true),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    assert_eq!(fs::read(installed).unwrap(), b"new");
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(receipt.format_version(), RECEIPT_FORMAT_VERSION);
    assert_eq!(receipt.package_identity(), Some(PackageIdentity::Unsigned));
    assert_eq!(receipt.payload_signer(), Some(PackageIdentity::Unsigned));
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(paths.receipt).unwrap()).unwrap();
    assert_eq!(stored["format_version"], 2);
}

#[test]
fn same_version_reinstall_repairs_modified_owned_file() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (first_bundle, manifest) = bundle(&[("app.bin", b"package")]);
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(first_bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    fs::write(&installed, b"modified").unwrap();

    let (bundle, manifest) = bundle(&[("app.bin", b"package")]);
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"package");
}

#[cfg(unix)]
#[test]
fn cancelled_reinstall_restores_the_actual_executable_mode() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (first_bundle, manifest) = bundle(&[("app.bin", b"package")]);
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(first_bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();

    let (bundle, manifest) = bundle(&[("app.bin", b"package")]);
    let cancel = Cell::new(false);
    let error = install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || cancel.get(),
        |event| {
            if matches!(
                event,
                InstallEvent::Progress(progress) if progress.completed_files == 1
            ) {
                cancel.set(true);
            }
        },
    )
    .unwrap_err();
    assert_eq!(error, InstallError::Cancelled);
    assert_ne!(
        fs::metadata(installed).unwrap().permissions().mode() & 0o111,
        0
    );
}

#[test]
fn cancelled_upgrade_restores_actual_files_and_previous_receipt() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle_version(
        Version::new(1, 0, 0),
        &[("obsolete.bin", b"old obsolete"), ("shared.bin", b"old")],
    );
    let package_id = manifest.package.id.clone();
    let install_root = install_base.join(manifest.install.directory.as_str());
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    fs::write(install_root.join("shared.bin"), b"user modified").unwrap();

    let (bundle, manifest) = bundle_version(
        Version::new(2, 0, 0),
        &[("shared.bin", b"new"), ("added.bin", b"added")],
    );
    let cancel = Cell::new(false);
    let error = install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || cancel.get(),
        |event| {
            if matches!(
                event,
                InstallEvent::Progress(progress) if progress.completed_files == 2
            ) {
                cancel.set(true);
            }
        },
    )
    .unwrap_err();

    assert_eq!(error, InstallError::Cancelled);
    assert_eq!(
        fs::read(install_root.join("shared.bin")).unwrap(),
        b"user modified"
    );
    assert_eq!(
        fs::read(install_root.join("obsolete.bin")).unwrap(),
        b"old obsolete"
    );
    assert!(!install_root.join("added.bin").exists());
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(receipt.format_version(), RECEIPT_FORMAT_VERSION);
    assert_eq!(receipt.version(), &Version::new(1, 0, 0));
    assert_eq!(receipt.package_identity(), Some(PackageIdentity::Unsigned));
    assert_eq!(receipt.payload_signer(), Some(PackageIdentity::Unsigned));
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn cancelled_upgrade_removes_new_nested_directories() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle_version(Version::new(1, 0, 0), &[("stable.bin", b"stable")]);
    let package_id = manifest.package.id.clone();
    let install_root = install_base.join(manifest.install.directory.as_str());
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    let (bundle, manifest) = bundle_version(
        Version::new(2, 0, 0),
        &[("nested/deep/new.bin", b"new"), ("stable.bin", b"stable")],
    );
    let cancel = Cell::new(false);
    let error = install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || cancel.get(),
        |event| {
            if matches!(
                event,
                InstallEvent::Progress(progress) if progress.completed_files == 1
            ) {
                cancel.set(true);
            }
        },
    )
    .unwrap_err();

    assert_eq!(error, InstallError::Cancelled);
    assert!(!install_root.join("nested").exists());
    assert_eq!(
        fs::read(install_root.join("stable.bin")).unwrap(),
        b"stable"
    );
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn upgrade_preflight_rejects_case_only_and_file_directory_transitions() {
    for (old_path, new_path) in [
        ("App.bin", "app.bin"),
        ("node", "node/child.bin"),
        ("tree/child.bin", "tree"),
    ] {
        let temp = tempdir().unwrap();
        let install_base = temp.path().join("install");
        let state_root = temp.path().join("state");
        let (bundle, manifest) = bundle_version(Version::new(1, 0, 0), &[(old_path, b"old")]);
        let package_id = manifest.package.id.clone();
        let directory = manifest.install.directory.clone();
        install(
            InstallCommand::new(manifest),
            &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
            || false,
            |_| {},
        )
        .unwrap();

        let (bundle, manifest) = bundle_version(Version::new(2, 0, 0), &[(new_path, b"new")]);
        let error = install(
            InstallCommand::new(manifest),
            &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
            || false,
            |_| {},
        )
        .unwrap_err();
        let rejected = if old_path.eq_ignore_ascii_case(new_path) {
            matches!(&error, InstallError::PathAliasChanged { .. })
        } else {
            matches!(
                &error,
                InstallError::Port {
                    step: "preflight",
                    ..
                }
            )
        };
        assert!(rejected, "{old_path} -> {new_path}: {error:?}");
        assert_eq!(
            fs::read(
                install_base
                    .join(directory.as_str())
                    .join(Path::new(old_path))
            )
            .unwrap(),
            b"old"
        );
        let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
        assert_eq!(
            adapter
                .load_receipt(&package_id)
                .unwrap()
                .unwrap()
                .version(),
            &Version::new(1, 0, 0)
        );
    }
}

#[test]
fn upgrade_rejects_an_unknown_new_path_without_adopting_it() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle_version(Version::new(1, 0, 0), &[("app.bin", b"old")]);
    let install_root = install_base.join(manifest.install.directory.as_str());
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    fs::write(install_root.join("new.bin"), b"user file").unwrap();

    let (bundle, manifest) = bundle_version(
        Version::new(2, 0, 0),
        &[("app.bin", b"new"), ("new.bin", b"package")],
    );
    let error = install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(
        error,
        InstallError::Port {
            step: "preflight",
            ..
        }
    ));
    assert_eq!(
        fs::read(install_root.join("new.bin")).unwrap(),
        b"user file"
    );
    assert_eq!(fs::read(install_root.join("app.bin")).unwrap(), b"old");
}

#[test]
fn reserved_install_directories_fail_before_creating_platform_state() {
    for directory in [".LUXURY-LOCKS", ".LuXuRy-Tx-dev.luxury.demo"] {
        let temp = tempdir().unwrap();
        let install_base = temp.path().join("install");
        let state_root = temp.path().join("state");
        let (bundle, manifest) = bundle_version_in_directory(
            Version::new(1, 0, 0),
            InstallDirectory::parse(directory).unwrap(),
            &[("app.bin", b"app")],
        );

        let error = install(
            InstallCommand::new(manifest),
            &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
            || false,
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(
            error,
            InstallError::Port {
                step: "preflight",
                ..
            }
        ));
        assert!(!install_base.exists());
        assert!(!state_root.exists());
    }
}

#[test]
fn install_root_cannot_overlap_state_receipts_transactions_or_locks() {
    for directory in ["receipts", "transactions", "locks"] {
        let temp = tempdir().unwrap();
        let shared_root = temp.path().join("shared");
        let (bundle, manifest) = bundle_version_in_directory(
            Version::new(1, 0, 0),
            InstallDirectory::parse(directory).unwrap(),
            &[("app.bin", b"app")],
        );

        let error = install(
            InstallCommand::new(manifest),
            &mut LocalInstallAdapter::new(bundle, &shared_root, &shared_root),
            || false,
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(
            error,
            InstallError::Port {
                step: "preflight",
                ..
            }
        ));
        assert!(!shared_root.exists());
    }
}

#[test]
fn uninstall_preserves_modified_owned_file() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"original")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    fs::write(&installed, b"user changed this").unwrap();

    let outcome = uninstall(
        UninstallCommand::new(package_id),
        &mut LocalUninstallAdapter::new(&install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    assert_eq!(
        outcome,
        UninstallOutcome::Uninstalled {
            removed_files: 0,
            missing_files: 0,
            preserved_modified_files: 1,
        }
    );
    assert_eq!(fs::read(installed).unwrap(), b"user changed this");
}

#[cfg(unix)]
#[test]
fn uninstall_preserves_owned_file_with_changed_executable_mode() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"original")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();

    let outcome = uninstall(
        UninstallCommand::new(package_id),
        &mut LocalUninstallAdapter::new(&install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    assert_eq!(
        outcome,
        UninstallOutcome::Uninstalled {
            removed_files: 0,
            missing_files: 0,
            preserved_modified_files: 1,
        }
    );
    assert_eq!(fs::read(&installed).unwrap(), b"original");
    assert_ne!(
        fs::metadata(installed).unwrap().permissions().mode() & 0o111,
        0
    );
}

#[test]
fn receipt_replay_against_other_install_base_is_rejected_without_mutation() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let other_base = temp.path().join("other");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let directory = manifest.install.directory.clone();
    let installed = install_base.join(directory.as_str()).join("app.bin");
    let unrelated = other_base.join(directory.as_str()).join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
    fs::write(&unrelated, b"owned").unwrap();

    let error = uninstall(
        UninstallCommand::new(package_id.clone()),
        &mut LocalUninstallAdapter::new(&other_base, &state_root),
        || false,
        |_| {},
    )
    .expect_err("a receipt must not authorize another install base");

    assert!(matches!(error, UninstallError::Port { .. }));
    assert_eq!(fs::read(installed).unwrap(), b"owned");
    assert_eq!(fs::read(unrelated).unwrap(), b"owned");
    assert!(
        transaction_paths(&install_base, &state_root, &package_id)
            .receipt
            .exists()
    );
}

#[test]
fn cancellation_rolls_back_files_and_receipt() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("one", b"1"), ("two", b"2")]);
    let package_id = manifest.package.id.clone();
    let directory = manifest.install.directory.clone();
    let cancel = Cell::new(false);

    let error = install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || cancel.get(),
        |event| {
            if matches!(
                event,
                InstallEvent::Progress(progress) if progress.completed_files == 1
            ) {
                cancel.set(true);
            }
        },
    )
    .unwrap_err();
    assert_eq!(error, InstallError::Cancelled);
    assert!(!install_base.join(directory.as_str()).join("one").exists());
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    assert!(!paths.receipt.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[cfg(windows)]
#[test]
fn cancellation_rollback_deletes_verified_handle_not_replacement_path() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("one", b"1"), ("two", b"2")]);
    let package_id = manifest.package.id.clone();
    let directory = manifest.install.directory.clone();
    let installed = install_base.join(directory.as_str()).join("one");
    let displaced = install_base.join(directory.as_str()).join("displaced-one");
    let hook_installed = installed.clone();
    let hook_displaced = displaced.clone();
    set_remove_regular_matching_hook(move || {
        fs::rename(&hook_installed, &hook_displaced).unwrap();
        fs::write(&hook_installed, b"foreign").unwrap();
    });
    let cancel = Cell::new(false);

    let error = install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || cancel.get(),
        |event| {
            if matches!(
                event,
                InstallEvent::Progress(progress) if progress.completed_files == 1
            ) {
                cancel.set(true);
            }
        },
    )
    .unwrap_err();

    assert_eq!(error, InstallError::Cancelled);
    assert!(!displaced.exists());
    assert_eq!(fs::read(installed).unwrap(), b"foreign");
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    assert!(!paths.receipt.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn next_run_recovers_an_interrupted_install() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    let path = PackagePath::parse("partial.bin").unwrap();
    let bytes = b"complete";
    let digest = digest(bytes);

    let mut transaction = begin_transaction(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
    )
    .unwrap();
    let root = install_base.join(directory.as_str());
    transaction
        .append(JournalRecord::RemoveDirectory { path: None })
        .unwrap();
    ensure_directory(&root, None).unwrap();
    transaction
        .append(JournalRecord::StageFile {
            path: path.clone(),
            sha256: digest.clone(),
        })
        .unwrap();
    transaction
        .append(JournalRecord::RemoveFile {
            path: path.clone(),
            sha256: digest,
        })
        .unwrap();
    fs::write(root.join(path.to_native_path()), bytes).unwrap();
    let journal = transaction.paths.journal.clone();
    drop(transaction);
    let mut journal = OpenOptions::new().append(true).open(journal).unwrap();
    journal.write_all(br#"{"kind":"remove_file"#).unwrap();
    journal.sync_all().unwrap();
    drop(journal);

    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    adapter.recover_pending(&package_id).unwrap();
    assert!(!root.join(path.to_native_path()).exists());
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn install_recovery_rejects_dangling_live_receipt_before_rollback() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    let path = PackagePath::parse("owned.bin").unwrap();
    let bytes = b"owned";
    let digest = digest(bytes);
    let mut transaction = begin_transaction(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
    )
    .unwrap();
    let installed = install_base
        .join(directory.as_str())
        .join(path.to_native_path());
    transaction
        .append(JournalRecord::RemoveDirectory { path: None })
        .unwrap();
    ensure_directory(installed.parent().unwrap(), None).unwrap();
    transaction
        .append(JournalRecord::StageFile {
            path: path.clone(),
            sha256: digest.clone(),
        })
        .unwrap();
    transaction
        .append(JournalRecord::RemoveFile {
            path,
            sha256: digest,
        })
        .unwrap();
    transaction.append(JournalRecord::Committing).unwrap();
    fs::write(&installed, bytes).unwrap();
    let paths = transaction.paths.clone();
    drop(transaction);
    let missing = temp.path().join("missing-receipt");
    if let Err(error) = create_file_link(&paths.receipt, &missing) {
        #[cfg(windows)]
        if error.raw_os_error() == Some(1314) {
            return;
        }
        panic!("creating dangling live receipt link failed: {error}");
    }

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("a dangling live receipt must fail before install rollback");

    assert_eq!(fs::read(&installed).unwrap(), bytes);
    assert!(paths.journal.is_file());
    assert!(fs::symlink_metadata(&paths.receipt).is_ok());
    assert!(!missing.exists());
}

#[test]
fn next_run_removes_a_partial_transaction_staging_file() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    let path = PackagePath::parse("partial.bin").unwrap();
    let mut transaction = begin_transaction(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
    )
    .unwrap();
    transaction
        .append(JournalRecord::StageFile {
            path: path.clone(),
            sha256: digest(b"complete"),
        })
        .unwrap();
    let staged = staged_file(&transaction.paths, &path);
    ensure_directory(staged.parent().unwrap(), Some(InstallScope::User)).unwrap();
    fs::write(&staged, b"partial").unwrap();
    let paths = transaction.paths.clone();
    drop(transaction);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert!(!staged.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn recovery_reads_a_legacy_v2_install_journal() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    let path = PackagePath::parse("legacy.bin").unwrap();
    let mut transaction = begin_transaction(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
    )
    .unwrap();
    transaction
        .append(JournalRecord::RemoveFile {
            path: path.clone(),
            sha256: digest(b"legacy"),
        })
        .unwrap();
    let installed = install_base
        .join(directory.as_str())
        .join(path.to_native_path());
    ensure_directory(installed.parent().unwrap(), None).unwrap();
    fs::write(&installed, b"legacy").unwrap();
    let paths = transaction.paths.clone();
    drop(transaction);
    let journal = fs::read_to_string(&paths.journal)
        .unwrap()
        .replacen("\"format_version\":4", "\"format_version\":2", 1)
        .replacen(",\"scope\":\"user\"", "", 1);
    let legacy_header = journal.lines().next().unwrap();
    assert!(legacy_header.contains("\"format_version\":2"));
    assert!(!legacy_header.contains("previous_receipt_sha256"));
    fs::write(&paths.journal, journal).unwrap();

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert!(!installed.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn active_legacy_v2_uninstall_recovery_fails_closed_before_mutation() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let paths = interrupted.active.as_ref().unwrap().paths.clone();
    let backup = paths.destination_dir.join("removed/app.bin");
    drop(interrupted);

    let journal = fs::read_to_string(&paths.journal).unwrap();
    let mut lines = journal.lines();
    let mut header: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    header["format_version"] = 2.into();
    header
        .as_object_mut()
        .unwrap()
        .remove("previous_receipt_sha256");
    header.as_object_mut().unwrap().remove("scope");
    let mut legacy = serde_json::to_string(&header).unwrap();
    for line in lines {
        legacy.push('\n');
        legacy.push_str(line);
    }
    legacy.push('\n');
    fs::write(&paths.journal, legacy).unwrap();

    let install_before = tree_snapshot(&install_base);
    let state_before = tree_snapshot(&state_root);
    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("legacy uninstall recovery must require a receipt-bound v3 journal");

    assert!(
        error.to_string().contains("receipt-bound journal"),
        "unexpected recovery error: {error}"
    );
    assert_eq!(tree_snapshot(&install_base), install_before);
    assert_eq!(tree_snapshot(&state_root), state_before);
    assert!(!installed.exists());
    assert_eq!(fs::read(backup).unwrap(), b"owned");
}

#[test]
fn rollback_marker_replaces_a_torn_tail_and_survives_a_second_crash() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    let mut journal = OpenOptions::new()
        .append(true)
        .open(&paths.journal)
        .unwrap();
    journal.write_all(br#"{"kind":"torn"#).unwrap();
    journal.sync_all().unwrap();
    drop(journal);

    let mut recovered = load_recovery(&install_base, &state_root, &package_id)
        .unwrap()
        .unwrap();
    recovered.mark_rolling_back().unwrap();
    drop(recovered);
    let journal = fs::read_to_string(&paths.journal).unwrap();
    assert!(!journal.contains("torn"));
    assert!(journal.ends_with("{\"kind\":\"rolling_back\"}\n"));

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"old");
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn recovery_rejects_a_rollback_marker_on_non_upgrade_journal() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    let transaction = begin_transaction(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
    )
    .unwrap();
    let paths = transaction.paths.clone();
    drop(transaction);
    append_journal_record(&paths.journal, &JournalRecord::RollingBack);

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("rollback markers are upgrade-only");
    assert!(error.to_string().contains("invalid rollback marker"));
    assert!(paths.journal.exists());
    assert!(paths.destination_dir.exists());
}

#[test]
fn v3_install_recovery_rejects_orphan_remove_before_touching_destination() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    let path = PackagePath::parse("foreign.bin").unwrap();
    let mut transaction = begin_transaction(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
    )
    .unwrap();
    transaction
        .append(JournalRecord::RemoveFile {
            path: path.clone(),
            sha256: digest(b"foreign"),
        })
        .unwrap();
    let destination = install_base
        .join(directory.as_str())
        .join(path.to_native_path());
    ensure_directory(destination.parent().unwrap(), None).unwrap();
    fs::write(&destination, b"foreign").unwrap();
    let paths = transaction.paths.clone();
    drop(transaction);

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("v3 RemoveFile requires a prior matching StageFile");
    assert!(error.to_string().contains("without prior staging"));
    assert_eq!(fs::read(destination).unwrap(), b"foreign");
    assert!(paths.journal.exists());
    assert!(paths.destination_dir.exists());
}

#[test]
fn upgrade_recovery_rolls_back_before_receipt_publish() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(false);
    let _keep_temp_alive = temp;

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"old");
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(receipt.version(), &Version::new(1, 0, 0));
    assert!(!paths.receipt_previous.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn upgrade_recovery_marks_and_rolls_back_a_crash_before_receipt_staging() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    fs::remove_file(&paths.receipt_pending).unwrap();
    super::rename_noreplace(&paths.receipt_previous, &paths.receipt)
        .unwrap()
        .sync()
        .unwrap();
    let journal = fs::read_to_string(&paths.journal).unwrap();
    let retained = journal
        .lines()
        .filter(|line| !line.contains("pending_receipt") && !line.contains("committing"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&paths.journal, format!("{retained}\n")).unwrap();

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"old");
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn upgrade_recovery_resumes_after_receipt_rollback_was_already_published() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    append_journal_record(&paths.journal, &JournalRecord::RollingBack);
    let backup = removed_file(&paths, &PackagePath::parse("app.bin").unwrap());
    fs::remove_file(&installed).unwrap();
    super::rename_noreplace(&backup, &installed)
        .unwrap()
        .sync()
        .unwrap();
    fs::remove_file(&paths.receipt_pending).unwrap();
    super::rename_noreplace(&paths.receipt_previous, &paths.receipt)
        .unwrap()
        .sync()
        .unwrap();

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"old");
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    assert_eq!(
        adapter
            .load_receipt(&package_id)
            .unwrap()
            .unwrap()
            .version(),
        &Version::new(1, 0, 0)
    );
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn same_version_recovery_uses_rollback_marker_after_receipt_was_restored() {
    let (temp, install_base, state_root, package_id, installed, paths) =
        interrupted_same_version_rollback();
    let _keep_temp_alive = temp;

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"user modified");
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    assert_eq!(
        adapter
            .load_receipt(&package_id)
            .unwrap()
            .unwrap()
            .version(),
        &Version::new(1, 0, 0)
    );
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn upgrade_recovery_finishes_after_receipt_publish() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(true);
    let _keep_temp_alive = temp;

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"new");
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(receipt.format_version(), RECEIPT_FORMAT_VERSION);
    assert_eq!(receipt.version(), &Version::new(2, 0, 0));
    assert_eq!(receipt.package_identity(), Some(PackageIdentity::Unsigned));
    assert_eq!(receipt.payload_signer(), Some(PackageIdentity::Unsigned));
    assert!(!paths.receipt_previous.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn rotation_recovery_before_receipt_cutover_restores_a_a_provenance() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    let key_a = PackageSigningKey::from_pkcs8_pem(SIGNING_KEY_PEM)
        .unwrap()
        .key_id();
    let key_b = PackageSigningKey::from_pkcs8_pem(NEXT_SIGNING_KEY_PEM)
        .unwrap()
        .key_id();

    let mut old: serde_json::Value =
        serde_json::from_slice(&fs::read(&paths.receipt_previous).unwrap()).unwrap();
    old["receipt"]["authorized_publisher"] =
        serde_json::json!({"kind": "trustedPublisher", "keyId": key_a.to_string()});
    old["receipt"]["payload_signer"] =
        serde_json::json!({"kind": "trustedPublisher", "keyId": key_a.to_string()});
    let old = serde_json::to_vec_pretty(&old).unwrap();
    fs::write(&paths.receipt_previous, &old).unwrap();

    let mut new: serde_json::Value =
        serde_json::from_slice(&fs::read(&paths.receipt_pending).unwrap()).unwrap();
    new["receipt"]["authorized_publisher"] =
        serde_json::json!({"kind": "trustedPublisher", "keyId": key_b.to_string()});
    new["receipt"]["payload_signer"] =
        serde_json::json!({"kind": "trustedPublisher", "keyId": key_a.to_string()});
    let new = serde_json::to_vec_pretty(&new).unwrap();
    fs::write(&paths.receipt_pending, &new).unwrap();

    let mut journal = String::new();
    for line in fs::read_to_string(&paths.journal).unwrap().lines() {
        let mut record: serde_json::Value = serde_json::from_str(line).unwrap();
        match record["kind"].as_str() {
            Some("header") => {
                record["previous_receipt_sha256"] = serde_json::json!(digest(&old).to_string());
            }
            Some("pending_receipt") => {
                record["sha256"] = serde_json::json!(digest(&new).to_string());
            }
            _ => {}
        }
        journal.push_str(&serde_json::to_string(&record).unwrap());
        journal.push('\n');
    }
    fs::write(&paths.journal, journal).unwrap();

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"old");
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(
        receipt.package_identity(),
        Some(PackageIdentity::TrustedPublisher { key_id: key_a })
    );
    assert_eq!(receipt.payload_signer(), receipt.package_identity());
}

#[test]
fn rotation_recovery_after_receipt_cutover_keeps_b_a_provenance() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(true);
    let _keep_temp_alive = temp;
    let key_a = PackageSigningKey::from_pkcs8_pem(SIGNING_KEY_PEM)
        .unwrap()
        .key_id();
    let key_b = PackageSigningKey::from_pkcs8_pem(NEXT_SIGNING_KEY_PEM)
        .unwrap()
        .key_id();

    let mut old: serde_json::Value =
        serde_json::from_slice(&fs::read(&paths.receipt_previous).unwrap()).unwrap();
    old["receipt"]["authorized_publisher"] =
        serde_json::json!({"kind": "trustedPublisher", "keyId": key_a.to_string()});
    old["receipt"]["payload_signer"] =
        serde_json::json!({"kind": "trustedPublisher", "keyId": key_a.to_string()});
    let old = serde_json::to_vec_pretty(&old).unwrap();
    fs::write(&paths.receipt_previous, &old).unwrap();

    let mut new: serde_json::Value =
        serde_json::from_slice(&fs::read(&paths.receipt).unwrap()).unwrap();
    new["receipt"]["authorized_publisher"] =
        serde_json::json!({"kind": "trustedPublisher", "keyId": key_b.to_string()});
    new["receipt"]["payload_signer"] =
        serde_json::json!({"kind": "trustedPublisher", "keyId": key_a.to_string()});
    let new = serde_json::to_vec_pretty(&new).unwrap();
    fs::write(&paths.receipt, &new).unwrap();

    let mut journal = String::new();
    for line in fs::read_to_string(&paths.journal).unwrap().lines() {
        let mut record: serde_json::Value = serde_json::from_str(line).unwrap();
        match record["kind"].as_str() {
            Some("header") => {
                record["previous_receipt_sha256"] = serde_json::json!(digest(&old).to_string());
            }
            Some("pending_receipt") => {
                record["sha256"] = serde_json::json!(digest(&new).to_string());
            }
            _ => {}
        }
        journal.push_str(&serde_json::to_string(&record).unwrap());
        journal.push('\n');
    }
    fs::write(&paths.journal, journal).unwrap();

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"new");
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(
        receipt.package_identity(),
        Some(PackageIdentity::TrustedPublisher { key_id: key_b })
    );
    assert_eq!(
        receipt.payload_signer(),
        Some(PackageIdentity::TrustedPublisher { key_id: key_a })
    );
}

#[test]
fn legacy_migration_recovery_rolls_back_exact_legacy_identity() {
    let (temp, install_base, state_root, package_id, installed, paths) =
        interrupted_legacy_upgrade(false);
    let _keep_temp_alive = temp;

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"old");
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(receipt.format_version(), 1);
    assert_eq!(receipt.package_identity(), None);
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn legacy_migration_recovery_finishes_current_unsigned_identity() {
    let (temp, install_base, state_root, package_id, installed, paths) =
        interrupted_legacy_upgrade(true);
    let _keep_temp_alive = temp;

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"new");
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    assert_eq!(receipt.format_version(), RECEIPT_FORMAT_VERSION);
    assert_eq!(receipt.package_identity(), Some(PackageIdentity::Unsigned));
    assert_eq!(receipt.payload_signer(), Some(PackageIdentity::Unsigned));
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn committed_upgrade_recovery_preserves_backups_when_new_payload_is_corrupt() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(true);
    let _keep_temp_alive = temp;
    fs::write(&installed, b"corrupt").unwrap();
    let backup = removed_file(&paths, &PackagePath::parse("app.bin").unwrap());

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("committed cleanup must prove the complete new payload");
    assert_eq!(fs::read(backup).unwrap(), b"old");
    assert!(paths.receipt_previous.exists());
    assert!(paths.journal.exists());
    assert!(paths.state_dir.exists());
    assert!(paths.destination_dir.exists());
}

#[test]
fn upgrade_recovery_preserves_a_foreign_pending_receipt() {
    let (temp, install_base, state_root, package_id, _installed, paths) =
        interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    fs::write(&paths.receipt_pending, b"foreign").unwrap();

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("an unbound pending receipt must be preserved");
    assert_eq!(fs::read(&paths.receipt_pending).unwrap(), b"foreign");
    assert!(paths.receipt_previous.exists());
    assert!(paths.journal.exists());
    assert!(paths.destination_dir.exists());
}

#[test]
fn upgrade_recovery_rejects_a_tampered_header_directory_before_file_mutation() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    let journal = fs::read_to_string(&paths.journal).unwrap().replacen(
        "\"directory\":\"LuxuryDemo\"",
        "\"directory\":\"OtherDemo\"",
        1,
    );
    fs::write(&paths.journal, journal).unwrap();
    let backup = removed_file(&paths, &PackagePath::parse("app.bin").unwrap());

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("receipt semantics must bind the journal directory");
    assert_eq!(fs::read(installed).unwrap(), b"new");
    assert_eq!(fs::read(backup).unwrap(), b"old");
    assert!(!install_base.join("OtherDemo").exists());
    assert!(paths.receipt_previous.exists());
    assert!(paths.receipt_pending.exists());
}

#[test]
fn upgrade_recovery_rejects_case_aliases_between_wal_records() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    let journal = fs::read_to_string(&paths.journal).unwrap().replacen(
        "\"kind\":\"restore_file\",\"path\":\"app.bin\"",
        "\"kind\":\"restore_file\",\"path\":\"App.bin\"",
        1,
    );
    fs::write(&paths.journal, &journal).unwrap();
    let backup = removed_file(&paths, &PackagePath::parse("app.bin").unwrap());

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("WAL aliases must fail before rollback mutation");
    assert!(error.to_string().contains("normalization aliases"));
    assert_eq!(fs::read(installed).unwrap(), b"new");
    assert_eq!(fs::read(backup).unwrap(), b"old");
    assert_eq!(fs::read_to_string(&paths.journal).unwrap(), journal);
}

#[cfg(unix)]
#[test]
fn upgrade_rollback_rejects_a_changed_backup_mode() {
    use std::os::unix::fs::PermissionsExt;

    let (temp, install_base, state_root, package_id, _installed, paths) =
        interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    let backup = removed_file(&paths, &PackagePath::parse("app.bin").unwrap());
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o755)).unwrap();

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("rollback must not accept a backup with changed mode");
    assert!(backup.exists());
    assert!(paths.receipt_previous.exists());
    assert!(paths.journal.exists());
}

#[test]
fn upgrade_recovery_rejects_file_mutation_after_pending_receipt_marker() {
    let (temp, install_base, state_root, package_id, _installed, paths) =
        interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    let source = fs::read_to_string(&paths.journal).unwrap();
    let mut lines = source.lines().map(str::to_owned).collect::<Vec<_>>();
    let mutation = serde_json::to_string(&JournalRecord::StageFile {
        path: PackagePath::parse("late.bin").unwrap(),
        sha256: digest(b"late"),
    })
    .unwrap();
    lines.insert(lines.len() - 1, mutation);
    fs::write(&paths.journal, format!("{}\n", lines.join("\n"))).unwrap();

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("receipt marker must freeze the file journal");
    assert!(error.to_string().contains("after staging its receipt"));
    assert!(paths.journal.exists());
    assert!(paths.receipt_previous.exists());
    assert!(paths.destination_dir.exists());
}

#[test]
fn upgrade_rollback_rejects_a_modified_legacy_hard_link_pair() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    append_journal_record(&paths.journal, &JournalRecord::RollingBack);
    let backup = removed_file(&paths, &PackagePath::parse("app.bin").unwrap());
    fs::remove_file(&installed).unwrap();
    fs::hard_link(&backup, &installed).unwrap();
    fs::write(&installed, b"changed").unwrap();

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("a changed legacy hard-link pair must be preserved");
    assert_eq!(fs::read(&installed).unwrap(), b"changed");
    assert_eq!(fs::read(&backup).unwrap(), b"changed");
    assert!(paths.journal.exists());
    assert!(paths.destination_dir.exists());
}

#[test]
fn upgrade_rollback_prevalidation_preserves_new_files_when_backup_is_invalid() {
    for corrupt in [false, true] {
        let (temp, install_base, state_root, package_id, installed, paths) =
            interrupted_upgrade(false);
        let _keep_temp_alive = temp;
        append_journal_record(&paths.journal, &JournalRecord::RollingBack);
        let backup = removed_file(&paths, &PackagePath::parse("app.bin").unwrap());
        if corrupt {
            fs::write(&backup, b"corrupt").unwrap();
        } else {
            fs::remove_file(&backup).unwrap();
        }
        let journal = fs::read(&paths.journal).unwrap();

        LocalUninstallAdapter::new(&install_base, &state_root)
            .recover_pending(&package_id)
            .expect_err("rollback must prove every backup before deleting new files");
        assert_eq!(fs::read(&installed).unwrap(), b"new");
        assert_eq!(fs::read(&paths.journal).unwrap(), journal);
        assert!(paths.receipt_previous.exists());
        assert!(paths.receipt_pending.exists());
        assert!(paths.destination_dir.exists());
    }
}

#[cfg(windows)]
#[test]
fn upgrade_rollback_prevalidation_preserves_new_file_when_backup_is_unsyncable() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};

    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    append_journal_record(&paths.journal, &JournalRecord::RollingBack);
    let backup = removed_file(&paths, &PackagePath::parse("app.bin").unwrap());
    let reader = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(&backup)
        .unwrap();
    let journal = fs::read(&paths.journal).unwrap();

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("rollback must prove backup durability before deleting the new file");

    assert_eq!(fs::read(installed).unwrap(), b"new");
    assert_eq!(fs::read(backup).unwrap(), b"old");
    assert_eq!(fs::read(&paths.journal).unwrap(), journal);
    assert!(paths.receipt_previous.exists());
    assert!(paths.receipt_pending.exists());
    drop(reader);
}

#[test]
fn upgrade_rollback_accepts_an_exact_legacy_hard_link_pair() {
    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    append_journal_record(&paths.journal, &JournalRecord::RollingBack);
    let backup = removed_file(&paths, &PackagePath::parse("app.bin").unwrap());
    fs::remove_file(&installed).unwrap();
    fs::hard_link(&backup, &installed).unwrap();

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"old");
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[cfg(unix)]
#[test]
fn upgrade_rollback_defers_same_bytes_legacy_pair_to_restore_mode() {
    use std::os::unix::fs::PermissionsExt;

    let (temp, install_base, state_root, package_id, installed, paths) = interrupted_upgrade(false);
    let _keep_temp_alive = temp;
    let old_sha256 = digest(b"old").to_string();
    let new_sha256 = digest(b"new").to_string();
    let journal = fs::read_to_string(&paths.journal)
        .unwrap()
        .replace(&new_sha256, &old_sha256)
        .replacen("\"executable\":false", "\"executable\":true", 1);
    fs::write(&paths.journal, journal).unwrap();
    let backup = removed_file(&paths, &PackagePath::parse("app.bin").unwrap());
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(&installed).unwrap();
    fs::hard_link(&backup, &installed).unwrap();
    append_journal_record(&paths.journal, &JournalRecord::RollingBack);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(&installed).unwrap(), b"old");
    assert_ne!(
        fs::metadata(installed).unwrap().permissions().mode() & 0o111,
        0
    );
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn install_recovery_keeps_pending_receipt_until_published_copy_is_valid() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let directory = manifest.install.directory.clone();
    let installed = install_base.join(directory.as_str()).join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let transaction = begin_transaction(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
    )
    .unwrap();
    let paths = transaction.paths.clone();
    fs::copy(&paths.receipt, &paths.receipt_pending).unwrap();
    let pending = fs::read(&paths.receipt_pending).unwrap();
    fs::write(&paths.receipt, b"{broken").unwrap();
    drop(transaction);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("a corrupt published receipt must keep the recovery copy");

    assert_eq!(fs::read(&paths.receipt_pending).unwrap(), pending);
    assert_eq!(fs::read(installed).unwrap(), b"owned");
    assert!(paths.state_dir.exists());
    assert!(paths.destination_dir.exists());
}

#[test]
fn install_recovery_accepts_the_original_pending_receipt_hard_link() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let directory = manifest.install.directory.clone();
    let installed = install_base.join(directory.as_str()).join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let transaction = begin_transaction(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
    )
    .unwrap();
    let paths = transaction.paths.clone();
    fs::hard_link(&paths.receipt, &paths.receipt_pending).unwrap();
    drop(transaction);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"owned");
    assert!(paths.receipt.exists());
    assert!(!paths.receipt_pending.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn install_recovery_preserves_an_unowned_pending_receipt() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    let transaction = begin_transaction(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
    )
    .unwrap();
    let paths = transaction.paths.clone();
    fs::write(&paths.receipt_pending, b"foreign").unwrap();
    drop(transaction);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("recovery must not delete an unbound pending receipt");

    assert_eq!(fs::read(&paths.receipt_pending).unwrap(), b"foreign");
    assert!(paths.journal.exists());
    assert!(paths.state_dir.exists());
}

#[test]
fn uninstall_recovery_validates_receipt_before_restoring_files() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let paths = interrupted.active.as_ref().unwrap().paths.clone();
    let backup = paths.destination_dir.join("removed").join("app.bin");
    let stored_receipt = fs::read(&paths.receipt).unwrap();
    fs::write(&paths.receipt, b"{broken").unwrap();
    drop(interrupted);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("uninstall recovery must validate its receipt before rollback");
    assert!(!installed.exists());
    assert_eq!(fs::read(&backup).unwrap(), b"owned");
    assert!(paths.state_dir.exists());

    fs::write(&paths.receipt, stored_receipt).unwrap();
    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"owned");
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[cfg(windows)]
#[test]
fn uninstall_recovery_accepts_a_legacy_file_hard_link_pair() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let paths = interrupted.active.as_ref().unwrap().paths.clone();
    let backup = paths.destination_dir.join("removed").join("app.bin");
    fs::hard_link(&backup, &installed).unwrap();
    drop(interrupted);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();

    assert_eq!(fs::read(installed).unwrap(), b"owned");
    assert!(!backup.exists());
    assert!(paths.receipt.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[cfg(windows)]
#[test]
fn uninstall_move_preflight_preserves_unsyncable_windows_sources() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};

    for readonly in [true, false] {
        let temp = tempdir().unwrap();
        let install_base = temp.path().join("install");
        let state_root = temp.path().join("state");
        let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
        let package_id = manifest.package.id.clone();
        let installed = install_base
            .join(manifest.install.directory.as_str())
            .join("app.bin");

        install(
            InstallCommand::new(manifest),
            &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
            || false,
            |_| {},
        )
        .unwrap();
        let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
        let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
        interrupted.begin(&receipt).unwrap();
        let paths = interrupted.active.as_ref().unwrap().paths.clone();
        let backup = paths.destination_dir.join("removed").join("app.bin");
        let original_permissions = fs::metadata(&installed).unwrap().permissions();
        let reader = if readonly {
            let mut permissions = original_permissions.clone();
            permissions.set_readonly(true);
            fs::set_permissions(&installed, permissions).unwrap();
            None
        } else {
            Some(
                OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
                    .open(&installed)
                    .unwrap(),
            )
        };

        interrupted
            .remove_if_unchanged(&receipt, &receipt.files()[0])
            .expect_err("an unsyncable source must fail before the move intent");

        assert_eq!(fs::read(&installed).unwrap(), b"owned");
        assert!(!backup.exists());
        assert_eq!(interrupted.active.as_ref().unwrap().records.len(), 1);
        assert_eq!(
            fs::metadata(&installed).unwrap().permissions().readonly(),
            readonly
        );
        interrupted.rollback().unwrap();
        assert!(!paths.state_dir.exists());
        assert!(!paths.destination_dir.exists());

        drop(reader);
        if readonly {
            fs::set_permissions(&installed, original_permissions).unwrap();
        }
    }
}

#[test]
fn recovery_preserves_unbound_destination_with_a_torn_first_header() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    let transaction = begin_transaction(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
    )
    .unwrap();
    let paths = transaction.paths.clone();
    drop(transaction);

    let mut journal = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&paths.journal)
        .unwrap();
    journal.write_all(br#"{"kind":"header"#).unwrap();
    journal.sync_all().unwrap();
    drop(journal);

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("a destination without a readable root binding must be preserved");
    assert!(error.to_string().contains("torn unbound journal"));
    assert!(paths.journal.exists());
    assert!(paths.state_dir.exists());
    assert!(paths.destination_dir.exists());
    assert!(install_base.is_dir());
    assert!(state_root.is_dir());
}

#[test]
fn recovery_rejects_a_terminated_malformed_journal_record() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    let transaction = begin_transaction(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Install,
    )
    .unwrap();
    let paths = transaction.paths.clone();
    drop(transaction);

    let mut journal = OpenOptions::new()
        .append(true)
        .open(&paths.journal)
        .unwrap();
    journal.write_all(b"{not-json}\n").unwrap();
    journal.sync_all().unwrap();
    drop(journal);

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap_err();
    assert!(error.to_string().contains("parsing transaction journal"));
    assert!(paths.journal.exists());
}

#[test]
fn destination_lock_serializes_packages_without_blocking_other_directories() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let shared = InstallDirectory::parse("Shared").unwrap();
    let independent = InstallDirectory::parse("Independent").unwrap();
    let alpha = PackageId::parse("dev.luxury.alpha").unwrap();
    let beta = PackageId::parse("dev.luxury.beta").unwrap();
    let gamma = PackageId::parse("dev.luxury.gamma").unwrap();

    let first = begin_transaction(
        &install_base,
        &state_root,
        &alpha,
        &shared,
        Operation::Install,
    )
    .unwrap();
    let error = begin_transaction(
        &install_base,
        &state_root,
        &beta,
        &shared,
        Operation::Install,
    )
    .err()
    .expect("second package must not enter the same destination");
    assert_eq!(error.kind(), PortErrorKind::Busy);

    let other = begin_transaction(
        &install_base,
        &state_root,
        &gamma,
        &independent,
        Operation::Install,
    )
    .unwrap();
    drop(other);
    drop(first);
}

#[test]
fn recovery_rejects_committing_uninstall_without_a_tombstone() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("bin/app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let install_root = install_base.join(manifest.install.directory.as_str());
    let installed = install_root.join("bin/app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    adapter.recover_pending(&package_id).unwrap();
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    adapter.begin(&receipt).unwrap();
    for file in receipt.files() {
        adapter.remove_if_unchanged(&receipt, file).unwrap();
    }
    let mut transaction = adapter.active.take().unwrap();
    transaction.append(JournalRecord::Committing).unwrap();
    let paths = transaction.paths.clone();
    let backup = paths.destination_dir.join("removed/bin/app.bin");
    fs::remove_file(&paths.receipt).unwrap();
    drop(transaction);

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("a journal marker alone cannot prove receipt removal committed");
    assert!(error.to_string().contains("both receipt links are missing"));
    assert!(!installed.exists());
    assert_eq!(fs::read(backup).unwrap(), b"owned");
    assert!(!paths.receipt.exists());
    assert!(!paths.receipt_deleted.exists());
    assert!(paths.state_dir.exists());
    assert!(paths.destination_dir.exists());
    assert!(install_root.exists());
}

#[test]
fn committed_uninstall_validates_tombstone_hash_before_cleanup() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let directory = manifest.install.directory.clone();
    let installed = install_base.join(directory.as_str()).join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let transaction = interrupted.active.as_mut().unwrap();
    transaction.append(JournalRecord::Committing).unwrap();
    let paths = transaction.paths.clone();
    let receipt_bytes = fs::read(&paths.receipt).unwrap();
    super::rename_noreplace(&paths.receipt, &paths.receipt_deleted)
        .unwrap()
        .sync()
        .unwrap();
    let forged = OwnershipReceipt::new(
        package_id.clone(),
        Version::new(9, 0, 0),
        InstallScope::User,
        directory,
        PackageIdentity::Unsigned,
        receipt.files().to_vec(),
    )
    .unwrap();
    write_stored_receipt(&paths.receipt_deleted, &install_base, &forged);
    let backup = paths.destination_dir.join("removed/app.bin");
    drop(interrupted);

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("tombstone hash must be checked before deleting rollback data");
    assert!(error.to_string().contains("transaction binding"));
    assert!(!installed.exists());
    assert_eq!(fs::read(&backup).unwrap(), b"owned");
    assert!(paths.journal.exists());
    assert!(paths.receipt_deleted.exists());
    assert!(paths.destination_dir.exists());

    fs::write(&paths.receipt_deleted, receipt_bytes).unwrap();
    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert!(!backup.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn committed_uninstall_rejects_unexpected_backup_before_cleanup() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let transaction = interrupted.active.as_mut().unwrap();
    transaction.append(JournalRecord::Committing).unwrap();
    let paths = transaction.paths.clone();
    super::rename_noreplace(&paths.receipt, &paths.receipt_deleted)
        .unwrap()
        .sync()
        .unwrap();
    let backup = paths.destination_dir.join("removed/app.bin");
    fs::write(paths.destination_dir.join("foreign"), b"foreign").unwrap();
    drop(interrupted);

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("unexpected backup state must fail before deleting owned rollback data");
    assert!(error.to_string().contains("unexpected entry"));
    assert_eq!(fs::read(backup).unwrap(), b"owned");
    assert!(paths.journal.exists());
    assert!(paths.receipt_deleted.exists());
}

#[test]
fn uninstall_cutover_without_committing_preserves_rollback_data() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let directory = manifest.install.directory.clone();
    let installed = install_base.join(directory.as_str()).join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let paths = interrupted.active.as_ref().unwrap().paths.clone();
    super::rename_noreplace(&paths.receipt, &paths.receipt_deleted)
        .unwrap()
        .sync()
        .unwrap();
    let backup = paths.destination_dir.join("removed/app.bin");
    drop(interrupted);

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("receipt cutover without final WAL marker must fail before cleanup");
    assert!(error.to_string().contains("final journal marker"));
    assert!(!installed.exists());
    assert_eq!(fs::read(&backup).unwrap(), b"owned");
    assert!(paths.journal.exists());
    assert!(paths.receipt_deleted.exists());

    super::rename_noreplace(&paths.receipt_deleted, &paths.receipt)
        .unwrap()
        .sync()
        .unwrap();
    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"owned");
}

#[test]
fn uninstall_journal_foreign_restore_is_rejected_before_rollback() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let transaction = interrupted.active.as_mut().unwrap();
    transaction
        .append(JournalRecord::RestoreFile {
            path: PackagePath::parse("foreign.bin").unwrap(),
            sha256: digest(b"foreign"),
            executable: false,
        })
        .unwrap();
    let paths = transaction.paths.clone();
    let backup = paths.destination_dir.join("removed/app.bin");
    drop(interrupted);

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("foreign restore intent must not mutate rollback state");
    assert!(error.to_string().contains("not owned by its receipt"));
    assert_eq!(fs::read(backup).unwrap(), b"owned");
    assert!(paths.journal.exists());
    assert!(paths.destination_dir.exists());
}

#[cfg(unix)]
#[test]
fn uninstall_rollback_rejects_equal_bytes_with_conflicting_modes() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let paths = interrupted.active.as_ref().unwrap().paths.clone();
    let backup = paths.destination_dir.join("removed/app.bin");
    fs::write(&installed, b"owned").unwrap();
    fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
    drop(interrupted);

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("same bytes with conflicting modes must remain ambiguous");
    assert!(error.to_string().contains("conflicting copies"));
    assert_eq!(fs::read(&installed).unwrap(), b"owned");
    assert_eq!(fs::read(&backup).unwrap(), b"owned");
    assert!(paths.journal.exists());
}

#[test]
fn recovery_finishes_cleanup_after_journal_deletion() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let transaction = interrupted.active.as_mut().unwrap();
    transaction.append(JournalRecord::Committing).unwrap();
    let paths = transaction.paths.clone();
    super::rename_noreplace(&paths.receipt, &paths.receipt_deleted)
        .unwrap()
        .sync()
        .unwrap();
    let backup = paths.destination_dir.join("removed/app.bin");
    fs::remove_file(&backup).unwrap();
    fs::remove_dir(backup.parent().unwrap()).unwrap();
    fs::remove_dir(&paths.destination_dir).unwrap();
    fs::remove_file(&paths.journal).unwrap();
    drop(interrupted);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert!(!installed.exists());
    assert!(!paths.receipt.exists());
    assert!(!paths.receipt_deleted.exists());
    assert!(!paths.state_dir.exists());
}

#[test]
fn recovery_finishes_committed_uninstall_from_cleanup_marker() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let transaction = interrupted.active.as_mut().unwrap();
    transaction.append(JournalRecord::Committing).unwrap();
    let paths = transaction.paths.clone();
    super::rename_noreplace(&paths.receipt, &paths.receipt_deleted)
        .unwrap()
        .sync()
        .unwrap();
    let backup = paths.destination_dir.join("removed/app.bin");
    fs::remove_file(&backup).unwrap();
    fs::remove_dir(backup.parent().unwrap()).unwrap();
    fs::remove_dir(&paths.destination_dir).unwrap();
    super::rename_noreplace(&paths.journal, &paths.journal_done)
        .unwrap()
        .sync()
        .unwrap();
    fs::remove_file(&paths.receipt_deleted).unwrap();
    drop(interrupted);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();

    assert!(!installed.exists());
    assert!(!paths.receipt.exists());
    assert!(!paths.receipt_deleted.exists());
    assert!(!paths.journal_done.exists());
    assert!(!paths.state_dir.exists());
}

#[test]
fn recovery_finishes_cleanup_marker_with_its_tombstone() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    let receipt = OwnershipReceipt::new(
        package_id.clone(),
        Version::new(1, 0, 0),
        InstallScope::User,
        directory.clone(),
        PackageIdentity::Unsigned,
        vec![FileEntry {
            path: PackagePath::parse("app.bin").unwrap(),
            size: 5,
            sha256: digest(b"owned"),
            executable: false,
        }],
    )
    .unwrap();
    ensure_directory(&install_base, None).unwrap();
    ensure_directory(&state_root.join("receipts"), Some(InstallScope::User)).unwrap();
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    write_stored_receipt(&paths.receipt, &install_base, &receipt);
    let mut transaction =
        begin_bound_uninstall_transaction(&install_base, &state_root, &package_id, &directory);
    transaction.append(JournalRecord::Committing).unwrap();
    super::rename_noreplace(&paths.receipt, &paths.receipt_deleted)
        .unwrap()
        .sync()
        .unwrap();
    fs::remove_dir(&paths.destination_dir).unwrap();
    super::rename_noreplace(&paths.journal, &paths.journal_done)
        .unwrap()
        .sync()
        .unwrap();
    drop(transaction);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();

    assert!(!paths.receipt_deleted.exists());
    assert!(!paths.journal_done.exists());
    assert!(!paths.state_dir.exists());
}

#[test]
fn recovery_rejects_cleanup_marker_with_a_live_receipt() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let directory = manifest.install.directory.clone();

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut transaction =
        begin_bound_uninstall_transaction(&install_base, &state_root, &package_id, &directory);
    transaction.append(JournalRecord::Committing).unwrap();
    let paths = transaction.paths.clone();
    fs::remove_dir(&paths.destination_dir).unwrap();
    super::rename_noreplace(&paths.journal, &paths.journal_done)
        .unwrap()
        .sync()
        .unwrap();
    drop(transaction);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("a cleanup marker cannot override a live receipt");

    assert!(paths.receipt.exists());
    assert!(paths.journal_done.exists());
    assert!(paths.state_dir.exists());
}

#[test]
fn recovery_rejects_active_journal_and_cleanup_marker_collision() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    ensure_directory(&install_base, None).unwrap();
    ensure_directory(&state_root.join("receipts"), Some(InstallScope::User)).unwrap();
    let receipt = OwnershipReceipt::new(
        package_id.clone(),
        Version::new(1, 0, 0),
        InstallScope::User,
        directory.clone(),
        PackageIdentity::Unsigned,
        vec![FileEntry {
            path: PackagePath::parse("app.bin").unwrap(),
            size: 5,
            sha256: digest(b"owned"),
            executable: false,
        }],
    )
    .unwrap();
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    write_stored_receipt(&paths.receipt, &install_base, &receipt);
    let transaction =
        begin_bound_uninstall_transaction(&install_base, &state_root, &package_id, &directory);
    fs::copy(&paths.journal, &paths.journal_done).unwrap();
    drop(transaction);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("an active journal and cleanup marker must fail closed");

    assert!(paths.journal.exists());
    assert!(paths.journal_done.exists());
    assert!(paths.destination_dir.exists());
}

#[test]
fn uninstall_recovery_accepts_the_preunlink_receipt_hard_link_pair() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let transaction = interrupted.active.as_mut().unwrap();
    transaction.append(JournalRecord::Committing).unwrap();
    let paths = transaction.paths.clone();
    fs::hard_link(&paths.receipt, &paths.receipt_deleted).unwrap();
    drop(interrupted);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"owned");
    assert!(paths.receipt.exists());
    assert!(!paths.receipt_deleted.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn uninstall_recovery_finishes_orphan_tombstone_hard_link_cleanup() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    ensure_directory(&paths.state_dir, Some(InstallScope::User)).unwrap();
    fs::hard_link(&paths.receipt, &paths.receipt_deleted).unwrap();

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"owned");
    assert!(paths.receipt.exists());
    assert!(!paths.receipt_deleted.exists());
    assert!(!paths.state_dir.exists());
}

#[test]
fn uninstall_rollback_preserves_an_unowned_tombstone() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    adapter.begin(&receipt).unwrap();
    adapter
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let paths = adapter.active.as_ref().unwrap().paths.clone();
    fs::write(&paths.receipt_deleted, b"foreign").unwrap();

    adapter
        .commit()
        .expect_err("an existing tombstone must block commit");
    adapter
        .rollback()
        .expect_err("rollback must preserve an unbound tombstone");

    assert_eq!(fs::read(installed).unwrap(), b"owned");
    assert_eq!(fs::read(&paths.receipt_deleted).unwrap(), b"foreign");
    assert!(paths.receipt.exists());
    assert!(paths.journal.exists());
}

#[test]
fn uninstall_recovery_rejects_a_recreated_live_receipt() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let transaction = interrupted.active.as_mut().unwrap();
    transaction.append(JournalRecord::Committing).unwrap();
    let paths = transaction.paths.clone();
    super::rename_noreplace(&paths.receipt, &paths.receipt_deleted)
        .unwrap()
        .sync()
        .unwrap();
    fs::copy(&paths.receipt_deleted, &paths.receipt).unwrap();
    let backup = paths.destination_dir.join("removed/app.bin");
    drop(interrupted);

    let error = LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("a recreated receipt must not reverse a committed uninstall");
    assert!(
        error
            .to_string()
            .contains("does not match its uninstall tombstone")
    );
    assert!(!installed.exists());
    assert_eq!(fs::read(&backup).unwrap(), b"owned");
    assert!(paths.receipt.exists());
    assert!(paths.receipt_deleted.exists());

    fs::remove_file(&paths.receipt).unwrap();
    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert!(!installed.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn journal_replay_against_other_install_base_is_rejected_without_mutation() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let other_base = temp.path().join("other");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let directory = manifest.install.directory.clone();
    let installed = install_base.join(directory.as_str()).join("app.bin");
    let unrelated = other_base.join(directory.as_str()).join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
    fs::write(&unrelated, b"owned").unwrap();

    let mut interrupted = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = interrupted.load_receipt(&package_id).unwrap().unwrap();
    interrupted.begin(&receipt).unwrap();
    interrupted
        .remove_if_unchanged(&receipt, &receipt.files()[0])
        .unwrap();
    let paths = interrupted.active.as_ref().unwrap().paths.clone();
    drop(interrupted);

    let error = LocalUninstallAdapter::new(&other_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("a journal must not replay against another install base");
    assert!(error.to_string().contains("different install base"));
    assert!(!installed.exists());
    assert_eq!(fs::read(&unrelated).unwrap(), b"owned");
    assert!(paths.state_dir.exists());
    assert!(paths.destination_dir.exists());

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(installed).unwrap(), b"owned");
    assert_eq!(fs::read(unrelated).unwrap(), b"owned");
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[test]
fn rename_noreplace_preserves_source_and_existing_backup() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("source");
    let backup = temp.path().join("backup");
    fs::write(&source, b"source").unwrap();
    fs::write(&backup, b"backup").unwrap();

    super::rename_noreplace(&source, &backup)
        .expect_err("existing transaction backup must not be replaced");

    assert_eq!(fs::read(source).unwrap(), b"source");
    assert_eq!(fs::read(backup).unwrap(), b"backup");
}

#[test]
fn restore_guard_rejects_a_replaced_backup_path() {
    let temp = tempdir().unwrap();
    let backup = temp.path().join("backup.bin");
    let displaced = temp.path().join("displaced.bin");
    let destination = temp.path().join("destination.bin");
    fs::write(&backup, b"owned").unwrap();
    let source = sync_movable_regular_snapshot(&backup, false).unwrap();
    fs::rename(&backup, &displaced).unwrap();
    fs::write(&backup, b"owned").unwrap();

    super::restore_moved_file(&backup, &destination, false, source)
        .expect_err("restore must stay bound to the already validated backup object");

    assert_eq!(fs::read(displaced).unwrap(), b"owned");
    assert_eq!(fs::read(destination).unwrap(), b"owned");
    assert!(!backup.exists());
}

#[test]
fn recovery_restores_the_exact_entry_moved_after_precheck() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    let path = PackagePath::parse("app.bin").unwrap();
    let owned = b"owned";
    let replacement = b"replacement";
    let destination = install_base.join(directory.as_str()).join("app.bin");
    ensure_directory(destination.parent().unwrap(), None).unwrap();
    fs::write(&destination, owned).unwrap();
    let receipt = OwnershipReceipt::new(
        package_id.clone(),
        Version::new(1, 0, 0),
        InstallScope::User,
        directory.clone(),
        PackageIdentity::Unsigned,
        vec![FileEntry {
            path: path.clone(),
            size: owned.len() as u64,
            sha256: digest(owned),
            executable: false,
        }],
    )
    .unwrap();
    ensure_directory(&state_root.join("receipts"), Some(InstallScope::User)).unwrap();
    let receipt_path = transaction_paths(&install_base, &state_root, &package_id).receipt;
    write_stored_receipt(&receipt_path, &install_base, &receipt);
    let mut transaction =
        begin_bound_uninstall_transaction(&install_base, &state_root, &package_id, &directory);
    transaction
        .append(JournalRecord::RestoreFile {
            path: path.clone(),
            sha256: digest(owned),
            executable: false,
        })
        .unwrap();

    fs::remove_file(&destination).unwrap();
    fs::write(&destination, replacement).unwrap();
    let backup = transaction
        .paths
        .destination_dir
        .join("removed")
        .join(path.to_native_path());
    ensure_directory(backup.parent().unwrap(), Some(InstallScope::User)).unwrap();
    fs::rename(&destination, &backup).unwrap();
    let paths = transaction.paths.clone();
    drop(transaction);

    LocalUninstallAdapter::new(&install_base, &state_root)
        .recover_pending(&package_id)
        .unwrap();
    assert_eq!(fs::read(destination).unwrap(), replacement);
    assert!(!backup.exists());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn recovery_preserves_wrong_base_tombstone_without_a_journal() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let other_base = temp.path().join("other");
    let state_root = temp.path().join("state");
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let directory = InstallDirectory::parse("LuxuryDemo").unwrap();
    fs::create_dir_all(&install_base).unwrap();
    fs::create_dir_all(&other_base).unwrap();
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    ensure_directory(&paths.state_dir, Some(InstallScope::User)).unwrap();
    let receipt = OwnershipReceipt::new(
        package_id.clone(),
        Version::new(1, 0, 0),
        InstallScope::User,
        directory,
        PackageIdentity::Unsigned,
        vec![FileEntry {
            path: PackagePath::parse("app.bin").unwrap(),
            size: 5,
            sha256: digest(b"owned"),
            executable: false,
        }],
    )
    .unwrap();
    write_stored_receipt(&paths.receipt_deleted, &install_base, &receipt);

    let error = LocalUninstallAdapter::new(&other_base, &state_root)
        .recover_pending(&package_id)
        .expect_err("a wrong-base tombstone must never authorize cleanup");
    assert!(error.to_string().contains("different install base"));
    assert!(paths.receipt_deleted.exists());
    assert!(paths.state_dir.exists());
    assert!(other_base.is_dir());
}

#[test]
fn tampered_receipt_is_rejected_before_mutation() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let receipt = transaction_paths(&install_base, &state_root, &package_id).receipt;
    let source = fs::read_to_string(&receipt).unwrap();
    fs::write(&receipt, source.replace("app.bin", "../escape")).unwrap();

    let error = uninstall(
        UninstallCommand::new(package_id),
        &mut LocalUninstallAdapter::new(&install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(error, UninstallError::Port { .. }));
    assert_eq!(fs::read(installed).unwrap(), b"owned");
}

#[test]
fn uninstall_rechecks_receipt_while_transaction_locks_are_held() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let stale = adapter.load_receipt(&package_id).unwrap().unwrap();
    let replacement = OwnershipReceipt::new(
        package_id.clone(),
        Version::new(2, 0, 0),
        stale.scope(),
        stale.directory().clone(),
        stale.package_identity().unwrap(),
        stale.files().to_vec(),
    )
    .unwrap();
    let paths = transaction_paths(&install_base, &state_root, &package_id);
    write_stored_receipt(&paths.receipt, &install_base, &replacement);

    let error = adapter
        .begin(&stale)
        .expect_err("a stale receipt must be rejected");
    assert_eq!(error.kind(), PortErrorKind::State);
    assert!(adapter.active.is_none());
    assert!(!paths.state_dir.exists());
    assert!(!paths.destination_dir.exists());
}

#[test]
fn active_uninstall_is_bound_to_the_locked_receipt() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    let mut adapter = LocalUninstallAdapter::new(&install_base, &state_root);
    let receipt = adapter.load_receipt(&package_id).unwrap().unwrap();
    adapter.begin(&receipt).unwrap();
    let substituted = OwnershipReceipt::new(
        package_id,
        Version::new(2, 0, 0),
        receipt.scope(),
        receipt.directory().clone(),
        receipt.package_identity().unwrap(),
        receipt.files().to_vec(),
    )
    .unwrap();

    let error = adapter
        .remove_if_unchanged(&substituted, &substituted.files()[0])
        .expect_err("the active receipt cannot be substituted");
    assert_eq!(error.kind(), PortErrorKind::State);
    assert_eq!(fs::read(&installed).unwrap(), b"owned");
    adapter.rollback().unwrap();
}

#[test]
fn state_root_inside_install_tree_is_rejected() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let install_root = install_base.join(manifest.install.directory.as_str());
    let state_root = install_root.join("state");

    let error = install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(
        error,
        InstallError::Port {
            step: "preflight",
            ..
        }
    ));
    assert!(!install_root.exists());
}

#[test]
fn destination_link_is_rejected_without_touching_target() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let external = temp.path().join("external");
    fs::create_dir_all(&external).unwrap();
    fs::write(external.join("sentinel"), b"keep").unwrap();
    let (bundle, manifest) = bundle(&[("bin/app", b"owned")]);
    let install_root = install_base.join(manifest.install.directory.as_str());
    fs::create_dir_all(&install_root).unwrap();
    let link = create_directory_link(&install_root.join("bin"), &external);
    #[cfg(windows)]
    if link
        .as_ref()
        .is_err_and(|error| error.raw_os_error() == Some(1314))
    {
        return;
    }
    link.unwrap();

    let error = install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(
        error,
        InstallError::Port {
            step: "preflight",
            ..
        }
    ));
    assert_eq!(fs::read(external.join("sentinel")).unwrap(), b"keep");
    assert!(!external.join("app").exists());
}

#[test]
fn hard_linked_owned_file_is_rejected_without_removing_either_name() {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"owned")]);
    let package_id = manifest.package.id.clone();
    let installed = install_base
        .join(manifest.install.directory.as_str())
        .join("app.bin");
    let alias = temp.path().join("alias.bin");

    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    fs::hard_link(&installed, &alias).unwrap();

    let error = uninstall(
        UninstallCommand::new(package_id.clone()),
        &mut LocalUninstallAdapter::new(&install_base, &state_root),
        || false,
        |_| {},
    )
    .expect_err("hard-linked owned files must fail closed");
    assert!(matches!(
        error,
        UninstallError::Port {
            step: "remove owned file",
            ..
        }
    ));
    assert_eq!(fs::read(&installed).unwrap(), b"owned");
    assert_eq!(fs::read(&alias).unwrap(), b"owned");
    assert!(
        transaction_paths(&install_base, &state_root, &package_id)
            .receipt
            .exists()
    );
}

#[cfg(any(unix, windows))]
#[test]
fn final_file_symlinks_are_rejected_by_shared_opener() {
    let temp = tempdir().unwrap();
    let target = temp.path().join("target");
    let link = temp.path().join("link");
    fs::write(&target, b"keep").unwrap();
    if let Err(error) = create_file_link(&link, &target) {
        #[cfg(windows)]
        if error.raw_os_error() == Some(1314) {
            return;
        }
        panic!("creating file symlink failed: {error}");
    }

    assert!(open_regular(&link, 16).is_err());
    assert!(hash_regular(&link).is_err());
    assert!(same_file(&link, &target).is_err());
    assert_eq!(fs::read(target).unwrap(), b"keep");
}

fn interrupted_upgrade(
    publish_receipt: bool,
) -> (
    TempDir,
    PathBuf,
    PathBuf,
    PackageId,
    PathBuf,
    super::transaction::TransactionPaths,
) {
    interrupted_upgrade_with_legacy(publish_receipt, false)
}

fn interrupted_legacy_upgrade(
    publish_receipt: bool,
) -> (
    TempDir,
    PathBuf,
    PathBuf,
    PackageId,
    PathBuf,
    super::transaction::TransactionPaths,
) {
    interrupted_upgrade_with_legacy(publish_receipt, true)
}

fn interrupted_upgrade_with_legacy(
    publish_receipt: bool,
    legacy: bool,
) -> (
    TempDir,
    PathBuf,
    PathBuf,
    PackageId,
    PathBuf,
    super::transaction::TransactionPaths,
) {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle_version(Version::new(1, 0, 0), &[("app.bin", b"old")]);
    let package_id = manifest.package.id.clone();
    let directory = manifest.install.directory.clone();
    let installed = install_base.join(directory.as_str()).join("app.bin");
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();

    let receipt_path = transaction_paths(&install_base, &state_root, &package_id).receipt;
    if legacy {
        rewrite_stored_receipt_as_legacy(&receipt_path);
    }
    let (old_receipt, old_receipt_sha256) =
        read_receipt_with_hash(&receipt_path, &install_base).unwrap();
    let package_lock = lock_package(&state_root, &package_id, InstallScope::User).unwrap();
    let mut transaction = begin_transaction_with_package_lock(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Upgrade,
        InstallScope::User,
        Some(old_receipt_sha256),
        package_lock,
    )
    .unwrap();
    let paths = transaction.paths.clone();
    let path = PackagePath::parse("app.bin").unwrap();
    let new_sha256 = digest(b"new");
    transaction
        .append(JournalRecord::StageFile {
            path: path.clone(),
            sha256: new_sha256.clone(),
        })
        .unwrap();
    let incoming = staged_file(&paths, &path);
    ensure_directory(incoming.parent().unwrap(), Some(InstallScope::User)).unwrap();
    fs::write(&incoming, b"new").unwrap();
    transaction
        .append(JournalRecord::RestoreFile {
            path: path.clone(),
            sha256: digest(b"old"),
            executable: false,
        })
        .unwrap();
    let backup = removed_file(&paths, &path);
    ensure_directory(backup.parent().unwrap(), Some(InstallScope::User)).unwrap();
    super::rename_noreplace(&installed, &backup)
        .unwrap()
        .sync()
        .unwrap();
    transaction
        .append(JournalRecord::RemoveFile {
            path: path.clone(),
            sha256: new_sha256.clone(),
        })
        .unwrap();
    super::rename_noreplace(&incoming, &installed)
        .unwrap()
        .sync()
        .unwrap();

    let new_receipt = OwnershipReceipt::new(
        package_id.clone(),
        Version::new(2, 0, 0),
        old_receipt.scope(),
        directory,
        PackageIdentity::Unsigned,
        vec![FileEntry {
            path,
            size: 3,
            sha256: new_sha256,
            executable: false,
        }],
    )
    .unwrap();
    let stored = super::StoredReceipt {
        format_version: super::STORED_RECEIPT_FORMAT_VERSION,
        install_base: super::install_base_identity(&install_base).unwrap(),
        receipt: new_receipt,
    };
    let receipt_bytes = serde_json::to_vec_pretty(&stored).unwrap();
    transaction
        .append(JournalRecord::PendingReceipt {
            sha256: digest(&receipt_bytes),
        })
        .unwrap();
    let incoming_receipt = staged_receipt(&paths);
    fs::write(&incoming_receipt, receipt_bytes).unwrap();
    super::rename_noreplace(&incoming_receipt, &paths.receipt_pending)
        .unwrap()
        .sync()
        .unwrap();
    transaction.append(JournalRecord::Committing).unwrap();
    super::rename_noreplace(&paths.receipt, &paths.receipt_previous)
        .unwrap()
        .sync()
        .unwrap();
    if publish_receipt {
        super::rename_noreplace(&paths.receipt_pending, &paths.receipt)
            .unwrap()
            .sync()
            .unwrap();
    }
    drop(transaction);

    (temp, install_base, state_root, package_id, installed, paths)
}

fn interrupted_same_version_rollback() -> (
    TempDir,
    PathBuf,
    PathBuf,
    PackageId,
    PathBuf,
    super::transaction::TransactionPaths,
) {
    let temp = tempdir().unwrap();
    let install_base = temp.path().join("install");
    let state_root = temp.path().join("state");
    let (bundle, manifest) = bundle(&[("app.bin", b"package")]);
    let package_id = manifest.package.id.clone();
    let directory = manifest.install.directory.clone();
    let installed = install_base.join(directory.as_str()).join("app.bin");
    install(
        InstallCommand::new(manifest),
        &mut LocalInstallAdapter::new(bundle, &install_base, &state_root),
        || false,
        |_| {},
    )
    .unwrap();
    fs::write(&installed, b"user modified").unwrap();

    let receipt_path = transaction_paths(&install_base, &state_root, &package_id).receipt;
    let (old_receipt, old_receipt_sha256) =
        read_receipt_with_hash(&receipt_path, &install_base).unwrap();
    let package_lock = lock_package(&state_root, &package_id, InstallScope::User).unwrap();
    let mut transaction = begin_transaction_with_package_lock(
        &install_base,
        &state_root,
        &package_id,
        &directory,
        Operation::Upgrade,
        InstallScope::User,
        Some(old_receipt_sha256),
        package_lock,
    )
    .unwrap();
    let paths = transaction.paths.clone();
    let path = PackagePath::parse("app.bin").unwrap();
    let package_sha256 = digest(b"package");
    transaction
        .append(JournalRecord::StageFile {
            path: path.clone(),
            sha256: package_sha256.clone(),
        })
        .unwrap();
    let incoming = staged_file(&paths, &path);
    ensure_directory(incoming.parent().unwrap(), Some(InstallScope::User)).unwrap();
    fs::write(&incoming, b"package").unwrap();
    transaction
        .append(JournalRecord::RestoreFile {
            path: path.clone(),
            sha256: digest(b"user modified"),
            executable: false,
        })
        .unwrap();
    let backup = removed_file(&paths, &path);
    ensure_directory(backup.parent().unwrap(), Some(InstallScope::User)).unwrap();
    super::rename_noreplace(&installed, &backup)
        .unwrap()
        .sync()
        .unwrap();
    transaction
        .append(JournalRecord::RemoveFile {
            path,
            sha256: package_sha256,
        })
        .unwrap();
    super::rename_noreplace(&incoming, &installed)
        .unwrap()
        .sync()
        .unwrap();

    let stored = super::StoredReceipt {
        format_version: super::STORED_RECEIPT_FORMAT_VERSION,
        install_base: super::install_base_identity(&install_base).unwrap(),
        receipt: old_receipt,
    };
    let receipt_bytes = serde_json::to_vec_pretty(&stored).unwrap();
    transaction
        .append(JournalRecord::PendingReceipt {
            sha256: digest(&receipt_bytes),
        })
        .unwrap();
    let incoming_receipt = staged_receipt(&paths);
    fs::write(&incoming_receipt, receipt_bytes).unwrap();
    super::rename_noreplace(&incoming_receipt, &paths.receipt_pending)
        .unwrap()
        .sync()
        .unwrap();
    transaction.append(JournalRecord::Committing).unwrap();
    super::rename_noreplace(&paths.receipt, &paths.receipt_previous)
        .unwrap()
        .sync()
        .unwrap();
    transaction.mark_rolling_back().unwrap();

    fs::remove_file(&installed).unwrap();
    super::rename_noreplace(&backup, &installed)
        .unwrap()
        .sync()
        .unwrap();
    fs::remove_file(&paths.receipt_pending).unwrap();
    super::rename_noreplace(&paths.receipt_previous, &paths.receipt)
        .unwrap()
        .sync()
        .unwrap();
    drop(transaction);

    (temp, install_base, state_root, package_id, installed, paths)
}

fn bundle(files: &[(&str, &[u8])]) -> (luxury_bundle::Bundle, Manifest) {
    bundle_version(Version::new(1, 0, 0), files)
}

fn system_bundle(files: &[(&str, &[u8])]) -> (luxury_bundle::Bundle, Manifest) {
    bundle_version_in_directory_scope(
        Version::new(1, 0, 0),
        InstallDirectory::parse("LuxuryDemo").unwrap(),
        InstallScope::System,
        files,
    )
}

fn bundle_version(version: Version, files: &[(&str, &[u8])]) -> (luxury_bundle::Bundle, Manifest) {
    bundle_version_in_directory(
        version,
        InstallDirectory::parse("LuxuryDemo").unwrap(),
        files,
    )
}

fn bundle_version_in_directory(
    version: Version,
    directory: InstallDirectory,
    files: &[(&str, &[u8])],
) -> (luxury_bundle::Bundle, Manifest) {
    bundle_version_in_directory_scope(version, directory, InstallScope::User, files)
}

fn bundle_version_in_directory_scope(
    version: Version,
    directory: InstallDirectory,
    scope: InstallScope,
    files: &[(&str, &[u8])],
) -> (luxury_bundle::Bundle, Manifest) {
    let temp = tempdir().unwrap();
    for (path, bytes) in files {
        let path = temp.path().join(Path::new(path));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    let mut manifest = Manifest {
        format_version: FORMAT_VERSION,
        schema_version: 1,
        package: Package {
            id: PackageId::parse("dev.luxury.demo").unwrap(),
            name: "Luxury Demo".into(),
            version,
            publisher: "Luxury Software".into(),
            description: None,
            license: None,
        },
        target: Target::host(),
        install: InstallPolicy {
            scope,
            directory,
            allow_downgrade: false,
            entrypoint: None,
            show_install_log: false,
            finish_links: Vec::new(),
            shortcuts: luxury_spec::ShortcutPolicy::default(),
        },
        publisher_rotation: None,
        files: files
            .iter()
            .map(|(path, bytes)| FileEntry {
                path: PackagePath::parse(*path).unwrap(),
                size: bytes.len() as u64,
                sha256: digest(bytes),
                executable: path.ends_with("/app"),
            })
            .collect(),
    };
    manifest.files.sort_by_key(|file| file.path.collision_key());
    manifest.validate().unwrap();
    let mut encoded = Vec::new();
    create_unsigned_bundle(&mut encoded, temp.path(), &manifest).unwrap();
    (open_bundle(Cursor::new(encoded), None).unwrap(), manifest)
}

fn signed_bundle(
    files: &[(&str, &[u8])],
) -> (luxury_bundle::Bundle, Manifest, luxury_spec::PublisherKeyId) {
    signed_bundle_with_keys(
        Version::new(1, 0, 0),
        files,
        SIGNING_KEY_PEM,
        TRUSTED_KEY_PEM,
    )
}

fn signed_bundle_with_keys(
    version: Version,
    files: &[(&str, &[u8])],
    signing_key_pem: &str,
    trusted_key_pem: &str,
) -> (luxury_bundle::Bundle, Manifest, luxury_spec::PublisherKeyId) {
    let temp = tempdir().unwrap();
    for (path, bytes) in files {
        let path = temp.path().join(Path::new(path));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    let mut manifest = Manifest {
        format_version: SIGNED_FORMAT_VERSION,
        schema_version: 1,
        package: Package {
            id: PackageId::parse("dev.luxury.demo").unwrap(),
            name: "Luxury Demo".into(),
            version,
            publisher: "Luxury Software".into(),
            description: None,
            license: None,
        },
        target: Target::host(),
        install: InstallPolicy {
            scope: InstallScope::User,
            directory: InstallDirectory::parse("LuxuryDemo").unwrap(),
            allow_downgrade: false,
            entrypoint: None,
            show_install_log: false,
            finish_links: Vec::new(),
            shortcuts: luxury_spec::ShortcutPolicy::default(),
        },
        publisher_rotation: None,
        files: files
            .iter()
            .map(|(path, bytes)| FileEntry {
                path: PackagePath::parse(*path).unwrap(),
                size: bytes.len() as u64,
                sha256: digest(bytes),
                executable: false,
            })
            .collect(),
    };
    manifest.files.sort_by_key(|file| file.path.collision_key());
    manifest.validate().unwrap();
    let signing_key = PackageSigningKey::from_pkcs8_pem(signing_key_pem).unwrap();
    let trusted_key = TrustedPublisherKey::from_public_key_pem(trusted_key_pem).unwrap();
    let key_id = signing_key.key_id();
    let mut encoded = Vec::new();
    create_signed_bundle(&mut encoded, temp.path(), &manifest, &signing_key).unwrap();
    (
        open_bundle(Cursor::new(encoded), Some(&trusted_key)).unwrap(),
        manifest,
        key_id,
    )
}

fn rotation_bundle(
    version: Version,
    files: &[(&str, &[u8])],
) -> (
    luxury_bundle::Bundle,
    Manifest,
    luxury_spec::PublisherKeyId,
    luxury_spec::PublisherKeyId,
) {
    let temp = tempdir().unwrap();
    for (path, bytes) in files {
        let path = temp.path().join(Path::new(path));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    let current = PackageSigningKey::from_pkcs8_pem(SIGNING_KEY_PEM).unwrap();
    let next = PackageSigningKey::from_pkcs8_pem(NEXT_SIGNING_KEY_PEM).unwrap();
    let package_id = PackageId::parse("dev.luxury.demo").unwrap();
    let rotation = next
        .create_publisher_rotation(&package_id, &version, current.key_id())
        .unwrap();
    let mut manifest = Manifest {
        format_version: PUBLISHER_ROTATION_FORMAT_VERSION,
        schema_version: 1,
        package: Package {
            id: package_id,
            name: "Luxury Demo".into(),
            version,
            publisher: "Luxury Software".into(),
            description: None,
            license: None,
        },
        target: Target::host(),
        install: InstallPolicy {
            scope: InstallScope::User,
            directory: InstallDirectory::parse("LuxuryDemo").unwrap(),
            allow_downgrade: false,
            entrypoint: None,
            show_install_log: false,
            finish_links: Vec::new(),
            shortcuts: luxury_spec::ShortcutPolicy::default(),
        },
        publisher_rotation: Some(rotation),
        files: files
            .iter()
            .map(|(path, bytes)| FileEntry {
                path: PackagePath::parse(*path).unwrap(),
                size: bytes.len() as u64,
                sha256: digest(bytes),
                executable: false,
            })
            .collect(),
    };
    manifest.files.sort_by_key(|file| file.path.collision_key());
    manifest.validate().unwrap();
    let trusted = TrustedPublisherKey::from_public_key_pem(TRUSTED_KEY_PEM).unwrap();
    let from_key_id = current.key_id();
    let to_key_id = next.key_id();
    let mut encoded = Vec::new();
    create_signed_bundle(&mut encoded, temp.path(), &manifest, &current).unwrap();
    (
        open_bundle(Cursor::new(encoded), Some(&trusted)).unwrap(),
        manifest,
        from_key_id,
        to_key_id,
    )
}

fn tree_snapshot(root: &Path) -> Vec<(PathBuf, SystemTime, Option<Vec<u8>>)> {
    fn visit(root: &Path, path: &Path, snapshot: &mut Vec<(PathBuf, SystemTime, Option<Vec<u8>>)>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        let bytes = metadata.is_file().then(|| fs::read(path).unwrap());
        snapshot.push((
            path.strip_prefix(root).unwrap().to_path_buf(),
            metadata.modified().unwrap(),
            bytes,
        ));
        if metadata.is_dir() {
            let mut children = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            children.sort();
            for child in children {
                visit(root, &child, snapshot);
            }
        }
    }

    let mut snapshot = Vec::new();
    if root.exists() {
        visit(root, root, &mut snapshot);
    }
    snapshot
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(hex::encode(Sha256::digest(bytes))).unwrap()
}

fn append_journal_record(path: &Path, record: &JournalRecord) {
    let mut journal = OpenOptions::new().append(true).open(path).unwrap();
    serde_json::to_writer(&mut journal, record).unwrap();
    journal.write_all(b"\n").unwrap();
    journal.sync_all().unwrap();
}

fn write_stored_receipt(path: &Path, install_base: &Path, receipt: &OwnershipReceipt) {
    let stored = super::StoredReceipt {
        format_version: super::STORED_RECEIPT_FORMAT_VERSION,
        install_base: super::install_base_identity(install_base).unwrap(),
        receipt: receipt.clone(),
    };
    fs::write(path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();
}

fn begin_bound_uninstall_transaction(
    install_base: &Path,
    state_root: &Path,
    package_id: &PackageId,
    directory: &InstallDirectory,
) -> ActiveTransaction {
    let receipt = transaction_paths(install_base, state_root, package_id).receipt;
    let (_, receipt_sha256) = read_receipt_with_hash(&receipt, install_base).unwrap();
    begin_uninstall_transaction(
        install_base,
        state_root,
        package_id,
        directory,
        receipt_sha256,
    )
    .unwrap()
}

fn rewrite_stored_receipt_as_legacy(path: &Path) {
    let mut stored: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let receipt = stored["receipt"].as_object_mut().unwrap();
    receipt.insert("format_version".into(), 1.into());
    receipt.remove("package_identity");
    receipt.remove("authorized_publisher");
    receipt.remove("payload_signer");
    fs::write(path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();
}

#[cfg(unix)]
fn create_directory_link(link: &Path, target: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_directory_link(link: &Path, target: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[cfg(unix)]
fn create_file_link(link: &Path, target: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_file_link(link: &Path, target: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}
