use std::{cell::Cell, rc::Rc};

use luxury_engine::{
    PortError, PortErrorKind,
    install::{
        InstallAction, InstallCommand, InstallError, InstallEvent, InstallPhase, InstallPlan,
        InstallPort, InstallPrepareOutcome, InstallPreparePort, PackageIdentity,
        VerifiedPackageIdentity, install, prepare_install, prepare_system_install,
    },
    uninstall::{OwnershipReceipt, RemoveFileOutcome},
};
use luxury_spec::{
    Architecture, FORMAT_VERSION, FileEntry, InstallDirectory, InstallPolicy, InstallScope,
    MANIFEST_SCHEMA_VERSION, Manifest, OperatingSystem, Package, PackageId, PackagePath,
    PublisherKeyId, Sha256Digest, Target,
};
use semver::Version;

struct FakeInstallPort {
    calls: Vec<String>,
    fail_at: Option<&'static str>,
    fail_kind: PortErrorKind,
    rollback_fails: bool,
    package_identity: PackageIdentity,
    rotation_to: Option<PublisherKeyId>,
    receipt: Option<OwnershipReceipt>,
    recovery_pending: bool,
    recovery_after_preflight_failure: bool,
    staged_receipt: Option<OwnershipReceipt>,
    applied: Rc<Cell<usize>>,
    obsolete_outcome: RemoveFileOutcome,
}

impl FakeInstallPort {
    fn new(applied: Rc<Cell<usize>>) -> Self {
        Self {
            calls: Vec::new(),
            fail_at: None,
            fail_kind: PortErrorKind::Other,
            rollback_fails: false,
            package_identity: PackageIdentity::Unsigned,
            rotation_to: None,
            receipt: None,
            recovery_pending: false,
            recovery_after_preflight_failure: false,
            staged_receipt: None,
            applied,
            obsolete_outcome: RemoveFileOutcome::Removed,
        }
    }

    fn call(&mut self, step: &'static str) -> Result<(), PortError> {
        self.calls.push(step.into());
        if self.fail_at == Some(step) {
            Err(PortError::with_kind(
                self.fail_kind,
                format!("{step} failed"),
            ))
        } else {
            Ok(())
        }
    }
}

impl InstallPreparePort for FakeInstallPort {
    fn verify_package(
        &mut self,
        _manifest: &Manifest,
    ) -> Result<VerifiedPackageIdentity, PortError> {
        self.call("verify")?;
        Ok(match self.package_identity {
            PackageIdentity::Unsigned => VerifiedPackageIdentity::Unsigned,
            PackageIdentity::TrustedPublisher { key_id } => {
                VerifiedPackageIdentity::TrustedPublisher {
                    signer_key_id: key_id,
                    rotation_to: self.rotation_to,
                }
            }
        })
    }

    fn recovery_pending(&mut self, _package_id: &PackageId) -> Result<bool, PortError> {
        self.call("recovery pending")?;
        Ok(self.recovery_pending)
    }

    fn load_receipt(
        &mut self,
        _package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError> {
        self.call("load receipt")?;
        Ok(self.receipt.clone())
    }

    fn preflight(
        &mut self,
        _plan: &InstallPlan,
        _previous: Option<&OwnershipReceipt>,
    ) -> Result<(), PortError> {
        let result = self.call("preflight");
        if result.is_err() && self.recovery_after_preflight_failure {
            self.recovery_pending = true;
        }
        result
    }
}

impl InstallPort for FakeInstallPort {
    fn recover_pending(&mut self, _package_id: &PackageId) -> Result<(), PortError> {
        self.call("recover")
    }

    fn begin(
        &mut self,
        _plan: &InstallPlan,
        _previous: Option<&OwnershipReceipt>,
    ) -> Result<(), PortError> {
        self.call("begin")
    }

    fn remove_obsolete(
        &mut self,
        _previous: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<RemoveFileOutcome, PortError> {
        self.calls.push(format!("remove:{}", file.path));
        if self.fail_at == Some("remove obsolete") {
            return Err(PortError::new("remove obsolete failed"));
        }
        self.applied.set(self.applied.get() + 1);
        Ok(self.obsolete_outcome)
    }

    fn apply_file(&mut self, file: &FileEntry) -> Result<(), PortError> {
        self.calls.push(format!("apply:{}", file.path));
        if self.fail_at == Some("apply") {
            return Err(PortError::new("apply failed"));
        }
        self.applied.set(self.applied.get() + 1);
        Ok(())
    }

    fn stage_receipt(&mut self, receipt: &OwnershipReceipt) -> Result<(), PortError> {
        self.call("stage receipt")?;
        self.staged_receipt = Some(receipt.clone());
        Ok(())
    }

    fn commit(&mut self) -> Result<(), PortError> {
        self.call("commit")?;
        self.receipt = self.staged_receipt.take();
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), PortError> {
        self.calls.push("rollback".into());
        self.staged_receipt = None;
        if self.rollback_fails {
            Err(PortError::new("rollback failed"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn installs_verified_user_package_and_emits_monotonic_progress() {
    let applied = Rc::new(Cell::new(0));
    let mut port = FakeInstallPort::new(applied.clone());
    let mut events = Vec::new();

    let outcome = install(
        InstallCommand::new(manifest(InstallScope::User, Target::host())),
        &mut port,
        || false,
        |event| {
            if matches!(event, InstallEvent::Action(_)) {
                assert_eq!(applied.get(), 0);
            }
            events.push(event);
        },
    )
    .unwrap();

    assert_eq!(outcome.package_id.as_str(), "dev.luxury.demo");
    assert_eq!(outcome.action, InstallAction::Install);
    assert_eq!(outcome.installed_files, 2);
    assert_eq!(outcome.installed_bytes, 7);
    assert_eq!(
        port.calls,
        [
            "verify",
            "recover",
            "load receipt",
            "preflight",
            "begin",
            "apply:bin/demo.exe",
            "apply:share/readme.txt",
            "stage receipt",
            "commit",
        ]
    );

    let receipt = port.receipt.unwrap();
    assert_eq!(receipt.format_version(), 4);
    assert_eq!(receipt.package_id().as_str(), "dev.luxury.demo");
    assert_eq!(receipt.package_identity(), Some(PackageIdentity::Unsigned));
    assert_eq!(receipt.payload_signer(), Some(PackageIdentity::Unsigned));
    assert_eq!(receipt.files().len(), 2);
    assert_eq!(receipt.directory().as_str(), "LuxuryDemo");
    assert_eq!(receipt.entrypoint(), None);

    let progress = events
        .iter()
        .filter_map(|event| match event {
            InstallEvent::Progress(progress) => Some(*progress),
            InstallEvent::Phase(_) | InstallEvent::Action(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, InstallEvent::Action(_)))
            .count(),
        1
    );
    let action_index = events
        .iter()
        .position(|event| matches!(event, InstallEvent::Action(InstallAction::Install)))
        .unwrap();
    let first_progress = events
        .iter()
        .position(|event| matches!(event, InstallEvent::Progress(_)))
        .unwrap();
    assert!(action_index < first_progress);
    assert_eq!(progress.len(), 3);
    assert!(progress.windows(2).all(|pair| {
        pair[0].completed_files <= pair[1].completed_files
            && pair[0].completed_bytes <= pair[1].completed_bytes
    }));
    assert_eq!(progress.last().unwrap().completed_files, 2);
    assert_eq!(progress.last().unwrap().completed_bytes, 7);
    assert_eq!(
        events.last(),
        Some(&InstallEvent::Phase(InstallPhase::Completed))
    );
}

#[test]
fn prepare_install_classifies_fresh_update_repair_and_migration_without_mutation() {
    let current = Version::new(1, 2, 3);
    let key = trusted_identity(0x0a);
    let cases = [
        (
            "fresh",
            None,
            PackageIdentity::Unsigned,
            InstallPrepareOutcome::Ready {
                action: InstallAction::Install,
                installed_version: None,
                publisher_migration_required: false,
            },
        ),
        (
            "update",
            Some((Version::new(1, 0, 0), PackageIdentity::Unsigned)),
            PackageIdentity::Unsigned,
            InstallPrepareOutcome::Ready {
                action: InstallAction::Update,
                installed_version: Some(Version::new(1, 0, 0)),
                publisher_migration_required: false,
            },
        ),
        (
            "repair",
            Some((current.clone(), PackageIdentity::Unsigned)),
            PackageIdentity::Unsigned,
            InstallPrepareOutcome::Ready {
                action: InstallAction::Repair,
                installed_version: Some(current.clone()),
                publisher_migration_required: false,
            },
        ),
        (
            "publisher migration",
            Some((Version::new(1, 0, 0), PackageIdentity::Unsigned)),
            key,
            InstallPrepareOutcome::Ready {
                action: InstallAction::Update,
                installed_version: Some(Version::new(1, 0, 0)),
                publisher_migration_required: true,
            },
        ),
    ];

    for (name, previous, requested, expected) in cases {
        let package = manifest(InstallScope::User, Target::host());
        let applied = Rc::new(Cell::new(0));
        let mut port = FakeInstallPort::new(applied.clone());
        port.package_identity = requested;
        port.receipt = previous.map(|(version, identity)| {
            receipt_with_identity(
                version,
                package.install.directory.clone(),
                identity,
                package.files.clone(),
            )
        });
        let receipt_before = port.receipt.clone();

        let outcome = prepare_install(package, &mut port).unwrap();

        assert_eq!(outcome, expected, "{name}");
        assert_eq!(
            port.calls,
            ["verify", "recovery pending", "load receipt", "preflight"],
            "{name}"
        );
        assert_eq!(port.receipt, receipt_before, "{name}");
        assert_eq!(applied.get(), 0, "{name}");
        assert!(port.staged_receipt.is_none(), "{name}");
    }
}

#[test]
fn capacity_is_advisory_only_for_prepare_install() {
    let package = manifest(InstallScope::User, Target::host());
    let applied = Rc::new(Cell::new(0));
    let mut prepare_port = FakeInstallPort::new(applied.clone());
    prepare_port.fail_at = Some("preflight");
    prepare_port.fail_kind = PortErrorKind::Capacity;

    assert_eq!(
        prepare_install(package.clone(), &mut prepare_port).unwrap(),
        InstallPrepareOutcome::InsufficientSpace {
            action: InstallAction::Install,
            installed_version: None,
            publisher_migration_required: false,
        }
    );
    assert_eq!(
        prepare_port.calls,
        [
            "verify",
            "recovery pending",
            "load receipt",
            "preflight",
            "recovery pending"
        ]
    );
    assert_eq!(applied.get(), 0);

    let mut install_port = FakeInstallPort::new(applied);
    install_port.fail_at = Some("preflight");
    install_port.fail_kind = PortErrorKind::Capacity;
    assert!(matches!(
        install(
            InstallCommand::new(package),
            &mut install_port,
            || false,
            |_| {}
        ),
        Err(InstallError::Port {
            step: "preflight",
            source
        }) if source.kind() == PortErrorKind::Capacity
    ));
    assert_eq!(
        install_port.calls,
        ["verify", "recover", "load receipt", "preflight"]
    );
}

#[test]
fn prepare_install_reports_recovery_before_or_during_preflight() {
    let package = manifest(InstallScope::User, Target::host());
    let mut pending = FakeInstallPort::new(Rc::new(Cell::new(0)));
    pending.recovery_pending = true;
    assert_eq!(
        prepare_install(package.clone(), &mut pending).unwrap(),
        InstallPrepareOutcome::RecoveryRequired
    );
    assert_eq!(pending.calls, ["verify", "recovery pending"]);

    let mut raced = FakeInstallPort::new(Rc::new(Cell::new(0)));
    raced.fail_at = Some("preflight");
    raced.recovery_after_preflight_failure = true;
    assert_eq!(
        prepare_install(package.clone(), &mut raced).unwrap(),
        InstallPrepareOutcome::RecoveryRequired
    );
    assert_eq!(
        raced.calls,
        [
            "verify",
            "recovery pending",
            "load receipt",
            "preflight",
            "recovery pending"
        ]
    );

    let mut failed = FakeInstallPort::new(Rc::new(Cell::new(0)));
    failed.fail_at = Some("preflight");
    assert!(matches!(
        prepare_install(package, &mut failed),
        Err(InstallError::Port {
            step: "preflight",
            ..
        })
    ));
    assert_eq!(
        failed.calls,
        [
            "verify",
            "recovery pending",
            "load receipt",
            "preflight",
            "recovery pending"
        ]
    );
}

#[test]
fn prepare_install_rejects_downgrade_and_mismatched_repair_before_preflight() {
    let mut older = manifest(InstallScope::User, Target::host());
    older.install.allow_downgrade = true;
    let mut downgrade = FakeInstallPort::new(Rc::new(Cell::new(0)));
    downgrade.receipt = Some(receipt(
        Version::new(2, 0, 0),
        older.install.directory.clone(),
        older.files.clone(),
    ));
    assert!(matches!(
        prepare_install(older, &mut downgrade),
        Err(InstallError::DowngradeDenied { .. })
    ));
    assert_eq!(
        downgrade.calls,
        ["verify", "recovery pending", "load receipt"]
    );

    let package = manifest(InstallScope::User, Target::host());
    let mut changed_files = package.files.clone();
    changed_files[0].sha256 = digest('9');
    let mut repair = FakeInstallPort::new(Rc::new(Cell::new(0)));
    repair.receipt = Some(receipt(
        package.package.version.clone(),
        package.install.directory.clone(),
        changed_files,
    ));
    assert!(matches!(
        prepare_install(package, &mut repair),
        Err(InstallError::ReinstallMismatch { .. })
    ));
    assert_eq!(repair.calls, ["verify", "recovery pending", "load receipt"]);
}

#[test]
fn package_identity_has_a_stable_tagged_representation() {
    let trusted = trusted_identity(0xab);
    assert_eq!(
        serde_json::to_value(PackageIdentity::Unsigned).unwrap(),
        serde_json::json!({"kind": "unsigned"})
    );
    assert_eq!(
        serde_json::to_value(trusted).unwrap(),
        serde_json::json!({
            "kind": "trustedPublisher",
            "keyId": "ab".repeat(32),
        })
    );
    assert!(
        serde_json::from_value::<PackageIdentity>(serde_json::json!({
            "kind": "trustedPublisher",
            "keyId": "AB".repeat(32),
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<PackageIdentity>(serde_json::json!({
            "kind": "unsigned",
            "keyId": "ab".repeat(32),
        }))
        .is_err()
    );
}

#[test]
fn package_verification_failure_cannot_reach_recovery() {
    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.fail_at = Some("verify");
    let mut events = Vec::new();

    let error = install(
        InstallCommand::new(manifest(InstallScope::User, Target::host())),
        &mut port,
        || false,
        |event| events.push(event),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        InstallError::Port {
            step: "verify package",
            ..
        }
    ));
    assert_eq!(port.calls, ["verify"]);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, InstallEvent::Action(_)))
    );
}

#[test]
fn rejects_non_host_target_and_system_scope_before_package_access() {
    let applied = Rc::new(Cell::new(0));
    let mut port = FakeInstallPort::new(applied.clone());
    let error = install(
        InstallCommand::new(manifest(InstallScope::User, non_host_target())),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(error, InstallError::UnsupportedTarget { .. }));
    assert!(port.calls.is_empty());

    let mut port = FakeInstallPort::new(applied);
    let error = install(
        InstallCommand::new(manifest(InstallScope::System, Target::host())),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(error, InstallError::UnsupportedScope { .. }));
    assert!(port.calls.is_empty());
}

#[test]
fn explicit_system_authority_preserves_scope_through_prepare_and_receipt() {
    let package = manifest(InstallScope::System, Target::host());
    let mut prepare_port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    let prepared = prepare_system_install(package.clone(), &mut prepare_port).unwrap();
    assert!(matches!(
        prepared,
        InstallPrepareOutcome::Ready {
            action: InstallAction::Install,
            ..
        }
    ));

    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    let outcome = install(
        InstallCommand::for_system(package),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap();
    assert_eq!(outcome.action, InstallAction::Install);
    let receipt = port.receipt.unwrap();
    assert_eq!(receipt.scope(), InstallScope::System);
    receipt.validate().unwrap();
}

#[test]
fn license_requires_caller_acceptance_before_package_access() {
    let applied = Rc::new(Cell::new(0));
    let mut package = manifest(InstallScope::User, Target::host());
    package.package.license = Some("Demo license terms.".into());

    let mut port = FakeInstallPort::new(applied.clone());
    let mut events = Vec::new();
    let error = install(
        InstallCommand::new(package.clone()),
        &mut port,
        || false,
        |event| events.push(event),
    )
    .unwrap_err();
    assert_eq!(error, InstallError::LicenseNotAccepted);
    assert!(port.calls.is_empty());
    assert_eq!(
        events,
        [
            InstallEvent::Phase(InstallPhase::Validating),
            InstallEvent::Phase(InstallPhase::Failed),
        ]
    );

    let mut port = FakeInstallPort::new(applied);
    install(
        InstallCommand::new(package).with_license_acceptance(true),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap();
    assert_eq!(port.calls.first().map(String::as_str), Some("verify"));
}

#[test]
fn downgrade_requires_package_policy_and_caller_approval() {
    for (package_allows, caller_allows, succeeds) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ] {
        let mut package = manifest(InstallScope::User, Target::host());
        package.install.allow_downgrade = package_allows;
        let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
        port.receipt = Some(receipt(
            Version::new(2, 0, 0),
            package.install.directory.clone(),
            package.files.clone(),
        ));

        let result = install(
            InstallCommand::new(package).with_downgrade_approval(caller_allows),
            &mut port,
            || false,
            |_| {},
        );

        if succeeds {
            assert_eq!(result.unwrap().action, InstallAction::Downgrade);
        } else {
            assert!(matches!(result, Err(InstallError::DowngradeDenied { .. })));
            assert_eq!(port.calls, ["verify", "recover", "load receipt"]);
        }
    }
}

#[test]
fn publisher_transition_matrix_is_fail_closed() {
    #[derive(Clone, Copy)]
    enum Previous {
        None,
        Legacy,
        Known(PackageIdentity),
    }

    #[derive(Clone, Copy)]
    enum Expected {
        Installed,
        MigrationDenied(Option<PackageIdentity>),
        Mismatch(PackageIdentity),
    }

    let key_a = trusted_identity(0x0a);
    let key_b = trusted_identity(0x0b);
    let cases = [
        (
            Previous::None,
            PackageIdentity::Unsigned,
            false,
            Expected::Installed,
        ),
        (Previous::None, key_a, false, Expected::Installed),
        (
            Previous::Legacy,
            PackageIdentity::Unsigned,
            false,
            Expected::MigrationDenied(None),
        ),
        (
            Previous::Legacy,
            PackageIdentity::Unsigned,
            true,
            Expected::Installed,
        ),
        (
            Previous::Legacy,
            key_a,
            false,
            Expected::MigrationDenied(None),
        ),
        (Previous::Legacy, key_a, true, Expected::Installed),
        (
            Previous::Known(PackageIdentity::Unsigned),
            PackageIdentity::Unsigned,
            false,
            Expected::Installed,
        ),
        (
            Previous::Known(PackageIdentity::Unsigned),
            key_a,
            false,
            Expected::MigrationDenied(Some(PackageIdentity::Unsigned)),
        ),
        (
            Previous::Known(PackageIdentity::Unsigned),
            key_a,
            true,
            Expected::Installed,
        ),
        (Previous::Known(key_a), key_a, false, Expected::Installed),
        (
            Previous::Known(key_a),
            key_b,
            false,
            Expected::Mismatch(key_a),
        ),
        (
            Previous::Known(key_a),
            key_b,
            true,
            Expected::Mismatch(key_a),
        ),
        (
            Previous::Known(key_a),
            PackageIdentity::Unsigned,
            false,
            Expected::Mismatch(key_a),
        ),
        (
            Previous::Known(key_a),
            PackageIdentity::Unsigned,
            true,
            Expected::Mismatch(key_a),
        ),
    ];

    for (previous, requested, migration_approved, expected) in cases {
        let mut package = manifest(InstallScope::User, Target::host());
        package.package.version = Version::new(2, 0, 0);
        let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
        port.package_identity = requested;
        port.receipt = match previous {
            Previous::None => None,
            Previous::Legacy => Some(legacy_receipt(
                Version::new(1, 0, 0),
                package.install.directory.clone(),
                package.files.clone(),
            )),
            Previous::Known(identity) => Some(receipt_with_identity(
                Version::new(1, 0, 0),
                package.install.directory.clone(),
                identity,
                package.files.clone(),
            )),
        };

        let result = install(
            InstallCommand::new(package).with_publisher_migration_approval(migration_approved),
            &mut port,
            || false,
            |_| {},
        );
        match expected {
            Expected::Installed => {
                result.unwrap();
                assert_eq!(
                    port.receipt.as_ref().unwrap().package_identity(),
                    Some(requested)
                );
                assert_eq!(
                    port.receipt.as_ref().unwrap().payload_signer(),
                    Some(requested)
                );
            }
            Expected::MigrationDenied(installed) => {
                assert_eq!(
                    result.unwrap_err(),
                    InstallError::PublisherMigrationDenied {
                        installed,
                        requested,
                    }
                );
                assert_eq!(port.calls, ["verify", "recover", "load receipt"]);
            }
            Expected::Mismatch(installed) => {
                assert_eq!(
                    result.unwrap_err(),
                    InstallError::PublisherMismatch {
                        installed,
                        requested,
                    }
                );
                assert_eq!(port.calls, ["verify", "recover", "load receipt"]);
            }
        }
    }
}

#[test]
fn publisher_rotation_requires_installed_signer_and_higher_precedence() {
    let key_a_id = PublisherKeyId::from_bytes([0x0a; 32]);
    let key_b_id = PublisherKeyId::from_bytes([0x0b; 32]);
    let key_a = PackageIdentity::TrustedPublisher { key_id: key_a_id };
    let key_b = PackageIdentity::TrustedPublisher { key_id: key_b_id };

    let mut package = manifest(InstallScope::User, Target::host());
    package.package.version = Version::new(2, 0, 0);
    package.install.allow_downgrade = true;
    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.package_identity = key_a;
    port.rotation_to = Some(key_b_id);
    port.receipt = Some(receipt_with_identity(
        Version::new(1, 0, 0),
        package.install.directory.clone(),
        key_a,
        package.files.clone(),
    ));

    install(
        InstallCommand::new(package.clone())
            .with_downgrade_approval(true)
            .with_publisher_migration_approval(true),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap();
    let receipt = port.receipt.unwrap();
    assert_eq!(receipt.package_identity(), Some(key_b));
    assert_eq!(receipt.payload_signer(), Some(key_a));

    enum Previous {
        None,
        Legacy,
        Known(Box<OwnershipReceipt>),
    }
    let cases = [
        Previous::None,
        Previous::Legacy,
        Previous::Known(Box::new(receipt_with_identity(
            Version::new(1, 0, 0),
            package.install.directory.clone(),
            PackageIdentity::Unsigned,
            package.files.clone(),
        ))),
        Previous::Known(Box::new(receipt_with_provenance(
            Version::new(1, 0, 0),
            package.install.directory.clone(),
            key_b,
            key_a,
            package.files.clone(),
        ))),
        Previous::Known(Box::new(receipt_with_identity(
            Version::new(2, 0, 0),
            package.install.directory.clone(),
            key_a,
            package.files.clone(),
        ))),
        Previous::Known(Box::new(receipt_with_identity(
            Version::new(3, 0, 0),
            package.install.directory.clone(),
            key_a,
            package.files.clone(),
        ))),
    ];

    for previous in cases {
        let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
        port.package_identity = key_a;
        port.rotation_to = Some(key_b_id);
        port.receipt = match previous {
            Previous::None => None,
            Previous::Legacy => Some(legacy_receipt(
                Version::new(1, 0, 0),
                package.install.directory.clone(),
                package.files.clone(),
            )),
            Previous::Known(receipt) => Some(*receipt),
        };
        let error = install(
            InstallCommand::new(package.clone())
                .with_downgrade_approval(true)
                .with_publisher_migration_approval(true),
            &mut port,
            || false,
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(
            error,
            InstallError::PublisherRotationDenied { .. }
        ));
        assert_eq!(port.calls, ["verify", "recover", "load receipt"]);
    }

    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.package_identity = key_a;
    port.rotation_to = Some(key_a_id);
    port.receipt = Some(receipt_with_identity(
        Version::new(1, 0, 0),
        package.install.directory.clone(),
        key_a,
        package.files.clone(),
    ));
    assert!(matches!(
        install(InstallCommand::new(package), &mut port, || false, |_| {}),
        Err(InstallError::PublisherRotationDenied { .. })
    ));
}

#[test]
fn publisher_migration_and_downgrade_approvals_are_independent() {
    for (migration_approved, downgrade_approved, succeeds) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ] {
        let mut package = manifest(InstallScope::User, Target::host());
        package.package.version = Version::new(1, 0, 0);
        package.install.allow_downgrade = true;
        let requested = trusted_identity(0x0a);
        let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
        port.package_identity = requested;
        port.receipt = Some(receipt_with_identity(
            Version::new(2, 0, 0),
            package.install.directory.clone(),
            PackageIdentity::Unsigned,
            package.files.clone(),
        ));

        let result = install(
            InstallCommand::new(package)
                .with_publisher_migration_approval(migration_approved)
                .with_downgrade_approval(downgrade_approved),
            &mut port,
            || false,
            |_| {},
        );
        if succeeds {
            result.unwrap();
            assert_eq!(port.receipt.unwrap().package_identity(), Some(requested));
        } else if migration_approved {
            assert!(matches!(result, Err(InstallError::DowngradeDenied { .. })));
        } else {
            assert!(matches!(
                result,
                Err(InstallError::PublisherMigrationDenied { .. })
            ));
        }
    }
}

#[test]
fn same_version_reinstall_requires_exact_file_entries() {
    let package = manifest(InstallScope::User, Target::host());
    let mut changed_files = package.files.clone();
    changed_files[0].sha256 = digest('9');
    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.receipt = Some(receipt(
        package.package.version.clone(),
        package.install.directory.clone(),
        changed_files,
    ));

    let error = install(
        InstallCommand::new(package.clone()),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap_err();

    assert!(matches!(error, InstallError::ReinstallMismatch { .. }));
    assert_eq!(port.calls, ["verify", "recover", "load receipt"]);

    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.receipt = Some(receipt(
        package.package.version.clone(),
        package.install.directory.clone(),
        package.files.clone(),
    ));
    let outcome = install(InstallCommand::new(package), &mut port, || false, |_| {}).unwrap();
    assert_eq!(outcome.action, InstallAction::Repair);
}

#[test]
fn same_version_repair_requires_exact_entrypoint_and_persists_it() {
    let mut package = manifest(InstallScope::User, Target::host());
    let entrypoint = PackagePath::parse("bin/demo.exe").unwrap();
    package.install.entrypoint = Some(entrypoint.clone());

    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.receipt = Some(receipt(
        package.package.version.clone(),
        package.install.directory.clone(),
        package.files.clone(),
    ));
    let error = install(
        InstallCommand::new(package.clone()),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(error, InstallError::ReinstallMismatch { .. }));
    assert_eq!(port.calls, ["verify", "recover", "load receipt"]);

    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.receipt = Some(receipt_with_entrypoint(
        package.package.version.clone(),
        package.install.directory.clone(),
        package.files.clone(),
        entrypoint.clone(),
    ));
    let outcome = install(InstallCommand::new(package), &mut port, || false, |_| {}).unwrap();

    assert_eq!(outcome.action, InstallAction::Repair);
    assert_eq!(port.receipt.unwrap().entrypoint(), Some(&entrypoint));
}

#[test]
fn build_metadata_cannot_bypass_same_version_reinstall_policy() {
    let mut package = manifest(InstallScope::User, Target::host());
    package.package.version = Version::parse("1.2.3+new").unwrap();
    let mut previous_files = package.files.clone();
    previous_files[0].sha256 = digest('9');
    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.receipt = Some(receipt(
        Version::parse("1.2.3+old").unwrap(),
        package.install.directory.clone(),
        previous_files,
    ));

    let error = install(InstallCommand::new(package), &mut port, || false, |_| {}).unwrap_err();

    assert!(matches!(error, InstallError::ReinstallMismatch { .. }));
    assert_eq!(port.calls, ["verify", "recover", "load receipt"]);
}

#[test]
fn upgrade_removes_obsolete_files_before_applying_and_tracks_total_work() {
    let mut package = manifest(InstallScope::User, Target::host());
    package.package.version = Version::new(2, 0, 0);
    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.receipt = Some(receipt(
        Version::new(1, 0, 0),
        package.install.directory.clone(),
        vec![
            package.files[0].clone(),
            file("legacy/old.dll", 5, 'c', false),
        ],
    ));
    let mut events = Vec::new();

    let outcome = install(
        InstallCommand::new(package.clone()),
        &mut port,
        || false,
        |event| events.push(event),
    )
    .unwrap();

    assert_eq!(outcome.action, InstallAction::Update);
    assert_eq!(outcome.installed_files, 2);
    assert_eq!(outcome.installed_bytes, 7);
    assert_eq!(
        &port.calls[5..9],
        [
            "remove:legacy/old.dll",
            "apply:bin/demo.exe",
            "apply:share/readme.txt",
            "stage receipt",
        ]
    );
    assert_eq!(port.receipt.unwrap().files(), package.files);
    let progress = events
        .iter()
        .filter_map(|event| match event {
            InstallEvent::Progress(progress) => Some(*progress),
            InstallEvent::Phase(_) | InstallEvent::Action(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(progress.first().unwrap().total_files, 3);
    assert_eq!(progress.last().unwrap().completed_files, 3);
    assert_eq!(progress.last().unwrap().completed_bytes, 7);
}

#[test]
fn obsolete_removal_failure_rolls_back_and_keeps_previous_receipt() {
    let mut package = manifest(InstallScope::User, Target::host());
    package.package.version = Version::new(2, 0, 0);
    let previous = receipt(
        Version::new(1, 0, 0),
        package.install.directory.clone(),
        vec![file("legacy/old.dll", 5, 'c', false)],
    );
    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.receipt = Some(previous.clone());
    port.fail_at = Some("remove obsolete");

    let error = install(InstallCommand::new(package), &mut port, || false, |_| {}).unwrap_err();

    assert!(matches!(
        error,
        InstallError::Port {
            step: "remove obsolete file",
            ..
        }
    ));
    assert_eq!(port.calls.last().map(String::as_str), Some("rollback"));
    assert_eq!(port.receipt, Some(previous));
}

#[test]
fn missing_or_modified_obsolete_files_are_preserved_but_no_longer_owned() {
    for outcome in [
        RemoveFileOutcome::Missing,
        RemoveFileOutcome::PreservedModified,
    ] {
        let mut package = manifest(InstallScope::User, Target::host());
        package.package.version = Version::new(2, 0, 0);
        let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
        port.receipt = Some(receipt(
            Version::new(1, 0, 0),
            package.install.directory.clone(),
            vec![file("legacy/user-edited.ini", 5, 'c', false)],
        ));
        port.obsolete_outcome = outcome;

        install(
            InstallCommand::new(package.clone()),
            &mut port,
            || false,
            |_| {},
        )
        .unwrap();

        assert_eq!(port.receipt.unwrap().files(), package.files);
    }
}

#[test]
fn cancellation_between_obsolete_files_rolls_back_before_apply() {
    let mut package = manifest(InstallScope::User, Target::host());
    package.package.version = Version::new(2, 0, 0);
    let previous = receipt(
        Version::new(1, 0, 0),
        package.install.directory.clone(),
        vec![
            file("legacy/one.dll", 5, 'c', false),
            file("legacy/two.dll", 6, 'd', false),
        ],
    );
    let processed = Rc::new(Cell::new(0));
    let mut port = FakeInstallPort::new(processed.clone());
    port.receipt = Some(previous.clone());

    let error = install(
        InstallCommand::new(package),
        &mut port,
        || processed.get() == 1,
        |_| {},
    )
    .unwrap_err();

    assert_eq!(error, InstallError::Cancelled);
    assert_eq!(port.calls.last().map(String::as_str), Some("rollback"));
    assert!(!port.calls.iter().any(|call| call.starts_with("apply:")));
    assert_eq!(port.receipt, Some(previous));
}

#[test]
fn rejects_mismatched_receipt_identity_before_preflight() {
    let package = manifest(InstallScope::User, Target::host());
    for (previous, field) in [
        (
            OwnershipReceipt::new(
                PackageId::parse("dev.luxury.other").unwrap(),
                Version::new(1, 0, 0),
                InstallScope::User,
                package.install.directory.clone(),
                PackageIdentity::Unsigned,
                package.files.clone(),
            )
            .unwrap(),
            "package id",
        ),
        (
            receipt(
                Version::new(1, 0, 0),
                InstallDirectory::parse("OtherDirectory").unwrap(),
                package.files.clone(),
            ),
            "directory",
        ),
    ] {
        let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
        port.receipt = Some(previous);
        let error = install(
            InstallCommand::new(package.clone()),
            &mut port,
            || false,
            |_| {},
        )
        .unwrap_err();

        assert_eq!(error, InstallError::ReceiptMismatch { field });
        assert_eq!(port.calls, ["verify", "recover", "load receipt"]);
    }

    let mut value = serde_json::to_value(receipt(
        Version::new(1, 0, 0),
        package.install.directory.clone(),
        package.files.clone(),
    ))
    .unwrap();
    value["scope"] = serde_json::Value::String("system".into());
    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.receipt = Some(serde_json::from_value(value).unwrap());
    let error = install(InstallCommand::new(package), &mut port, || false, |_| {}).unwrap_err();
    assert_eq!(error, InstallError::ReceiptMismatch { field: "scope" });
    assert_eq!(port.calls, ["verify", "recover", "load receipt"]);
}

#[test]
fn rejects_cross_platform_path_alias_changes_before_preflight() {
    let mut package = manifest(InstallScope::User, Target::host());
    package.package.version = Version::new(2, 0, 0);
    let mut previous_files = package.files.clone();
    previous_files[0].path = PackagePath::parse("Bin/Demo.exe").unwrap();
    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.receipt = Some(receipt(
        Version::new(1, 0, 0),
        package.install.directory.clone(),
        previous_files,
    ));

    let error = install(InstallCommand::new(package), &mut port, || false, |_| {}).unwrap_err();

    assert!(matches!(error, InstallError::PathAliasChanged { .. }));
    assert_eq!(port.calls, ["verify", "recover", "load receipt"]);
}

#[test]
fn receipt_load_failure_is_terminal_before_preflight() {
    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.fail_at = Some("load receipt");

    let error = install(
        InstallCommand::new(manifest(InstallScope::User, Target::host())),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap_err();

    assert!(matches!(
        error,
        InstallError::Port {
            step: "load receipt",
            ..
        }
    ));
    assert_eq!(port.calls, ["verify", "recover", "load receipt"]);
}

#[test]
fn cancellation_after_planning_skips_filesystem_preflight() {
    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    let checks = Cell::new(0);

    let error = install(
        InstallCommand::new(manifest(InstallScope::User, Target::host())),
        &mut port,
        || {
            checks.set(checks.get() + 1);
            checks.get() == 3
        },
        |_| {},
    )
    .unwrap_err();

    assert_eq!(error, InstallError::Cancelled);
    assert_eq!(port.calls, ["verify", "recover", "load receipt"]);
}

#[test]
fn observer_panic_after_mutation_rolls_back() {
    let applied = Rc::new(Cell::new(0));
    let mut port = FakeInstallPort::new(applied);

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = install(
            InstallCommand::new(manifest(InstallScope::User, Target::host())),
            &mut port,
            || false,
            |event| {
                if matches!(
                    event,
                    InstallEvent::Progress(progress) if progress.completed_files == 1
                ) {
                    panic!("observer failed");
                }
            },
        );
    }));

    assert!(panic.is_err());
    assert_eq!(port.calls.last().map(String::as_str), Some("rollback"));
}

#[test]
fn every_transaction_failure_attempts_rollback() {
    for fail_at in ["begin", "apply", "stage receipt", "commit"] {
        let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
        port.fail_at = Some(fail_at);

        let error = install(
            InstallCommand::new(manifest(InstallScope::User, Target::host())),
            &mut port,
            || false,
            |_| {},
        )
        .unwrap_err();

        assert!(matches!(error, InstallError::Port { .. }), "{fail_at}");
        assert_eq!(port.calls.last().map(String::as_str), Some("rollback"));
        assert!(port.receipt.is_none());
    }
}

#[test]
fn cancellation_after_mutation_rolls_back_at_the_next_checkpoint() {
    let applied = Rc::new(Cell::new(0));
    let mut port = FakeInstallPort::new(applied.clone());
    let mut events = Vec::new();

    let error = install(
        InstallCommand::new(manifest(InstallScope::User, Target::host())),
        &mut port,
        || applied.get() == 1,
        |event| events.push(event),
    )
    .unwrap_err();

    assert_eq!(error, InstallError::Cancelled);
    assert_eq!(applied.get(), 1);
    assert_eq!(port.calls.last().map(String::as_str), Some("rollback"));
    assert_eq!(
        events.last(),
        Some(&InstallEvent::Phase(InstallPhase::Cancelled))
    );
}

#[test]
fn reports_rollback_failure_without_hiding_the_original_failure() {
    let mut port = FakeInstallPort::new(Rc::new(Cell::new(0)));
    port.fail_at = Some("apply");
    port.rollback_fails = true;

    let error = install(
        InstallCommand::new(manifest(InstallScope::User, Target::host())),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap_err();

    match error {
        InstallError::Rollback { cause, rollback } => {
            assert!(matches!(
                *cause,
                InstallError::Port {
                    step: "apply file",
                    ..
                }
            ));
            assert_eq!(rollback.message(), "rollback failed");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

fn manifest(scope: InstallScope, target: Target) -> Manifest {
    Manifest {
        format_version: FORMAT_VERSION,
        schema_version: MANIFEST_SCHEMA_VERSION,
        package: Package {
            id: PackageId::parse("dev.luxury.demo").unwrap(),
            name: "Luxury Demo".into(),
            version: Version::new(1, 2, 3),
            publisher: "Luxury Software".into(),
            description: None,
            license: None,
        },
        target,
        install: InstallPolicy {
            scope,
            directory: InstallDirectory::parse("LuxuryDemo").unwrap(),
            allow_downgrade: false,
            entrypoint: None,
            show_install_log: false,
            finish_links: Vec::new(),
        },
        publisher_rotation: None,
        files: vec![
            file("bin/demo.exe", 4, 'a', true),
            file("share/readme.txt", 3, 'b', false),
        ],
    }
}

fn receipt(
    version: Version,
    directory: InstallDirectory,
    files: Vec<FileEntry>,
) -> OwnershipReceipt {
    receipt_with_identity(version, directory, PackageIdentity::Unsigned, files)
}

fn receipt_with_identity(
    version: Version,
    directory: InstallDirectory,
    package_identity: PackageIdentity,
    files: Vec<FileEntry>,
) -> OwnershipReceipt {
    OwnershipReceipt::new(
        PackageId::parse("dev.luxury.demo").unwrap(),
        version,
        InstallScope::User,
        directory,
        package_identity,
        files,
    )
    .unwrap()
}

fn receipt_with_entrypoint(
    version: Version,
    directory: InstallDirectory,
    files: Vec<FileEntry>,
    entrypoint: PackagePath,
) -> OwnershipReceipt {
    let receipt = receipt(version, directory, files);
    let mut value = serde_json::to_value(receipt).unwrap();
    value["entrypoint"] = serde_json::to_value(entrypoint).unwrap();
    let receipt: OwnershipReceipt = serde_json::from_value(value).unwrap();
    receipt.validate().unwrap();
    receipt
}

fn receipt_with_provenance(
    version: Version,
    directory: InstallDirectory,
    authorized_publisher: PackageIdentity,
    payload_signer: PackageIdentity,
    files: Vec<FileEntry>,
) -> OwnershipReceipt {
    let receipt = receipt_with_identity(version, directory, authorized_publisher, files);
    let mut value = serde_json::to_value(receipt).unwrap();
    value["payload_signer"] = serde_json::to_value(payload_signer).unwrap();
    let receipt: OwnershipReceipt = serde_json::from_value(value).unwrap();
    receipt.validate().unwrap();
    receipt
}

fn legacy_receipt(
    version: Version,
    directory: InstallDirectory,
    files: Vec<FileEntry>,
) -> OwnershipReceipt {
    let mut value = serde_json::to_value(receipt(version, directory, files)).unwrap();
    value["format_version"] = serde_json::json!(1);
    let value = value.as_object_mut().unwrap();
    value.remove("package_identity");
    value.remove("authorized_publisher");
    value.remove("payload_signer");
    let value = serde_json::Value::Object(value.clone());
    let receipt: OwnershipReceipt = serde_json::from_value(value).unwrap();
    receipt.validate().unwrap();
    receipt
}

fn trusted_identity(byte: u8) -> PackageIdentity {
    PackageIdentity::TrustedPublisher {
        key_id: PublisherKeyId::from_bytes([byte; 32]),
    }
}

fn file(path: &str, size: u64, digest: char, executable: bool) -> FileEntry {
    FileEntry {
        path: PackagePath::parse(path).unwrap(),
        size,
        sha256: self::digest(digest),
        executable,
    }
}

fn digest(value: char) -> Sha256Digest {
    Sha256Digest::parse(value.to_string().repeat(64)).unwrap()
}

fn non_host_target() -> Target {
    let host = Target::host();
    let os = match host.os {
        OperatingSystem::Windows => OperatingSystem::Linux,
        OperatingSystem::Linux => OperatingSystem::Macos,
        OperatingSystem::Macos => OperatingSystem::Windows,
    };
    Target {
        os,
        arch: match host.arch {
            Architecture::X86_64 => Architecture::X86_64,
            Architecture::Aarch64 => Architecture::Aarch64,
        },
    }
}
