use std::{cell::Cell, collections::BTreeMap, rc::Rc};

use luxury_engine::{
    PortError,
    install::PackageIdentity,
    uninstall::{
        OwnershipReceipt, ReceiptError, RemoveFileOutcome, UninstallCommand, UninstallError,
        UninstallEvent, UninstallOutcome, UninstallPhase, UninstallPort, uninstall,
    },
};
use luxury_spec::{
    FileEntry, InstallDirectory, InstallScope, PackageId, PackagePath, PublisherKeyId,
    Sha256Digest, SpecError,
};
use semver::Version;

struct FakeUninstallPort {
    receipt: Option<OwnershipReceipt>,
    files: BTreeMap<String, Sha256Digest>,
    removed: Vec<(String, Sha256Digest)>,
    calls: Vec<String>,
    fail_at: Option<&'static str>,
    rollback_fails: bool,
    processed: Rc<Cell<usize>>,
}

impl FakeUninstallPort {
    fn new(receipt: Option<OwnershipReceipt>, processed: Rc<Cell<usize>>) -> Self {
        Self {
            receipt,
            files: BTreeMap::new(),
            removed: Vec::new(),
            calls: Vec::new(),
            fail_at: None,
            rollback_fails: false,
            processed,
        }
    }

    fn fail(&self, step: &'static str) -> Result<(), PortError> {
        if self.fail_at == Some(step) {
            Err(PortError::new(format!("{step} failed")))
        } else {
            Ok(())
        }
    }
}

impl UninstallPort for FakeUninstallPort {
    fn recover_pending(&mut self, _package_id: &PackageId) -> Result<(), PortError> {
        self.calls.push("recover".into());
        self.fail("recover")
    }

    fn load_receipt(
        &mut self,
        _package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError> {
        self.calls.push("load receipt".into());
        self.fail("load receipt")?;
        Ok(self.receipt.clone())
    }

    fn begin(&mut self, _receipt: &OwnershipReceipt) -> Result<(), PortError> {
        self.calls.push("begin".into());
        self.fail("begin")
    }

    fn remove_if_unchanged(
        &mut self,
        _receipt: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<RemoveFileOutcome, PortError> {
        self.calls.push(format!("remove:{}", file.path));
        self.fail("remove")?;
        self.processed.set(self.processed.get() + 1);

        let Some(current) = self.files.get(file.path.as_str()) else {
            return Ok(RemoveFileOutcome::Missing);
        };
        if current != &file.sha256 {
            return Ok(RemoveFileOutcome::PreservedModified);
        }

        let digest = self.files.remove(file.path.as_str()).unwrap();
        self.removed.push((file.path.to_string(), digest));
        Ok(RemoveFileOutcome::Removed)
    }

    fn commit(&mut self) -> Result<(), PortError> {
        self.calls.push("commit".into());
        self.fail("commit")?;
        self.receipt = None;
        self.removed.clear();
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), PortError> {
        self.calls.push("rollback".into());
        for (path, digest) in self.removed.drain(..) {
            self.files.insert(path, digest);
        }
        if self.rollback_fails {
            Err(PortError::new("rollback failed"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn removes_only_unchanged_owned_files_and_preserves_everything_else() {
    let receipt = receipt("dev.luxury.demo");
    let processed = Rc::new(Cell::new(0));
    let mut port = FakeUninstallPort::new(Some(receipt), processed);
    port.files.insert("bin/demo.exe".into(), digest('a'));
    port.files.insert("share/readme.txt".into(), digest('9'));
    port.files.insert("notes/user.txt".into(), digest('f'));
    let mut events = Vec::new();

    let outcome = uninstall(
        UninstallCommand::new(PackageId::parse("dev.luxury.demo").unwrap()),
        &mut port,
        || false,
        |event| events.push(event),
    )
    .unwrap();

    assert_eq!(
        outcome,
        UninstallOutcome::Uninstalled {
            removed_files: 1,
            missing_files: 1,
            preserved_modified_files: 1,
        }
    );
    assert!(!port.files.contains_key("bin/demo.exe"));
    assert!(port.files.contains_key("share/readme.txt"));
    assert!(port.files.contains_key("notes/user.txt"));
    assert!(
        port.calls
            .iter()
            .all(|call| !call.contains("notes/user.txt"))
    );
    assert!(port.receipt.is_none());

    let progress = events
        .iter()
        .filter_map(|event| match event {
            UninstallEvent::Progress(progress) => Some(*progress),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        progress
            .windows(2)
            .all(|pair| pair[0].processed_files <= pair[1].processed_files)
    );
    assert_eq!(progress.last().unwrap().processed_files, 3);
    assert!(events.iter().any(|event| matches!(
        event,
        UninstallEvent::PreservedModified(path) if path.as_str() == "share/readme.txt"
    )));
    assert_eq!(
        events.last(),
        Some(&UninstallEvent::Phase(UninstallPhase::Completed))
    );
}

#[test]
fn missing_receipt_is_an_idempotent_noop() {
    let mut port = FakeUninstallPort::new(None, Rc::new(Cell::new(0)));

    let outcome = uninstall(
        UninstallCommand::new(PackageId::parse("dev.luxury.demo").unwrap()),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap();

    assert_eq!(outcome, UninstallOutcome::NotInstalled);
    assert_eq!(port.calls, ["recover", "load receipt"]);
}

#[test]
fn receipt_v5_binds_shortcuts_and_reads_v1_through_v4() {
    let current = receipt("dev.luxury.demo");
    assert_eq!(
        current.format_version(),
        luxury_engine::uninstall::RECEIPT_FORMAT_VERSION
    );
    assert_eq!(current.package_identity(), Some(PackageIdentity::Unsigned));
    assert_eq!(current.payload_signer(), Some(PackageIdentity::Unsigned));
    assert_eq!(current.entrypoint(), None);
    assert_eq!(current.shortcuts(), luxury_spec::ShortcutPolicy::default());
    let current_json = serde_json::to_value(&current).unwrap();
    assert_eq!(
        current_json["authorized_publisher"],
        serde_json::json!({"kind": "unsigned"})
    );
    assert_eq!(
        current_json["payload_signer"],
        serde_json::json!({"kind": "unsigned"})
    );
    assert!(current_json.get("package_identity").is_none());

    let mut v3_json = current_json.clone();
    v3_json["format_version"] = serde_json::json!(3);
    let v3: OwnershipReceipt = serde_json::from_value(v3_json.clone()).unwrap();
    v3.validate().unwrap();
    assert_eq!(v3.entrypoint(), None);

    let mut v4_json = current_json.clone();
    v4_json["format_version"] = serde_json::json!(4);
    let v4: OwnershipReceipt = serde_json::from_value(v4_json).unwrap();
    v4.validate().unwrap();
    assert_eq!(v4.shortcuts(), luxury_spec::ShortcutPolicy::default());

    let mut legacy_shortcuts_json = current_json.clone();
    legacy_shortcuts_json["format_version"] = serde_json::json!(4);
    legacy_shortcuts_json["shortcuts"] = serde_json::json!({"application_menu": true});
    let legacy_shortcuts: OwnershipReceipt = serde_json::from_value(legacy_shortcuts_json).unwrap();
    assert_eq!(
        legacy_shortcuts.validate(),
        Err(ReceiptError::LegacyShortcuts)
    );

    let mut shortcuts_without_entrypoint_json = current_json.clone();
    shortcuts_without_entrypoint_json["shortcuts"] = serde_json::json!({"desktop": true});
    let shortcuts_without_entrypoint: OwnershipReceipt =
        serde_json::from_value(shortcuts_without_entrypoint_json).unwrap();
    assert_eq!(
        shortcuts_without_entrypoint.validate(),
        Err(ReceiptError::ShortcutsWithoutEntrypoint)
    );

    let mut legacy_json = current_json.clone();
    legacy_json["format_version"] = serde_json::json!(1);
    let legacy_fields = legacy_json.as_object_mut().unwrap();
    legacy_fields.remove("authorized_publisher");
    legacy_fields.remove("payload_signer");
    let legacy: OwnershipReceipt = serde_json::from_value(legacy_json).unwrap();
    legacy.validate().unwrap();
    assert_eq!(legacy.package_identity(), None);
    assert_eq!(legacy.payload_signer(), None);

    let mut v2_json = current_json.clone();
    v2_json["format_version"] = serde_json::json!(2);
    let v2_fields = v2_json.as_object_mut().unwrap();
    v2_fields.remove("authorized_publisher");
    v2_fields.remove("payload_signer");
    v2_fields.insert(
        "package_identity".into(),
        serde_json::json!({"kind": "unsigned"}),
    );
    let v2: OwnershipReceipt = serde_json::from_value(v2_json).unwrap();
    v2.validate().unwrap();
    assert_eq!(v2.package_identity(), Some(PackageIdentity::Unsigned));
    assert_eq!(v2.payload_signer(), None);

    let mut missing_identity = current_json.clone();
    missing_identity
        .as_object_mut()
        .unwrap()
        .remove("authorized_publisher");
    let missing_identity: OwnershipReceipt = serde_json::from_value(missing_identity).unwrap();
    assert_eq!(
        missing_identity.validate(),
        Err(ReceiptError::MissingPackageIdentity)
    );

    let mut missing_signer = current_json.clone();
    missing_signer
        .as_object_mut()
        .unwrap()
        .remove("payload_signer");
    let missing_signer: OwnershipReceipt = serde_json::from_value(missing_signer).unwrap();
    assert_eq!(
        missing_signer.validate(),
        Err(ReceiptError::MissingPayloadSigner)
    );

    let mut mixed = current_json.clone();
    mixed["payload_signer"] = serde_json::json!({
        "kind": "trustedPublisher",
        "keyId": PublisherKeyId::from_bytes([7; 32]).to_string(),
    });
    let mixed: OwnershipReceipt = serde_json::from_value(mixed).unwrap();
    assert_eq!(
        mixed.validate(),
        Err(ReceiptError::MismatchedPublisherKinds)
    );

    let mut unsupported = current_json.clone();
    unsupported["format_version"] = serde_json::json!(6);
    let unsupported: OwnershipReceipt = serde_json::from_value(unsupported).unwrap();
    assert_eq!(
        unsupported.validate(),
        Err(ReceiptError::UnsupportedFormat {
            found: 6,
            supported: luxury_engine::uninstall::RECEIPT_FORMAT_VERSION,
        })
    );

    v3_json["entrypoint"] = serde_json::json!("bin/demo.exe");
    let v3_with_entrypoint: OwnershipReceipt = serde_json::from_value(v3_json).unwrap();
    assert_eq!(
        v3_with_entrypoint.validate(),
        Err(ReceiptError::LegacyEntrypoint)
    );

    let mut entrypoint_json = current_json.clone();
    entrypoint_json["entrypoint"] = serde_json::json!("bin/demo.exe");
    let with_entrypoint: OwnershipReceipt =
        serde_json::from_value(entrypoint_json.clone()).unwrap();
    with_entrypoint.validate().unwrap();
    assert_eq!(
        with_entrypoint.entrypoint().map(PackagePath::as_str),
        Some("bin/demo.exe")
    );

    entrypoint_json["entrypoint"] = serde_json::json!("bin/missing.exe");
    let non_owned_entrypoint: OwnershipReceipt = serde_json::from_value(entrypoint_json).unwrap();
    assert_eq!(
        non_owned_entrypoint.validate(),
        Err(ReceiptError::InvalidEntrypoint(
            SpecError::EntrypointMissingFile("bin/missing.exe".into())
        ))
    );

    let mut legacy_with_identity = current_json;
    legacy_with_identity["format_version"] = serde_json::json!(1);
    let legacy_with_identity: OwnershipReceipt =
        serde_json::from_value(legacy_with_identity).unwrap();
    assert_eq!(
        legacy_with_identity.validate(),
        Err(ReceiptError::LegacyPackageIdentity)
    );

    let processed = Rc::new(Cell::new(0));
    let mut port = FakeUninstallPort::new(Some(legacy), processed);
    port.files.insert("bin/demo.exe".into(), digest('a'));
    port.files.insert("share/readme.txt".into(), digest('b'));
    port.files.insert("missing.dat".into(), digest('c'));
    let outcome = uninstall(
        UninstallCommand::new(PackageId::parse("dev.luxury.demo").unwrap()),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap();
    assert!(matches!(outcome, UninstallOutcome::Uninstalled { .. }));
    assert!(port.receipt.is_none());
}

#[test]
fn receipt_load_failure_is_terminal_without_rollback() {
    let mut port = FakeUninstallPort::new(None, Rc::new(Cell::new(0)));
    port.fail_at = Some("load receipt");
    let mut events = Vec::new();

    let error = uninstall(
        UninstallCommand::new(PackageId::parse("dev.luxury.demo").unwrap()),
        &mut port,
        || false,
        |event| events.push(event),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        UninstallError::Port {
            step: "load receipt",
            ..
        }
    ));
    assert_eq!(port.calls, ["recover", "load receipt"]);
    assert_eq!(
        events.last(),
        Some(&UninstallEvent::Phase(UninstallPhase::Failed))
    );
}

#[test]
fn cancellation_restores_files_removed_in_the_current_transaction() {
    let receipt = receipt("dev.luxury.demo");
    let processed = Rc::new(Cell::new(0));
    let mut port = FakeUninstallPort::new(Some(receipt), processed.clone());
    port.files.insert("bin/demo.exe".into(), digest('a'));
    port.files.insert("share/readme.txt".into(), digest('b'));
    port.files.insert("missing.dat".into(), digest('c'));

    let error = uninstall(
        UninstallCommand::new(PackageId::parse("dev.luxury.demo").unwrap()),
        &mut port,
        || processed.get() == 1,
        |_| {},
    )
    .unwrap_err();

    assert_eq!(error, UninstallError::Cancelled);
    assert!(port.files.contains_key("bin/demo.exe"));
    assert!(port.files.contains_key("share/readme.txt"));
    assert!(port.receipt.is_some());
    assert_eq!(port.calls.last().map(String::as_str), Some("rollback"));
}

#[test]
fn commit_failure_rolls_back_removed_files_and_keeps_receipt() {
    let receipt = receipt("dev.luxury.demo");
    let mut port = FakeUninstallPort::new(Some(receipt), Rc::new(Cell::new(0)));
    port.files.insert("bin/demo.exe".into(), digest('a'));
    port.files.insert("share/readme.txt".into(), digest('b'));
    port.fail_at = Some("commit");

    let error = uninstall(
        UninstallCommand::new(PackageId::parse("dev.luxury.demo").unwrap()),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap_err();

    assert!(matches!(error, UninstallError::Port { step: "commit", .. }));
    assert!(port.files.contains_key("bin/demo.exe"));
    assert!(port.files.contains_key("share/readme.txt"));
    assert!(port.receipt.is_some());
    assert_eq!(port.calls.last().map(String::as_str), Some("rollback"));
}

#[test]
fn rejects_tampered_or_wrong_package_receipts_before_mutation() {
    let valid = receipt("dev.luxury.demo");
    let mut json = serde_json::to_value(&valid).unwrap();
    let files = json["files"].as_array_mut().unwrap();
    files.push(files[0].clone());
    let duplicate: OwnershipReceipt = serde_json::from_value(json).unwrap();
    assert!(matches!(
        duplicate.validate(),
        Err(ReceiptError::DuplicatePath(_))
    ));

    let mut port = FakeUninstallPort::new(Some(duplicate), Rc::new(Cell::new(0)));
    let error = uninstall(
        UninstallCommand::new(PackageId::parse("dev.luxury.demo").unwrap()),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(error, UninstallError::InvalidReceipt(_)));
    assert_eq!(port.calls, ["recover", "load receipt"]);

    let mut port = FakeUninstallPort::new(Some(receipt("dev.luxury.other")), Rc::new(Cell::new(0)));
    let error = uninstall(
        UninstallCommand::new(PackageId::parse("dev.luxury.demo").unwrap()),
        &mut port,
        || false,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(
        error,
        UninstallError::ReceiptPackageMismatch { .. }
    ));
    assert_eq!(port.calls, ["recover", "load receipt"]);
}

#[test]
fn system_receipt_requires_explicit_system_uninstall_authority() {
    let receipt = receipt("dev.luxury.demo");
    let mut value = serde_json::to_value(receipt).unwrap();
    value["scope"] = serde_json::json!("system");
    let receipt: OwnershipReceipt = serde_json::from_value(value).unwrap();
    receipt.validate().unwrap();

    let mut user_port = FakeUninstallPort::new(Some(receipt.clone()), Rc::new(Cell::new(0)));
    let error = uninstall(
        UninstallCommand::new(PackageId::parse("dev.luxury.demo").unwrap()),
        &mut user_port,
        || false,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(error, UninstallError::UnsupportedScope { .. }));
    assert_eq!(user_port.calls, ["recover", "load receipt"]);

    let mut system_port = FakeUninstallPort::new(Some(receipt), Rc::new(Cell::new(0)));
    let outcome = uninstall(
        UninstallCommand::for_system(PackageId::parse("dev.luxury.demo").unwrap()),
        &mut system_port,
        || false,
        |_| {},
    )
    .unwrap();
    assert_eq!(
        outcome,
        UninstallOutcome::Uninstalled {
            removed_files: 0,
            missing_files: 3,
            preserved_modified_files: 0,
        }
    );
}

#[test]
fn observer_panic_after_mutation_rolls_back() {
    let receipt = receipt("dev.luxury.demo");
    let mut port = FakeUninstallPort::new(Some(receipt), Rc::new(Cell::new(0)));
    port.files.insert("bin/demo.exe".into(), digest('a'));

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = uninstall(
            UninstallCommand::new(PackageId::parse("dev.luxury.demo").unwrap()),
            &mut port,
            || false,
            |event| {
                if matches!(
                    event,
                    UninstallEvent::Progress(progress) if progress.processed_files == 1
                ) {
                    panic!("observer failed");
                }
            },
        );
    }));

    assert!(panic.is_err());
    assert_eq!(port.calls.last().map(String::as_str), Some("rollback"));
    assert!(port.files.contains_key("bin/demo.exe"));
}

fn receipt(package_id: &str) -> OwnershipReceipt {
    OwnershipReceipt::new(
        PackageId::parse(package_id).unwrap(),
        Version::new(1, 2, 3),
        InstallScope::User,
        InstallDirectory::parse("LuxuryDemo").unwrap(),
        PackageIdentity::Unsigned,
        vec![
            file("bin/demo.exe", 'a'),
            file("share/readme.txt", 'b'),
            file("missing.dat", 'c'),
        ],
    )
    .unwrap()
}

fn file(path: &str, sha256: char) -> FileEntry {
    FileEntry {
        path: PackagePath::parse(path).unwrap(),
        size: 4,
        sha256: digest(sha256),
        executable: path.ends_with(".exe"),
    }
}

fn digest(value: char) -> Sha256Digest {
    Sha256Digest::parse(value.to_string().repeat(64)).unwrap()
}
