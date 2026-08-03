use luxury_engine::{
    PortError,
    launch::{LaunchCommand, LaunchError, LaunchPort, launch},
    uninstall::{OwnershipReceipt, ReceiptError},
};
use luxury_spec::{
    FileEntry, InstallDirectory, InstallScope, PackageId, PackagePath, Sha256Digest, SpecError,
};
use semver::Version;

struct FakeLaunchPort {
    receipt: Option<OwnershipReceipt>,
    recovery_pending: bool,
    fail_at: Option<&'static str>,
    calls: Vec<String>,
    launched: Option<(OwnershipReceipt, FileEntry)>,
}

impl FakeLaunchPort {
    fn new(receipt: Option<OwnershipReceipt>) -> Self {
        Self {
            receipt,
            recovery_pending: false,
            fail_at: None,
            calls: Vec::new(),
            launched: None,
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

impl LaunchPort for FakeLaunchPort {
    fn recovery_pending(&mut self, _package_id: &PackageId) -> Result<bool, PortError> {
        self.calls.push("recovery pending".into());
        self.fail("recovery pending")?;
        Ok(self.recovery_pending)
    }

    fn load_receipt(
        &mut self,
        _package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError> {
        self.calls.push("load receipt".into());
        self.fail("load receipt")?;
        Ok(self.receipt.clone())
    }

    fn launch_owned_entrypoint(
        &mut self,
        receipt: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<(), PortError> {
        self.calls.push(format!("launch:{}", file.path));
        self.fail("launch")?;
        self.launched = Some((receipt.clone(), file.clone()));
        Ok(())
    }
}

#[test]
fn launches_only_the_exact_receipt_owned_entrypoint_in_port_order() {
    let receipt = receipt_with_entrypoint("dev.luxury.demo", "bin/demo.exe");
    let expected_file = receipt
        .files()
        .iter()
        .find(|file| file.path.as_str() == "bin/demo.exe")
        .unwrap()
        .clone();
    let mut port = FakeLaunchPort::new(Some(receipt.clone()));

    launch(command("dev.luxury.demo"), &mut port).unwrap();

    assert_eq!(
        port.calls,
        ["recovery pending", "load receipt", "launch:bin/demo.exe"]
    );
    assert_eq!(port.launched, Some((receipt, expected_file)));
}

#[test]
fn pending_recovery_stops_before_reading_or_launching() {
    let mut port = FakeLaunchPort::new(Some(receipt_with_entrypoint(
        "dev.luxury.demo",
        "bin/demo.exe",
    )));
    port.recovery_pending = true;

    let error = launch(command("dev.luxury.demo"), &mut port).unwrap_err();

    assert!(matches!(error, LaunchError::RecoveryPending { .. }));
    assert_eq!(port.calls, ["recovery pending"]);
    assert!(port.launched.is_none());
}

#[test]
fn missing_receipt_stops_after_the_ordered_reads() {
    let mut port = FakeLaunchPort::new(None);

    let error = launch(command("dev.luxury.demo"), &mut port).unwrap_err();

    assert!(matches!(error, LaunchError::NotInstalled { .. }));
    assert_eq!(port.calls, ["recovery pending", "load receipt"]);
}

#[test]
fn invalid_receipt_stops_before_package_or_entrypoint_use() {
    let valid = receipt_with_entrypoint("dev.luxury.other", "bin/demo.exe");
    let mut value = serde_json::to_value(valid).unwrap();
    let files = value["files"].as_array_mut().unwrap();
    files.push(files[0].clone());
    let invalid: OwnershipReceipt = serde_json::from_value(value).unwrap();
    let mut port = FakeLaunchPort::new(Some(invalid));

    let error = launch(command("dev.luxury.demo"), &mut port).unwrap_err();

    assert!(matches!(
        error,
        LaunchError::InvalidReceipt(ReceiptError::DuplicatePath(_))
    ));
    assert_eq!(port.calls, ["recovery pending", "load receipt"]);
}

#[test]
fn wrong_package_receipt_stops_before_entrypoint_launch() {
    let mut port = FakeLaunchPort::new(Some(receipt_with_entrypoint(
        "dev.luxury.other",
        "bin/demo.exe",
    )));

    let error = launch(command("dev.luxury.demo"), &mut port).unwrap_err();

    assert!(matches!(error, LaunchError::ReceiptPackageMismatch { .. }));
    assert_eq!(port.calls, ["recovery pending", "load receipt"]);
}

#[test]
fn system_receipt_requires_explicit_system_launch_authority() {
    let receipt = receipt_with_entrypoint("dev.luxury.demo", "bin/demo.exe");
    let mut value = serde_json::to_value(receipt).unwrap();
    value["scope"] = serde_json::json!("system");
    let receipt: OwnershipReceipt = serde_json::from_value(value).unwrap();
    receipt.validate().unwrap();

    let mut user_port = FakeLaunchPort::new(Some(receipt.clone()));
    let error = launch(command("dev.luxury.demo"), &mut user_port).unwrap_err();
    assert!(matches!(error, LaunchError::UnsupportedScope { .. }));
    assert_eq!(user_port.calls, ["recovery pending", "load receipt"]);

    let mut system_port = FakeLaunchPort::new(Some(receipt));
    launch(
        LaunchCommand::for_system(PackageId::parse("dev.luxury.demo").unwrap()),
        &mut system_port,
    )
    .unwrap();
    assert_eq!(
        system_port.calls,
        ["recovery pending", "load receipt", "launch:bin/demo.exe"]
    );
}

#[test]
fn absent_entrypoint_is_rejected_without_launching() {
    let mut port = FakeLaunchPort::new(Some(receipt("dev.luxury.demo")));

    let error = launch(command("dev.luxury.demo"), &mut port).unwrap_err();

    assert!(matches!(error, LaunchError::MissingEntrypoint { .. }));
    assert_eq!(port.calls, ["recovery pending", "load receipt"]);
}

#[test]
fn non_owned_entrypoint_is_an_invalid_receipt_and_never_reaches_the_port() {
    let receipt = receipt("dev.luxury.demo");
    let mut value = serde_json::to_value(receipt).unwrap();
    value["entrypoint"] = serde_json::json!("bin/missing.exe");
    let invalid: OwnershipReceipt = serde_json::from_value(value).unwrap();
    let mut port = FakeLaunchPort::new(Some(invalid));

    let error = launch(command("dev.luxury.demo"), &mut port).unwrap_err();

    assert_eq!(
        error,
        LaunchError::InvalidReceipt(ReceiptError::InvalidEntrypoint(
            SpecError::EntrypointMissingFile("bin/missing.exe".into())
        ))
    );
    assert_eq!(port.calls, ["recovery pending", "load receipt"]);
}

#[test]
fn every_port_failure_is_terminal_at_its_exact_step() {
    for (fail_at, expected_step, expected_calls) in [
        (
            "recovery pending",
            "check pending recovery",
            vec!["recovery pending"],
        ),
        (
            "load receipt",
            "load receipt",
            vec!["recovery pending", "load receipt"],
        ),
        (
            "launch",
            "launch owned entrypoint",
            vec!["recovery pending", "load receipt", "launch:bin/demo.exe"],
        ),
    ] {
        let mut port = FakeLaunchPort::new(Some(receipt_with_entrypoint(
            "dev.luxury.demo",
            "bin/demo.exe",
        )));
        port.fail_at = Some(fail_at);

        let error = launch(command("dev.luxury.demo"), &mut port).unwrap_err();

        assert!(matches!(
            error,
            LaunchError::Port { step, .. } if step == expected_step
        ));
        assert_eq!(port.calls, expected_calls);
        assert!(port.launched.is_none());
    }
}

fn command(package_id: &str) -> LaunchCommand {
    LaunchCommand::new(PackageId::parse(package_id).unwrap())
}

fn receipt_with_entrypoint(package_id: &str, entrypoint: &str) -> OwnershipReceipt {
    let receipt = receipt(package_id);
    let mut value = serde_json::to_value(receipt).unwrap();
    value["entrypoint"] = serde_json::json!(entrypoint);
    let receipt: OwnershipReceipt = serde_json::from_value(value).unwrap();
    receipt.validate().unwrap();
    receipt
}

fn receipt(package_id: &str) -> OwnershipReceipt {
    OwnershipReceipt::new(
        PackageId::parse(package_id).unwrap(),
        Version::new(1, 2, 3),
        InstallScope::User,
        InstallDirectory::parse("LuxuryDemo").unwrap(),
        luxury_engine::install::PackageIdentity::Unsigned,
        vec![
            file("bin/demo.exe", 'a', true),
            file("share/readme.txt", 'b', false),
        ],
    )
    .unwrap()
}

fn file(path: &str, digest: char, executable: bool) -> FileEntry {
    FileEntry {
        path: PackagePath::parse(path).unwrap(),
        size: 4,
        sha256: Sha256Digest::parse(digest.to_string().repeat(64)).unwrap(),
        executable,
    }
}
