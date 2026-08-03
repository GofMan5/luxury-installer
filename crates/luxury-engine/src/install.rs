//! Transactional install vertical slice.

use std::{
    cmp::Ordering,
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};

use luxury_spec::{
    FileEntry, InstallDirectory, InstallScope, Manifest, PackageId, PackagePath, PublisherKeyId,
    SpecError, Target,
};
use semver::Version;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use crate::{
    PortError, PortErrorKind,
    uninstall::{OwnershipReceipt, ReceiptError, RemoveFileOutcome},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallCommand {
    pub manifest: Manifest,
    allowed_scope: InstallScope,
    license_accepted: bool,
    allow_downgrade: bool,
    allow_publisher_migration: bool,
}

impl InstallCommand {
    pub fn new(manifest: Manifest) -> Self {
        Self {
            manifest,
            allowed_scope: InstallScope::User,
            license_accepted: false,
            allow_downgrade: false,
            allow_publisher_migration: false,
        }
    }

    /// Construct a command for an already-authenticated privileged composition root.
    /// Ordinary CLI/stdio callers must keep using [`Self::new`].
    pub fn for_system(manifest: Manifest) -> Self {
        Self {
            allowed_scope: InstallScope::System,
            ..Self::new(manifest)
        }
    }

    /// Confirm that the caller presented and accepted the exact license text
    /// carried by this manifest. Packages without a license need no approval.
    pub fn with_license_acceptance(mut self, accepted: bool) -> Self {
        self.license_accepted = accepted;
        self
    }

    /// Approve replacing a newer installed version. The package policy and
    /// this caller-owned approval must both allow the downgrade.
    pub fn with_downgrade_approval(mut self, allow: bool) -> Self {
        self.allow_downgrade = allow;
        self
    }

    /// Approve adopting the verified package identity for a legacy or unsigned
    /// installation. This never permits replacing or dropping a trusted key.
    pub fn with_publisher_migration_approval(mut self, allow: bool) -> Self {
        self.allow_publisher_migration = allow;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PackageIdentity {
    Unsigned,
    TrustedPublisher {
        #[serde(rename = "keyId")]
        key_id: PublisherKeyId,
    },
}

/// Identity proven by the bundle adapter. A rotation target is accepted only
/// after the bundle format has verified its proof of possession.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedPackageIdentity {
    Unsigned,
    TrustedPublisher {
        signer_key_id: PublisherKeyId,
        rotation_to: Option<PublisherKeyId>,
    },
}

impl VerifiedPackageIdentity {
    pub const fn package_identity(self) -> PackageIdentity {
        match self {
            Self::Unsigned => PackageIdentity::Unsigned,
            Self::TrustedPublisher {
                signer_key_id,
                rotation_to,
            } => PackageIdentity::TrustedPublisher {
                key_id: match rotation_to {
                    Some(key_id) => key_id,
                    None => signer_key_id,
                },
            },
        }
    }

    pub const fn payload_signer(self) -> PackageIdentity {
        match self {
            Self::Unsigned => PackageIdentity::Unsigned,
            Self::TrustedPublisher { signer_key_id, .. } => PackageIdentity::TrustedPublisher {
                key_id: signer_key_id,
            },
        }
    }
}

impl<'de> Deserialize<'de> for PackageIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StoredIdentity {
            kind: IdentityKind,
            #[serde(default, rename = "keyId")]
            key_id: Option<PublisherKeyId>,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        enum IdentityKind {
            Unsigned,
            TrustedPublisher,
        }

        let stored = StoredIdentity::deserialize(deserializer)?;
        match (stored.kind, stored.key_id) {
            (IdentityKind::Unsigned, None) => Ok(Self::Unsigned),
            (IdentityKind::TrustedPublisher, Some(key_id)) => Ok(Self::TrustedPublisher { key_id }),
            (IdentityKind::Unsigned, Some(_)) => Err(D::Error::custom(
                "unsigned package identity must not contain keyId",
            )),
            (IdentityKind::TrustedPublisher, None) => Err(D::Error::custom(
                "trustedPublisher package identity requires keyId",
            )),
        }
    }
}

/// A validated, host-compatible plan created during preparation or installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    package_id: PackageId,
    version: Version,
    scope: InstallScope,
    directory: InstallDirectory,
    entrypoint: Option<PackagePath>,
    verified_identity: VerifiedPackageIdentity,
    files: Vec<FileEntry>,
    total_bytes: u64,
}

impl InstallPlan {
    fn from_manifest(manifest: &Manifest, verified_identity: VerifiedPackageIdentity) -> Self {
        Self {
            package_id: manifest.package.id.clone(),
            version: manifest.package.version.clone(),
            scope: manifest.install.scope,
            directory: manifest.install.directory.clone(),
            entrypoint: manifest.install.entrypoint.clone(),
            verified_identity,
            files: manifest.files.clone(),
            total_bytes: manifest.payload_size(),
        }
    }

    pub fn package_id(&self) -> &PackageId {
        &self.package_id
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn scope(&self) -> InstallScope {
        self.scope
    }

    pub fn directory(&self) -> &InstallDirectory {
        &self.directory
    }

    pub fn entrypoint(&self) -> Option<&PackagePath> {
        self.entrypoint.as_ref()
    }

    pub fn package_identity(&self) -> PackageIdentity {
        self.verified_identity.package_identity()
    }

    pub fn payload_signer(&self) -> PackageIdentity {
        self.verified_identity.payload_signer()
    }

    pub fn verified_identity(&self) -> VerifiedPackageIdentity {
        self.verified_identity
    }

    pub fn files(&self) -> &[FileEntry] {
        &self.files
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Build the durable ownership state for this verified plan.
    pub fn ownership_receipt(&self) -> OwnershipReceipt {
        OwnershipReceipt::from_install_plan(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallPhase {
    Validating,
    Verifying,
    Recovering,
    Planning,
    Applying,
    Committing,
    RollingBack,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallProgress {
    pub completed_files: usize,
    pub total_files: usize,
    pub completed_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallEvent {
    Phase(InstallPhase),
    Action(InstallAction),
    Progress(InstallProgress),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    pub package_id: PackageId,
    pub action: InstallAction,
    pub installed_files: usize,
    pub installed_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallAction {
    Install,
    Update,
    Repair,
    Downgrade,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallPrepareOutcome {
    Ready {
        action: InstallAction,
        installed_version: Option<Version>,
        publisher_migration_required: bool,
    },
    InsufficientSpace {
        action: InstallAction,
        installed_version: Option<Version>,
        publisher_migration_required: bool,
    },
    RecoveryRequired,
}

/// Read-only checks shared by advisory preparation and the mutating install.
pub trait InstallPreparePort {
    /// Authenticate and fully verify the package payload without mutating the destination.
    fn verify_package(&mut self, manifest: &Manifest)
    -> Result<VerifiedPackageIdentity, PortError>;

    /// Report whether interrupted state must be recovered by a mutating install.
    fn recovery_pending(&mut self, package_id: &PackageId) -> Result<bool, PortError>;

    /// Read the external ownership receipt without mutating installed state.
    fn load_receipt(
        &mut self,
        package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError>;

    /// Re-check recovery and receipt state, destination collisions, and bounded-work
    /// limits without mutating the destination.
    fn preflight(
        &mut self,
        plan: &InstallPlan,
        previous: Option<&OwnershipReceipt>,
    ) -> Result<(), PortError>;
}

/// Mutating methods are transactional. `rollback` must be idempotent and undo
/// everything performed since `begin`, including a staged ownership receipt.
pub trait InstallPort: InstallPreparePort {
    /// Recover or finish an interrupted transaction for this package after
    /// authentication and before any new destination mutation begins.
    fn recover_pending(&mut self, package_id: &PackageId) -> Result<(), PortError>;

    /// Acquire the package and destination locks, re-check the receipt snapshot
    /// and all destination collisions, then create durable transaction state.
    fn begin(
        &mut self,
        plan: &InstallPlan,
        previous: Option<&OwnershipReceipt>,
    ) -> Result<(), PortError>;

    /// Remove one file owned only by the previous receipt if its content is
    /// unchanged. Missing or modified files are preserved.
    fn remove_obsolete(
        &mut self,
        previous: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<RemoveFileOutcome, PortError>;

    /// Stage/apply exactly one verified regular file from the package.
    fn apply_file(&mut self, file: &FileEntry) -> Result<(), PortError>;

    /// Stage the receipt in the platform state root, outside the installed tree.
    fn stage_receipt(&mut self, receipt: &OwnershipReceipt) -> Result<(), PortError>;

    /// Atomically publish the external receipt as the commit point. `Err` means
    /// the transaction is definitely still rollbackable; cleanup after a
    /// successful publish must be deferred instead of returned as an error.
    /// Cancellation is ignored here.
    fn commit(&mut self) -> Result<(), PortError>;

    fn rollback(&mut self) -> Result<(), PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InstallError {
    #[error(transparent)]
    InvalidManifest(#[from] SpecError),
    #[error("package target {package:?} does not match host {host:?}")]
    UnsupportedTarget { package: Target, host: Target },
    #[error("install scope {found:?} is not supported; only user scope is enabled")]
    UnsupportedScope { found: InstallScope },
    #[error("package license must be accepted before installation")]
    LicenseNotAccepted,
    #[error(transparent)]
    InvalidReceipt(#[from] ReceiptError),
    #[error("installed receipt does not match requested {field}")]
    ReceiptMismatch { field: &'static str },
    #[error("publisher migration from {installed:?} to {requested:?} requires caller approval")]
    PublisherMigrationDenied {
        installed: Option<PackageIdentity>,
        requested: PackageIdentity,
    },
    #[error("installed publisher identity {installed:?} does not match {requested:?}")]
    PublisherMismatch {
        installed: PackageIdentity,
        requested: PackageIdentity,
    },
    #[error(
        "publisher rotation from signer {signer_key_id} to {rotation_to} is not valid for installed identity {installed:?}"
    )]
    PublisherRotationDenied {
        installed: Option<PackageIdentity>,
        signer_key_id: PublisherKeyId,
        rotation_to: PublisherKeyId,
    },
    #[error(
        "downgrade from {installed} to {requested} requires package policy and caller approval"
    )]
    DowngradeDenied {
        installed: Version,
        requested: Version,
    },
    #[error(
        "installed version {version} has different files or entrypoint; same-version reinstall is refused"
    )]
    ReinstallMismatch { version: Version },
    #[error(
        "installed path `{installed}` aliases requested path `{requested}`; portable path renames require an explicit migration"
    )]
    PathAliasChanged {
        installed: PackagePath,
        requested: PackagePath,
    },
    #[error("installation cancelled")]
    Cancelled,
    #[error("install step `{step}` failed: {source}")]
    Port {
        step: &'static str,
        source: PortError,
    },
    #[error("{cause}; rollback failed: {rollback}")]
    Rollback {
        cause: Box<InstallError>,
        rollback: PortError,
    },
}

/// Inspect whether an installation can start without recovering or mutating state.
pub fn prepare_install<P>(
    manifest: Manifest,
    port: &mut P,
) -> Result<InstallPrepareOutcome, InstallError>
where
    P: InstallPreparePort,
{
    prepare_install_for_scope(manifest, InstallScope::User, port)
}

/// Read-only preparation for an authenticated system helper.
pub fn prepare_system_install<P>(
    manifest: Manifest,
    port: &mut P,
) -> Result<InstallPrepareOutcome, InstallError>
where
    P: InstallPreparePort,
{
    prepare_install_for_scope(manifest, InstallScope::System, port)
}

fn prepare_install_for_scope<P>(
    manifest: Manifest,
    allowed_scope: InstallScope,
    port: &mut P,
) -> Result<InstallPrepareOutcome, InstallError>
where
    P: InstallPreparePort,
{
    validate_install_manifest(&manifest, allowed_scope)?;
    let verified_identity =
        port.verify_package(&manifest)
            .map_err(|source| InstallError::Port {
                step: "verify package",
                source,
            })?;
    let plan = InstallPlan::from_manifest(&manifest, verified_identity);
    if port
        .recovery_pending(plan.package_id())
        .map_err(|source| InstallError::Port {
            step: "check pending recovery",
            source,
        })?
    {
        return Ok(InstallPrepareOutcome::RecoveryRequired);
    }
    let previous = port
        .load_receipt(plan.package_id())
        .map_err(|source| InstallError::Port {
            step: "load receipt",
            source,
        })?;
    let assessment = assess_install(&plan, previous.as_ref(), AssessmentMode::Prepare)?;
    if let Err(source) = port.preflight(&plan, previous.as_ref()) {
        if port
            .recovery_pending(plan.package_id())
            .map_err(|source| InstallError::Port {
                step: "check pending recovery",
                source,
            })?
        {
            return Ok(InstallPrepareOutcome::RecoveryRequired);
        }
        if source.kind() == PortErrorKind::Capacity {
            return Ok(InstallPrepareOutcome::InsufficientSpace {
                action: assessment.action,
                installed_version: assessment.installed_version,
                publisher_migration_required: assessment.publisher_migration_required,
            });
        }
        return Err(InstallError::Port {
            step: "preflight",
            source,
        });
    }

    Ok(InstallPrepareOutcome::Ready {
        action: assessment.action,
        installed_version: assessment.installed_version,
        publisher_migration_required: assessment.publisher_migration_required,
    })
}

/// Execute one installation. The cancellation callback is sampled only at safe
/// checkpoints; once `commit` starts it runs to completion.
pub fn install<P, C, E>(
    command: InstallCommand,
    port: &mut P,
    mut is_cancelled: C,
    mut emit: E,
) -> Result<InstallOutcome, InstallError>
where
    P: InstallPort,
    C: FnMut() -> bool,
    E: FnMut(InstallEvent),
{
    if is_cancelled() {
        emit(InstallEvent::Phase(InstallPhase::Cancelled));
        return Err(InstallError::Cancelled);
    }

    emit(InstallEvent::Phase(InstallPhase::Validating));
    if let Err(error) = validate_install_manifest(&command.manifest, command.allowed_scope) {
        emit(InstallEvent::Phase(InstallPhase::Failed));
        return Err(error);
    }
    if command.manifest.package.license.is_some() && !command.license_accepted {
        emit(InstallEvent::Phase(InstallPhase::Failed));
        return Err(InstallError::LicenseNotAccepted);
    }

    emit(InstallEvent::Phase(InstallPhase::Verifying));
    let verified_identity = match port.verify_package(&command.manifest) {
        Ok(identity) => identity,
        Err(source) => {
            emit(InstallEvent::Phase(InstallPhase::Failed));
            return Err(InstallError::Port {
                step: "verify package",
                source,
            });
        }
    };

    emit(InstallEvent::Phase(InstallPhase::Recovering));
    if let Err(source) = port.recover_pending(&command.manifest.package.id) {
        emit(InstallEvent::Phase(InstallPhase::Failed));
        return Err(InstallError::Port {
            step: "recover pending transaction",
            source,
        });
    }
    if is_cancelled() {
        emit(InstallEvent::Phase(InstallPhase::Cancelled));
        return Err(InstallError::Cancelled);
    }

    emit(InstallEvent::Phase(InstallPhase::Planning));
    let plan = InstallPlan::from_manifest(&command.manifest, verified_identity);
    let previous = match port.load_receipt(plan.package_id()) {
        Ok(receipt) => receipt,
        Err(source) => {
            emit(InstallEvent::Phase(InstallPhase::Failed));
            return Err(InstallError::Port {
                step: "load receipt",
                source,
            });
        }
    };
    let assessment = match assess_install(
        &plan,
        previous.as_ref(),
        AssessmentMode::Install {
            allow_publisher_migration: command.allow_publisher_migration,
            allow_downgrade: command.manifest.install.allow_downgrade && command.allow_downgrade,
        },
    ) {
        Ok(assessment) => assessment,
        Err(error) => {
            emit(InstallEvent::Phase(InstallPhase::Failed));
            return Err(error);
        }
    };
    let action = assessment.action;
    emit(InstallEvent::Action(action));
    let obsolete = assessment.obsolete;
    let mut progress = InstallProgress {
        completed_files: 0,
        total_files: plan.files.len() + obsolete.len(),
        completed_bytes: 0,
        total_bytes: plan.total_bytes,
    };
    emit(InstallEvent::Progress(progress));
    if is_cancelled() {
        emit(InstallEvent::Phase(InstallPhase::Cancelled));
        return Err(InstallError::Cancelled);
    }
    if let Err(source) = port.preflight(&plan, previous.as_ref()) {
        emit(InstallEvent::Phase(InstallPhase::Failed));
        return Err(InstallError::Port {
            step: "preflight",
            source,
        });
    }
    if is_cancelled() {
        emit(InstallEvent::Phase(InstallPhase::Cancelled));
        return Err(InstallError::Cancelled);
    }

    let mut transaction_started = false;
    let mut committed = false;
    let result = catch_unwind(AssertUnwindSafe(|| {
        emit(InstallEvent::Phase(InstallPhase::Applying));
        transaction_started = true;
        if let Err(source) = port.begin(&plan, previous.as_ref()) {
            let error = rollback(
                port,
                InstallError::Port {
                    step: "begin transaction",
                    source,
                },
                &mut emit,
            );
            emit_terminal_error(&error, &mut emit);
            return Err(error);
        }

        if let Some(previous) = &previous {
            for file in &obsolete {
                if is_cancelled() {
                    let error = rollback(port, InstallError::Cancelled, &mut emit);
                    emit_terminal_error(&error, &mut emit);
                    return Err(error);
                }
                if let Err(source) = port.remove_obsolete(previous, file) {
                    let error = rollback(
                        port,
                        InstallError::Port {
                            step: "remove obsolete file",
                            source,
                        },
                        &mut emit,
                    );
                    emit_terminal_error(&error, &mut emit);
                    return Err(error);
                }
                progress.completed_files += 1;
                emit(InstallEvent::Progress(progress));
            }
        }

        for file in &plan.files {
            if is_cancelled() {
                let error = rollback(port, InstallError::Cancelled, &mut emit);
                emit_terminal_error(&error, &mut emit);
                return Err(error);
            }
            if let Err(source) = port.apply_file(file) {
                let error = rollback(
                    port,
                    InstallError::Port {
                        step: "apply file",
                        source,
                    },
                    &mut emit,
                );
                emit_terminal_error(&error, &mut emit);
                return Err(error);
            }
            progress.completed_files += 1;
            progress.completed_bytes += file.size;
            emit(InstallEvent::Progress(progress));
        }

        if is_cancelled() {
            let error = rollback(port, InstallError::Cancelled, &mut emit);
            emit_terminal_error(&error, &mut emit);
            return Err(error);
        }

        emit(InstallEvent::Phase(InstallPhase::Committing));
        let receipt = plan.ownership_receipt();
        if let Err(source) = port.stage_receipt(&receipt) {
            let error = rollback(
                port,
                InstallError::Port {
                    step: "stage receipt",
                    source,
                },
                &mut emit,
            );
            emit_terminal_error(&error, &mut emit);
            return Err(error);
        }
        if is_cancelled() {
            let error = rollback(port, InstallError::Cancelled, &mut emit);
            emit_terminal_error(&error, &mut emit);
            return Err(error);
        }
        if let Err(source) = port.commit() {
            let error = rollback(
                port,
                InstallError::Port {
                    step: "commit",
                    source,
                },
                &mut emit,
            );
            emit_terminal_error(&error, &mut emit);
            return Err(error);
        }

        committed = true;
        emit(InstallEvent::Phase(InstallPhase::Completed));
        Ok(InstallOutcome {
            package_id: plan.package_id,
            action,
            installed_files: plan.files.len(),
            installed_bytes: plan.total_bytes,
        })
    }));

    match result {
        Ok(result) => result,
        Err(panic) => {
            if transaction_started && !committed {
                let _ = catch_unwind(AssertUnwindSafe(|| port.rollback()));
            }
            resume_unwind(panic)
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AssessmentMode {
    Prepare,
    Install {
        allow_publisher_migration: bool,
        allow_downgrade: bool,
    },
}

struct InstallAssessment {
    action: InstallAction,
    installed_version: Option<Version>,
    publisher_migration_required: bool,
    obsolete: Vec<FileEntry>,
}

fn assess_install(
    plan: &InstallPlan,
    previous: Option<&OwnershipReceipt>,
    mode: AssessmentMode,
) -> Result<InstallAssessment, InstallError> {
    let Some(previous) = previous else {
        validate_fresh_publisher(plan.verified_identity())?;
        return Ok(InstallAssessment {
            action: InstallAction::Install,
            installed_version: None,
            publisher_migration_required: false,
            obsolete: Vec::new(),
        });
    };

    previous.validate()?;
    if previous.package_id() != plan.package_id() {
        return Err(InstallError::ReceiptMismatch {
            field: "package id",
        });
    }
    if previous.scope() != plan.scope() {
        return Err(InstallError::ReceiptMismatch { field: "scope" });
    }
    if previous.directory() != plan.directory() {
        return Err(InstallError::ReceiptMismatch { field: "directory" });
    }
    let precedence = plan.version().cmp_precedence(previous.version());
    let publisher_migration_required =
        assess_publisher_transition(plan.verified_identity(), previous, precedence)?;
    if publisher_migration_required
        && matches!(
            mode,
            AssessmentMode::Install {
                allow_publisher_migration: false,
                ..
            }
        )
    {
        return Err(InstallError::PublisherMigrationDenied {
            installed: previous.package_identity(),
            requested: plan.package_identity(),
        });
    }

    let action = match precedence {
        Ordering::Less => {
            if !matches!(
                mode,
                AssessmentMode::Install {
                    allow_downgrade: true,
                    ..
                }
            ) {
                return Err(InstallError::DowngradeDenied {
                    installed: previous.version().clone(),
                    requested: plan.version().clone(),
                });
            }
            InstallAction::Downgrade
        }
        Ordering::Equal => {
            if previous.files() != plan.files() || previous.entrypoint() != plan.entrypoint() {
                return Err(InstallError::ReinstallMismatch {
                    version: plan.version().clone(),
                });
            }
            InstallAction::Repair
        }
        Ordering::Greater => InstallAction::Update,
    };

    let requested_paths = plan
        .files()
        .iter()
        .map(|file| (file.path.collision_key(), &file.path))
        .collect::<HashMap<_, _>>();
    let mut obsolete = Vec::new();
    for file in previous.files() {
        match requested_paths.get(&file.path.collision_key()) {
            Some(requested) if *requested != &file.path => {
                return Err(InstallError::PathAliasChanged {
                    installed: file.path.clone(),
                    requested: (*requested).clone(),
                });
            }
            Some(_) => {}
            None => obsolete.push(file.clone()),
        }
    }
    Ok(InstallAssessment {
        action,
        installed_version: Some(previous.version().clone()),
        publisher_migration_required,
        obsolete,
    })
}

fn assess_publisher_transition(
    verified: VerifiedPackageIdentity,
    previous: &OwnershipReceipt,
    precedence: Ordering,
) -> Result<bool, InstallError> {
    if let VerifiedPackageIdentity::TrustedPublisher {
        signer_key_id,
        rotation_to: Some(rotation_to),
    } = verified
    {
        let signer = PackageIdentity::TrustedPublisher {
            key_id: signer_key_id,
        };
        if signer_key_id == rotation_to
            || previous.package_identity() != Some(signer)
            || precedence != Ordering::Greater
        {
            return Err(InstallError::PublisherRotationDenied {
                installed: previous.package_identity(),
                signer_key_id,
                rotation_to,
            });
        }
        return Ok(false);
    }

    let requested = verified.package_identity();
    let installed = previous.package_identity();
    match (installed, requested) {
        (Some(installed), requested) if installed == requested => Ok(false),
        (None, _) | (Some(PackageIdentity::Unsigned), PackageIdentity::TrustedPublisher { .. }) => {
            Ok(true)
        }
        (Some(installed @ PackageIdentity::TrustedPublisher { .. }), requested)
        | (Some(installed @ PackageIdentity::Unsigned), requested) => {
            Err(InstallError::PublisherMismatch {
                installed,
                requested,
            })
        }
    }
}

fn validate_install_manifest(
    manifest: &Manifest,
    allowed_scope: InstallScope,
) -> Result<(), InstallError> {
    manifest.validate()?;
    let host = Target::host();
    if manifest.target != host {
        return Err(InstallError::UnsupportedTarget {
            package: manifest.target,
            host,
        });
    }
    if manifest.install.scope != allowed_scope {
        return Err(InstallError::UnsupportedScope {
            found: manifest.install.scope,
        });
    }
    Ok(())
}

fn validate_fresh_publisher(verified: VerifiedPackageIdentity) -> Result<(), InstallError> {
    if let VerifiedPackageIdentity::TrustedPublisher {
        signer_key_id,
        rotation_to: Some(rotation_to),
    } = verified
    {
        return Err(InstallError::PublisherRotationDenied {
            installed: None,
            signer_key_id,
            rotation_to,
        });
    }
    Ok(())
}

fn rollback<P, E>(port: &mut P, cause: InstallError, emit: &mut E) -> InstallError
where
    P: InstallPort,
    E: FnMut(InstallEvent),
{
    emit(InstallEvent::Phase(InstallPhase::RollingBack));
    match port.rollback() {
        Ok(()) => cause,
        Err(rollback) => InstallError::Rollback {
            cause: Box::new(cause),
            rollback,
        },
    }
}

fn emit_terminal_error<E>(error: &InstallError, emit: &mut E)
where
    E: FnMut(InstallEvent),
{
    let phase = if matches!(error, InstallError::Cancelled) {
        InstallPhase::Cancelled
    } else {
        InstallPhase::Failed
    };
    emit(InstallEvent::Phase(phase));
}
