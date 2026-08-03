//! Ownership-aware uninstall vertical slice.

use std::{
    collections::HashSet,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};

use luxury_spec::{
    FileEntry, InstallDirectory, InstallScope, OperatingSystem, PackageId, PackagePath, SpecError,
    validate_entrypoint,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    PortError,
    install::{InstallPlan, PackageIdentity},
};

const LEGACY_RECEIPT_FORMAT_VERSION: u32 = 1;
const IDENTITY_RECEIPT_FORMAT_VERSION: u32 = 2;
const PROVENANCE_RECEIPT_FORMAT_VERSION: u32 = 3;
pub const RECEIPT_FORMAT_VERSION: u32 = 4;
const MAX_RECEIPT_FILES: usize = 100_000;

/// Durable ownership data. Adapters persist it outside the removable app tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipReceipt {
    format_version: u32,
    package_id: PackageId,
    version: Version,
    scope: InstallScope,
    directory: InstallDirectory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package_identity: Option<PackageIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorized_publisher: Option<PackageIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload_signer: Option<PackageIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entrypoint: Option<PackagePath>,
    files: Vec<FileEntry>,
}

impl OwnershipReceipt {
    pub fn new(
        package_id: PackageId,
        version: Version,
        scope: InstallScope,
        directory: InstallDirectory,
        package_identity: PackageIdentity,
        files: Vec<FileEntry>,
    ) -> Result<Self, ReceiptError> {
        let receipt = Self {
            format_version: RECEIPT_FORMAT_VERSION,
            package_id,
            version,
            scope,
            directory,
            package_identity: None,
            authorized_publisher: Some(package_identity),
            payload_signer: Some(package_identity),
            entrypoint: None,
            files,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub(crate) fn from_install_plan(plan: &InstallPlan) -> Self {
        Self {
            format_version: RECEIPT_FORMAT_VERSION,
            package_id: plan.package_id().clone(),
            version: plan.version().clone(),
            scope: plan.scope(),
            directory: plan.directory().clone(),
            package_identity: None,
            authorized_publisher: Some(plan.package_identity()),
            payload_signer: Some(plan.payload_signer()),
            entrypoint: plan.entrypoint().cloned(),
            files: plan.files().to_vec(),
        }
    }

    pub fn validate(&self) -> Result<(), ReceiptError> {
        match (
            self.format_version,
            self.package_identity,
            self.authorized_publisher,
            self.payload_signer,
        ) {
            (LEGACY_RECEIPT_FORMAT_VERSION, None, None, None)
            | (IDENTITY_RECEIPT_FORMAT_VERSION, Some(_), None, None)
            | (
                PROVENANCE_RECEIPT_FORMAT_VERSION | RECEIPT_FORMAT_VERSION,
                None,
                Some(PackageIdentity::Unsigned),
                Some(PackageIdentity::Unsigned),
            )
            | (
                PROVENANCE_RECEIPT_FORMAT_VERSION | RECEIPT_FORMAT_VERSION,
                None,
                Some(PackageIdentity::TrustedPublisher { .. }),
                Some(PackageIdentity::TrustedPublisher { .. }),
            ) => {}
            (LEGACY_RECEIPT_FORMAT_VERSION, _, _, _) => {
                return Err(ReceiptError::LegacyPackageIdentity);
            }
            (IDENTITY_RECEIPT_FORMAT_VERSION, None, _, _) => {
                return Err(ReceiptError::MissingPackageIdentity);
            }
            (IDENTITY_RECEIPT_FORMAT_VERSION, Some(_), _, _) => {
                return Err(ReceiptError::V2PayloadSigner);
            }
            (PROVENANCE_RECEIPT_FORMAT_VERSION | RECEIPT_FORMAT_VERSION, Some(_), _, _) => {
                return Err(ReceiptError::V3LegacyPackageIdentity);
            }
            (PROVENANCE_RECEIPT_FORMAT_VERSION | RECEIPT_FORMAT_VERSION, None, None, _) => {
                return Err(ReceiptError::MissingPackageIdentity);
            }
            (PROVENANCE_RECEIPT_FORMAT_VERSION | RECEIPT_FORMAT_VERSION, None, Some(_), None) => {
                return Err(ReceiptError::MissingPayloadSigner);
            }
            (
                PROVENANCE_RECEIPT_FORMAT_VERSION | RECEIPT_FORMAT_VERSION,
                None,
                Some(_),
                Some(_),
            ) => {
                return Err(ReceiptError::MismatchedPublisherKinds);
            }
            (found, _, _, _) => {
                return Err(ReceiptError::UnsupportedFormat {
                    found,
                    supported: RECEIPT_FORMAT_VERSION,
                });
            }
        }
        if self.files.is_empty() {
            return Err(ReceiptError::EmptyFiles);
        }
        if self.files.len() > MAX_RECEIPT_FILES {
            return Err(ReceiptError::TooManyFiles(self.files.len()));
        }

        let mut paths = HashSet::with_capacity(self.files.len());
        for file in &self.files {
            if !paths.insert(file.path.collision_key()) {
                return Err(ReceiptError::DuplicatePath(file.path.to_string()));
            }
        }
        match self.format_version {
            LEGACY_RECEIPT_FORMAT_VERSION
            | IDENTITY_RECEIPT_FORMAT_VERSION
            | PROVENANCE_RECEIPT_FORMAT_VERSION
                if self.entrypoint.is_some() =>
            {
                return Err(ReceiptError::LegacyEntrypoint);
            }
            RECEIPT_FORMAT_VERSION => {
                validate_entrypoint(
                    OperatingSystem::host(),
                    self.entrypoint.as_ref(),
                    &self.files,
                )
                .map_err(ReceiptError::InvalidEntrypoint)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn format_version(&self) -> u32 {
        self.format_version
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

    /// `None` is accepted only for persisted legacy v1 receipts.
    pub fn package_identity(&self) -> Option<PackageIdentity> {
        self.authorized_publisher()
    }

    /// Publisher authorized to sign the next package.
    pub fn authorized_publisher(&self) -> Option<PackageIdentity> {
        self.authorized_publisher.or(self.package_identity)
    }

    /// Signer that authenticated the payload bytes. Absent only in v1/v2 receipts.
    pub fn payload_signer(&self) -> Option<PackageIdentity> {
        self.payload_signer
    }

    pub fn entrypoint(&self) -> Option<&PackagePath> {
        self.entrypoint.as_ref()
    }

    pub fn files(&self) -> &[FileEntry] {
        &self.files
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReceiptError {
    #[error("unsupported receipt format {found}; latest supported format is {supported}")]
    UnsupportedFormat { found: u32, supported: u32 },
    #[error("legacy receipt format must not contain a package identity")]
    LegacyPackageIdentity,
    #[error("current receipt format is missing package identity")]
    MissingPackageIdentity,
    #[error("receipt format 2 must not contain payload signer provenance")]
    V2PayloadSigner,
    #[error("receipt format 3 or later must use authorized_publisher instead of package_identity")]
    V3LegacyPackageIdentity,
    #[error("current receipt format is missing payload signer provenance")]
    MissingPayloadSigner,
    #[error("authorized publisher and payload signer must use the same trust kind")]
    MismatchedPublisherKinds,
    #[error("receipt formats 1 through 3 must not contain an entrypoint")]
    LegacyEntrypoint,
    #[error("invalid receipt entrypoint: {0}")]
    InvalidEntrypoint(#[source] SpecError),
    #[error("receipt scope {found:?} is not supported; only user scope is enabled")]
    UnsupportedScope { found: InstallScope },
    #[error("receipt contains no owned files")]
    EmptyFiles,
    #[error("receipt contains too many files: {0}")]
    TooManyFiles(usize),
    #[error("receipt contains duplicate or case-colliding path `{0}`")]
    DuplicatePath(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallCommand {
    pub package_id: PackageId,
    allowed_scope: InstallScope,
}

impl UninstallCommand {
    pub fn new(package_id: PackageId) -> Self {
        Self {
            package_id,
            allowed_scope: InstallScope::User,
        }
    }

    /// Construct a command for an already-authenticated privileged composition root.
    pub fn for_system(package_id: PackageId) -> Self {
        Self {
            package_id,
            allowed_scope: InstallScope::System,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninstallPhase {
    Recovering,
    LoadingReceipt,
    Removing,
    Committing,
    RollingBack,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UninstallProgress {
    pub processed_files: usize,
    pub total_files: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UninstallEvent {
    Phase(UninstallPhase),
    Progress(UninstallProgress),
    PreservedModified(luxury_spec::PackagePath),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UninstallOutcome {
    NotInstalled,
    Uninstalled {
        removed_files: usize,
        missing_files: usize,
        preserved_modified_files: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveFileOutcome {
    Removed,
    Missing,
    PreservedModified,
}

/// The engine never asks this port to delete a directory tree or an unknown
/// path: only receipt-owned regular files can reach `remove_if_unchanged`.
pub trait UninstallPort {
    /// Recover or finish an interrupted transaction for this package before
    /// trusting the receipt or mutating installed state again.
    fn recover_pending(&mut self, package_id: &PackageId) -> Result<(), PortError>;

    /// Read the external receipt without mutating installed state.
    fn load_receipt(
        &mut self,
        package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError>;

    /// Acquire the destination lock and create durable undo state.
    fn begin(&mut self, receipt: &OwnershipReceipt) -> Result<(), PortError>;

    /// Re-check the current file atomically and remove it only if it still
    /// matches the receipt digest. Links, aliases and non-regular files must fail closed.
    fn remove_if_unchanged(
        &mut self,
        receipt: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<RemoveFileOutcome, PortError>;

    /// Publish removal of the external receipt as the commit point. `Err`
    /// means the transaction is definitely still rollbackable; post-commit
    /// cleanup failures must be deferred. Unknown files remain untouched.
    fn commit(&mut self) -> Result<(), PortError>;

    fn rollback(&mut self) -> Result<(), PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UninstallError {
    #[error(transparent)]
    InvalidReceipt(#[from] ReceiptError),
    #[error("unsupported installed scope `{found:?}` for this uninstall authority")]
    UnsupportedScope { found: InstallScope },
    #[error("receipt belongs to `{receipt}`, not requested package `{requested}`")]
    ReceiptPackageMismatch {
        requested: PackageId,
        receipt: PackageId,
    },
    #[error("uninstallation cancelled")]
    Cancelled,
    #[error("uninstall step `{step}` failed: {source}")]
    Port {
        step: &'static str,
        source: PortError,
    },
    #[error("{cause}; rollback failed: {rollback}")]
    Rollback {
        cause: Box<UninstallError>,
        rollback: PortError,
    },
}

pub fn uninstall<P, C, E>(
    command: UninstallCommand,
    port: &mut P,
    mut is_cancelled: C,
    mut emit: E,
) -> Result<UninstallOutcome, UninstallError>
where
    P: UninstallPort,
    C: FnMut() -> bool,
    E: FnMut(UninstallEvent),
{
    if is_cancelled() {
        emit(UninstallEvent::Phase(UninstallPhase::Cancelled));
        return Err(UninstallError::Cancelled);
    }

    emit(UninstallEvent::Phase(UninstallPhase::Recovering));
    if let Err(source) = port.recover_pending(&command.package_id) {
        emit(UninstallEvent::Phase(UninstallPhase::Failed));
        return Err(UninstallError::Port {
            step: "recover pending transaction",
            source,
        });
    }

    emit(UninstallEvent::Phase(UninstallPhase::LoadingReceipt));
    let receipt = match port.load_receipt(&command.package_id) {
        Ok(receipt) => receipt,
        Err(source) => {
            emit(UninstallEvent::Phase(UninstallPhase::Failed));
            return Err(UninstallError::Port {
                step: "load receipt",
                source,
            });
        }
    };
    let Some(receipt) = receipt else {
        emit(UninstallEvent::Phase(UninstallPhase::Completed));
        return Ok(UninstallOutcome::NotInstalled);
    };

    if let Err(error) = receipt.validate() {
        emit(UninstallEvent::Phase(UninstallPhase::Failed));
        return Err(error.into());
    }
    if receipt.scope != command.allowed_scope {
        emit(UninstallEvent::Phase(UninstallPhase::Failed));
        return Err(UninstallError::UnsupportedScope {
            found: receipt.scope,
        });
    }
    if receipt.package_id != command.package_id {
        emit(UninstallEvent::Phase(UninstallPhase::Failed));
        return Err(UninstallError::ReceiptPackageMismatch {
            requested: command.package_id,
            receipt: receipt.package_id.clone(),
        });
    }
    if is_cancelled() {
        emit(UninstallEvent::Phase(UninstallPhase::Cancelled));
        return Err(UninstallError::Cancelled);
    }

    let mut progress = UninstallProgress {
        processed_files: 0,
        total_files: receipt.files.len(),
    };
    emit(UninstallEvent::Progress(progress));
    let mut transaction_started = false;
    let mut committed = false;
    let result = catch_unwind(AssertUnwindSafe(|| {
        emit(UninstallEvent::Phase(UninstallPhase::Removing));
        transaction_started = true;
        if let Err(source) = port.begin(&receipt) {
            let error = rollback(
                port,
                UninstallError::Port {
                    step: "begin transaction",
                    source,
                },
                &mut emit,
            );
            emit_terminal_error(&error, &mut emit);
            return Err(error);
        }

        let mut removed_files = 0;
        let mut missing_files = 0;
        let mut preserved_modified_files = 0;
        for file in &receipt.files {
            if is_cancelled() {
                let error = rollback(port, UninstallError::Cancelled, &mut emit);
                emit_terminal_error(&error, &mut emit);
                return Err(error);
            }

            let disposition = match port.remove_if_unchanged(&receipt, file) {
                Ok(disposition) => disposition,
                Err(source) => {
                    let error = rollback(
                        port,
                        UninstallError::Port {
                            step: "remove owned file",
                            source,
                        },
                        &mut emit,
                    );
                    emit_terminal_error(&error, &mut emit);
                    return Err(error);
                }
            };
            match disposition {
                RemoveFileOutcome::Removed => removed_files += 1,
                RemoveFileOutcome::Missing => missing_files += 1,
                RemoveFileOutcome::PreservedModified => {
                    preserved_modified_files += 1;
                    emit(UninstallEvent::PreservedModified(file.path.clone()));
                }
            }
            progress.processed_files += 1;
            emit(UninstallEvent::Progress(progress));
        }

        if is_cancelled() {
            let error = rollback(port, UninstallError::Cancelled, &mut emit);
            emit_terminal_error(&error, &mut emit);
            return Err(error);
        }
        emit(UninstallEvent::Phase(UninstallPhase::Committing));
        if let Err(source) = port.commit() {
            let error = rollback(
                port,
                UninstallError::Port {
                    step: "commit",
                    source,
                },
                &mut emit,
            );
            emit_terminal_error(&error, &mut emit);
            return Err(error);
        }

        committed = true;
        emit(UninstallEvent::Phase(UninstallPhase::Completed));
        Ok(UninstallOutcome::Uninstalled {
            removed_files,
            missing_files,
            preserved_modified_files,
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

fn rollback<P, E>(port: &mut P, cause: UninstallError, emit: &mut E) -> UninstallError
where
    P: UninstallPort,
    E: FnMut(UninstallEvent),
{
    emit(UninstallEvent::Phase(UninstallPhase::RollingBack));
    match port.rollback() {
        Ok(()) => cause,
        Err(rollback) => UninstallError::Rollback {
            cause: Box::new(cause),
            rollback,
        },
    }
}

fn emit_terminal_error<E>(error: &UninstallError, emit: &mut E)
where
    E: FnMut(UninstallEvent),
{
    let phase = if matches!(error, UninstallError::Cancelled) {
        UninstallPhase::Cancelled
    } else {
        UninstallPhase::Failed
    };
    emit(UninstallEvent::Phase(phase));
}
