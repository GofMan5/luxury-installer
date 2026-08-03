//! Receipt-owned application launch vertical slice.

use luxury_spec::{FileEntry, InstallScope, PackageId, PackagePath};
use thiserror::Error;

use crate::{
    PortError,
    uninstall::{OwnershipReceipt, ReceiptError},
};

/// A pathless launch request. The installed receipt is the only path authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchCommand {
    pub package_id: PackageId,
    allowed_scope: InstallScope,
}

impl LaunchCommand {
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

pub trait LaunchPort {
    /// Launch is blocked while an interrupted install/uninstall transaction
    /// could make the receipt or installed tree inconsistent.
    fn recovery_pending(&mut self, package_id: &PackageId) -> Result<bool, PortError>;

    /// Read the external ownership receipt without mutating installed state.
    fn load_receipt(
        &mut self,
        package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError>;

    /// Launch exactly the supplied receipt-owned file without arguments.
    /// The adapter must fail closed if the current destination is not the same
    /// regular file bound by the receipt (including links or path aliases).
    fn launch_owned_entrypoint(
        &mut self,
        receipt: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<(), PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LaunchError {
    #[error("package `{package_id}` has pending recovery and cannot be launched")]
    RecoveryPending { package_id: PackageId },
    #[error("package `{package_id}` is not installed")]
    NotInstalled { package_id: PackageId },
    #[error(transparent)]
    InvalidReceipt(#[from] ReceiptError),
    #[error("unsupported installed scope `{found:?}` for this launch authority")]
    UnsupportedScope { found: InstallScope },
    #[error("receipt belongs to `{receipt}`, not requested package `{requested}`")]
    ReceiptPackageMismatch {
        requested: PackageId,
        receipt: PackageId,
    },
    #[error("installed package `{package_id}` has no launch entrypoint")]
    MissingEntrypoint { package_id: PackageId },
    #[error("receipt entrypoint `{entrypoint}` is not an owned file")]
    EntrypointNotOwned { entrypoint: PackagePath },
    #[error("launch step `{step}` failed: {source}")]
    Port {
        step: &'static str,
        source: PortError,
    },
}

pub fn launch<P>(command: LaunchCommand, port: &mut P) -> Result<(), LaunchError>
where
    P: LaunchPort,
{
    if port
        .recovery_pending(&command.package_id)
        .map_err(|source| LaunchError::Port {
            step: "check pending recovery",
            source,
        })?
    {
        return Err(LaunchError::RecoveryPending {
            package_id: command.package_id,
        });
    }

    let receipt = port
        .load_receipt(&command.package_id)
        .map_err(|source| LaunchError::Port {
            step: "load receipt",
            source,
        })?
        .ok_or_else(|| LaunchError::NotInstalled {
            package_id: command.package_id.clone(),
        })?;

    receipt.validate()?;
    if receipt.scope() != command.allowed_scope {
        return Err(LaunchError::UnsupportedScope {
            found: receipt.scope(),
        });
    }
    if receipt.package_id() != &command.package_id {
        return Err(LaunchError::ReceiptPackageMismatch {
            requested: command.package_id,
            receipt: receipt.package_id().clone(),
        });
    }

    let entrypoint = receipt.entrypoint().ok_or(LaunchError::MissingEntrypoint {
        package_id: command.package_id,
    })?;
    let file = receipt
        .files()
        .iter()
        .find(|file| &file.path == entrypoint)
        .ok_or_else(|| LaunchError::EntrypointNotOwned {
            entrypoint: entrypoint.clone(),
        })?;

    port.launch_owned_entrypoint(&receipt, file)
        .map_err(|source| LaunchError::Port {
            step: "launch owned entrypoint",
            source,
        })
}
