mod capacity;
mod launch;
mod transaction;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use luxury_bundle::{Bundle, PackageTrust};
use luxury_engine::{
    PortError, PortErrorKind,
    install::{InstallPlan, InstallPort, InstallPreparePort, VerifiedPackageIdentity},
    uninstall::{OwnershipReceipt, RemoveFileOutcome, UninstallPort},
};
use luxury_spec::{
    FileEntry, InstallDirectory, InstallScope, Manifest, PackageId, PackagePath, Sha256Digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use self::capacity::{
    check_directory_write_access, check_journal_capacity, check_storage_capacity,
};
use self::transaction::{
    ActiveTransaction, DESTINATION_LOCK_DIRECTORY, InstallBaseIdentity, JournalRecord,
    MAX_RECEIPT_BYTES, MatchingFileRemoval, Operation, RecoveredTransaction, SyncedRegular,
    TRANSACTION_DIRECTORY_PREFIX, begin_transaction_with_package_lock, ensure_directory,
    hash_internal_regular, hash_regular, install_base_identity, install_directory,
    internal_regular_file_executable, io_error, is_rolling_back, load_recovery_for_scope,
    lock_package, open_internal_regular, open_regular, operation, path_present,
    regular_file_executable, remove_directory_if_empty, remove_empty_directory,
    remove_internal_link, remove_regular, remove_regular_matching, rename_noreplace,
    roots_are_separate, same_file, scope as transaction_scope, set_installed_file,
    set_private_file, state_error, sync_movable_regular_snapshot, sync_parent,
    sync_regular_snapshot, transaction_paths, uninstall_receipt_hash, upgrade_receipt_hashes,
    validate_directory, validate_directory_chain, validate_private_directory,
    validate_private_file,
};
#[cfg(test)]
use self::transaction::{begin_transaction, begin_uninstall_transaction, load_recovery};
#[cfg(target_os = "linux")]
pub use launch::LinuxSystemLaunchAdapter;
pub use launch::LocalLaunchAdapter;
#[cfg(target_os = "macos")]
pub use launch::MacosSystemLaunchAdapter;
#[cfg(windows)]
pub use launch::WindowsSystemLaunchAdapter;

const STORED_RECEIPT_FORMAT_VERSION: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReceipt {
    format_version: u32,
    install_base: InstallBaseIdentity,
    receipt: OwnershipReceipt,
}

pub struct LocalInstallAdapter {
    bundle: Bundle,
    bundle_file_index: BTreeMap<String, usize>,
    install_base: PathBuf,
    state_root: PathBuf,
    scope: InstallScope,
    active: Option<ActiveTransaction>,
    active_previous: Option<OwnershipReceipt>,
    active_previous_index: BTreeMap<String, usize>,
}

impl LocalInstallAdapter {
    pub fn new(
        bundle: Bundle,
        install_base: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
    ) -> Self {
        Self::with_scope(bundle, install_base, state_root, InstallScope::User)
    }

    pub fn for_system(
        bundle: Bundle,
        install_base: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
    ) -> Self {
        Self::with_scope(bundle, install_base, state_root, InstallScope::System)
    }

    fn with_scope(
        bundle: Bundle,
        install_base: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        scope: InstallScope,
    ) -> Self {
        let bundle_file_index = file_collision_index(&bundle.manifest().files);
        Self {
            bundle,
            bundle_file_index,
            install_base: install_base.into(),
            state_root: state_root.into(),
            scope,
            active: None,
            active_previous: None,
            active_previous_index: BTreeMap::new(),
        }
    }
}

impl InstallPreparePort for LocalInstallAdapter {
    fn verify_package(
        &mut self,
        manifest: &Manifest,
    ) -> Result<VerifiedPackageIdentity, PortError> {
        if self.bundle.manifest() != manifest || manifest.install.scope != self.scope {
            return Err(PortError::with_kind(
                PortErrorKind::Integrity,
                "verified bundle manifest does not match the install command",
            ));
        }
        verified_package_identity(&self.bundle)
    }

    fn recovery_pending(&mut self, package_id: &PackageId) -> Result<bool, PortError> {
        install_recovery_pending(&self.install_base, &self.state_root, package_id)
    }

    fn load_receipt(
        &mut self,
        package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError> {
        load_receipt(&self.install_base, &self.state_root, package_id, self.scope)
    }

    fn preflight(
        &mut self,
        plan: &InstallPlan,
        previous: Option<&OwnershipReceipt>,
    ) -> Result<(), PortError> {
        require_plan_identity(plan, &self.bundle)?;
        check_install_plan(&self.install_base, &self.state_root, plan, previous)
    }
}

impl InstallPort for LocalInstallAdapter {
    fn recover_pending(&mut self, package_id: &PackageId) -> Result<(), PortError> {
        recover_pending(&self.install_base, &self.state_root, package_id, self.scope)
    }

    fn begin(
        &mut self,
        plan: &InstallPlan,
        previous: Option<&OwnershipReceipt>,
    ) -> Result<(), PortError> {
        if self.active.is_some() || self.active_previous.is_some() {
            return Err(state_error("install transaction is already active"));
        }
        require_plan_identity(plan, &self.bundle)?;
        validate_install_directory_namespace(plan.directory())?;
        let package_lock = lock_package(&self.state_root, plan.package_id(), self.scope)?;
        check_install_plan(&self.install_base, &self.state_root, plan, previous)?;
        let previous_hash = match previous {
            Some(expected) => {
                let paths =
                    transaction_paths(&self.install_base, &self.state_root, plan.package_id());
                let (current, sha256) = read_receipt_with_hash(&paths.receipt, &self.install_base)?;
                require_receipt_scope(&current, self.scope)?;
                if &current != expected {
                    return Err(state_error(
                        "ownership receipt changed before replacement began",
                    ));
                }
                Some(sha256)
            }
            None => None,
        };
        self.active = Some(begin_transaction_with_package_lock(
            &self.install_base,
            &self.state_root,
            plan.package_id(),
            plan.directory(),
            if previous.is_some() {
                Operation::Upgrade
            } else {
                Operation::Install
            },
            plan.scope(),
            previous_hash,
            package_lock,
        )?);
        self.active_previous = previous.cloned();
        self.active_previous_index = previous
            .map(|receipt| file_collision_index(receipt.files()))
            .unwrap_or_default();
        if let Err(error) = check_destination_files(&self.install_base, plan, previous) {
            if let Err(rollback) = self.rollback() {
                return Err(state_error(format!(
                    "destination changed while acquiring its lock: {error}; rollback failed: {rollback}"
                )));
            }
            return Err(error);
        }
        Ok(())
    }

    fn remove_obsolete(
        &mut self,
        previous: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<RemoveFileOutcome, PortError> {
        let active_previous = self
            .active_previous
            .as_ref()
            .ok_or_else(|| state_error("upgrade transaction has no previous receipt"))?;
        let indexed = self
            .active_previous_index
            .get(&file.path.collision_key())
            .and_then(|index| active_previous.files().get(*index));
        if !same_receipt_identity(active_previous, previous) || indexed != Some(file) {
            return Err(state_error(
                "obsolete-file request does not match the active replacement",
            ));
        }
        remove_obsolete_file(&self.install_base, self.active.as_mut(), file)
    }

    fn apply_file(&mut self, file: &FileEntry) -> Result<(), PortError> {
        let (package_id, directory, operation, _) = self
            .active
            .as_ref()
            .ok_or_else(|| state_error("install transaction has not begun"))?
            .header();
        if !matches!(operation, Operation::Install | Operation::Upgrade) {
            return Err(state_error("active transaction cannot apply install files"));
        }
        let collision_key = file.path.collision_key();
        let requested = self
            .bundle_file_index
            .get(&collision_key)
            .and_then(|index| self.bundle.manifest().files.get(*index));
        if requested != Some(file) || self.bundle.manifest().package.id != *package_id {
            return Err(PortError::with_kind(
                PortErrorKind::Integrity,
                "engine requested a file that is not in the verified bundle",
            ));
        }

        let previous_file = self
            .active_previous
            .as_ref()
            .and_then(|receipt| {
                self.active_previous_index
                    .get(&collision_key)
                    .and_then(|index| receipt.files().get(*index))
            })
            .cloned();
        if operation == Operation::Upgrade && self.active_previous.is_none() {
            return Err(state_error("upgrade transaction has no previous receipt"));
        }
        if previous_file
            .as_ref()
            .is_some_and(|previous| previous.path != file.path)
        {
            return Err(PortError::with_kind(
                PortErrorKind::Collision,
                "case-only replacement paths are unsupported",
            ));
        }

        let install_root = self.install_base.join(directory.as_str());
        ensure_destination_directories(
            self.active
                .as_mut()
                .expect("active transaction checked above"),
            &install_root,
            &file.path,
        )?;
        let destination = install_root.join(file.path.to_native_path());
        if previous_file.is_none() {
            require_missing(&destination)?;
        } else {
            match fs::symlink_metadata(&destination) {
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(io_error(
                        "inspecting replacement file",
                        &destination,
                        source,
                    ));
                }
                Ok(_) => {
                    let (size, sha256) = hash_regular(&destination)?;
                    if size == file.size
                        && sha256 == file.sha256
                        && regular_file_executable(&destination)? == file.executable
                    {
                        return Ok(());
                    }
                }
            }
        }

        let mut source = self.bundle.open_file(&file.path).map_err(|error| {
            PortError::with_kind(
                PortErrorKind::Integrity,
                format!("opening verified bundle object failed: {error}"),
            )
        })?;
        let transaction = self
            .active
            .as_mut()
            .expect("active transaction checked above");
        transaction.append(JournalRecord::StageFile {
            path: file.path.clone(),
            sha256: file.sha256.clone(),
        })?;
        let staged = staged_file(&transaction.paths, &file.path);
        stage_verified_file(&mut source, file, &staged, self.scope)?;

        if previous_file.is_some() && path_present(&destination)? {
            let backup = removed_file(&transaction.paths, &file.path);
            require_missing(&backup)?;
            let mut moved = sync_movable_regular_snapshot(&destination, false)?;
            let (sha256, executable) = moved.digest_and_executable();
            transaction.append(JournalRecord::RestoreFile {
                path: file.path.clone(),
                sha256: sha256.clone(),
                executable,
            })?;
            if let Some(parent) = backup.parent() {
                ensure_directory(parent, Some(self.scope))?;
            }
            let durability = rename_noreplace(&destination, &backup).map_err(|source| {
                io_error(
                    "moving replaced file into transaction storage",
                    &backup,
                    source,
                )
            })?;
            let (pinned, unchanged) = moved.verify_moved_path(&backup, false)?;
            if !unchanged {
                drop(pinned);
                drop(durability);
                restore_moved_file(&backup, &destination, false, moved)?;
                return Err(state_error(format!(
                    "replacement source `{}` changed while moving",
                    file.path
                )));
            }
            durability
                .sync()
                .map_err(|source| io_error("syncing replaced file move", &backup, source))?;
        } else {
            require_missing(&destination)?;
        }

        transaction.append(JournalRecord::RemoveFile {
            path: file.path.clone(),
            sha256: file.sha256.clone(),
        })?;
        let durability = rename_noreplace(&staged, &destination)
            .map_err(|source| io_error("publishing installed file", &destination, source))?;
        durability.sync().map_err(|source| {
            io_error("syncing installed file publication", &destination, source)
        })?;
        let (installed_size, installed_hash) = hash_regular(&destination)?;
        if installed_size != file.size || installed_hash != file.sha256 {
            return Err(PortError::with_kind(
                PortErrorKind::Integrity,
                format!(
                    "installed file `{}` failed post-write verification",
                    file.path
                ),
            ));
        }
        Ok(())
    }

    fn stage_receipt(&mut self, receipt: &OwnershipReceipt) -> Result<(), PortError> {
        receipt
            .validate()
            .map_err(|error| state_error(format!("invalid ownership receipt: {error}")))?;
        require_receipt_scope(receipt, self.scope)?;
        let transaction = self
            .active
            .as_ref()
            .ok_or_else(|| state_error("install transaction has not begun"))?;
        let (package_id, directory, operation, install_base) = transaction.header();
        let verified = verified_package_identity(&self.bundle)?;
        if !matches!(operation, Operation::Install | Operation::Upgrade)
            || receipt.package_id() != package_id
            || receipt.directory() != directory
            || receipt.package_identity() != Some(verified.package_identity())
            || receipt.payload_signer() != Some(verified.payload_signer())
        {
            return Err(state_error(
                "ownership receipt does not match the active install",
            ));
        }

        let stored = StoredReceipt {
            format_version: STORED_RECEIPT_FORMAT_VERSION,
            install_base: install_base.clone(),
            receipt: receipt.clone(),
        };
        let bytes = stored_receipt_bytes(&stored)?;
        if bytes.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(state_error("ownership receipt exceeds the size limit"));
        }
        let pending_path = transaction.paths.receipt_pending.clone();
        let path = if operation == Operation::Upgrade {
            staged_receipt(&transaction.paths)
        } else {
            pending_path.clone()
        };
        if operation == Operation::Upgrade {
            self.active
                .as_mut()
                .expect("active transaction checked above")
                .append(JournalRecord::PendingReceipt {
                    sha256: digest_bytes(&bytes),
                })?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|source| io_error("creating staged ownership receipt", &path, source))?;
        set_private_file(&path, self.scope)?;
        if let Err(source) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = remove_regular(&path);
            return Err(io_error("writing staged ownership receipt", &path, source));
        }
        sync_parent(&path)?;
        if operation == Operation::Upgrade {
            let (_, found) = hash_internal_regular(&path)?;
            if found != digest_bytes(&bytes) {
                return Err(state_error(
                    "staged ownership receipt failed post-write verification",
                ));
            }
            let durability = rename_noreplace(&path, &pending_path).map_err(|source| {
                io_error("publishing staged ownership receipt", &pending_path, source)
            })?;
            durability.sync().map_err(|source| {
                io_error("syncing staged ownership receipt", &pending_path, source)
            })?;
        }
        Ok(())
    }

    fn commit(&mut self) -> Result<(), PortError> {
        let mut transaction = self
            .active
            .take()
            .ok_or_else(|| state_error("install transaction has not begun"))?;
        if let Err(error) = transaction.append(JournalRecord::Committing) {
            self.active = Some(transaction);
            return Err(error);
        }
        match transaction.header().2 {
            Operation::Install => {
                if let Err(error) = require_missing(&transaction.paths.receipt) {
                    self.active = Some(transaction);
                    return Err(error);
                }
                let durability = match rename_noreplace(
                    &transaction.paths.receipt_pending,
                    &transaction.paths.receipt,
                ) {
                    Ok(durability) => durability,
                    Err(source) => {
                        let error = io_error(
                            "publishing ownership receipt",
                            &transaction.paths.receipt,
                            source,
                        );
                        self.active = Some(transaction);
                        return Err(error);
                    }
                };

                // Publishing the receipt crosses the commit point. A durability error
                // cannot be returned as rollbackable, so retain the journal for recovery.
                if durability.sync().is_ok() {
                    let _ = cleanup_transaction(
                        &self.install_base,
                        &transaction.paths,
                        &transaction.records,
                        Operation::Install,
                        None,
                    );
                }
                self.active_previous = None;
                self.active_previous_index.clear();
                Ok(())
            }
            Operation::Upgrade => {
                let (previous_sha256, pending_sha256) =
                    match upgrade_receipt_hashes(&transaction.records) {
                        Ok((previous, Some(pending))) => (previous.clone(), pending.clone()),
                        Ok((_, None)) => {
                            self.active = Some(transaction);
                            return Err(state_error(
                                "upgrade transaction has no pending receipt marker",
                            ));
                        }
                        Err(error) => {
                            self.active = Some(transaction);
                            return Err(error);
                        }
                    };
                if let Err(error) = require_missing(&transaction.paths.receipt_previous) {
                    self.active = Some(transaction);
                    return Err(error);
                }
                if let Err(error) = validate_upgrade_receipt(
                    &transaction.paths.receipt,
                    &self.install_base,
                    &previous_sha256,
                    &transaction.records,
                )
                .and_then(|_| {
                    validate_upgrade_receipt(
                        &transaction.paths.receipt_pending,
                        &self.install_base,
                        &pending_sha256,
                        &transaction.records,
                    )
                }) {
                    self.active = Some(transaction);
                    return Err(error);
                }
                let durability = match rename_noreplace(
                    &transaction.paths.receipt,
                    &transaction.paths.receipt_previous,
                ) {
                    Ok(durability) => durability,
                    Err(source) => {
                        let error = io_error(
                            "staging previous ownership receipt",
                            &transaction.paths.receipt_previous,
                            source,
                        );
                        self.active = Some(transaction);
                        return Err(error);
                    }
                };
                if let Err(source) = durability.sync() {
                    let error = io_error(
                        "syncing previous ownership receipt",
                        &transaction.paths.receipt_previous,
                        source,
                    );
                    self.active = Some(transaction);
                    return Err(error);
                }
                let durability = match rename_noreplace(
                    &transaction.paths.receipt_pending,
                    &transaction.paths.receipt,
                ) {
                    Ok(durability) => durability,
                    Err(source) => {
                        let error = io_error(
                            "publishing replacement ownership receipt",
                            &transaction.paths.receipt,
                            source,
                        );
                        self.active = Some(transaction);
                        return Err(error);
                    }
                };

                // The pending receipt is now live: all later failures are recovered
                // by the journal and must not be reported as rollbackable.
                if durability.sync().is_ok() {
                    let _ = cleanup_transaction(
                        &self.install_base,
                        &transaction.paths,
                        &transaction.records,
                        Operation::Upgrade,
                        Some(true),
                    );
                    remove_owned_empty_directories(
                        &self.install_base.join(transaction.header().1.as_str()),
                        &transaction.records,
                    );
                }
                self.active_previous = None;
                self.active_previous_index.clear();
                Ok(())
            }
            Operation::Uninstall => {
                self.active = Some(transaction);
                Err(state_error("uninstall transaction used by install adapter"))
            }
        }
    }

    fn rollback(&mut self) -> Result<(), PortError> {
        let previous = self.active_previous.take();
        let previous_index = std::mem::take(&mut self.active_previous_index);
        let Some(mut transaction) = self.active.take() else {
            return Ok(());
        };
        let result = match transaction.header().2 {
            Operation::Install => {
                rollback_install(&self.install_base, &transaction.paths, &transaction.records)
            }
            Operation::Upgrade => transaction.mark_rolling_back().and_then(|_| {
                rollback_upgrade(&self.install_base, &transaction.paths, &transaction.records)
            }),
            Operation::Uninstall => Err(state_error(
                "uninstall transaction used by install adapter rollback",
            )),
        };
        if result.is_err() {
            self.active = Some(transaction);
            self.active_previous = previous;
            self.active_previous_index = previous_index;
        }
        result
    }
}

pub struct LocalUninstallAdapter {
    install_base: PathBuf,
    state_root: PathBuf,
    scope: InstallScope,
    active: Option<ActiveTransaction>,
    active_receipt: Option<OwnershipReceipt>,
    active_receipt_index: BTreeMap<String, usize>,
}

impl LocalUninstallAdapter {
    pub fn new(install_base: impl Into<PathBuf>, state_root: impl Into<PathBuf>) -> Self {
        Self::with_scope(install_base, state_root, InstallScope::User)
    }

    pub fn for_system(install_base: impl Into<PathBuf>, state_root: impl Into<PathBuf>) -> Self {
        Self::with_scope(install_base, state_root, InstallScope::System)
    }

    fn with_scope(
        install_base: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        scope: InstallScope,
    ) -> Self {
        Self {
            install_base: install_base.into(),
            state_root: state_root.into(),
            scope,
            active: None,
            active_receipt: None,
            active_receipt_index: BTreeMap::new(),
        }
    }
}

impl UninstallPort for LocalUninstallAdapter {
    fn recover_pending(&mut self, package_id: &PackageId) -> Result<(), PortError> {
        recover_pending(&self.install_base, &self.state_root, package_id, self.scope)
    }

    fn load_receipt(
        &mut self,
        package_id: &PackageId,
    ) -> Result<Option<OwnershipReceipt>, PortError> {
        let path = transaction_paths(&self.install_base, &self.state_root, package_id).receipt;
        match fs::symlink_metadata(&path) {
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(io_error("inspecting ownership receipt", &path, source)),
            Ok(_) => {
                let receipt = read_receipt(&path, &self.install_base)?;
                require_receipt_scope(&receipt, self.scope)?;
                if receipt.package_id() != package_id {
                    return Err(state_error(
                        "ownership receipt package id does not match its path",
                    ));
                }
                Ok(Some(receipt))
            }
        }
    }

    fn begin(&mut self, receipt: &OwnershipReceipt) -> Result<(), PortError> {
        if self.active.is_some() || self.active_receipt.is_some() {
            return Err(state_error("uninstall transaction is already active"));
        }
        receipt
            .validate()
            .map_err(|error| state_error(format!("invalid ownership receipt: {error}")))?;
        require_receipt_scope(receipt, self.scope)?;
        let install_root = self.install_base.join(receipt.directory().as_str());
        roots_are_separate(&install_root, &self.state_root)?;
        validate_directory_chain(&self.install_base)?;
        validate_directory_chain(&self.state_root)?;
        let package_lock = lock_package(&self.state_root, receipt.package_id(), self.scope)?;
        let (current, current_sha256) = read_receipt_with_hash(
            &transaction_paths(&self.install_base, &self.state_root, receipt.package_id()).receipt,
            &self.install_base,
        )?;
        require_receipt_scope(&current, self.scope)?;
        if current != *receipt {
            return Err(state_error(
                "ownership receipt changed before uninstall began",
            ));
        }
        let transaction = begin_transaction_with_package_lock(
            &self.install_base,
            &self.state_root,
            receipt.package_id(),
            receipt.directory(),
            Operation::Uninstall,
            receipt.scope(),
            Some(current_sha256),
            package_lock,
        )?;
        self.active = Some(transaction);
        self.active_receipt_index = file_collision_index(current.files());
        self.active_receipt = Some(current);
        Ok(())
    }

    fn remove_if_unchanged(
        &mut self,
        receipt: &OwnershipReceipt,
        file: &FileEntry,
    ) -> Result<RemoveFileOutcome, PortError> {
        let transaction = self
            .active
            .as_ref()
            .ok_or_else(|| state_error("uninstall transaction has not begun"))?;
        let (package_id, directory, operation, _) = transaction.header();
        let active_receipt = self
            .active_receipt
            .as_ref()
            .ok_or_else(|| state_error("uninstall transaction has no locked receipt"))?;
        let indexed = self
            .active_receipt_index
            .get(&file.path.collision_key())
            .and_then(|index| active_receipt.files().get(*index));
        if operation != Operation::Uninstall
            || receipt.package_id() != package_id
            || receipt.directory() != directory
            || !same_receipt_identity(active_receipt, receipt)
            || indexed != Some(file)
        {
            return Err(state_error(
                "uninstall request does not match the active receipt",
            ));
        }

        let destination = self
            .install_base
            .join(directory.as_str())
            .join(file.path.to_native_path());
        if let Some(parent) = destination.parent() {
            validate_directory_chain(parent)?;
        }
        match fs::symlink_metadata(&destination) {
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RemoveFileOutcome::Missing);
            }
            Err(source) => return Err(io_error("inspecting installed file", &destination, source)),
            Ok(_) => {}
        }
        let (size, digest) = hash_regular(&destination)?;
        if size != file.size
            || digest != file.sha256
            || !installed_executable_matches(&destination, file.executable)?
        {
            return Ok(RemoveFileOutcome::PreservedModified);
        }

        let backup = transaction
            .paths
            .destination_dir
            .join("removed")
            .join(file.path.to_native_path());
        require_missing(&backup)?;
        let mut moved = sync_movable_regular_snapshot(&destination, false)?;
        if !moved.matches(file.size, &file.sha256, file.executable) {
            return Ok(RemoveFileOutcome::PreservedModified);
        }
        self.active
            .as_mut()
            .expect("active transaction checked above")
            .append(JournalRecord::RestoreFile {
                path: file.path.clone(),
                sha256: file.sha256.clone(),
                executable: file.executable,
            })?;
        if let Some(parent) = backup.parent() {
            ensure_directory(parent, Some(self.scope))?;
        }

        if let Some(parent) = destination.parent() {
            validate_directory_chain(parent)?;
        }

        let durability = rename_noreplace(&destination, &backup).map_err(|source| {
            io_error(
                "moving owned file into transaction storage",
                &backup,
                source,
            )
        })?;
        let (pinned, unchanged) = moved.verify_moved_path(&backup, false)?;
        if !unchanged {
            drop(pinned);
            drop(durability);
            restore_moved_file(&backup, &destination, false, moved)?;
            return Ok(RemoveFileOutcome::PreservedModified);
        }
        durability
            .sync()
            .map_err(|source| io_error("syncing owned file move", &backup, source))?;
        Ok(RemoveFileOutcome::Removed)
    }

    fn commit(&mut self) -> Result<(), PortError> {
        if self.active_receipt.is_none() {
            return Err(state_error("uninstall transaction has no locked receipt"));
        }
        let mut transaction = self
            .active
            .take()
            .ok_or_else(|| state_error("uninstall transaction has not begun"))?;
        if let Err(error) = transaction.append(JournalRecord::Committing) {
            self.active = Some(transaction);
            return Err(error);
        }
        if let Err(error) = require_missing(&transaction.paths.receipt_deleted) {
            self.active = Some(transaction);
            return Err(error);
        }
        let durability = match rename_noreplace(
            &transaction.paths.receipt,
            &transaction.paths.receipt_deleted,
        ) {
            Ok(durability) => durability,
            Err(source) => {
                let error = io_error(
                    "committing ownership receipt removal",
                    &transaction.paths.receipt_deleted,
                    source,
                );
                self.active = Some(transaction);
                return Err(error);
            }
        };
        self.active_receipt = None;
        self.active_receipt_index.clear();

        // The live receipt moved atomically: keep the tombstone, backups and journal if
        // the rename cannot be confirmed durable without violating commit's
        // "Err is rollbackable" contract.
        if durability.sync().is_err() {
            return Ok(());
        }
        let _ = cleanup_transaction(
            &self.install_base,
            &transaction.paths,
            &transaction.records,
            Operation::Uninstall,
            None,
        );
        remove_owned_empty_directories(
            &self.install_base.join(transaction.header().1.as_str()),
            &transaction.records,
        );
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), PortError> {
        let receipt = self.active_receipt.take();
        let receipt_index = std::mem::take(&mut self.active_receipt_index);
        let Some(transaction) = self.active.take() else {
            return Ok(());
        };
        let result = receipt.as_ref().map_or_else(
            || Err(state_error("uninstall transaction has no locked receipt")),
            |receipt| {
                rollback_uninstall(
                    &self.install_base,
                    &transaction.paths,
                    &transaction.records,
                    receipt,
                )
            },
        );
        if result.is_err() {
            self.active = Some(transaction);
            self.active_receipt = receipt;
            self.active_receipt_index = receipt_index;
        }
        result
    }
}

fn check_install_plan(
    install_base: &Path,
    state_root: &Path,
    plan: &InstallPlan,
    previous: Option<&OwnershipReceipt>,
) -> Result<(), PortError> {
    validate_install_directory_namespace(plan.directory())?;
    validate_directory_chain(install_base)?;
    validate_directory_chain(state_root)?;
    check_directory_write_access(install_base)?;
    check_directory_write_access(state_root)?;
    let install_root = install_base.join(plan.directory().as_str());
    roots_are_separate(&install_root, state_root)?;

    if install_recovery_pending(install_base, state_root, plan.package_id())? {
        return Err(state_error("pending transaction must be recovered first"));
    }
    let current = load_receipt(install_base, state_root, plan.package_id(), plan.scope())?;
    if current.as_ref() != previous {
        return Err(state_error(
            "ownership receipt changed after replacement planning",
        ));
    }
    let journal_bytes = check_journal_capacity(plan, previous)?;
    check_destination_files(install_base, plan, previous)?;
    check_storage_capacity(install_base, state_root, plan, previous, journal_bytes)
}

fn install_recovery_pending(
    install_base: &Path,
    state_root: &Path,
    package_id: &PackageId,
) -> Result<bool, PortError> {
    let paths = transaction_paths(install_base, state_root, package_id);
    let state_pending = path_present(&paths.state_dir)?;
    let destination_pending = path_present(&paths.destination_dir)?;
    Ok(state_pending || destination_pending)
}

fn validate_install_directory_namespace(directory: &InstallDirectory) -> Result<(), PortError> {
    let key = PackagePath::parse(directory.as_str())
        .expect("install directory is a valid package path")
        .collision_key();
    if key == DESTINATION_LOCK_DIRECTORY || key.starts_with(TRANSACTION_DIRECTORY_PREFIX) {
        return Err(PortError::with_kind(
            PortErrorKind::Collision,
            format!("install directory `{directory}` conflicts with reserved installer state"),
        ));
    }
    Ok(())
}

fn file_collision_index(files: &[FileEntry]) -> BTreeMap<String, usize> {
    files
        .iter()
        .enumerate()
        .map(|(index, file)| (file.path.collision_key(), index))
        .collect()
}

fn verified_package_identity(bundle: &Bundle) -> Result<VerifiedPackageIdentity, PortError> {
    match (bundle.trust(), bundle.publisher_rotation()) {
        (PackageTrust::Unsigned, None) => Ok(VerifiedPackageIdentity::Unsigned),
        (PackageTrust::Unsigned, Some(_)) => Err(PortError::with_kind(
            PortErrorKind::Integrity,
            "unsigned bundle exposed a publisher rotation",
        )),
        (PackageTrust::TrustedPublisher { key_id }, None) => {
            Ok(VerifiedPackageIdentity::TrustedPublisher {
                signer_key_id: key_id,
                rotation_to: None,
            })
        }
        (PackageTrust::TrustedPublisher { key_id }, Some(rotation))
            if rotation.from_key_id == key_id =>
        {
            Ok(VerifiedPackageIdentity::TrustedPublisher {
                signer_key_id: key_id,
                rotation_to: Some(rotation.to_key_id),
            })
        }
        (PackageTrust::TrustedPublisher { .. }, Some(_)) => Err(PortError::with_kind(
            PortErrorKind::Integrity,
            "publisher rotation signer does not match the authenticated bundle",
        )),
    }
}

fn require_plan_identity(plan: &InstallPlan, bundle: &Bundle) -> Result<(), PortError> {
    if plan.verified_identity() != verified_package_identity(bundle)? {
        return Err(PortError::with_kind(
            PortErrorKind::Integrity,
            "install plan verified identity does not match the authenticated bundle",
        ));
    }
    Ok(())
}

fn same_receipt_identity(left: &OwnershipReceipt, right: &OwnershipReceipt) -> bool {
    left.format_version() == right.format_version()
        && left.package_id() == right.package_id()
        && left.version() == right.version()
        && left.scope() == right.scope()
        && left.directory() == right.directory()
        && left.package_identity() == right.package_identity()
        && left.payload_signer() == right.payload_signer()
}

fn check_destination_files(
    install_base: &Path,
    plan: &InstallPlan,
    previous: Option<&OwnershipReceipt>,
) -> Result<(), PortError> {
    let install_root = install_base.join(plan.directory().as_str());
    match fs::symlink_metadata(&install_root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            validate_directory(&install_root)?;
        }
        Ok(_) => {
            return Err(PortError::with_kind(
                PortErrorKind::Collision,
                format!(
                    "install root `{}` is not a real directory",
                    install_root.display()
                ),
            ));
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(io_error("inspecting install root", &install_root, source)),
    }

    let previous_files = previous
        .map(|receipt| {
            receipt
                .files()
                .iter()
                .map(|file| (file.path.collision_key(), file))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    reject_unsupported_path_transitions(&previous_files, plan.files())?;

    for file in plan.files() {
        let destination = install_root.join(file.path.to_native_path());
        if let Some(parent) = destination.parent() {
            validate_directory_chain(parent)?;
        }
        if previous_files.contains_key(&file.path.collision_key()) {
            match fs::symlink_metadata(&destination) {
                Ok(_) => {
                    hash_regular(&destination)?;
                }
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(io_error(
                        "inspecting replacement file",
                        &destination,
                        source,
                    ));
                }
            }
        } else {
            require_missing(&destination)?;
        }
    }
    Ok(())
}

fn reject_unsupported_path_transitions(
    previous: &BTreeMap<String, &FileEntry>,
    next: &[FileEntry],
) -> Result<(), PortError> {
    let next = next
        .iter()
        .map(|file| (file.path.collision_key(), file))
        .collect::<BTreeMap<_, _>>();
    for (key, old) in previous {
        if let Some(new) = next.get(key)
            && old.path != new.path
        {
            return Err(PortError::with_kind(
                PortErrorKind::Collision,
                format!(
                    "case-only replacement `{}` -> `{}` is unsupported",
                    old.path, new.path
                ),
            ));
        }
        if key
            .match_indices('/')
            .any(|(index, _)| next.contains_key(&key[..index]))
        {
            return Err(PortError::with_kind(
                PortErrorKind::Collision,
                format!(
                    "directory-to-file replacement `{}` is unsupported",
                    old.path
                ),
            ));
        }
    }
    for (key, new) in &next {
        if key
            .match_indices('/')
            .any(|(index, _)| previous.contains_key(&key[..index]))
        {
            return Err(PortError::with_kind(
                PortErrorKind::Collision,
                format!(
                    "file-to-directory replacement `{}` is unsupported",
                    new.path
                ),
            ));
        }
    }
    Ok(())
}

fn ensure_destination_directories(
    transaction: &mut ActiveTransaction,
    install_root: &Path,
    file: &PackagePath,
) -> Result<(), PortError> {
    if !path_present(install_root)? {
        transaction.append(JournalRecord::RemoveDirectory { path: None })?;
        ensure_directory(install_root, None)?;
    } else {
        validate_directory(install_root)?;
    }

    let components = file.as_str().split('/').collect::<Vec<_>>();
    let mut relative = String::new();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        if !relative.is_empty() {
            relative.push('/');
        }
        relative.push_str(component);
        let package_path = PackagePath::parse(relative.clone())
            .map_err(|error| PortError::with_kind(PortErrorKind::Integrity, error.to_string()))?;
        let directory = install_root.join(package_path.to_native_path());
        if !path_present(&directory)? {
            transaction.append(JournalRecord::RemoveDirectory {
                path: Some(package_path),
            })?;
            ensure_directory(&directory, None)?;
        } else {
            validate_directory(&directory)?;
        }
    }
    Ok(())
}

fn staged_file(paths: &transaction::TransactionPaths, path: &PackagePath) -> PathBuf {
    paths
        .destination_dir
        .join("incoming")
        .join(path.to_native_path())
}

fn removed_file(paths: &transaction::TransactionPaths, path: &PackagePath) -> PathBuf {
    paths
        .destination_dir
        .join("removed")
        .join(path.to_native_path())
}

fn restore_moved_file(
    backup: &Path,
    destination: &Path,
    allow_multiple_links: bool,
    mut source: SyncedRegular,
) -> Result<(), PortError> {
    let durability = rename_noreplace(backup, destination)
        .map_err(|source| io_error("restoring transaction backup", destination, source))?;
    let (_pinned, unchanged) = source.verify_moved_path(destination, allow_multiple_links)?;
    if !unchanged {
        return Err(state_error(format!(
            "restored transaction backup `{}` changed while moving",
            destination.display()
        )));
    }
    durability
        .sync()
        .map_err(|source| io_error("syncing restored transaction backup", destination, source))?;
    Ok(())
}

fn staged_receipt(paths: &transaction::TransactionPaths) -> PathBuf {
    paths.state_dir.join("receipt.incoming")
}

fn stage_verified_file(
    source: &mut File,
    expected: &FileEntry,
    staged: &Path,
    scope: InstallScope,
) -> Result<(), PortError> {
    if let Some(parent) = staged.parent() {
        ensure_directory(parent, Some(scope))?;
    }
    require_missing(staged)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staged)
        .map_err(|source| io_error("creating staged installed file", staged, source))?;
    let copied = copy_and_hash(source, &mut output);
    let (size, sha256) = match copied {
        Ok(copied) => copied,
        Err(error) => {
            drop(output);
            let _ = remove_internal_link(staged);
            return Err(error);
        }
    };
    if size != expected.size || sha256 != expected.sha256 {
        drop(output);
        let _ = remove_internal_link(staged);
        return Err(PortError::with_kind(
            PortErrorKind::Integrity,
            format!(
                "payload `{}` changed while staging: expected {} bytes / {}, found {size} bytes / {sha256}",
                expected.path, expected.size, expected.sha256
            ),
        ));
    }
    set_installed_file(staged, expected.executable)?;
    output
        .sync_all()
        .map_err(|source| io_error("syncing staged installed file", staged, source))?;
    drop(output);
    let (staged_size, staged_sha256) = hash_regular(staged)?;
    if staged_size != expected.size || staged_sha256 != expected.sha256 {
        return Err(PortError::with_kind(
            PortErrorKind::Integrity,
            format!("staged file `{}` failed verification", expected.path),
        ));
    }
    sync_parent(staged)
}

fn remove_obsolete_file(
    install_base: &Path,
    active: Option<&mut ActiveTransaction>,
    file: &FileEntry,
) -> Result<RemoveFileOutcome, PortError> {
    let transaction = active.ok_or_else(|| state_error("upgrade transaction has not begun"))?;
    let (_, directory, operation, _) = transaction.header();
    if operation != Operation::Upgrade {
        return Err(state_error(
            "obsolete-file request does not match the active replacement",
        ));
    }

    let destination = install_base
        .join(directory.as_str())
        .join(file.path.to_native_path());
    if let Some(parent) = destination.parent() {
        validate_directory_chain(parent)?;
    }
    match fs::symlink_metadata(&destination) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RemoveFileOutcome::Missing);
        }
        Err(source) => return Err(io_error("inspecting obsolete file", &destination, source)),
        Ok(_) => {}
    }
    let (size, sha256) = hash_regular(&destination)?;
    if size != file.size
        || sha256 != file.sha256
        || !installed_executable_matches(&destination, file.executable)?
    {
        return Ok(RemoveFileOutcome::PreservedModified);
    }

    let backup = removed_file(&transaction.paths, &file.path);
    require_missing(&backup)?;
    let mut moved = sync_movable_regular_snapshot(&destination, false)?;
    if !moved.matches(size, &sha256, file.executable) {
        return Ok(RemoveFileOutcome::PreservedModified);
    }
    transaction.append(JournalRecord::RestoreFile {
        path: file.path.clone(),
        sha256: sha256.clone(),
        executable: file.executable,
    })?;
    if let Some(parent) = backup.parent() {
        ensure_directory(parent, Some(transaction_scope(&transaction.records)?))?;
    }
    let durability = rename_noreplace(&destination, &backup).map_err(|source| {
        io_error(
            "moving obsolete file into transaction storage",
            &backup,
            source,
        )
    })?;
    let (pinned, unchanged) = moved.verify_moved_path(&backup, false)?;
    if !unchanged {
        drop(pinned);
        drop(durability);
        restore_moved_file(&backup, &destination, false, moved)?;
        return Ok(RemoveFileOutcome::PreservedModified);
    }
    durability
        .sync()
        .map_err(|source| io_error("syncing obsolete file move", &backup, source))?;
    Ok(RemoveFileOutcome::Removed)
}

fn recover_pending(
    install_base: &Path,
    state_root: &Path,
    package_id: &PackageId,
    expected_scope: InstallScope,
) -> Result<(), PortError> {
    let Some(transaction) =
        load_recovery_for_scope(install_base, state_root, package_id, expected_scope)?
    else {
        return Ok(());
    };
    match transaction.header().2 {
        Operation::Install => recover_install(install_base, transaction),
        Operation::Upgrade => recover_upgrade(install_base, transaction),
        Operation::Uninstall => recover_uninstall(install_base, transaction),
    }
}

fn recover_install(
    install_base: &Path,
    transaction: RecoveredTransaction,
) -> Result<(), PortError> {
    let (package_id, directory, _, _) = transaction.header();
    let expected_scope = transaction_scope(&transaction.records)?;
    if path_present(&transaction.paths.receipt)? {
        if path_present(&transaction.paths.receipt_pending)?
            && !same_file(
                &transaction.paths.receipt,
                &transaction.paths.receipt_pending,
            )?
        {
            return Err(state_error(
                "published ownership receipt does not match its pending hard link",
            ));
        }
        let linked_pending = path_present(&transaction.paths.receipt_pending)?;
        let receipt =
            read_receipt_with_hash_links(&transaction.paths.receipt, install_base, linked_pending)?
                .0;
        require_receipt_scope(&receipt, expected_scope)?;
        if receipt.package_id() != package_id || receipt.directory() != directory {
            return Err(state_error(
                "committed receipt does not match install journal",
            ));
        }
        remove_internal_link(&transaction.paths.receipt_pending)?;
        cleanup_transaction(
            install_base,
            &transaction.paths,
            &transaction.records,
            Operation::Install,
            None,
        )
    } else {
        rollback_install(install_base, &transaction.paths, &transaction.records)
    }
}

fn recover_upgrade(
    install_base: &Path,
    mut transaction: RecoveredTransaction,
) -> Result<(), PortError> {
    if is_rolling_back(&transaction.records) {
        return rollback_upgrade(install_base, &transaction.paths, &transaction.records);
    }
    let (previous_sha256, pending_sha256) = upgrade_receipt_hashes(&transaction.records)?;
    let previous_sha256 = previous_sha256.clone();
    let pending_sha256 = pending_sha256.cloned();
    let committing = matches!(transaction.records.last(), Some(JournalRecord::Committing));
    let live = path_present(&transaction.paths.receipt)?;
    let previous = path_present(&transaction.paths.receipt_previous)?;
    let pending = path_present(&transaction.paths.receipt_pending)?;

    if committing {
        let pending_sha256 = pending_sha256
            .as_ref()
            .ok_or_else(|| state_error("committing upgrade has no pending receipt binding"))?;
        if live {
            let (live_receipt, live_sha256) =
                read_receipt_with_hash(&transaction.paths.receipt, install_base)?;
            require_receipt_scope(&live_receipt, transaction_scope(&transaction.records)?)?;
            if !pending && &live_sha256 == pending_sha256 {
                if previous {
                    validate_upgrade_receipt(
                        &transaction.paths.receipt_previous,
                        install_base,
                        &previous_sha256,
                        &transaction.records,
                    )?;
                }
                cleanup_transaction(
                    install_base,
                    &transaction.paths,
                    &transaction.records,
                    Operation::Upgrade,
                    Some(true),
                )?;
                remove_owned_empty_directories(
                    &install_base.join(transaction.header().1.as_str()),
                    &transaction.records,
                );
                return Ok(());
            }
            if !previous && !pending && live_sha256 == previous_sha256 {
                return mark_and_rollback_upgrade(install_base, &mut transaction);
            }
            if previous || !pending || live_sha256 != previous_sha256 {
                return Err(state_error(
                    "upgrade receipt transition is inconsistent with its journal",
                ));
            }
            validate_upgrade_receipt(
                &transaction.paths.receipt_pending,
                install_base,
                pending_sha256,
                &transaction.records,
            )?;
            return mark_and_rollback_upgrade(install_base, &mut transaction);
        }
        if !previous || !pending {
            return Err(state_error(
                "upgrade recovery is ambiguous while the live receipt is missing",
            ));
        }
        validate_upgrade_receipt(
            &transaction.paths.receipt_previous,
            install_base,
            &previous_sha256,
            &transaction.records,
        )?;
        validate_upgrade_receipt(
            &transaction.paths.receipt_pending,
            install_base,
            pending_sha256,
            &transaction.records,
        )?;
        return mark_and_rollback_upgrade(install_base, &mut transaction);
    }

    if previous || !live {
        return Err(state_error(
            "uncommitted upgrade has an invalid previous receipt transition",
        ));
    }
    validate_upgrade_receipt(
        &transaction.paths.receipt,
        install_base,
        &previous_sha256,
        &transaction.records,
    )?;
    mark_and_rollback_upgrade(install_base, &mut transaction)
}

fn mark_and_rollback_upgrade(
    install_base: &Path,
    transaction: &mut RecoveredTransaction,
) -> Result<(), PortError> {
    transaction.mark_rolling_back()?;
    rollback_upgrade(install_base, &transaction.paths, &transaction.records)
}

fn recover_uninstall(
    install_base: &Path,
    transaction: RecoveredTransaction,
) -> Result<(), PortError> {
    let state = validate_uninstall_transaction_state(
        install_base,
        &transaction.paths,
        &transaction.records,
    )?;
    if state.live_receipt {
        rollback_uninstall(
            install_base,
            &transaction.paths,
            &transaction.records,
            &state.receipt,
        )
    } else {
        let install_root = install_base.join(transaction.header().1.as_str());
        cleanup_transaction(
            install_base,
            &transaction.paths,
            &transaction.records,
            Operation::Uninstall,
            None,
        )?;
        remove_owned_empty_directories(&install_root, &transaction.records);
        Ok(())
    }
}

fn rollback_install(
    install_base: &Path,
    paths: &transaction::TransactionPaths,
    records: &[JournalRecord],
) -> Result<(), PortError> {
    let root = install_base.join(install_directory(records)?.as_str());
    for record in records.iter().rev() {
        match record {
            JournalRecord::StageFile { path, .. } => {
                let staged = staged_file(paths, path);
                if let Some(parent) = staged.parent() {
                    validate_directory_chain(parent)?;
                }
                remove_internal_link(&staged)?;
            }
            JournalRecord::RemoveFile { path, sha256 } => {
                let destination = root.join(path.to_native_path());
                if let Some(parent) = destination.parent() {
                    validate_directory_chain(parent)?;
                }
                if remove_regular_matching(&destination, sha256, false)?
                    == MatchingFileRemoval::Modified
                {
                    return Err(state_error(format!(
                        "rollback preserved changed file `{}`; manual recovery is required",
                        destination.display()
                    )));
                }
            }
            JournalRecord::RemoveDirectory { path } => {
                let directory = path
                    .as_ref()
                    .map_or_else(|| root.clone(), |path| root.join(path.to_native_path()));
                if let Some(parent) = directory.parent() {
                    validate_directory_chain(parent)?;
                }
                remove_directory_if_empty(&directory)?;
            }
            _ => {}
        }
    }
    cleanup_transaction(install_base, paths, records, Operation::Install, None)
}

fn validate_upgrade_rollback_files(
    root: &Path,
    paths: &transaction::TransactionPaths,
    records: &[JournalRecord],
) -> Result<BTreeSet<PackagePath>, PortError> {
    let mut restores = BTreeMap::new();
    let mut removes = BTreeMap::new();
    let mut stages = BTreeSet::new();
    for record in records {
        match record {
            JournalRecord::RestoreFile {
                path,
                sha256,
                executable,
            } => {
                if restores.insert(path, (sha256, *executable)).is_some() {
                    return Err(state_error(format!(
                        "upgrade rollback contains duplicate restore state for `{path}`"
                    )));
                }
            }
            JournalRecord::RemoveFile { path, sha256 } => {
                if removes.insert(path, sha256).is_some() {
                    return Err(state_error(format!(
                        "upgrade rollback contains duplicate remove state for `{path}`"
                    )));
                }
            }
            JournalRecord::StageFile { path, .. } if !stages.insert(path) => {
                return Err(state_error(format!(
                    "upgrade rollback contains duplicate staging state for `{path}`"
                )));
            }
            _ => {}
        }
    }

    for (path, (old_sha256, executable)) in &restores {
        let destination = root.join(path.to_native_path());
        let backup = removed_file(paths, path);
        if let Some(parent) = destination.parent() {
            validate_directory_chain(parent)?;
        }
        if let Some(parent) = backup.parent() {
            validate_directory_chain(parent)?;
        }
        let destination_exists = path_present(&destination)?;
        let backup_exists = path_present(&backup)?;
        match (destination_exists, backup_exists) {
            (true, true) if same_file(&destination, &backup)? => {
                let synced = sync_regular_snapshot(&destination, true)?;
                if !synced.matches_digest(old_sha256, *executable) {
                    return Err(state_error(format!(
                        "legacy rollback pair `{path}` changed unexpectedly"
                    )));
                }
            }
            (true, true) => {
                let synced = sync_regular_snapshot(&backup, true)?;
                if !synced.matches_digest(old_sha256, *executable) {
                    return Err(state_error(format!(
                        "replacement backup `{path}` changed unexpectedly"
                    )));
                }
                let Some(new_sha256) = removes.get(path) else {
                    return Err(state_error(format!(
                        "obsolete rollback state for `{path}` has conflicting copies"
                    )));
                };
                let (_, destination_sha256) = hash_regular(&destination)?;
                if &destination_sha256 != *new_sha256 {
                    return Err(state_error(format!(
                        "replacement destination `{path}` changed unexpectedly"
                    )));
                }
            }
            (true, false) => {
                let synced = sync_regular_snapshot(&destination, false)?;
                if !synced.matches_digest(old_sha256, *executable) {
                    return Err(state_error(format!(
                        "restored replacement `{path}` changed unexpectedly"
                    )));
                }
            }
            (false, true) => {
                let synced = sync_regular_snapshot(&backup, true)?;
                if !synced.matches_digest(old_sha256, *executable) {
                    return Err(state_error(format!(
                        "replacement backup `{path}` changed unexpectedly"
                    )));
                }
            }
            (false, false) => {
                return Err(state_error(format!(
                    "rollback cannot restore `{path}` because both copies are missing"
                )));
            }
        }
    }

    for (path, new_sha256) in &removes {
        if restores.contains_key(path) {
            continue;
        }
        let destination = root.join(path.to_native_path());
        if let Some(parent) = destination.parent() {
            validate_directory_chain(parent)?;
        }
        if path_present(&destination)? {
            let (_, found) = hash_regular(&destination)?;
            if &found != *new_sha256 {
                return Err(state_error(format!(
                    "new rollback destination `{path}` changed unexpectedly"
                )));
            }
        }
    }

    for path in stages {
        let staged = staged_file(paths, path);
        if let Some(parent) = staged.parent() {
            validate_directory_chain(parent)?;
        }
        if path_present(&staged)? {
            hash_internal_regular(&staged)?;
        }
    }
    for record in records {
        let JournalRecord::RemoveDirectory { path } = record else {
            continue;
        };
        let directory = path.as_ref().map_or_else(
            || root.to_path_buf(),
            |path| root.join(path.to_native_path()),
        );
        if let Some(parent) = directory.parent() {
            validate_directory_chain(parent)?;
        }
        if path_present(&directory)? {
            validate_directory(&directory)?;
        }
    }
    Ok(restores.keys().map(|path| (*path).clone()).collect())
}

fn rollback_upgrade(
    install_base: &Path,
    paths: &transaction::TransactionPaths,
    records: &[JournalRecord],
) -> Result<(), PortError> {
    if !is_rolling_back(records) {
        return Err(state_error(
            "upgrade rollback has no durable rollback marker",
        ));
    }
    let root = install_base.join(install_directory(records)?.as_str());
    let (previous_sha256, pending_sha256) = upgrade_receipt_hashes(records)?;
    let live = path_present(&paths.receipt)?;
    let previous = path_present(&paths.receipt_previous)?;
    match (live, previous) {
        (true, false) => {
            validate_upgrade_receipt(&paths.receipt, install_base, previous_sha256, records)?;
        }
        (false, true) => {
            validate_upgrade_receipt(
                &paths.receipt_previous,
                install_base,
                previous_sha256,
                records,
            )?;
        }
        _ => {
            return Err(state_error(
                "upgrade rollback has an ambiguous ownership receipt transition",
            ));
        }
    }
    if path_present(&paths.receipt_pending)? {
        let Some(pending_sha256) = pending_sha256 else {
            return Err(state_error(
                "upgrade rollback found an unbound pending ownership receipt",
            ));
        };
        validate_upgrade_receipt(
            &paths.receipt_pending,
            install_base,
            pending_sha256,
            records,
        )?;
    }
    let restore_paths = validate_upgrade_rollback_files(&root, paths, records)?;

    for record in records.iter().rev() {
        let JournalRecord::RemoveFile { path, sha256 } = record else {
            continue;
        };
        let destination = root.join(path.to_native_path());
        if let Some(parent) = destination.parent() {
            validate_directory_chain(parent)?;
        }
        let has_restore = restore_paths.contains(path);
        if has_restore {
            let backup = removed_file(paths, path);
            if path_present(&destination)?
                && path_present(&backup)?
                && same_file(&destination, &backup)?
            {
                continue;
            }
        }
        if remove_regular_matching(&destination, sha256, has_restore)?
            == MatchingFileRemoval::Modified
            && !has_restore
        {
            return Err(state_error(format!(
                "rollback preserved changed new file `{path}`; manual recovery is required"
            )));
        }
    }

    for record in records.iter().rev() {
        let JournalRecord::RestoreFile {
            path,
            sha256,
            executable,
        } = record
        else {
            continue;
        };
        let destination = root.join(path.to_native_path());
        let backup = removed_file(paths, path);
        if let Some(parent) = destination.parent() {
            validate_directory_chain(parent)?;
        }
        if let Some(parent) = backup.parent() {
            validate_directory_chain(parent)?;
        }
        let destination_exists = path_present(&destination)?;
        let backup_exists = path_present(&backup)?;
        match (destination_exists, backup_exists) {
            (true, true) if same_file(&destination, &backup)? => {
                let restored = sync_regular_snapshot(&destination, true)?;
                if !restored.matches_digest(sha256, *executable) {
                    return Err(state_error(format!(
                        "legacy rollback pair `{path}` changed unexpectedly"
                    )));
                }
                drop(restored);
                remove_internal_link(&backup)?;
            }
            (true, true) => {
                let restored = sync_regular_snapshot(&destination, false)?;
                let retained = sync_regular_snapshot(&backup, true)?;
                if !restored.matches_digest(sha256, *executable)
                    || !retained.matches_digest(sha256, *executable)
                {
                    return Err(state_error(format!(
                        "rollback found conflicting replacement copies of `{path}`"
                    )));
                }
                drop(retained);
                drop(restored);
                remove_internal_link(&backup)?;
            }
            (true, false) => {
                let restored = sync_regular_snapshot(&destination, false)?;
                if !restored.matches_digest(sha256, *executable) {
                    return Err(state_error(format!(
                        "rollback preserved changed replacement `{path}`; manual recovery is required"
                    )));
                }
            }
            (false, true) => {
                let retained = sync_movable_regular_snapshot(&backup, true)?;
                if !retained.matches_digest(sha256, *executable) {
                    return Err(state_error(format!(
                        "replacement backup `{path}` changed unexpectedly"
                    )));
                }
                if let Some(parent) = destination.parent() {
                    ensure_directory(parent, None)?;
                }
                restore_moved_file(&backup, &destination, true, retained)?;
            }
            (false, false) => {
                return Err(state_error(format!(
                    "rollback cannot restore `{path}` because both copies are missing"
                )));
            }
        }
    }

    for record in records.iter().rev() {
        let JournalRecord::StageFile { path, .. } = record else {
            continue;
        };
        let staged = staged_file(paths, path);
        if let Some(parent) = staged.parent() {
            validate_directory_chain(parent)?;
        }
        remove_internal_link(&staged)?;
    }

    for record in records.iter().rev() {
        let JournalRecord::RemoveDirectory { path } = record else {
            continue;
        };
        let directory = path
            .as_ref()
            .map_or_else(|| root.clone(), |path| root.join(path.to_native_path()));
        if let Some(parent) = directory.parent() {
            validate_directory_chain(parent)?;
        }
        remove_directory_if_empty(&directory)?;
    }

    match (live, previous) {
        (true, false) => {}
        (false, true) => {
            let durability =
                rename_noreplace(&paths.receipt_previous, &paths.receipt).map_err(|source| {
                    io_error(
                        "restoring previous ownership receipt",
                        &paths.receipt,
                        source,
                    )
                })?;
            durability.sync().map_err(|source| {
                io_error(
                    "syncing previous ownership receipt restore",
                    &paths.receipt,
                    source,
                )
            })?;
        }
        _ => unreachable!("receipt transition validated before rollback mutation"),
    }
    if path_present(&staged_receipt(paths))? {
        if pending_sha256.is_none() {
            return Err(state_error(
                "upgrade rollback found an unbound staged ownership receipt",
            ));
        }
        remove_internal_link(&staged_receipt(paths))?;
    }
    if path_present(&paths.receipt_pending)? {
        if pending_sha256.is_none() {
            return Err(state_error(
                "upgrade rollback found an unbound pending ownership receipt",
            ));
        }
        remove_internal_link(&paths.receipt_pending)?;
    }
    cleanup_transaction(
        install_base,
        paths,
        records,
        Operation::Upgrade,
        Some(false),
    )
}

fn rollback_uninstall(
    install_base: &Path,
    paths: &transaction::TransactionPaths,
    records: &[JournalRecord],
    expected_receipt: &OwnershipReceipt,
) -> Result<(), PortError> {
    if !path_present(&paths.receipt)? {
        return Err(state_error(
            "uninstall rollback has no live ownership receipt",
        ));
    }
    let linked_pair =
        path_present(&paths.receipt_deleted)? && same_file(&paths.receipt, &paths.receipt_deleted)?;
    let receipt =
        validate_uninstall_receipt_and_records(&paths.receipt, install_base, records, linked_pair)?;
    if receipt != *expected_receipt {
        return Err(state_error(
            "uninstall rollback receipt changed before recovery",
        ));
    }
    let root = install_base.join(install_directory(records)?.as_str());
    for record in records.iter().rev() {
        let JournalRecord::RestoreFile { path, .. } = record else {
            continue;
        };
        let destination = root.join(path.to_native_path());
        let backup = paths
            .destination_dir
            .join("removed")
            .join(path.to_native_path());
        if let Some(parent) = backup.parent() {
            validate_directory_chain(parent)?;
        }
        if let Some(parent) = destination.parent() {
            validate_directory_chain(parent)?;
        }
        let destination_exists = path_present(&destination)?;
        let backup_exists = path_present(&backup)?;
        match (destination_exists, backup_exists) {
            (true, true) if same_file(&destination, &backup)? => {
                let synced = sync_regular_snapshot(&destination, true)?;
                drop(synced);
                remove_internal_link(&backup)?;
            }
            (true, true) => {
                let restored = sync_regular_snapshot(&destination, true)?;
                let retained = sync_regular_snapshot(&backup, true)?;
                if !restored.same_contents(&retained) {
                    return Err(state_error(format!(
                        "rollback found conflicting copies of `{}`",
                        path
                    )));
                }
                drop(retained);
                drop(restored);
                remove_internal_link(&backup)?;
            }
            (true, false) => {
                sync_regular_snapshot(&destination, true)?;
            }
            (false, true) => {
                let retained = sync_movable_regular_snapshot(&backup, true)?;
                if let Some(parent) = destination.parent() {
                    ensure_directory(parent, None)?;
                }
                restore_moved_file(&backup, &destination, true, retained)?;
            }
            (false, false) => {
                return Err(state_error(format!(
                    "rollback cannot restore `{}` because both copies are missing",
                    path
                )));
            }
        }
    }
    cleanup_transaction(install_base, paths, records, Operation::Uninstall, None)
}

fn cleanup_transaction(
    install_base: &Path,
    paths: &transaction::TransactionPaths,
    records: &[JournalRecord],
    expected_operation: Operation,
    upgrade_committed: Option<bool>,
) -> Result<(), PortError> {
    if operation(records)? != expected_operation {
        return Err(state_error("transaction operation changed during cleanup"));
    }
    let uninstall_state = if expected_operation == Operation::Uninstall {
        Some(validate_uninstall_transaction_state(
            install_base,
            paths,
            records,
        )?)
    } else {
        None
    };
    let uninstall_receipt_index = uninstall_state
        .as_ref()
        .map(|state| file_collision_index(state.receipt.files()));
    if expected_operation == Operation::Uninstall {
        validate_uninstall_cleanup_layout(paths, records)?;
    }
    validate_directory_chain(&paths.state_dir)?;
    if path_present(&paths.destination_dir)? {
        validate_directory_chain(&paths.destination_dir)?;
    }
    require_missing(&paths.journal_done)?;
    if expected_operation == Operation::Upgrade {
        validate_upgrade_cleanup_state(
            install_base,
            paths,
            records,
            upgrade_committed.ok_or_else(|| state_error("upgrade cleanup has no outcome"))?,
        )?;
        let (_, pending_sha256) = upgrade_receipt_hashes(records)?;
        if path_present(&staged_receipt(paths))? {
            if pending_sha256.is_none() {
                return Err(state_error(
                    "upgrade cleanup found an unbound staged receipt",
                ));
            }
            remove_internal_link(&staged_receipt(paths))?;
        }
    } else if upgrade_committed.is_some() {
        return Err(state_error("non-upgrade cleanup has an upgrade outcome"));
    }

    let mut directories = BTreeSet::new();
    for record in records {
        let internal = match record {
            JournalRecord::RestoreFile {
                path,
                sha256,
                executable,
            } => {
                let backup = removed_file(paths, path);
                if let Some(parent) = backup.parent() {
                    validate_directory_chain(parent)?;
                }
                if path_present(&backup)? {
                    let (size, found) = hash_internal_regular(&backup)?;
                    let uninstall_file = uninstall_state.as_ref().and_then(|state| {
                        uninstall_receipt_index
                            .as_ref()
                            .and_then(|index| index.get(&path.collision_key()))
                            .and_then(|index| state.receipt.files().get(*index))
                    });
                    if &found != sha256
                        || (expected_operation == Operation::Upgrade
                            && !internal_executable_matches(&backup, *executable)?)
                        || (expected_operation == Operation::Uninstall
                            && !uninstall_file.is_some_and(|file| {
                                file.path == *path
                                    && file.size == size
                                    && file.sha256 == found
                                    && file.executable == *executable
                            }))
                        || (expected_operation == Operation::Uninstall
                            && !internal_executable_matches(&backup, *executable)?)
                    {
                        return Err(state_error(format!(
                            "transaction backup `{}` changed unexpectedly",
                            backup.display()
                        )));
                    }
                    remove_internal_link(&backup)?;
                }
                Some(backup)
            }
            JournalRecord::StageFile { path, .. } => {
                let staged = staged_file(paths, path);
                if let Some(parent) = staged.parent() {
                    validate_directory_chain(parent)?;
                }
                remove_internal_link(&staged)?;
                Some(staged)
            }
            _ => None,
        };
        if let Some(internal) = internal {
            let mut parent = internal.parent();
            while let Some(directory) = parent {
                if !directory.starts_with(&paths.destination_dir) {
                    break;
                }
                directories.insert(directory.to_path_buf());
                if directory == paths.destination_dir {
                    break;
                }
                parent = directory.parent();
            }
        }
    }
    directories.insert(paths.destination_dir.clone());
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        if let Some(parent) = directory.parent() {
            validate_directory_chain(parent)?;
        }
        remove_empty_directory(&directory)?;
    }

    match expected_operation {
        Operation::Install => {
            require_missing(&paths.receipt_previous)?;
            require_missing(&paths.receipt_deleted)?;
            if path_present(&paths.receipt_pending)? {
                validate_transaction_receipt(&paths.receipt_pending, install_base, records)?;
                remove_internal_link(&paths.receipt_pending)?;
            }
            remove_regular(&paths.journal)?;
        }
        Operation::Upgrade => {
            require_missing(&paths.receipt_deleted)?;
            let (previous_sha256, pending_sha256) = upgrade_receipt_hashes(records)?;
            if path_present(&paths.receipt_pending)? {
                let Some(pending_sha256) = pending_sha256 else {
                    return Err(state_error(
                        "upgrade cleanup found an unbound pending receipt",
                    ));
                };
                validate_upgrade_receipt(
                    &paths.receipt_pending,
                    install_base,
                    pending_sha256,
                    records,
                )?;
                remove_internal_link(&paths.receipt_pending)?;
            }
            if path_present(&paths.receipt_previous)? {
                validate_upgrade_receipt(
                    &paths.receipt_previous,
                    install_base,
                    previous_sha256,
                    records,
                )?;
                remove_internal_link(&paths.receipt_previous)?;
            }
            remove_regular(&paths.journal)?;
        }
        Operation::Uninstall => {
            require_missing(&paths.receipt_previous)?;
            require_missing(&paths.receipt_pending)?;
            let live_receipt = path_present(&paths.receipt)?;
            let tombstone = path_present(&paths.receipt_deleted)?;
            if tombstone {
                if live_receipt {
                    if !same_file(&paths.receipt, &paths.receipt_deleted)? {
                        return Err(state_error(
                            "live ownership receipt does not match its uninstall tombstone",
                        ));
                    }
                } else {
                    validate_transaction_receipt(&paths.receipt_deleted, install_base, records)?;
                }
            }
            if live_receipt {
                remove_regular(&paths.journal)?;
                remove_internal_link(&paths.receipt_deleted)?;
            } else {
                if !tombstone {
                    return Err(state_error(
                        "committed uninstall cleanup has no ownership receipt tombstone",
                    ));
                }
                if !matches!(records.last(), Some(JournalRecord::Committing)) {
                    return Err(state_error(
                        "uninstall cleanup cannot commit without a durable journal marker",
                    ));
                }
                let durability =
                    rename_noreplace(&paths.journal, &paths.journal_done).map_err(|source| {
                        io_error(
                            "publishing transaction cleanup marker",
                            &paths.journal_done,
                            source,
                        )
                    })?;
                durability.sync().map_err(|source| {
                    io_error(
                        "syncing transaction cleanup marker",
                        &paths.journal_done,
                        source,
                    )
                })?;
                remove_internal_link(&paths.receipt_deleted)?;
                remove_regular(&paths.journal_done)?;
            }
        }
    }
    remove_empty_directory(&paths.state_dir)
}

fn validate_upgrade_cleanup_state(
    install_base: &Path,
    paths: &transaction::TransactionPaths,
    records: &[JournalRecord],
    committed: bool,
) -> Result<(), PortError> {
    let (previous_sha256, pending_sha256) = upgrade_receipt_hashes(records)?;
    let previous = path_present(&paths.receipt_previous)?;
    let pending = path_present(&paths.receipt_pending)?;
    if committed {
        let Some(pending_sha256) = pending_sha256 else {
            return Err(state_error(
                "upgrade receipt transition has no pending receipt binding",
            ));
        };
        if !matches!(records.last(), Some(JournalRecord::Committing)) || pending {
            return Err(state_error(
                "upgrade cleanup cannot prove the replacement receipt committed",
            ));
        }
        let live_receipt =
            validate_upgrade_receipt(&paths.receipt, install_base, pending_sha256, records)?;
        if previous {
            validate_upgrade_receipt(
                &paths.receipt_previous,
                install_base,
                previous_sha256,
                records,
            )?;
        }
        validate_installed_receipt_files(install_base, &live_receipt)?;
    } else {
        if previous || pending {
            return Err(state_error(
                "upgrade rollback did not restore its previous receipt",
            ));
        }
        validate_upgrade_receipt(&paths.receipt, install_base, previous_sha256, records)?;
    }
    Ok(())
}

fn validate_installed_receipt_files(
    install_base: &Path,
    receipt: &OwnershipReceipt,
) -> Result<(), PortError> {
    let root = install_base.join(receipt.directory().as_str());
    for file in receipt.files() {
        let destination = root.join(file.path.to_native_path());
        if let Some(parent) = destination.parent() {
            validate_directory_chain(parent)?;
        }
        let (size, sha256) = hash_regular(&destination)?;
        if size != file.size
            || sha256 != file.sha256
            || !installed_executable_matches(&destination, file.executable)?
        {
            return Err(state_error(format!(
                "committed replacement file `{}` does not match its receipt",
                file.path
            )));
        }
    }
    Ok(())
}

fn installed_executable_matches(path: &Path, expected: bool) -> Result<bool, PortError> {
    #[cfg(unix)]
    {
        Ok(regular_file_executable(path)? == expected)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, expected);
        Ok(true)
    }
}

fn internal_executable_matches(path: &Path, expected: bool) -> Result<bool, PortError> {
    let actual = internal_regular_file_executable(path)?;
    #[cfg(unix)]
    {
        Ok(actual == expected)
    }
    #[cfg(not(unix))]
    {
        let _ = (actual, expected);
        Ok(true)
    }
}

fn validate_transaction_receipt(
    path: &Path,
    install_base: &Path,
    records: &[JournalRecord],
) -> Result<(), PortError> {
    let receipt = read_receipt(path, install_base)?;
    let Some(JournalRecord::Header {
        package_id,
        directory,
        ..
    }) = records.first()
    else {
        return Err(state_error("transaction journal has no header"));
    };
    if receipt.package_id() != package_id || receipt.directory() != directory {
        return Err(state_error(
            "transaction receipt does not match its journal",
        ));
    }
    Ok(())
}

struct ValidatedUninstallTransaction {
    receipt: OwnershipReceipt,
    live_receipt: bool,
}

fn validate_uninstall_transaction_state(
    install_base: &Path,
    paths: &transaction::TransactionPaths,
    records: &[JournalRecord],
) -> Result<ValidatedUninstallTransaction, PortError> {
    require_missing(&paths.receipt_previous)?;
    require_missing(&paths.receipt_pending)?;
    let live_receipt = path_present(&paths.receipt)?;
    let tombstone = path_present(&paths.receipt_deleted)?;
    if !live_receipt && !tombstone {
        return Err(state_error(
            "uninstall recovery is ambiguous: both receipt links are missing",
        ));
    }
    if !live_receipt && !matches!(records.last(), Some(JournalRecord::Committing)) {
        return Err(state_error(
            "committed uninstall has no final journal marker",
        ));
    }
    let linked_pair =
        live_receipt && tombstone && same_file(&paths.receipt, &paths.receipt_deleted)?;
    if live_receipt && tombstone && !linked_pair {
        return Err(state_error(
            "live ownership receipt does not match its uninstall tombstone",
        ));
    }
    let receipt_path = if live_receipt {
        &paths.receipt
    } else {
        &paths.receipt_deleted
    };
    let receipt =
        validate_uninstall_receipt_and_records(receipt_path, install_base, records, linked_pair)?;
    Ok(ValidatedUninstallTransaction {
        receipt,
        live_receipt,
    })
}

fn validate_uninstall_receipt_and_records(
    receipt_path: &Path,
    install_base: &Path,
    records: &[JournalRecord],
    allow_multiple_links: bool,
) -> Result<OwnershipReceipt, PortError> {
    let receipt = validate_receipt_hash_with_links(
        receipt_path,
        install_base,
        uninstall_receipt_hash(records)?,
        allow_multiple_links,
    )?;
    require_receipt_scope(&receipt, transaction_scope(records)?)?;
    let Some(JournalRecord::Header {
        package_id,
        directory,
        ..
    }) = records.first()
    else {
        return Err(state_error("uninstall transaction has no header"));
    };
    if receipt.package_id() != package_id || receipt.directory() != directory {
        return Err(state_error(
            "ownership receipt does not match uninstall journal",
        ));
    }
    let index = file_collision_index(receipt.files());
    for record in records.iter().skip(1) {
        match record {
            JournalRecord::RestoreFile {
                path,
                sha256,
                executable,
            } => {
                let expected = index
                    .get(&path.collision_key())
                    .and_then(|index| receipt.files().get(*index));
                if !expected.is_some_and(|file| {
                    file.path == *path && &file.sha256 == sha256 && file.executable == *executable
                }) {
                    return Err(state_error(format!(
                        "uninstall journal restore intent for `{path}` is not owned by its receipt"
                    )));
                }
            }
            JournalRecord::Committing => {}
            _ => {
                return Err(state_error("uninstall journal contains an invalid record"));
            }
        }
    }
    Ok(receipt)
}

fn validate_uninstall_cleanup_layout(
    paths: &transaction::TransactionPaths,
    records: &[JournalRecord],
) -> Result<(), PortError> {
    let tombstone = path_present(&paths.receipt_deleted)?;
    for entry in fs::read_dir(&paths.state_dir).map_err(|source| {
        io_error(
            "reading uninstall transaction state",
            &paths.state_dir,
            source,
        )
    })? {
        let entry = entry.map_err(|source| {
            io_error(
                "reading uninstall transaction state entry",
                &paths.state_dir,
                source,
            )
        })?;
        let name = entry.file_name();
        let allowed = name == "journal.jsonl" || (tombstone && name == "receipt.deleted");
        if !allowed {
            return Err(state_error(
                "uninstall transaction state contains an unexpected entry",
            ));
        }
    }

    if !path_present(&paths.destination_dir)? {
        return Ok(());
    }
    let mut allowed_files = BTreeSet::new();
    let mut allowed_directories = BTreeSet::from([paths.destination_dir.clone()]);
    for record in records {
        let JournalRecord::RestoreFile { path, .. } = record else {
            continue;
        };
        let backup = removed_file(paths, path);
        allowed_files.insert(backup.clone());
        let mut parent = backup.parent();
        while let Some(directory) = parent {
            if !directory.starts_with(&paths.destination_dir) {
                break;
            }
            allowed_directories.insert(directory.to_path_buf());
            if directory == paths.destination_dir {
                break;
            }
            parent = directory.parent();
        }
    }

    let mut pending = vec![paths.destination_dir.clone()];
    while let Some(directory) = pending.pop() {
        validate_directory(&directory)?;
        for entry in fs::read_dir(&directory).map_err(|source| {
            io_error("reading uninstall transaction backup", &directory, source)
        })? {
            let entry = entry.map_err(|source| {
                io_error(
                    "reading uninstall transaction backup entry",
                    &directory,
                    source,
                )
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("inspecting uninstall backup entry", &path, source))?;
            if metadata.is_dir() && allowed_directories.contains(&path) {
                pending.push(path);
            } else if metadata.is_file() && allowed_files.contains(&path) {
                drop(open_internal_regular(&path, u64::MAX)?);
            } else {
                return Err(state_error(
                    "uninstall transaction backup contains an unexpected entry",
                ));
            }
        }
    }
    Ok(())
}

fn remove_owned_empty_directories(root: &Path, records: &[JournalRecord]) {
    let mut directories = BTreeSet::new();
    for record in records {
        if let JournalRecord::RestoreFile { path, .. } = record {
            let mut parent = root.join(path.to_native_path());
            parent.pop();
            while parent.starts_with(root) && parent != root {
                directories.insert(parent.clone());
                if !parent.pop() {
                    break;
                }
            }
        }
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        if let Some(parent) = directory.parent()
            && validate_directory_chain(parent).is_err()
        {
            continue;
        }
        let _ = remove_directory_if_empty(&directory);
    }
    let _ = remove_directory_if_empty(root);
}

fn load_receipt(
    install_base: &Path,
    state_root: &Path,
    package_id: &PackageId,
    expected_scope: InstallScope,
) -> Result<Option<OwnershipReceipt>, PortError> {
    let path = transaction_paths(install_base, state_root, package_id).receipt;
    match fs::symlink_metadata(&path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error("inspecting ownership receipt", &path, source)),
        Ok(_) => {
            if expected_scope == InstallScope::System {
                validate_private_directory(state_root, expected_scope)?;
                validate_private_directory(&state_root.join("receipts"), expected_scope)?;
                validate_private_file(&path, expected_scope)?;
            }
            let receipt = read_receipt(&path, install_base)?;
            require_receipt_scope(&receipt, expected_scope)?;
            if receipt.package_id() != package_id {
                return Err(state_error(
                    "ownership receipt package id does not match its path",
                ));
            }
            Ok(Some(receipt))
        }
    }
}

fn require_receipt_scope(
    receipt: &OwnershipReceipt,
    expected_scope: InstallScope,
) -> Result<(), PortError> {
    if receipt.scope() == expected_scope {
        Ok(())
    } else {
        Err(state_error(format!(
            "ownership receipt scope {:?} does not match {expected_scope:?} adapter",
            receipt.scope()
        )))
    }
}

fn read_receipt(path: &Path, install_base: &Path) -> Result<OwnershipReceipt, PortError> {
    Ok(read_receipt_with_hash(path, install_base)?.0)
}

fn read_receipt_with_hash(
    path: &Path,
    install_base: &Path,
) -> Result<(OwnershipReceipt, Sha256Digest), PortError> {
    read_receipt_with_hash_links(path, install_base, false)
}

fn read_receipt_with_hash_links(
    path: &Path,
    install_base: &Path,
    allow_multiple_links: bool,
) -> Result<(OwnershipReceipt, Sha256Digest), PortError> {
    if let Some(parent) = path.parent() {
        validate_directory_chain(parent)?;
    }
    let file = if allow_multiple_links {
        open_internal_regular(path, MAX_RECEIPT_BYTES)?
    } else {
        open_regular(path, MAX_RECEIPT_BYTES)?
    };
    let mut bytes = Vec::new();
    file.take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("reading ownership receipt", path, source))?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(state_error("ownership receipt exceeds the size limit"));
    }
    let stored: StoredReceipt = serde_json::from_slice(&bytes).map_err(|error| {
        state_error(format!(
            "parsing ownership receipt `{}` failed: {error}",
            path.display()
        ))
    })?;
    if stored.format_version != STORED_RECEIPT_FORMAT_VERSION {
        return Err(state_error(format!(
            "unsupported stored receipt format {}",
            stored.format_version
        )));
    }
    if stored.install_base != install_base_identity(install_base)? {
        return Err(state_error(
            "ownership receipt belongs to a different install base",
        ));
    }
    stored
        .receipt
        .validate()
        .map_err(|error| state_error(format!("invalid ownership receipt: {error}")))?;
    Ok((stored.receipt, digest_bytes(&bytes)))
}

fn validate_receipt_hash(
    path: &Path,
    install_base: &Path,
    expected: &Sha256Digest,
) -> Result<OwnershipReceipt, PortError> {
    validate_receipt_hash_with_links(path, install_base, expected, false)
}

fn validate_receipt_hash_with_links(
    path: &Path,
    install_base: &Path,
    expected: &Sha256Digest,
    allow_multiple_links: bool,
) -> Result<OwnershipReceipt, PortError> {
    let (receipt, found) = read_receipt_with_hash_links(path, install_base, allow_multiple_links)?;
    if &found != expected {
        return Err(state_error(format!(
            "ownership receipt `{}` does not match its transaction binding",
            path.display()
        )));
    }
    Ok(receipt)
}

fn validate_upgrade_receipt(
    path: &Path,
    install_base: &Path,
    expected: &Sha256Digest,
    records: &[JournalRecord],
) -> Result<OwnershipReceipt, PortError> {
    let receipt = validate_receipt_hash(path, install_base, expected)?;
    require_receipt_scope(&receipt, transaction_scope(records)?)?;
    let Some(JournalRecord::Header {
        operation: Operation::Upgrade,
        package_id,
        directory,
        ..
    }) = records.first()
    else {
        return Err(state_error("transaction has no upgrade receipt binding"));
    };
    if receipt.package_id() != package_id || receipt.directory() != directory {
        return Err(state_error(
            "upgrade ownership receipt does not match its journal header",
        ));
    }
    Ok(receipt)
}

fn stored_receipt_bytes(stored: &StoredReceipt) -> Result<Vec<u8>, PortError> {
    serde_json::to_vec_pretty(stored)
        .map_err(|error| state_error(format!("serializing ownership receipt failed: {error}")))
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(hex::encode(Sha256::digest(bytes)))
        .expect("SHA-256 output is a valid digest")
}

fn require_missing(path: &Path) -> Result<(), PortError> {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspecting destination", path, source)),
        Ok(_) => Err(PortError::with_kind(
            PortErrorKind::Collision,
            format!("destination `{}` already exists", path.display()),
        )),
    }
}

fn copy_and_hash(input: &mut File, output: &mut File) -> Result<(u64, Sha256Digest), PortError> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(|source| {
            PortError::with_kind(
                PortErrorKind::Integrity,
                format!("reading verified bundle object failed: {source}"),
            )
        })?;
        if read == 0 {
            break;
        }
        size = size.checked_add(read as u64).ok_or_else(|| {
            PortError::with_kind(PortErrorKind::Integrity, "payload size overflow")
        })?;
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|source| PortError::with_kind(PortErrorKind::Io, source.to_string()))?;
    }
    let digest = Sha256Digest::parse(hex::encode(hasher.finalize()))
        .map_err(|error| PortError::with_kind(PortErrorKind::Integrity, error.to_string()))?;
    Ok((size, digest))
}

#[cfg(test)]
mod tests;
