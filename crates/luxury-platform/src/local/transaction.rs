use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use luxury_engine::{PortError, PortErrorKind};
use luxury_spec::{InstallDirectory, InstallScope, PackageId, PackagePath, Sha256Digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LEGACY_JOURNAL_VERSION: u32 = 2;
const RECEIPT_BOUND_JOURNAL_VERSION: u32 = 3;
const JOURNAL_VERSION: u32 = 4;
pub(super) const MAX_JOURNAL_BYTES: u64 = 128 * 1024 * 1024;
// The byte cap normally binds first; this separately bounds tiny-record amplification.
pub(super) const MAX_JOURNAL_RECORDS: usize = 1_000_010;
pub(super) const DESTINATION_LOCK_DIRECTORY: &str = ".luxury-locks";
pub(super) const TRANSACTION_DIRECTORY_PREFIX: &str = ".luxury-tx-";
pub(super) const MAX_RECEIPT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstallBaseIdentity {
    canonical_path_sha256: Sha256Digest,
    filesystem_id: u64,
    file_id: [u8; 16],
}

impl InstallBaseIdentity {
    pub(super) fn maximum_serialized_size_placeholder() -> Self {
        Self {
            canonical_path_sha256: Sha256Digest::parse(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
            .expect("fixed SHA-256 is valid"),
            filesystem_id: u64::MAX,
            file_id: [u8::MAX; 16],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Operation {
    Install,
    Upgrade,
    Uninstall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum JournalRecord {
    Header {
        format_version: u32,
        operation: Operation,
        package_id: PackageId,
        directory: InstallDirectory,
        install_base: InstallBaseIdentity,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<InstallScope>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_receipt_sha256: Option<Sha256Digest>,
    },
    RemoveFile {
        path: PackagePath,
        sha256: Sha256Digest,
    },
    RemoveDirectory {
        path: Option<PackagePath>,
    },
    RestoreFile {
        path: PackagePath,
        sha256: Sha256Digest,
        executable: bool,
    },
    StageFile {
        path: PackagePath,
        sha256: Sha256Digest,
    },
    PendingReceipt {
        sha256: Sha256Digest,
    },
    Committing,
    RollingBack,
}

#[derive(Debug, Clone)]
pub(super) struct TransactionPaths {
    pub state_dir: PathBuf,
    pub journal: PathBuf,
    pub journal_done: PathBuf,
    pub receipt_pending: PathBuf,
    pub receipt_previous: PathBuf,
    pub receipt_deleted: PathBuf,
    pub destination_dir: PathBuf,
    pub receipt: PathBuf,
}

pub(super) struct ActiveTransaction {
    pub paths: TransactionPaths,
    pub records: Vec<JournalRecord>,
    journal: File,
    _package_lock: File,
    _destination_lock: File,
}

impl ActiveTransaction {
    pub fn append(&mut self, record: JournalRecord) -> Result<(), PortError> {
        if self.records.len() >= MAX_JOURNAL_RECORDS {
            return Err(state_error("transaction journal record limit exceeded"));
        }
        write_record(&mut self.journal, &record)?;
        self.records.push(record);
        Ok(())
    }

    pub fn header(
        &self,
    ) -> (
        &PackageId,
        &InstallDirectory,
        Operation,
        &InstallBaseIdentity,
    ) {
        header(&self.records).expect("active transaction always has a validated header")
    }

    pub fn mark_rolling_back(&mut self) -> Result<(), PortError> {
        if matches!(self.records.last(), Some(JournalRecord::RollingBack)) {
            return Ok(());
        }
        if self.header().2 != Operation::Upgrade {
            return Err(state_error(
                "rollback marker is only valid for upgrade transactions",
            ));
        }
        prepare_rollback_marker(&mut self.journal, &self.paths.journal, &self.records)?;
        self.records.push(JournalRecord::RollingBack);
        Ok(())
    }
}

pub(super) struct RecoveredTransaction {
    pub paths: TransactionPaths,
    pub records: Vec<JournalRecord>,
    _package_lock: File,
    _destination_lock: File,
}

impl RecoveredTransaction {
    pub fn header(
        &self,
    ) -> (
        &PackageId,
        &InstallDirectory,
        Operation,
        &InstallBaseIdentity,
    ) {
        header(&self.records).expect("recovered transaction has a validated header")
    }

    pub fn mark_rolling_back(&mut self) -> Result<(), PortError> {
        if matches!(self.records.last(), Some(JournalRecord::RollingBack)) {
            return Ok(());
        }
        if self.header().2 != Operation::Upgrade {
            return Err(state_error(
                "rollback marker is only valid for upgrade transactions",
            ));
        }

        let mut options = OpenOptions::new();
        options.read(true).write(true);
        let mut journal = open_nofollow(&mut options, &self.paths.journal).map_err(|source| {
            io_error("reopening transaction journal", &self.paths.journal, source)
        })?;
        let metadata = validate_open_regular(&self.paths.journal, &journal, false)?;
        if metadata.len() > MAX_JOURNAL_BYTES {
            return Err(state_error("transaction journal exceeds the size limit"));
        }
        prepare_rollback_marker(&mut journal, &self.paths.journal, &self.records)?;
        self.records.push(JournalRecord::RollingBack);
        Ok(())
    }
}

pub(super) fn transaction_paths(
    install_base: &Path,
    state_root: &Path,
    package_id: &PackageId,
) -> TransactionPaths {
    let state_dir = state_root.join("transactions").join(package_id.as_str());
    TransactionPaths {
        journal: state_dir.join("journal.jsonl"),
        journal_done: state_dir.join("journal.done"),
        receipt_pending: state_dir.join("receipt.pending"),
        receipt_previous: state_dir.join("receipt.previous"),
        receipt_deleted: state_dir.join("receipt.deleted"),
        destination_dir: install_base.join(format!(
            "{TRANSACTION_DIRECTORY_PREFIX}{}",
            package_id.as_str()
        )),
        receipt: state_root
            .join("receipts")
            .join(format!("{}.json", package_id.as_str())),
        state_dir,
    }
}

#[cfg(test)]
pub(super) fn begin_transaction(
    install_base: &Path,
    state_root: &Path,
    package_id: &PackageId,
    directory: &InstallDirectory,
    operation: Operation,
) -> Result<ActiveTransaction, PortError> {
    if operation != Operation::Install {
        return Err(state_error(
            "test transactions for receipt-bound operations need an explicit receipt hash",
        ));
    }
    let package_lock = lock_package(state_root, package_id, InstallScope::User)?;
    begin_transaction_with_package_lock(
        install_base,
        state_root,
        package_id,
        directory,
        operation,
        InstallScope::User,
        None,
        package_lock,
    )
}

#[cfg(test)]
pub(super) fn begin_uninstall_transaction(
    install_base: &Path,
    state_root: &Path,
    package_id: &PackageId,
    directory: &InstallDirectory,
    receipt_sha256: Sha256Digest,
) -> Result<ActiveTransaction, PortError> {
    let package_lock = lock_package(state_root, package_id, InstallScope::User)?;
    begin_transaction_with_package_lock(
        install_base,
        state_root,
        package_id,
        directory,
        Operation::Uninstall,
        InstallScope::User,
        Some(receipt_sha256),
        package_lock,
    )
}

pub(super) fn lock_package(
    state_root: &Path,
    package_id: &PackageId,
    scope: InstallScope,
) -> Result<File, PortError> {
    ensure_directory(state_root, Some(scope))?;
    ensure_directory(&state_root.join("locks"), Some(scope))?;
    ensure_directory(&state_root.join("transactions"), Some(scope))?;
    ensure_directory(&state_root.join("receipts"), Some(scope))?;
    acquire_package_lock(state_root, package_id, scope)
}

#[allow(
    clippy::too_many_arguments,
    reason = "transaction authority, receipt binding, and the already-held lock stay explicit"
)]
pub(super) fn begin_transaction_with_package_lock(
    install_base: &Path,
    state_root: &Path,
    package_id: &PackageId,
    directory: &InstallDirectory,
    operation: Operation,
    scope: InstallScope,
    previous_receipt_sha256: Option<Sha256Digest>,
    package_lock: File,
) -> Result<ActiveTransaction, PortError> {
    if matches!(operation, Operation::Upgrade | Operation::Uninstall)
        != previous_receipt_sha256.is_some()
    {
        return Err(state_error("transaction receipt binding is invalid"));
    }
    ensure_directory(install_base, None)?;
    ensure_directory(&state_root.join("transactions"), Some(scope))?;
    ensure_directory(&state_root.join("receipts"), Some(scope))?;
    ensure_directory(&install_base.join(DESTINATION_LOCK_DIRECTORY), Some(scope))?;
    let canonical_install_base = fs::canonicalize(install_base)
        .map_err(|source| io_error("canonicalizing install base", install_base, source))?;
    let canonical_state_root = fs::canonicalize(state_root)
        .map_err(|source| io_error("canonicalizing state root", state_root, source))?;
    roots_are_separate(
        &canonical_install_base.join(directory.as_str()),
        &canonical_state_root,
    )?;
    let install_base_identity = identity_from_canonical_install_base(&canonical_install_base)?;

    let paths = transaction_paths(install_base, state_root, package_id);
    let destination_lock = acquire_destination_lock(install_base, directory, scope)?;
    if path_present(&paths.state_dir)? || path_present(&paths.destination_dir)? {
        return Err(state_error(
            "pending transaction exists; recovery must finish before begin",
        ));
    }

    create_directory(&paths.state_dir, Some(scope))?;
    let mut journal = match OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(&paths.journal)
    {
        Ok(file) => file,
        Err(source) => {
            let _ = unlink_directory(&paths.state_dir);
            return Err(io_error(
                "creating transaction journal",
                &paths.journal,
                source,
            ));
        }
    };
    if let Err(error) = set_private_file(&paths.journal, scope) {
        drop(journal);
        let _ = unlink_file(&paths.journal);
        let _ = unlink_directory(&paths.state_dir);
        return Err(error);
    }

    let record = JournalRecord::Header {
        format_version: JOURNAL_VERSION,
        operation,
        package_id: package_id.clone(),
        directory: directory.clone(),
        install_base: install_base_identity,
        scope: Some(scope),
        previous_receipt_sha256,
    };
    if let Err(error) = write_record(&mut journal, &record) {
        drop(journal);
        let _ = unlink_file(&paths.journal);
        let _ = unlink_directory(&paths.state_dir);
        return Err(error);
    }
    sync_parent(&paths.journal)?;
    create_directory(&paths.destination_dir, Some(scope))?;

    Ok(ActiveTransaction {
        paths,
        records: vec![record],
        journal,
        _package_lock: package_lock,
        _destination_lock: destination_lock,
    })
}

#[cfg(test)]
pub(super) fn load_recovery(
    install_base: &Path,
    state_root: &Path,
    package_id: &PackageId,
) -> Result<Option<RecoveredTransaction>, PortError> {
    load_recovery_for_scope(install_base, state_root, package_id, InstallScope::User)
}

pub(super) fn load_recovery_for_scope(
    install_base: &Path,
    state_root: &Path,
    package_id: &PackageId,
    expected_scope: InstallScope,
) -> Result<Option<RecoveredTransaction>, PortError> {
    let paths = transaction_paths(install_base, state_root, package_id);
    let state_present = path_present(&paths.state_dir)?;
    let destination_present = path_present(&paths.destination_dir)?;
    if !state_present && !destination_present {
        return Ok(None);
    }
    let package_lock = lock_package(state_root, package_id, expected_scope)?;
    let state_present = path_present(&paths.state_dir)?;
    let destination_present = path_present(&paths.destination_dir)?;
    if !state_present && !destination_present {
        return Ok(None);
    }

    if !state_present {
        return Err(state_error(format!(
            "orphan destination transaction directory `{}`",
            paths.destination_dir.display()
        )));
    }
    validate_directory(&paths.state_dir)?;

    let journal_present = path_present(&paths.journal)?;
    let cleanup_marker_present = path_present(&paths.journal_done)?;
    if journal_present && cleanup_marker_present {
        return Err(state_error(
            "transaction state contains both an active journal and cleanup marker",
        ));
    }

    if !journal_present {
        if destination_present {
            return Err(state_error(
                "transaction state has no bound journal; preserving destination data for recovery",
            ));
        }
        let mut has_tombstone = false;
        let mut has_cleanup_marker = false;
        let mut has_previous_receipt = false;
        for entry in fs::read_dir(&paths.state_dir).map_err(|source| {
            io_error(
                "reading transaction state directory",
                &paths.state_dir,
                source,
            )
        })? {
            let entry = entry.map_err(|source| {
                io_error(
                    "reading transaction state directory entry",
                    &paths.state_dir,
                    source,
                )
            })?;
            match entry.file_name().to_str() {
                Some("receipt.deleted") => has_tombstone = true,
                Some("receipt.previous") => has_previous_receipt = true,
                Some("journal.done") => has_cleanup_marker = true,
                _ => {
                    return Err(state_error(
                        "transaction state has no bound journal; preserving unexpected state for recovery",
                    ));
                }
            }
        }
        if has_previous_receipt {
            return Err(state_error(
                "transaction state has no bound journal; preserving previous receipt for recovery",
            ));
        }
        if has_cleanup_marker {
            let records = read_bound_journal(
                &paths.journal_done,
                install_base,
                package_id,
                expected_scope,
            )?;
            let (_, _, operation, _) = header(&records)?;
            if operation != Operation::Uninstall
                || !matches!(records.last(), Some(JournalRecord::Committing))
            {
                return Err(state_error(
                    "transaction cleanup marker does not finalize an uninstall",
                ));
            }
            harden_recovery_directories(&paths, expected_scope)?;
            if path_present(&paths.receipt)? {
                return Err(state_error(
                    "committed uninstall cleanup marker conflicts with a live receipt",
                ));
            }
            if has_tombstone {
                super::validate_uninstall_receipt_and_records(
                    &paths.receipt_deleted,
                    install_base,
                    &records,
                    false,
                )?;
                remove_internal_link(&paths.receipt_deleted)?;
            }
            remove_regular(&paths.journal_done)?;
            remove_empty_directory(&paths.state_dir)?;
            return Ok(None);
        }
        if has_tombstone {
            let live_receipt = path_present(&paths.receipt)?;
            let linked_pair = live_receipt && same_file(&paths.receipt, &paths.receipt_deleted)?;
            if expected_scope == InstallScope::System {
                validate_private_file(&paths.receipt_deleted, expected_scope)?;
                if live_receipt {
                    validate_private_file(&paths.receipt, expected_scope)?;
                }
            }
            let receipt = super::read_receipt_with_hash_links(
                &paths.receipt_deleted,
                install_base,
                linked_pair,
            )?
            .0;
            require_receipt_scope(&receipt, expected_scope)?;
            if live_receipt {
                if !linked_pair {
                    return Err(state_error(
                        "live ownership receipt does not match its orphan tombstone",
                    ));
                }
            } else {
                if receipt.package_id() != package_id {
                    return Err(state_error(
                        "ownership receipt tombstone package id does not match its path",
                    ));
                }
            }
            harden_recovery_directories(&paths, expected_scope)?;
            remove_internal_link(&paths.receipt_deleted)?;
        }
        remove_empty_directory(&paths.state_dir)?;
        return Ok(None);
    }

    let records = read_bound_journal(&paths.journal, install_base, package_id, expected_scope)?;
    let (_, directory, _, _) = header(&records)?;
    harden_recovery_directories(&paths, expected_scope)?;
    ensure_directory(
        &install_base.join(DESTINATION_LOCK_DIRECTORY),
        Some(expected_scope),
    )?;
    let destination_lock = acquire_destination_lock(install_base, directory, expected_scope)?;

    Ok(Some(RecoveredTransaction {
        paths,
        records,
        _package_lock: package_lock,
        _destination_lock: destination_lock,
    }))
}

fn harden_recovery_directories(
    paths: &TransactionPaths,
    scope: InstallScope,
) -> Result<(), PortError> {
    ensure_directory(&paths.state_dir, Some(scope))?;
    if path_present(&paths.destination_dir)? {
        ensure_directory(&paths.destination_dir, Some(scope))?;
    }
    Ok(())
}

fn read_bound_journal(
    path: &Path,
    install_base: &Path,
    package_id: &PackageId,
    expected_scope: InstallScope,
) -> Result<Vec<JournalRecord>, PortError> {
    if expected_scope == InstallScope::System {
        validate_private_file(path, expected_scope)?;
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspecting transaction journal", path, source))?;
    if metadata.len() == 0 {
        return Err(state_error(
            "transaction state has an empty unbound journal; preserving it for recovery",
        ));
    }
    let records = read_journal(path)?;
    if records.is_empty() {
        return Err(state_error(
            "transaction state has a torn unbound journal; preserving it for recovery",
        ));
    }
    let (found_id, _, _, recorded_install_base) = header(&records)?;
    if found_id != package_id {
        return Err(state_error(
            "transaction journal package id does not match its path",
        ));
    }
    if recorded_install_base != &install_base_identity(install_base)? {
        return Err(state_error(
            "transaction journal belongs to a different install base",
        ));
    }
    require_journal_scope(&records, expected_scope)?;
    Ok(records)
}

fn require_journal_scope(
    records: &[JournalRecord],
    expected_scope: InstallScope,
) -> Result<(), PortError> {
    let found = scope(records)?;
    if found == expected_scope {
        Ok(())
    } else {
        Err(state_error(format!(
            "transaction journal scope {found:?} does not match {expected_scope:?} authority"
        )))
    }
}

fn require_receipt_scope(
    receipt: &luxury_engine::uninstall::OwnershipReceipt,
    expected_scope: InstallScope,
) -> Result<(), PortError> {
    if receipt.scope() == expected_scope {
        Ok(())
    } else {
        Err(state_error(format!(
            "ownership receipt scope {:?} does not match {expected_scope:?} authority",
            receipt.scope()
        )))
    }
}

pub(super) fn path_present(path: &Path) -> Result<bool, PortError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("inspecting transaction state", path, source)),
    }
}

pub(super) fn operation(records: &[JournalRecord]) -> Result<Operation, PortError> {
    Ok(header(records)?.2)
}

pub(super) fn install_directory(records: &[JournalRecord]) -> Result<&InstallDirectory, PortError> {
    Ok(header(records)?.1)
}

fn header(
    records: &[JournalRecord],
) -> Result<
    (
        &PackageId,
        &InstallDirectory,
        Operation,
        &InstallBaseIdentity,
    ),
    PortError,
> {
    match records.first() {
        Some(JournalRecord::Header {
            format_version,
            operation,
            package_id,
            directory,
            install_base,
            scope,
            previous_receipt_sha256,
        }) if (*format_version == LEGACY_JOURNAL_VERSION
            && scope.is_none()
            && matches!(operation, Operation::Install | Operation::Uninstall)
            && previous_receipt_sha256.is_none())
            || (*format_version == RECEIPT_BOUND_JOURNAL_VERSION
                && scope.is_none()
                && ((*operation == Operation::Install && previous_receipt_sha256.is_none())
                    || (*operation == Operation::Uninstall
                        && previous_receipt_sha256.is_some())
                    || (*operation == Operation::Upgrade
                        && previous_receipt_sha256.is_some())))
            || (*format_version == JOURNAL_VERSION
                && scope.is_some()
                && ((*operation == Operation::Install && previous_receipt_sha256.is_none())
                    || (*operation == Operation::Uninstall
                        && previous_receipt_sha256.is_some())
                    || (*operation == Operation::Upgrade
                        && previous_receipt_sha256.is_some()))) =>
        {
            Ok((package_id, directory, *operation, install_base))
        }
        Some(JournalRecord::Header { format_version, .. }) => Err(state_error(format!(
            "unsupported transaction journal format {format_version}"
        ))),
        _ => Err(state_error("transaction journal has no valid header")),
    }
}

pub(super) fn scope(records: &[JournalRecord]) -> Result<InstallScope, PortError> {
    header(records)?;
    match records.first() {
        Some(JournalRecord::Header {
            format_version: JOURNAL_VERSION,
            scope: Some(scope),
            ..
        }) => Ok(*scope),
        Some(JournalRecord::Header {
            format_version: LEGACY_JOURNAL_VERSION | RECEIPT_BOUND_JOURNAL_VERSION,
            scope: None,
            ..
        }) => Ok(InstallScope::User),
        _ => Err(state_error(
            "transaction journal has no valid scope binding",
        )),
    }
}

pub(super) fn uninstall_receipt_hash(
    records: &[JournalRecord],
) -> Result<&Sha256Digest, PortError> {
    let Some(JournalRecord::Header {
        format_version,
        operation: Operation::Uninstall,
        previous_receipt_sha256: Some(receipt_sha256),
        ..
    }) = records.first()
    else {
        return Err(state_error(
            "uninstall transaction has no receipt-bound journal header",
        ));
    };
    if !matches!(
        *format_version,
        RECEIPT_BOUND_JOURNAL_VERSION | JOURNAL_VERSION
    ) {
        return Err(state_error(
            "uninstall transaction has no receipt-bound journal header",
        ));
    }
    Ok(receipt_sha256)
}

pub(super) fn upgrade_receipt_hashes(
    records: &[JournalRecord],
) -> Result<(&Sha256Digest, Option<&Sha256Digest>), PortError> {
    let Some(JournalRecord::Header {
        format_version,
        operation: Operation::Upgrade,
        previous_receipt_sha256: Some(previous),
        ..
    }) = records.first()
    else {
        return Err(state_error("transaction has no valid upgrade header"));
    };
    if !matches!(
        *format_version,
        RECEIPT_BOUND_JOURNAL_VERSION | JOURNAL_VERSION
    ) {
        return Err(state_error(format!(
            "unsupported upgrade transaction journal format {format_version}"
        )));
    }

    let mut pending = None;
    let mut committing = false;
    let rolling_back = matches!(records.last(), Some(JournalRecord::RollingBack));
    let effective_len = records.len() - usize::from(rolling_back);
    for (index, record) in records.iter().take(effective_len).enumerate().skip(1) {
        match record {
            JournalRecord::PendingReceipt { sha256 } if pending.is_none() && !committing => {
                pending = Some(sha256);
            }
            JournalRecord::PendingReceipt { .. } => {
                return Err(state_error(
                    "upgrade journal contains an invalid pending receipt marker",
                ));
            }
            JournalRecord::Committing if !committing && index + 1 == effective_len => {
                if pending.is_none() {
                    return Err(state_error(
                        "upgrade journal commits without a pending receipt",
                    ));
                }
                committing = true;
            }
            JournalRecord::Committing => {
                return Err(state_error(
                    "transaction commit marker must precede only rollback state",
                ));
            }
            JournalRecord::RollingBack => {
                return Err(state_error(
                    "transaction rollback marker must be the final record",
                ));
            }
            JournalRecord::Header { .. } => {
                return Err(state_error(
                    "transaction journal contains a duplicate header",
                ));
            }
            _ if committing => {
                return Err(state_error(
                    "transaction journal continues after commit marker",
                ));
            }
            _ if pending.is_some() => {
                return Err(state_error(
                    "upgrade journal mutates files after staging its receipt",
                ));
            }
            _ => {}
        }
    }
    Ok((previous, pending))
}

pub(super) fn is_rolling_back(records: &[JournalRecord]) -> bool {
    matches!(records.last(), Some(JournalRecord::RollingBack))
}

pub(super) fn install_base_identity(install_base: &Path) -> Result<InstallBaseIdentity, PortError> {
    let canonical = fs::canonicalize(install_base)
        .map_err(|source| io_error("canonicalizing install base", install_base, source))?;
    identity_from_canonical_install_base(&canonical)
}

fn identity_from_canonical_install_base(
    canonical: &Path,
) -> Result<InstallBaseIdentity, PortError> {
    validate_directory(canonical)?;
    let (filesystem_id, file_id) = directory_identity(canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(b"luxury-install-base-identity-v1\0");
    hash_native_path(&mut hasher, canonical)?;
    let canonical_path_sha256 = Sha256Digest::parse(hex::encode(hasher.finalize()))
        .expect("SHA-256 output is a valid digest");
    Ok(InstallBaseIdentity {
        canonical_path_sha256,
        filesystem_id,
        file_id,
    })
}

#[cfg(unix)]
fn directory_identity(path: &Path) -> Result<(u64, [u8; 16]), PortError> {
    use std::os::unix::fs::MetadataExt;

    let file = File::open(path).map_err(|source| io_error("opening install base", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("reading install base identity", path, source))?;
    if !metadata.is_dir() {
        return Err(state_error(
            "install base changed while reading its identity",
        ));
    }
    let mut file_id = [0_u8; 16];
    file_id[..8].copy_from_slice(&metadata.ino().to_le_bytes());
    Ok((metadata.dev(), file_id))
}

#[cfg(windows)]
fn directory_identity(path: &Path) -> Result<(u64, [u8; 16]), PortError> {
    super::windows::directory_identity(path)
        .map_err(|source| io_error("reading install base identity", path, source))
}

#[cfg(not(any(unix, windows)))]
fn directory_identity(_: &Path) -> Result<(u64, [u8; 16]), PortError> {
    Err(state_error(
        "install base identity is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn hash_native_path(hasher: &mut Sha256, path: &Path) -> Result<(), PortError> {
    use std::os::unix::ffi::OsStrExt;

    hasher.update(b"unix\0");
    hasher.update(path.as_os_str().as_bytes());
    Ok(())
}

#[cfg(windows)]
fn hash_native_path(hasher: &mut Sha256, path: &Path) -> Result<(), PortError> {
    use std::os::windows::ffi::OsStrExt;

    hasher.update(b"windows\0");
    for unit in path.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn hash_native_path(_: &mut Sha256, _: &Path) -> Result<(), PortError> {
    Err(state_error(
        "install base identity is unsupported on this platform",
    ))
}

fn acquire_package_lock(
    state_root: &Path,
    package_id: &PackageId,
    scope: InstallScope,
) -> Result<File, PortError> {
    let path = state_root
        .join("locks")
        .join(format!("{}.lock", package_id.as_str()));
    acquire_lock(&path, format!("package `{package_id}` is busy"), scope)
}

pub(super) fn acquire_destination_lock(
    install_base: &Path,
    directory: &InstallDirectory,
    scope: InstallScope,
) -> Result<File, PortError> {
    #[cfg(any(windows, target_os = "macos"))]
    let key = PackagePath::parse(directory.as_str())
        .expect("install directory is a valid package path")
        .collision_key();
    #[cfg(not(any(windows, target_os = "macos")))]
    let key = directory.as_str();
    let digest = hex::encode(Sha256::digest(key.as_bytes()));
    let path = install_base
        .join(DESTINATION_LOCK_DIRECTORY)
        .join(format!("destination-{digest}.lock"));
    acquire_lock(&path, format!("destination `{directory}` is busy"), scope)
}

fn acquire_lock(path: &Path, busy: String, scope: InstallScope) -> Result<File, PortError> {
    let mut create = OpenOptions::new();
    create.read(true).write(true).create_new(true);
    let (file, created) = match open_nofollow(&mut create, path) {
        Ok(file) => (file, true),
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut existing = OpenOptions::new();
            existing.read(true).write(true);
            (
                open_nofollow(&mut existing, path)
                    .map_err(|source| io_error("opening transaction lock", path, source))?,
                false,
            )
        }
        Err(source) => return Err(io_error("creating transaction lock", path, source)),
    };
    validate_open_regular(path, &file, false)?;
    if created {
        set_private_file(path, scope)?;
    } else {
        validate_private_file(path, scope)?;
    }
    file.try_lock().map_err(|source| match source {
        fs::TryLockError::WouldBlock => PortError::with_kind(PortErrorKind::Busy, busy),
        fs::TryLockError::Error(source) => io_error("locking transaction state", path, source),
    })?;
    Ok(file)
}

fn write_record(file: &mut File, record: &JournalRecord) -> Result<(), PortError> {
    let encoded = serde_json::to_vec(record).map_err(|source| {
        PortError::with_kind(
            PortErrorKind::State,
            format!("serializing transaction journal failed: {source}"),
        )
    })?;
    let current = file
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error("seeking transaction journal", Path::new("journal"), source))?;
    let next = current
        .checked_add(encoded.len() as u64)
        .and_then(|size| size.checked_add(1))
        .ok_or_else(|| state_error("transaction journal size overflow"))?;
    if next > MAX_JOURNAL_BYTES {
        return Err(state_error("transaction journal byte limit exceeded"));
    }
    file.write_all(&encoded)
        .map_err(|source| io_error("writing transaction journal", Path::new("journal"), source))?;
    file.write_all(b"\n")
        .map_err(|source| io_error("writing transaction journal", Path::new("journal"), source))?;
    file.sync_data()
        .map_err(|source| io_error("syncing transaction journal", Path::new("journal"), source))
}

fn prepare_rollback_marker(
    journal: &mut File,
    path: &Path,
    expected: &[JournalRecord],
) -> Result<(), PortError> {
    let (current, valid_end) = read_journal_from(journal, path)?;
    if current != expected {
        return Err(state_error(
            "transaction journal changed before rollback marker publication",
        ));
    }
    if expected.len() >= MAX_JOURNAL_RECORDS {
        return Err(state_error("transaction journal record limit exceeded"));
    }
    let length = journal
        .metadata()
        .map_err(|source| io_error("reading transaction journal metadata", path, source))?
        .len();
    if length != valid_end {
        journal
            .set_len(valid_end)
            .map_err(|source| io_error("truncating torn transaction journal", path, source))?;
        journal
            .sync_all()
            .map_err(|source| io_error("syncing truncated transaction journal", path, source))?;
    }
    write_record(journal, &JournalRecord::RollingBack)
}

fn read_journal(path: &Path) -> Result<Vec<JournalRecord>, PortError> {
    let mut file = open_regular(path, MAX_JOURNAL_BYTES)?;
    Ok(read_journal_from(&mut file, path)?.0)
}

fn read_journal_from(file: &mut File, path: &Path) -> Result<(Vec<JournalRecord>, u64), PortError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("seeking transaction journal", path, source))?;
    let mut reader = BufReader::new(file);
    let mut records = Vec::new();
    let mut line = Vec::new();
    let mut valid_end = 0_u64;
    loop {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .map_err(|source| io_error("reading transaction journal", path, source))?;
        if read == 0 {
            break;
        }
        if line.last() != Some(&b'\n') {
            // Mutations start only after append + newline + sync_data succeeds,
            // so only this unterminated final record is safe to ignore.
            break;
        }
        valid_end = valid_end
            .checked_add(read as u64)
            .ok_or_else(|| state_error("transaction journal offset overflow"))?;
        line.pop();
        if line.is_empty() {
            return Err(state_error("transaction journal contains an empty record"));
        }
        let record = serde_json::from_slice(&line).map_err(|source| {
            PortError::with_kind(
                PortErrorKind::State,
                format!(
                    "parsing transaction journal `{}` failed: {source}",
                    path.display()
                ),
            )
        })?;
        records.push(record);
        if records.len() > MAX_JOURNAL_RECORDS {
            return Err(state_error("transaction journal contains too many records"));
        }
    }

    if records
        .iter()
        .skip(1)
        .any(|record| matches!(record, JournalRecord::Header { .. }))
    {
        return Err(state_error(
            "transaction journal contains a duplicate header",
        ));
    }
    if matches!(
        records.first(),
        Some(JournalRecord::Header {
            format_version: LEGACY_JOURNAL_VERSION,
            ..
        })
    ) && records.iter().skip(1).any(|record| {
        matches!(
            record,
            JournalRecord::StageFile { .. }
                | JournalRecord::PendingReceipt { .. }
                | JournalRecord::RollingBack
        )
    }) {
        return Err(state_error(
            "legacy v2 journal contains records introduced by v3",
        ));
    }
    let rollback_markers = records
        .iter()
        .filter(|record| matches!(record, JournalRecord::RollingBack))
        .count();
    if rollback_markers > 0
        && (rollback_markers != 1
            || !matches!(records.last(), Some(JournalRecord::RollingBack))
            || header(&records)?.2 != Operation::Upgrade)
    {
        return Err(state_error(
            "transaction journal contains an invalid rollback marker",
        ));
    }
    validate_v3_file_journal(&records)?;
    Ok((records, valid_end))
}

fn validate_v3_file_journal(records: &[JournalRecord]) -> Result<(), PortError> {
    let Some(JournalRecord::Header {
        format_version,
        operation,
        ..
    }) = records.first()
    else {
        return Ok(());
    };
    if !matches!(
        *format_version,
        RECEIPT_BOUND_JOURNAL_VERSION | JOURNAL_VERSION
    ) {
        return Ok(());
    }
    if *operation == Operation::Uninstall {
        return validate_v3_uninstall_journal(records);
    }
    if !matches!(operation, Operation::Install | Operation::Upgrade) {
        return Ok(());
    }

    #[derive(Default)]
    struct FileState<'a> {
        path: Option<&'a PackagePath>,
        staged_sha256: Option<&'a Sha256Digest>,
        restored: bool,
        removed: bool,
    }

    let mut files = std::collections::BTreeMap::<String, FileState<'_>>::new();
    for record in records.iter().skip(1) {
        let (path, state) = match record {
            JournalRecord::StageFile { path, .. }
            | JournalRecord::RestoreFile { path, .. }
            | JournalRecord::RemoveFile { path, .. } => {
                let state = files.entry(path.collision_key()).or_default();
                if state.path.is_some_and(|bound| bound != path) {
                    return Err(state_error(format!(
                        "transaction journal contains case or normalization aliases for `{path}`"
                    )));
                }
                state.path.get_or_insert(path);
                (path, state)
            }
            _ => continue,
        };

        match record {
            JournalRecord::StageFile { sha256, .. } => {
                if state.staged_sha256.is_some() || state.restored || state.removed {
                    return Err(state_error(format!(
                        "transaction journal stages `{path}` out of order"
                    )));
                }
                state.staged_sha256 = Some(sha256);
            }
            JournalRecord::RestoreFile { .. } => {
                if *operation == Operation::Install || state.restored || state.removed {
                    return Err(state_error(format!(
                        "transaction journal restores `{path}` out of order"
                    )));
                }
                state.restored = true;
            }
            JournalRecord::RemoveFile { sha256, .. } => {
                let Some(staged_sha256) = state.staged_sha256 else {
                    return Err(state_error(format!(
                        "transaction journal removes `{path}` without prior staging"
                    )));
                };
                if state.removed || staged_sha256 != sha256 {
                    return Err(state_error(format!(
                        "transaction journal removal for `{path}` does not match its staging intent"
                    )));
                }
                state.removed = true;
            }
            _ => unreachable!("file record matched above"),
        }
    }
    Ok(())
}

fn validate_v3_uninstall_journal(records: &[JournalRecord]) -> Result<(), PortError> {
    let mut paths = std::collections::BTreeMap::<String, &PackagePath>::new();
    let mut committing = false;
    for (index, record) in records.iter().enumerate().skip(1) {
        match record {
            JournalRecord::RestoreFile { path, .. } if !committing => {
                let key = path.collision_key();
                if let Some(bound) = paths.insert(key, path) {
                    let reason = if bound == path {
                        "duplicate"
                    } else {
                        "aliasing"
                    };
                    return Err(state_error(format!(
                        "uninstall journal contains {reason} restore intent for `{path}`"
                    )));
                }
            }
            JournalRecord::Committing if !committing && index + 1 == records.len() => {
                committing = true;
            }
            _ => {
                return Err(state_error(
                    "uninstall journal contains an invalid or out-of-order record",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn open_regular(path: &Path, max_bytes: u64) -> Result<File, PortError> {
    open_bounded_regular(path, max_bytes, false)
}

pub(super) fn open_internal_regular(path: &Path, max_bytes: u64) -> Result<File, PortError> {
    open_bounded_regular(path, max_bytes, true)
}

fn open_bounded_regular(
    path: &Path,
    max_bytes: u64,
    allow_multiple_links: bool,
) -> Result<File, PortError> {
    let file = open_existing_nofollow(path)?;
    let metadata = validate_open_regular(path, &file, allow_multiple_links)?;
    if metadata.len() > max_bytes {
        return Err(state_error(format!(
            "file `{}` is too large: {} bytes",
            path.display(),
            metadata.len()
        )));
    }
    Ok(file)
}

pub(super) fn hash_regular(path: &Path) -> Result<(u64, Sha256Digest), PortError> {
    hash_file(path, false)
}

pub(super) fn hash_internal_regular(path: &Path) -> Result<(u64, Sha256Digest), PortError> {
    hash_file(path, true)
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RegularSnapshot {
    size: u64,
    sha256: Sha256Digest,
    executable: bool,
    links: u64,
}

#[derive(Debug)]
pub(super) struct SyncedRegular {
    _file: File,
    snapshot: RegularSnapshot,
}

impl SyncedRegular {
    pub(super) fn digest_and_executable(&self) -> (&Sha256Digest, bool) {
        (&self.snapshot.sha256, self.snapshot.executable)
    }

    pub(super) fn matches(&self, size: u64, sha256: &Sha256Digest, executable: bool) -> bool {
        self.snapshot.size == size
            && &self.snapshot.sha256 == sha256
            && executable_matches(self.snapshot.executable, executable)
    }

    pub(super) fn matches_digest(&self, sha256: &Sha256Digest, executable: bool) -> bool {
        &self.snapshot.sha256 == sha256 && executable_matches(self.snapshot.executable, executable)
    }

    pub(super) fn same_contents(&self, other: &Self) -> bool {
        self.snapshot.size == other.snapshot.size
            && self.snapshot.sha256 == other.snapshot.sha256
            && executable_matches(self.snapshot.executable, other.snapshot.executable)
    }

    pub(super) fn verify_moved_path(
        &mut self,
        path: &Path,
        allow_multiple_links: bool,
    ) -> Result<(File, bool), PortError> {
        let pinned = open_pinned_nofollow(path)
            .map_err(|source| io_error("opening moved regular file", path, source))?;
        validate_open_regular(path, &pinned, allow_multiple_links)?;
        if !same_opened_file(path, &self._file, path, &pinned)? {
            return Err(state_error(format!(
                "moved regular file `{}` changed identity",
                path.display()
            )));
        }

        self._file
            .seek(SeekFrom::Start(0))
            .map_err(|source| io_error("rewinding moved regular file", path, source))?;
        let refreshed = snapshot_and_sync_opened(path, &mut self._file, allow_multiple_links)?;
        let pinned_metadata = validate_open_regular(path, &pinned, allow_multiple_links)?;
        let pinned_links = opened_link_count(path, &pinned, &pinned_metadata)?;
        let unchanged = self.snapshot == refreshed
            && pinned_metadata.len() == refreshed.size
            && metadata_executable(&pinned_metadata) == refreshed.executable
            && pinned_links == refreshed.links;
        self.snapshot = refreshed;
        Ok((pinned, unchanged))
    }
}

pub(super) fn sync_regular_snapshot(
    path: &Path,
    allow_multiple_links: bool,
) -> Result<SyncedRegular, PortError> {
    let file = open_sync_nofollow(path)
        .map_err(|source| io_error("opening regular file for sync", path, source))?;
    sync_opened_regular_snapshot(path, file, allow_multiple_links)
}

pub(super) fn sync_movable_regular_snapshot(
    path: &Path,
    allow_multiple_links: bool,
) -> Result<SyncedRegular, PortError> {
    let file = open_movable_sync_nofollow(path)
        .map_err(|source| io_error("opening movable regular file for sync", path, source))?;
    sync_opened_regular_snapshot(path, file, allow_multiple_links)
}

fn sync_opened_regular_snapshot(
    path: &Path,
    mut file: File,
    allow_multiple_links: bool,
) -> Result<SyncedRegular, PortError> {
    let snapshot = snapshot_and_sync_opened(path, &mut file, allow_multiple_links)?;
    Ok(SyncedRegular {
        _file: file,
        snapshot,
    })
}

fn snapshot_and_sync_opened(
    path: &Path,
    file: &mut File,
    allow_multiple_links: bool,
) -> Result<RegularSnapshot, PortError> {
    let (size, sha256) = hash_opened_file(path, file, allow_multiple_links)?;
    let metadata = validate_open_regular(path, file, allow_multiple_links)?;
    let links = opened_link_count(path, file, &metadata)?;
    let executable = metadata_executable(&metadata);
    if metadata.len() != size {
        return Err(state_error(format!(
            "regular file `{}` changed while hashing",
            path.display()
        )));
    }
    file.sync_all()
        .map_err(|source| io_error("syncing regular file data", path, source))?;
    let synced = validate_open_regular(path, file, allow_multiple_links)?;
    let synced_links = opened_link_count(path, file, &synced)?;
    if synced.len() != size || synced_links != links || metadata_executable(&synced) != executable {
        return Err(state_error(format!(
            "regular file `{}` changed while syncing",
            path.display()
        )));
    }
    Ok(RegularSnapshot {
        size,
        sha256,
        executable,
        links,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MatchingFileRemoval {
    Missing,
    Modified,
    Removed,
}

#[cfg(all(test, windows))]
thread_local! {
    static REMOVE_REGULAR_MATCHING_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, windows))]
pub(super) fn set_remove_regular_matching_hook(hook: impl FnOnce() + 'static) {
    REMOVE_REGULAR_MATCHING_HOOK.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
    });
}

pub(super) fn remove_regular_matching(
    path: &Path,
    expected: &Sha256Digest,
    allow_multiple_links_while_hashing: bool,
) -> Result<MatchingFileRemoval, PortError> {
    #[cfg(windows)]
    {
        let mut file = match super::windows::open_delete_nofollow(path) {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(MatchingFileRemoval::Missing);
            }
            Err(source) => return Err(io_error("opening file for verified removal", path, source)),
        };
        let (_, found) = hash_opened_file(path, &mut file, allow_multiple_links_while_hashing)?;
        if &found != expected {
            return Ok(MatchingFileRemoval::Modified);
        }
        validate_open_regular(path, &file, false)?;
        #[cfg(test)]
        REMOVE_REGULAR_MATCHING_HOOK.with(|slot| {
            if let Some(hook) = slot.borrow_mut().take() {
                hook();
            }
        });
        super::windows::delete_opened(file)
            .map_err(|source| io_error("removing verified opened file", path, source))?;
        sync_after_unlink(path)?;
        Ok(MatchingFileRemoval::Removed)
    }

    #[cfg(not(windows))]
    {
        match fs::symlink_metadata(path) {
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                Ok(MatchingFileRemoval::Missing)
            }
            Err(source) => Err(io_error(
                "inspecting file for verified removal",
                path,
                source,
            )),
            Ok(_) => {
                let (_, found) = hash_file(path, allow_multiple_links_while_hashing)?;
                if &found != expected {
                    return Ok(MatchingFileRemoval::Modified);
                }
                remove_regular(path)?;
                Ok(MatchingFileRemoval::Removed)
            }
        }
    }
}

pub(super) fn regular_file_executable(path: &Path) -> Result<bool, PortError> {
    file_executable(path, false)
}

pub(super) fn internal_regular_file_executable(path: &Path) -> Result<bool, PortError> {
    file_executable(path, true)
}

fn file_executable(path: &Path, allow_multiple_links: bool) -> Result<bool, PortError> {
    let file = open_existing_nofollow(path)?;
    let metadata = validate_open_regular(path, &file, allow_multiple_links)?;
    Ok(metadata_executable(&metadata))
}

fn metadata_executable(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

fn executable_matches(actual: bool, expected: bool) -> bool {
    #[cfg(unix)]
    {
        actual == expected
    }
    #[cfg(not(unix))]
    {
        let _ = (actual, expected);
        true
    }
}

pub(super) fn same_file(left: &Path, right: &Path) -> Result<bool, PortError> {
    let left_file = open_existing_nofollow(left)?;
    let right_file = open_existing_nofollow(right)?;
    let _left_metadata = validate_open_regular(left, &left_file, true)?;
    let _right_metadata = validate_open_regular(right, &right_file, true)?;

    same_opened_file(left, &left_file, right, &right_file)
}

fn same_opened_file(
    left_path: &Path,
    left: &File,
    right_path: &Path,
    right: &File,
) -> Result<bool, PortError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let left_metadata = left
            .metadata()
            .map_err(|source| io_error("reading opened file identity", left_path, source))?;
        let right_metadata = right
            .metadata()
            .map_err(|source| io_error("reading opened file identity", right_path, source))?;
        Ok((left_metadata.dev(), left_metadata.ino())
            == (right_metadata.dev(), right_metadata.ino()))
    }
    #[cfg(windows)]
    {
        let left_identity = super::windows::file_identity(left)
            .map_err(|source| io_error("reading opened file identity", left_path, source))?;
        let right_identity = super::windows::file_identity(right)
            .map_err(|source| io_error("reading opened file identity", right_path, source))?;
        Ok(left_identity == right_identity)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(state_error("file identity is unsupported on this platform"))
    }
}

#[must_use = "a successful rename is not durable until its platform token is synced"]
#[derive(Debug)]
pub(super) struct RenameDurability {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    inner: super::unix::RenameDurability,
}

impl RenameDurability {
    pub(super) fn sync(self) -> std::io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.sync()
        }
        #[cfg(windows)]
        {
            Ok(())
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "rename durability is unsupported on this platform",
            ))
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn rename_noreplace(
    source: &Path,
    destination: &Path,
) -> std::io::Result<RenameDurability> {
    super::unix::rename_noreplace(source, destination).map(|inner| RenameDurability { inner })
}

#[cfg(windows)]
pub(super) fn rename_noreplace(
    source: &Path,
    destination: &Path,
) -> std::io::Result<RenameDurability> {
    super::windows::rename_noreplace(source, destination)?;
    Ok(RenameDurability {})
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub(super) fn rename_noreplace(_: &Path, _: &Path) -> std::io::Result<RenameDurability> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-clobber rename is unsupported on this platform",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unlink_file(path: &Path) -> std::io::Result<()> {
    super::unix::remove_file(path)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unlink_file(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unlink_directory(path: &Path) -> std::io::Result<()> {
    super::unix::remove_directory(path)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unlink_directory(path: &Path) -> std::io::Result<()> {
    fs::remove_dir(path)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sync_after_unlink(_: &Path) -> Result<(), PortError> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn sync_after_unlink(path: &Path) -> Result<(), PortError> {
    sync_parent(path)
}

fn hash_file(path: &Path, allow_multiple_links: bool) -> Result<(u64, Sha256Digest), PortError> {
    let mut file = open_existing_nofollow(path)?;
    hash_opened_file(path, &mut file, allow_multiple_links)
}

pub(super) fn hash_opened_file(
    path: &Path,
    file: &mut File,
    allow_multiple_links: bool,
) -> Result<(u64, Sha256Digest), PortError> {
    validate_open_regular(path, file, allow_multiple_links)?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("hashing file", path, source))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| PortError::with_kind(PortErrorKind::Integrity, "file size overflow"))?;
        hasher.update(&buffer[..read]);
    }
    validate_open_regular(path, file, allow_multiple_links)?;
    let digest = Sha256Digest::parse(hex::encode(hasher.finalize()))
        .map_err(|error| PortError::with_kind(PortErrorKind::Integrity, error.to_string()))?;
    Ok((size, digest))
}

pub(super) fn validate_directory(path: &Path) -> Result<(), PortError> {
    let metadata = link_metadata(path)?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(PortError::with_kind(
            PortErrorKind::State,
            format!("`{}` is not a real directory", path.display()),
        ));
    }
    Ok(())
}

pub(super) fn validate_directory_chain(path: &Path) -> Result<(), PortError> {
    let absolute = std::path::absolute(path)
        .map_err(|source| io_error("resolving directory", path, source))?;
    let mut ancestors = absolute.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if is_link_or_reparse(&metadata) || !metadata.is_dir() {
                    return Err(PortError::with_kind(
                        PortErrorKind::State,
                        format!(
                            "directory chain contains non-directory `{}`",
                            ancestor.display()
                        ),
                    ));
                }
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(io_error("inspecting directory chain", ancestor, source));
            }
        }
    }
    Ok(())
}

pub(super) fn ensure_directory(
    path: &Path,
    private_scope: Option<InstallScope>,
) -> Result<(), PortError> {
    ensure_directory_inner(path, private_scope, true)
}

fn ensure_directory_inner(
    path: &Path,
    private_scope: Option<InstallScope>,
    harden_existing: bool,
) -> Result<(), PortError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if is_link_or_reparse(&metadata) || !metadata.is_dir() {
                return Err(PortError::with_kind(
                    PortErrorKind::State,
                    format!("`{}` is not a real directory", path.display()),
                ));
            }
            if let (Some(scope), true) = (private_scope, harden_existing) {
                validate_private_directory(path, scope)?;
            }
            return Ok(());
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(io_error("inspecting directory", path, source)),
    }

    let parent = path
        .parent()
        .ok_or_else(|| state_error("directory has no parent"))?;
    if !parent.as_os_str().is_empty() {
        // Validate the first pre-existing ancestor without changing its ACL. Only the
        // requested directory and descendants created here belong to this operation.
        ensure_directory_inner(parent, private_scope, false)?;
    }
    create_directory(path, private_scope)
}

fn create_directory(path: &Path, private_scope: Option<InstallScope>) -> Result<(), PortError> {
    if let Some(scope) = private_scope {
        create_private_directory(path, scope)?;
    } else {
        fs::create_dir(path).map_err(|source| io_error("creating directory", path, source))?;
        set_install_directory(path)?;
    }
    validate_directory(path)?;
    sync_parent(path)
}

#[cfg(windows)]
fn create_private_directory(path: &Path, scope: InstallScope) -> Result<(), PortError> {
    super::windows::create_private_directory(path, scope)
        .map_err(|source| io_error("creating private directory", path, source))
}

#[cfg(not(windows))]
fn create_private_directory(path: &Path, scope: InstallScope) -> Result<(), PortError> {
    require_private_authority(scope)?;
    fs::create_dir(path).map_err(|source| io_error("creating directory", path, source))?;
    if let Err(error) = set_private_directory(path, scope) {
        let _ = fs::remove_dir(path);
        return Err(error);
    }
    Ok(())
}

pub(super) fn remove_regular(path: &Path) -> Result<(), PortError> {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspecting file for removal", path, source)),
        Ok(metadata) => {
            validate_regular_metadata(path, &metadata)?;
            match unlink_file(path) {
                Ok(()) => sync_after_unlink(path),
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(io_error("removing file", path, source)),
            }
        }
    }
}

/// Removes one internal transaction link. Hard-link count is deliberately not
/// checked so recovery remains compatible with legacy receipt commit pairs.
pub(super) fn remove_internal_link(path: &Path) -> Result<(), PortError> {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspecting transaction link", path, source)),
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_file() => {
            match unlink_file(path) {
                Ok(()) => sync_after_unlink(path),
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(io_error("removing transaction link", path, source)),
            }
        }
        Ok(_) => Err(state_error(format!(
            "transaction link `{}` is not a regular file",
            path.display()
        ))),
    }
}

pub(super) fn remove_empty_directory(path: &Path) -> Result<(), PortError> {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspecting directory for removal", path, source)),
        Ok(metadata) => {
            if is_link_or_reparse(&metadata) || !metadata.is_dir() {
                return Err(state_error(format!(
                    "`{}` is not a removable real directory",
                    path.display()
                )));
            }
            match unlink_directory(path) {
                Ok(()) => sync_after_unlink(path),
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(state_io_error("removing directory", path, source)),
            }
        }
    }
}

pub(super) fn remove_directory_if_empty(path: &Path) -> Result<(), PortError> {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspecting directory for removal", path, source)),
        Ok(metadata) => {
            if is_link_or_reparse(&metadata) || !metadata.is_dir() {
                return Err(state_error(format!(
                    "`{}` is not a removable real directory",
                    path.display()
                )));
            }
            match unlink_directory(path) {
                Ok(()) => sync_after_unlink(path),
                Err(source)
                    if matches!(
                        source.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                    ) =>
                {
                    Ok(())
                }
                Err(source) => Err(state_io_error("removing directory", path, source)),
            }
        }
    }
}

pub(super) fn set_installed_file(path: &Path, executable: bool) -> Result<(), PortError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|source| io_error("setting installed file permissions", path, source))?;
    }
    #[cfg(not(unix))]
    let _ = (path, executable);
    Ok(())
}

#[cfg(unix)]
pub(super) fn sync_parent(path: &Path) -> Result<(), PortError> {
    let parent = path
        .parent()
        .ok_or_else(|| state_error(format!("`{}` has no parent directory", path.display())))?;
    let directory = File::open(parent)
        .map_err(|source| io_error("opening parent directory for sync", parent, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error("syncing parent directory", parent, source))
}

#[cfg(not(unix))]
pub(super) fn sync_parent(path: &Path) -> Result<(), PortError> {
    // ponytail: std has no documented Windows directory flush; the journaled
    // state machine is crash-idempotent, but native write-through is required
    // before claiming metadata durability across sudden power loss.
    let _ = path;
    Ok(())
}

pub(super) fn roots_are_separate(install_root: &Path, state_root: &Path) -> Result<(), PortError> {
    let install = comparable_path(install_root)?;
    let state = comparable_path(state_root)?;
    if path_starts_with(&state, &install) {
        return Err(PortError::with_kind(
            PortErrorKind::State,
            "state root must live outside the removable install tree",
        ));
    }
    for internal in ["receipts", "transactions", "locks"] {
        let internal = comparable_path(&state_root.join(internal))?;
        if path_starts_with(&install, &internal) || path_starts_with(&internal, &install) {
            return Err(PortError::with_kind(
                PortErrorKind::State,
                "install root must not overlap installer state directories",
            ));
        }
    }
    Ok(())
}

fn comparable_path(path: &Path) -> Result<PathBuf, PortError> {
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            std::path::absolute(path).map_err(|source| io_error("resolving path", path, source))
        }
        Err(source) => Err(io_error("canonicalizing path", path, source)),
    }
}

#[cfg(windows)]
fn path_starts_with(path: &Path, base: &Path) -> bool {
    let path = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
        .collect::<Vec<_>>();
    let base = base
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
        .collect::<Vec<_>>();
    path.starts_with(&base)
}

#[cfg(not(windows))]
fn path_starts_with(path: &Path, base: &Path) -> bool {
    path.starts_with(base)
}

pub(super) fn open_existing_nofollow(path: &Path) -> Result<File, PortError> {
    let mut options = OpenOptions::new();
    options.read(true);
    open_nofollow(&mut options, path).map_err(|source| io_error("opening file", path, source))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_sync_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    open_nofollow(&mut options, path)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_movable_sync_nofollow(path: &Path) -> std::io::Result<File> {
    open_sync_nofollow(path)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_pinned_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    open_nofollow(&mut options, path)
}

#[cfg(windows)]
fn open_sync_nofollow(path: &Path) -> std::io::Result<File> {
    super::windows::open_sync_nofollow(path)
}

#[cfg(windows)]
fn open_movable_sync_nofollow(path: &Path) -> std::io::Result<File> {
    super::windows::open_movable_sync_nofollow(path)
}

#[cfg(windows)]
fn open_pinned_nofollow(path: &Path) -> std::io::Result<File> {
    super::windows::open_pinned_nofollow(path)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn open_sync_nofollow(_: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no-follow file sync is unsupported on this platform",
    ))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn open_movable_sync_nofollow(_: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no-follow movable file sync is unsupported on this platform",
    ))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn open_pinned_nofollow(_: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no-follow moved file pinning is unsupported on this platform",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_nofollow(options: &mut OpenOptions, path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
    options.custom_flags(flags.bits() as i32).open(path)
}

#[cfg(windows)]
fn open_nofollow(options: &mut OpenOptions, path: &Path) -> std::io::Result<File> {
    super::windows::open_nofollow(options, path)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn open_nofollow(_: &mut OpenOptions, _: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no-follow file open is unsupported on this platform",
    ))
}

pub(super) fn validate_open_regular(
    path: &Path,
    file: &File,
    allow_multiple_links: bool,
) -> Result<Metadata, PortError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("reading opened file metadata", path, source))?;
    let links = opened_link_count(path, file, &metadata)?;
    if is_link_or_reparse(&metadata)
        || !metadata.is_file()
        || links == 0
        || (!allow_multiple_links && links > 1)
    {
        return Err(PortError::with_kind(
            PortErrorKind::State,
            format!("`{}` is not an acceptable regular file", path.display()),
        ));
    }
    Ok(metadata)
}

fn validate_regular_metadata(path: &Path, metadata: &Metadata) -> Result<(), PortError> {
    if is_link_or_reparse(metadata) || !metadata.is_file() || has_multiple_links(metadata) {
        return Err(PortError::with_kind(
            PortErrorKind::State,
            format!("`{}` is not a single-link regular file", path.display()),
        ));
    }
    Ok(())
}

fn link_metadata(path: &Path) -> Result<Metadata, PortError> {
    fs::symlink_metadata(path).map_err(|source| io_error("reading metadata", path, source))
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(unix)]
fn has_multiple_links(metadata: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() > 1
}

#[cfg(not(unix))]
fn has_multiple_links(_: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn opened_link_count(_: &Path, _: &File, metadata: &Metadata) -> Result<u64, PortError> {
    use std::os::unix::fs::MetadataExt;
    Ok(metadata.nlink())
}

#[cfg(windows)]
fn opened_link_count(path: &Path, file: &File, _: &Metadata) -> Result<u64, PortError> {
    super::windows::number_of_links(file)
        .map(u64::from)
        .map_err(|source| io_error("reading opened file information", path, source))
}

#[cfg(not(any(unix, windows)))]
fn opened_link_count(_: &Path, _: &File, _: &Metadata) -> Result<u64, PortError> {
    Ok(1)
}

#[cfg(unix)]
pub(super) fn validate_private_directory(
    path: &Path,
    scope: InstallScope,
) -> Result<(), PortError> {
    validate_unix_private_path(path, scope, true, 0o700)
}

#[cfg(windows)]
pub(super) fn validate_private_directory(
    path: &Path,
    scope: InstallScope,
) -> Result<(), PortError> {
    super::windows::validate_private_directory(path, scope)
        .map_err(|source| io_error("validating private directory ACL", path, source))
}

#[cfg(not(any(unix, windows)))]
pub(super) fn validate_private_directory(_: &Path, scope: InstallScope) -> Result<(), PortError> {
    require_private_authority(scope)
}

#[cfg(unix)]
fn set_private_directory(path: &Path, scope: InstallScope) -> Result<(), PortError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    require_private_authority(scope)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspecting private directory owner", path, source))?;
    require_private_owner(path, metadata.uid(), scope)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("setting private directory permissions", path, source))
}

#[cfg(not(any(unix, windows)))]
fn set_private_directory(_: &Path, scope: InstallScope) -> Result<(), PortError> {
    require_private_authority(scope)
}

#[cfg(unix)]
fn set_install_directory(path: &Path) -> Result<(), PortError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|source| io_error("setting install directory permissions", path, source))
}

#[cfg(not(unix))]
fn set_install_directory(_: &Path) -> Result<(), PortError> {
    Ok(())
}

#[cfg(unix)]
pub(super) fn validate_private_file(path: &Path, scope: InstallScope) -> Result<(), PortError> {
    validate_unix_private_path(path, scope, false, 0o600)
}

#[cfg(windows)]
pub(super) fn validate_private_file(path: &Path, scope: InstallScope) -> Result<(), PortError> {
    super::windows::validate_private_file(path, scope)
        .map_err(|source| io_error("validating private file ACL", path, source))
}

#[cfg(not(any(unix, windows)))]
pub(super) fn validate_private_file(_: &Path, scope: InstallScope) -> Result<(), PortError> {
    require_private_authority(scope)
}

#[cfg(unix)]
pub(super) fn set_private_file(path: &Path, scope: InstallScope) -> Result<(), PortError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    require_private_authority(scope)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspecting private file owner", path, source))?;
    require_private_owner(path, metadata.uid(), scope)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error("setting private file permissions", path, source))
}

#[cfg(windows)]
pub(super) fn set_private_file(path: &Path, scope: InstallScope) -> Result<(), PortError> {
    super::windows::set_private_file(path, scope)
        .map_err(|source| io_error("setting private file ACL", path, source))
}

#[cfg(not(any(unix, windows)))]
pub(super) fn set_private_file(_: &Path, scope: InstallScope) -> Result<(), PortError> {
    require_private_authority(scope)
}

#[cfg(unix)]
fn require_private_authority(scope: InstallScope) -> Result<(), PortError> {
    if scope == InstallScope::System && !rustix::process::geteuid().is_root() {
        return Err(PortError::with_kind(
            PortErrorKind::Permission,
            "system-private state requires root authority",
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn require_private_authority(scope: InstallScope) -> Result<(), PortError> {
    if scope == InstallScope::System {
        Err(PortError::with_kind(
            PortErrorKind::Permission,
            "system-private state is unsupported on this platform",
        ))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn require_private_owner(path: &Path, owner: u32, scope: InstallScope) -> Result<(), PortError> {
    let expected = match scope {
        InstallScope::User => rustix::process::geteuid().as_raw(),
        InstallScope::System => 0,
    };
    if owner == expected {
        Ok(())
    } else {
        Err(PortError::with_kind(
            PortErrorKind::Permission,
            format!(
                "private path `{}` has owner UID {owner}, expected {expected} for {scope:?} scope",
                path.display()
            ),
        ))
    }
}

#[cfg(unix)]
fn validate_unix_private_path(
    path: &Path,
    scope: InstallScope,
    directory: bool,
    mode: u32,
) -> Result<(), PortError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    require_private_authority(scope)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspecting private path", path, source))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink()
        || file_type.is_block_device()
        || file_type.is_char_device()
        || file_type.is_fifo()
        || file_type.is_socket()
        || metadata.is_dir() != directory
    {
        return Err(state_error(format!(
            "private path `{}` has an unexpected type",
            path.display()
        )));
    }
    require_private_owner(path, metadata.uid(), scope)?;
    let found = metadata.permissions().mode() & 0o777;
    if found != mode {
        return Err(PortError::with_kind(
            PortErrorKind::Permission,
            format!(
                "private path `{}` has mode {found:04o}, expected {mode:04o}",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub(super) fn io_error(action: &str, path: &Path, source: std::io::Error) -> PortError {
    PortError::with_kind(
        match source.kind() {
            std::io::ErrorKind::PermissionDenied => PortErrorKind::Permission,
            std::io::ErrorKind::AlreadyExists => PortErrorKind::Collision,
            std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => {
                PortErrorKind::Capacity
            }
            std::io::ErrorKind::Unsupported => PortErrorKind::Unsupported,
            _ => PortErrorKind::Io,
        },
        format!("{action} `{}` failed: {source}", path.display()),
    )
}

pub(super) fn state_error(message: impl Into<String>) -> PortError {
    PortError::with_kind(PortErrorKind::State, message)
}

fn state_io_error(action: &str, path: &Path, source: std::io::Error) -> PortError {
    PortError::with_kind(
        PortErrorKind::State,
        format!("{action} `{}` failed safely: {source}", path.display()),
    )
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn synced_regular_records_one_exact_opened_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("backup.bin");
        let alias = temp.path().join("backup.alias");
        fs::write(&path, b"owned").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let executable = cfg!(unix);
        let sha256 = Sha256Digest::parse(hex::encode(Sha256::digest(b"owned"))).unwrap();

        let synced = sync_regular_snapshot(&path, false).unwrap();
        assert!(synced.matches(5, &sha256, executable));
        drop(synced);

        fs::hard_link(&path, &alias).unwrap();
        assert!(sync_regular_snapshot(&path, false).is_err());
        let linked = sync_regular_snapshot(&path, true).unwrap();
        assert!(linked.matches(5, &sha256, executable));
    }

    #[cfg(unix)]
    #[test]
    fn synced_regular_accepts_read_only_files() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("backup.bin");
        fs::write(&path, b"owned").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        let sha256 = Sha256Digest::parse(hex::encode(Sha256::digest(b"owned"))).unwrap();

        let synced = sync_regular_snapshot(&path, false).unwrap();

        assert!(synced.matches(5, &sha256, false));
    }

    #[cfg(windows)]
    #[test]
    fn synced_regular_denies_writers_and_delete_while_guarded() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("backup.bin");
        fs::write(&path, b"owned").unwrap();

        let writer = OpenOptions::new().write(true).open(&path).unwrap();
        assert!(sync_regular_snapshot(&path, false).is_err());
        drop(writer);

        let synced = sync_regular_snapshot(&path, false).unwrap();
        assert!(OpenOptions::new().read(true).open(&path).is_ok());
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::remove_file(&path).is_err());

        drop(synced);
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .write_all(b"safe")
            .unwrap();
        fs::remove_file(path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn movable_synced_regular_denies_writers_and_pins_the_moved_name() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.bin");
        let destination = temp.path().join("destination.bin");
        let other = temp.path().join("other.bin");
        fs::write(&source, b"owned").unwrap();

        let mut synced = sync_movable_regular_snapshot(&source, false).unwrap();
        assert!(OpenOptions::new().write(true).open(&source).is_err());
        fs::rename(&source, &destination).unwrap();
        let (pinned, unchanged) = synced.verify_moved_path(&destination, false).unwrap();

        assert!(unchanged);
        assert!(fs::rename(&destination, &other).is_err());
        assert!(OpenOptions::new().write(true).open(&destination).is_err());

        drop(pinned);
        drop(synced);
        fs::rename(&destination, &other).unwrap();
        fs::remove_file(other).unwrap();
    }

    #[test]
    fn writer_rejects_the_first_byte_past_the_recovery_limit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("journal.jsonl");
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.set_len(MAX_JOURNAL_BYTES).unwrap();

        let error = write_record(&mut file, &JournalRecord::Committing).unwrap_err();
        assert!(error.to_string().contains("byte limit"));
        assert_eq!(file.metadata().unwrap().len(), MAX_JOURNAL_BYTES);
    }

    #[test]
    fn uninstall_journal_allows_only_unique_restore_intents_and_final_commit() {
        let header_record = JournalRecord::Header {
            format_version: JOURNAL_VERSION,
            operation: Operation::Uninstall,
            package_id: PackageId::parse("dev.luxury.demo").unwrap(),
            directory: InstallDirectory::parse("LuxuryDemo").unwrap(),
            install_base: InstallBaseIdentity::maximum_serialized_size_placeholder(),
            scope: Some(InstallScope::User),
            previous_receipt_sha256: Some(Sha256Digest::parse("a".repeat(64)).unwrap()),
        };
        let restore = JournalRecord::RestoreFile {
            path: PackagePath::parse("bin/app").unwrap(),
            sha256: Sha256Digest::parse("b".repeat(64)).unwrap(),
            executable: true,
        };
        assert!(
            validate_v3_file_journal(&[
                header_record.clone(),
                restore.clone(),
                JournalRecord::Committing,
            ])
            .is_ok()
        );
        assert!(
            validate_v3_file_journal(&[header_record.clone(), restore.clone(), restore]).is_err()
        );
        assert!(
            validate_v3_file_journal(&[
                header_record,
                JournalRecord::Committing,
                JournalRecord::RestoreFile {
                    path: PackagePath::parse("later").unwrap(),
                    sha256: Sha256Digest::parse("c".repeat(64)).unwrap(),
                    executable: false,
                },
            ])
            .is_err()
        );

        let legacy = JournalRecord::Header {
            format_version: LEGACY_JOURNAL_VERSION,
            operation: Operation::Uninstall,
            package_id: PackageId::parse("dev.luxury.demo").unwrap(),
            directory: InstallDirectory::parse("LuxuryDemo").unwrap(),
            install_base: InstallBaseIdentity::maximum_serialized_size_placeholder(),
            scope: None,
            previous_receipt_sha256: None,
        };
        assert!(uninstall_receipt_hash(&[legacy]).is_err());
        let unbound_v3 = JournalRecord::Header {
            format_version: JOURNAL_VERSION,
            operation: Operation::Uninstall,
            package_id: PackageId::parse("dev.luxury.demo").unwrap(),
            directory: InstallDirectory::parse("LuxuryDemo").unwrap(),
            install_base: InstallBaseIdentity::maximum_serialized_size_placeholder(),
            scope: None,
            previous_receipt_sha256: None,
        };
        assert!(header(&[unbound_v3]).is_err());
    }

    #[test]
    fn v3_is_user_only_and_v4_binds_exact_scope() {
        let base = InstallBaseIdentity::maximum_serialized_size_placeholder();
        let v3 = JournalRecord::Header {
            format_version: RECEIPT_BOUND_JOURNAL_VERSION,
            operation: Operation::Install,
            package_id: PackageId::parse("dev.luxury.demo").unwrap(),
            directory: InstallDirectory::parse("LuxuryDemo").unwrap(),
            install_base: base.clone(),
            scope: None,
            previous_receipt_sha256: None,
        };
        assert_eq!(scope(&[v3]).unwrap(), InstallScope::User);

        let v4 = JournalRecord::Header {
            format_version: JOURNAL_VERSION,
            operation: Operation::Install,
            package_id: PackageId::parse("dev.luxury.demo").unwrap(),
            directory: InstallDirectory::parse("LuxuryDemo").unwrap(),
            install_base: base,
            scope: Some(InstallScope::System),
            previous_receipt_sha256: None,
        };
        assert_eq!(scope(&[v4]).unwrap(), InstallScope::System);
    }
}
