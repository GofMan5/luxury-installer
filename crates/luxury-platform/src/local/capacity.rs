use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use luxury_engine::{PortError, PortErrorKind, install::InstallPlan, uninstall::OwnershipReceipt};

use super::{
    STORED_RECEIPT_FORMAT_VERSION, StoredReceipt, stored_receipt_bytes,
    transaction::{
        InstallBaseIdentity, MAX_JOURNAL_BYTES, MAX_JOURNAL_RECORDS, MAX_RECEIPT_BYTES, io_error,
        state_error, validate_directory, validate_directory_chain,
    },
};

pub(super) const CAPACITY_MIN_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;
const CAPACITY_MAX_HEADROOM_BYTES: u64 = 1024 * 1024 * 1024;
const CAPACITY_METADATA_ENTRY_BYTES: u64 = 4 * 1024;
const CAPACITY_FIXED_INSTALL_ENTRIES: u64 = 8;
const CAPACITY_FIXED_STATE_ENTRIES: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SpaceSnapshot {
    pub(super) volume_id: u64,
    pub(super) available_bytes: u64,
    pub(super) allocation_unit: u64,
}

pub(super) fn check_journal_capacity(
    plan: &InstallPlan,
    previous: Option<&OwnershipReceipt>,
) -> Result<u64, PortError> {
    let mut directories = BTreeSet::new();
    for file in plan.files() {
        for (index, _) in file.path.as_str().match_indices('/') {
            directories.insert(&file.path.as_str()[..index]);
        }
    }
    let previous_files = previous.map_or(0, |receipt| receipt.files().len());
    let new_file_records = plan
        .files()
        .len()
        .checked_mul(2)
        .ok_or_else(|| state_error("transaction journal record estimate overflow"))?;
    let records = 4_usize
        .checked_add(new_file_records)
        .and_then(|count| count.checked_add(previous_files))
        .and_then(|count| count.checked_add(directories.len()))
        .ok_or_else(|| state_error("transaction journal record estimate overflow"))?;
    if records > MAX_JOURNAL_RECORDS {
        return Err(state_error(format!(
            "transaction requires about {records} journal records; limit is {MAX_JOURNAL_RECORDS}"
        )));
    }

    let mut bytes = 4_096_u64;
    for file in plan.files() {
        bytes = bytes
            .checked_add((file.path.as_str().len() as u64 + 192) * 2)
            .ok_or_else(|| state_error("transaction journal size estimate overflow"))?;
    }
    if let Some(previous) = previous {
        for file in previous.files() {
            bytes = bytes
                .checked_add(file.path.as_str().len() as u64 + 256)
                .ok_or_else(|| state_error("transaction journal size estimate overflow"))?;
        }
    }
    for directory in directories {
        bytes = bytes
            .checked_add(directory.len() as u64 + 128)
            .ok_or_else(|| state_error("transaction journal size estimate overflow"))?;
    }
    if bytes > MAX_JOURNAL_BYTES {
        return Err(state_error(format!(
            "transaction journal requires about {bytes} bytes; limit is {MAX_JOURNAL_BYTES}"
        )));
    }
    Ok(bytes)
}

pub(super) fn check_storage_capacity(
    install_base: &Path,
    state_root: &Path,
    plan: &InstallPlan,
    previous: Option<&OwnershipReceipt>,
    journal_bytes: u64,
) -> Result<(), PortError> {
    let install = query_space(install_base)?;
    let state = query_space(state_root)?;
    // ponytail: reserve the full next payload because external writers can turn a
    // matching repair file into a rewrite after preflight; native space reservation
    // is the upgrade path if this conservative bound becomes a measured UX problem.
    let install_bytes = allocated_bytes(
        plan.files().iter().map(|file| file.size),
        install.allocation_unit,
    )?;
    let receipt_bytes = planned_receipt_bytes(plan)?;
    let state_bytes = round_up(journal_bytes, state.allocation_unit)?
        .checked_add(round_up(receipt_bytes, state.allocation_unit)?)
        .ok_or_else(capacity_overflow)?;
    let (install_entries, state_entries) = capacity_entries(plan, previous, plan.files().len())?;

    require_storage_capacity(
        install,
        install_bytes,
        install_entries,
        state,
        state_bytes,
        state_entries,
    )
}

pub(super) fn check_directory_write_access(path: &Path) -> Result<(), PortError> {
    let anchor = existing_capacity_anchor(path)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    rustix::fs::access(
        &anchor,
        rustix::fs::Access::WRITE_OK | rustix::fs::Access::EXEC_OK,
    )
    .map_err(|source| io_error("checking directory write access", &anchor, source.into()))?;
    #[cfg(windows)]
    super::windows::check_directory_write_access(&anchor)
        .map_err(|source| io_error("checking directory write access", &anchor, source))?;
    Ok(())
}

fn planned_receipt_bytes(plan: &InstallPlan) -> Result<u64, PortError> {
    let stored = StoredReceipt {
        format_version: STORED_RECEIPT_FORMAT_VERSION,
        install_base: InstallBaseIdentity::maximum_serialized_size_placeholder(),
        receipt: plan.ownership_receipt(),
    };
    let bytes = stored_receipt_bytes(&stored)?.len() as u64;
    if bytes > MAX_RECEIPT_BYTES {
        return Err(state_error("ownership receipt exceeds the size limit"));
    }
    Ok(bytes)
}

fn capacity_entries(
    plan: &InstallPlan,
    previous: Option<&OwnershipReceipt>,
    write_count: usize,
) -> Result<(u64, u64), PortError> {
    let mut directories = BTreeSet::new();
    for file in plan
        .files()
        .iter()
        .chain(previous.into_iter().flat_map(OwnershipReceipt::files))
    {
        for (index, _) in file.path.as_str().match_indices('/') {
            directories.insert(&file.path.as_str()[..index]);
        }
    }
    let next = plan
        .files()
        .iter()
        .map(|file| file.path.collision_key())
        .collect::<BTreeSet<_>>();
    let obsolete = previous.map_or(0, |receipt| {
        receipt
            .files()
            .iter()
            .filter(|file| !next.contains(&file.path.collision_key()))
            .count()
    });
    let write_count = u64::try_from(write_count).map_err(|_| capacity_overflow())?;
    let obsolete = u64::try_from(obsolete).map_err(|_| capacity_overflow())?;
    let directories = u64::try_from(directories.len()).map_err(|_| capacity_overflow())?;
    let install_entries = CAPACITY_FIXED_INSTALL_ENTRIES
        .checked_add(write_count.checked_mul(3).ok_or_else(capacity_overflow)?)
        .and_then(|value| value.checked_add(obsolete))
        .and_then(|value| value.checked_add(directories.checked_mul(3)?))
        .ok_or_else(capacity_overflow)?;
    Ok((install_entries, CAPACITY_FIXED_STATE_ENTRIES))
}

fn allocated_bytes(
    sizes: impl IntoIterator<Item = u64>,
    allocation_unit: u64,
) -> Result<u64, PortError> {
    sizes.into_iter().try_fold(0_u64, |total, size| {
        total
            .checked_add(round_up(size, allocation_unit)?)
            .ok_or_else(capacity_overflow)
    })
}

pub(super) fn round_up(bytes: u64, allocation_unit: u64) -> Result<u64, PortError> {
    if allocation_unit == 0 {
        return Err(state_error("filesystem reported a zero allocation unit"));
    }
    let blocks = bytes
        .checked_add(allocation_unit - 1)
        .ok_or_else(capacity_overflow)?
        / allocation_unit;
    blocks
        .checked_mul(allocation_unit)
        .ok_or_else(capacity_overflow)
}

pub(super) fn require_storage_capacity(
    install: SpaceSnapshot,
    install_bytes: u64,
    install_entries: u64,
    state: SpaceSnapshot,
    state_bytes: u64,
    state_entries: u64,
) -> Result<(), PortError> {
    if install.volume_id == state.volume_id {
        let bytes = install_bytes
            .checked_add(state_bytes)
            .ok_or_else(capacity_overflow)?;
        let entries = install_entries
            .checked_add(state_entries)
            .ok_or_else(capacity_overflow)?;
        require_volume_capacity(
            "installation and state volume",
            SpaceSnapshot {
                available_bytes: install.available_bytes.min(state.available_bytes),
                allocation_unit: install.allocation_unit.max(state.allocation_unit),
                ..install
            },
            bytes,
            entries,
        )
    } else {
        require_volume_capacity(
            "installation volume",
            install,
            install_bytes,
            install_entries,
        )?;
        require_volume_capacity("state volume", state, state_bytes, state_entries)
    }
}

fn require_volume_capacity(
    label: &str,
    space: SpaceSnapshot,
    data_bytes: u64,
    entries: u64,
) -> Result<(), PortError> {
    let metadata_bytes = entries
        .checked_mul(CAPACITY_METADATA_ENTRY_BYTES)
        .ok_or_else(capacity_overflow)?;
    let deterministic = data_bytes
        .checked_add(metadata_bytes)
        .ok_or_else(capacity_overflow)?;
    let percent = deterministic
        .checked_add(99)
        .ok_or_else(capacity_overflow)?
        / 100;
    let headroom = percent.clamp(CAPACITY_MIN_HEADROOM_BYTES, CAPACITY_MAX_HEADROOM_BYTES);
    let required = deterministic
        .checked_add(round_up(headroom, space.allocation_unit)?)
        .ok_or_else(capacity_overflow)?;
    if space.available_bytes < required {
        return Err(PortError::with_kind(
            PortErrorKind::Capacity,
            format!(
                "{label} requires {required} available bytes; only {} are available",
                space.available_bytes
            ),
        ));
    }
    Ok(())
}

fn capacity_overflow() -> PortError {
    PortError::with_kind(
        PortErrorKind::Capacity,
        "storage capacity estimate overflow",
    )
}

pub(super) fn query_space(path: &Path) -> Result<SpaceSnapshot, PortError> {
    let anchor = existing_capacity_anchor(path)?;
    query_existing_space(&anchor)
}

fn existing_capacity_anchor(path: &Path) -> Result<PathBuf, PortError> {
    let absolute = std::path::absolute(path)
        .map_err(|source| io_error("resolving capacity path", path, source))?;
    validate_directory_chain(&absolute)?;
    for ancestor in absolute.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => {
                validate_directory(ancestor)?;
                return Ok(ancestor.to_path_buf());
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(io_error("inspecting capacity path", ancestor, source));
            }
        }
    }
    Err(state_error(
        "capacity path has no existing directory ancestor",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn query_existing_space(path: &Path) -> Result<SpaceSnapshot, PortError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let flags =
        rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::DIRECTORY;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(path)
        .map_err(|source| io_error("opening capacity directory", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("reading capacity directory identity", path, source))?;
    if !metadata.is_dir() {
        return Err(state_error("capacity anchor changed from a directory"));
    }
    let stats = rustix::fs::fstatvfs(&file)
        .map_err(|source| io_error("querying filesystem capacity", path, source.into()))?;
    if stats.f_bavail > stats.f_bfree || stats.f_bfree > stats.f_blocks {
        return Err(state_error(
            "filesystem reported inconsistent block capacity",
        ));
    }
    let allocation_unit = if stats.f_frsize == 0 {
        stats.f_bsize
    } else {
        stats.f_frsize
    };
    if allocation_unit == 0 {
        return Err(state_error("filesystem reported a zero allocation unit"));
    }
    let available_bytes = stats
        .f_bavail
        .checked_mul(allocation_unit)
        .ok_or_else(capacity_overflow)?;
    Ok(SpaceSnapshot {
        volume_id: metadata.dev(),
        available_bytes,
        allocation_unit,
    })
}

#[cfg(windows)]
fn query_existing_space(path: &Path) -> Result<SpaceSnapshot, PortError> {
    let (volume_id, available_bytes, allocation_unit) = super::windows::volume_space(path)
        .map_err(|source| io_error("querying filesystem capacity", path, source))?;
    Ok(SpaceSnapshot {
        volume_id,
        available_bytes,
        allocation_unit,
    })
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn query_existing_space(_: &Path) -> Result<SpaceSnapshot, PortError> {
    Err(PortError::with_kind(
        PortErrorKind::Unsupported,
        "storage capacity queries are unsupported on this platform",
    ))
}
