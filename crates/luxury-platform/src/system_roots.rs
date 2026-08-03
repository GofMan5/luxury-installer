use std::{io, path::PathBuf};

#[cfg(windows)]
pub(super) fn get() -> io::Result<(PathBuf, PathBuf)> {
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, FOLDERID_ProgramFiles};

    let program_files = known_folder(&FOLDERID_ProgramFiles)?;
    let program_data = known_folder(&FOLDERID_ProgramData)?;
    Ok((
        program_files.join("Luxury Installer").join("Apps"),
        program_data.join("Luxury Installer").join("State"),
    ))
}

#[cfg(target_os = "linux")]
pub(super) fn get() -> io::Result<(PathBuf, PathBuf)> {
    Ok((
        PathBuf::from("/opt/luxury-installer/apps"),
        PathBuf::from("/var/lib/luxury-installer"),
    ))
}

#[cfg(target_os = "macos")]
pub(super) fn get() -> io::Result<(PathBuf, PathBuf)> {
    Ok((
        PathBuf::from("/Applications"),
        PathBuf::from("/Library/Application Support/Luxury Installer/State"),
    ))
}

#[cfg(windows)]
fn known_folder(folder: &windows_sys::core::GUID) -> io::Result<PathBuf> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr::null_mut, slice};

    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath},
    };

    const MAX_PATH_UNITS: usize = 32_768;

    let mut raw = null_mut();
    // SAFETY: `folder` is a supported static known-folder ID and `raw` is writable.
    let status =
        unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT as u32, null_mut(), &mut raw) };
    if status < 0 {
        return Err(io::Error::other(format!(
            "Windows known-folder lookup failed (0x{status:08x})"
        )));
    }
    if raw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an empty known-folder path",
        ));
    }

    let mut length = 0;
    // SAFETY: SHGetKnownFolderPath returns a NUL-terminated task-allocated UTF-16 string.
    while length < MAX_PATH_UNITS && unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    let result = if length == 0 || length == MAX_PATH_UNITS {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid known-folder path",
        ))
    } else {
        // SAFETY: the bounded loop found the terminator after exactly `length` initialized units.
        let value = unsafe { slice::from_raw_parts(raw, length) };
        let path = PathBuf::from(OsString::from_wide(value));
        if path.is_absolute() {
            Ok(path)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned a relative known-folder path",
            ))
        }
    };
    // SAFETY: `raw` is the task-allocated pointer returned by SHGetKnownFolderPath.
    unsafe { CoTaskMemFree(raw.cast()) };
    result
}
