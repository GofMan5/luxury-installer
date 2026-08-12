//! Host-native fixed roots for system-scope installation authority.

#![deny(unsafe_code)]

use std::{io, path::PathBuf};

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use std::{
        ffi::OsString, io, os::windows::ffi::OsStringExt, path::PathBuf, ptr::null_mut, slice,
    };

    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{
            FOLDERID_ProgramData, FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
        },
    };

    pub(super) fn get() -> io::Result<(PathBuf, PathBuf)> {
        let program_files = known_folder(&FOLDERID_ProgramFiles)?;
        let program_data = known_folder(&FOLDERID_ProgramData)?;
        Ok((
            program_files.join("Luxury Installer").join("Apps"),
            program_data.join("Luxury Installer").join("State"),
        ))
    }

    fn known_folder(folder: &windows_sys::core::GUID) -> io::Result<PathBuf> {
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
}

/// Return the fixed install and private-state roots for system scope on this host.
pub fn get() -> io::Result<(PathBuf, PathBuf)> {
    #[cfg(windows)]
    {
        windows::get()
    }
    #[cfg(target_os = "linux")]
    {
        Ok((
            PathBuf::from("/opt/luxury-installer/apps"),
            PathBuf::from("/var/lib/luxury-installer"),
        ))
    }
    #[cfg(target_os = "macos")]
    {
        Ok((
            PathBuf::from("/Applications"),
            PathBuf::from("/Library/Application Support/Luxury Installer/State"),
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn roots_are_absolute_separate_and_fixed() {
        let (install, state) = super::get().unwrap();
        assert!(install.is_absolute());
        assert!(state.is_absolute());
        assert!(!install.starts_with(&state));
        assert!(!state.starts_with(&install));

        #[cfg(windows)]
        {
            assert!(install.ends_with(r"Luxury Installer\Apps"));
            assert!(state.ends_with(r"Luxury Installer\State"));
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(install, std::path::Path::new("/opt/luxury-installer/apps"));
            assert_eq!(state, std::path::Path::new("/var/lib/luxury-installer"));
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(install, std::path::Path::new("/Applications"));
            assert_eq!(
                state,
                std::path::Path::new("/Library/Application Support/Luxury Installer/State")
            );
        }
    }
}
