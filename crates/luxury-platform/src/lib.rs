//! Windows, Linux and macOS adapters for installer ports.

#![deny(unsafe_code)]

use std::{env, io, path::PathBuf};

mod local;
#[allow(unsafe_code)]
mod system_roots;

#[cfg(target_os = "linux")]
pub use local::LinuxSystemLaunchAdapter;
#[cfg(target_os = "macos")]
pub use local::MacosSystemLaunchAdapter;
#[cfg(windows)]
pub use local::WindowsSystemLaunchAdapter;
pub use local::{LocalInstallAdapter, LocalLaunchAdapter, LocalUninstallAdapter};

/// Return host-native fixed system install and private state roots.
pub fn default_system_roots() -> io::Result<(PathBuf, PathBuf)> {
    system_roots::get()
}

/// Return host-native user install and external state roots.
pub fn default_user_roots() -> io::Result<(PathBuf, PathBuf)> {
    #[cfg(windows)]
    {
        let base = required_absolute_env("LOCALAPPDATA")?.join("Luxury Installer");
        Ok((base.join("Apps"), base.join("State")))
    }
    #[cfg(target_os = "macos")]
    {
        let base = required_absolute_env("HOME")?
            .join("Library")
            .join("Application Support")
            .join("Luxury Installer");
        Ok((base.join("Apps"), base.join("State")))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let home = required_absolute_env("HOME")?;
        let data = optional_absolute_env("XDG_DATA_HOME")?
            .unwrap_or_else(|| home.join(".local").join("share"));
        let state = optional_absolute_env("XDG_STATE_HOME")?
            .unwrap_or_else(|| home.join(".local").join("state"));
        Ok((
            data.join("luxury-installer").join("apps"),
            state.join("luxury-installer"),
        ))
    }
}

fn required_absolute_env(name: &str) -> io::Result<PathBuf> {
    let value = env::var_os(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{name} is required to determine the user installation roots"),
            )
        })?;
    absolute_env_path(name, value.into())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn optional_absolute_env(name: &str) -> io::Result<Option<PathBuf>> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(|value| absolute_env_path(name, value.into()))
        .transpose()
}

fn absolute_env_path(name: &str, path: PathBuf) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be an absolute path"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::default_system_roots;

    #[test]
    fn system_roots_are_absolute_separate_and_fixed() {
        let (install, state) = default_system_roots().unwrap();
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
