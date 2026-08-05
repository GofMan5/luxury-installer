//! Windows, Linux and macOS adapters for installer ports.

#![deny(unsafe_code)]

use std::{env, io, path::PathBuf};

mod local;

#[cfg(target_os = "linux")]
pub use local::LinuxSystemLaunchAdapter;
#[cfg(target_os = "macos")]
pub use local::MacosSystemLaunchAdapter;
#[cfg(windows)]
pub use local::WindowsSystemLaunchAdapter;
pub use local::{LocalInstallAdapter, LocalLaunchAdapter, LocalUninstallAdapter};

/// Return host-native fixed system install and private state roots.
pub fn default_system_roots() -> io::Result<(PathBuf, PathBuf)> {
    luxury_system_roots::get()
}

/// Return host-native user install and external state roots.
pub fn default_user_roots() -> io::Result<(PathBuf, PathBuf)> {
    #[cfg(windows)]
    {
        let base = required_absolute_env("LOCALAPPDATA")?.join("Luxury Installer");
        Ok((base.join("Apps"), base.join("State-v1")))
    }
    #[cfg(target_os = "macos")]
    {
        let base = required_absolute_env("HOME")?
            .join("Library")
            .join("Application Support")
            .join("Luxury Installer");
        Ok((base.join("Apps"), base.join("State-v1")))
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
            state.join("luxury-installer-v1"),
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
    use super::default_user_roots;

    #[test]
    fn user_roots_are_absolute_separate_and_versioned() {
        let (install, state) = default_user_roots().unwrap();
        assert!(install.is_absolute());
        assert!(state.is_absolute());
        assert!(!install.starts_with(&state));
        assert!(!state.starts_with(&install));

        #[cfg(any(windows, target_os = "macos"))]
        assert!(state.ends_with("State-v1"));
        #[cfg(all(unix, not(target_os = "macos")))]
        assert!(state.ends_with("luxury-installer-v1"));
    }
}
