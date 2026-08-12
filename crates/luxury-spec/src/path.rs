use std::{fmt, path::Path};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use unicode_normalization::UnicodeNormalization;

use crate::SpecError;

const MAX_PATH_BYTES: usize = 512;
const MAX_COMPONENT_BYTES: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct PackagePath(String);

impl PackagePath {
    pub fn parse(value: impl Into<String>) -> Result<Self, SpecError> {
        let value = value.into();
        validate_portable_path(&value, false)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_native_path(&self) -> &Path {
        Path::new(&self.0)
    }

    pub fn collision_key(&self) -> String {
        self.0
            .nfc()
            .flat_map(char::to_lowercase)
            .collect::<String>()
    }
}

impl fmt::Display for PackagePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PackagePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct InstallDirectory(String);

impl InstallDirectory {
    pub fn parse(value: impl Into<String>) -> Result<Self, SpecError> {
        let value = value.into();
        validate_portable_path(&value, true)
            .map_err(|_| SpecError::InvalidInstallDirectory(value.clone()))?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InstallDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for InstallDirectory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

fn validate_portable_path(value: &str, single_component: bool) -> Result<(), SpecError> {
    let invalid = |reason| SpecError::InvalidPath {
        path: value.to_owned(),
        reason,
    };

    if value.is_empty() {
        return Err(invalid("path is empty"));
    }
    if value.len() > MAX_PATH_BYTES {
        return Err(invalid("path is longer than 512 bytes"));
    }
    if value.starts_with('/') {
        return Err(invalid("absolute paths are forbidden"));
    }
    if value.contains(['\\', '\0', ':', '<', '>', '"', '|', '?', '*']) {
        return Err(invalid("characters invalid on Windows are forbidden"));
    }

    let components = value.split('/').collect::<Vec<_>>();
    if single_component && components.len() != 1 {
        return Err(invalid("install directory must be one component"));
    }

    for component in components {
        if component.is_empty() || component == "." || component == ".." {
            return Err(invalid(
                "empty, current and parent components are forbidden",
            ));
        }
        if component.len() > MAX_COMPONENT_BYTES {
            return Err(invalid("path component is longer than 255 bytes"));
        }
        if component.ends_with(['.', ' ']) {
            return Err(invalid("components ending in a dot or space are forbidden"));
        }
        if component.chars().any(|character| character.is_control()) {
            return Err(invalid("control characters are forbidden"));
        }
        if is_windows_device_name(component) {
            return Err(invalid("Windows device names are forbidden"));
        }
    }

    Ok(())
}

fn is_windows_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or_default();
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper
            .strip_prefix("COM")
            .or_else(|| upper.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_hostile_and_non_portable_paths() {
        for value in [
            "",
            ".",
            "..",
            "../escape",
            "/absolute",
            "C:/absolute",
            "server\\share",
            "file:stream",
            "bad?.txt",
            "bad|name.txt",
            "CON",
            "aux.txt",
            "bin/COM1.exe",
            "LPT².txt",
            "trailing.",
            "trailing ",
            "double//slash",
        ] {
            assert!(PackagePath::parse(value).is_err(), "accepted `{value}`");
        }
    }

    #[test]
    fn accepts_portable_nested_path() {
        let path = PackagePath::parse("bin/Luxury Installer.exe").unwrap();
        assert_eq!(path.as_str(), "bin/Luxury Installer.exe");
    }

    #[test]
    fn keeps_every_component_within_common_filesystem_limits() {
        assert!(PackagePath::parse("a".repeat(MAX_COMPONENT_BYTES)).is_ok());
        assert!(PackagePath::parse("a".repeat(MAX_COMPONENT_BYTES + 1)).is_err());
        assert!(InstallDirectory::parse("a".repeat(MAX_COMPONENT_BYTES + 1)).is_err());
        assert!(PackagePath::parse(format!("{}/{}", "a".repeat(255), "b".repeat(255))).is_ok());
    }

    #[test]
    fn normalizes_unicode_for_collision_detection() {
        let composed = PackagePath::parse("café.txt").unwrap();
        let decomposed = PackagePath::parse("cafe\u{301}.txt").unwrap();
        assert_eq!(composed.collision_key(), decomposed.collision_key());
    }
}
