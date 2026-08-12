use std::{collections::HashSet, fmt, str::FromStr};

use semver::Version;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{
    ENTRYPOINT_SCHEMA_VERSION, FORMAT_VERSION, InstallDirectory, LICENSE_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION, PRODUCT_IDENTITY_SCHEMA_VERSION, PUBLISHER_ROTATION_FORMAT_VERSION,
    PackagePath, PublisherRotation, REQUIREMENTS_SCHEMA_VERSION, SHORTCUT_SCHEMA_VERSION,
    SIGNED_FORMAT_VERSION, SpecError,
};

pub const MAX_PAYLOAD_FILES: usize = 100_000;
pub const MAX_PAYLOAD_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_LICENSE_CHARS: usize = 16_384;
const MAX_FINISH_LINKS: usize = 4;
const MAX_FINISH_LINK_LABEL_CHARS: usize = 48;
const MAX_FINISH_LINK_URL_BYTES: usize = 2_048;
pub const MAX_PRODUCT_ICON_BYTES: u64 = 4 * 1024 * 1024;
const RESERVED_NATIVE_ID: &str = "software.luxury.installer";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u32,
    #[serde(
        default = "legacy_schema_version",
        skip_serializing_if = "is_legacy_schema_version"
    )]
    pub schema_version: u32,
    pub package: Package,
    pub target: Target,
    pub install: InstallPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_rotation: Option<PublisherRotation>,
    pub files: Vec<FileEntry>,
}

impl Manifest {
    pub fn from_toml(source: &str) -> Result<Self, SpecError> {
        let manifest: Self = toml::from_str(source).map_err(|mut error| {
            error.set_input(None);
            SpecError::InvalidToml(error.to_string().trim().to_owned())
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn to_toml(&self) -> Result<String, SpecError> {
        self.validate()?;
        toml::to_string(self).map_err(|error| SpecError::Serialization(error.to_string()))
    }

    pub fn validate(&self) -> Result<(), SpecError> {
        if !(1..=MANIFEST_SCHEMA_VERSION).contains(&self.schema_version) {
            return Err(SpecError::UnsupportedSchema {
                found: self.schema_version,
                supported: MANIFEST_SCHEMA_VERSION,
            });
        }
        if !matches!(
            self.format_version,
            FORMAT_VERSION | SIGNED_FORMAT_VERSION | PUBLISHER_ROTATION_FORMAT_VERSION
        ) {
            return Err(SpecError::UnsupportedFormat {
                found: self.format_version,
                supported: PUBLISHER_ROTATION_FORMAT_VERSION,
            });
        }
        match (self.format_version, self.publisher_rotation.is_some()) {
            (PUBLISHER_ROTATION_FORMAT_VERSION, false) => {
                return Err(SpecError::PublisherRotationRequired);
            }
            (FORMAT_VERSION | SIGNED_FORMAT_VERSION, true) => {
                return Err(SpecError::PublisherRotationForbidden {
                    format_version: self.format_version,
                });
            }
            _ => {}
        }
        validate_text("package.name", &self.package.name, 128)?;
        validate_text("package.publisher", &self.package.publisher, 128)?;
        if let Some(description) = &self.package.description {
            validate_text("package.description", description, 1024)?;
        }
        if self.package.has_native_identity_metadata()
            && self.schema_version < PRODUCT_IDENTITY_SCHEMA_VERSION
        {
            return Err(SpecError::ProductIdentityRequiresSchema {
                found: self.schema_version,
                required: PRODUCT_IDENTITY_SCHEMA_VERSION,
            });
        }
        // The namespace belongs to the installer infrastructure at every schema version: receipts
        // persist product identity for legacy schemas too, so opting out of schema 5 must not
        // hand an author the reserved ID.
        if self.package.id.is_reserved_native_identity() {
            return Err(SpecError::ReservedNativePackageId(
                self.package.id.to_string(),
            ));
        }
        if let Some(homepage) = &self.package.homepage {
            validate_product_url("homepage", homepage)?;
        }
        if let Some(support) = &self.package.support {
            validate_product_url("support", support)?;
        }
        if self.schema_version < ENTRYPOINT_SCHEMA_VERSION && self.install.entrypoint.is_some() {
            return Err(SpecError::EntrypointRequiresSchema {
                found: self.schema_version,
                required: ENTRYPOINT_SCHEMA_VERSION,
            });
        }
        if let Some(license) = &self.package.license {
            if self.schema_version < LICENSE_SCHEMA_VERSION {
                return Err(SpecError::LicenseRequiresSchema {
                    found: self.schema_version,
                    required: LICENSE_SCHEMA_VERSION,
                });
            }
            validate_license(license)?;
        }
        if self.install.shortcuts.enabled() {
            if self.schema_version < SHORTCUT_SCHEMA_VERSION {
                return Err(SpecError::ShortcutsRequireSchema {
                    found: self.schema_version,
                    required: SHORTCUT_SCHEMA_VERSION,
                });
            }
            if self.install.entrypoint.is_none() {
                return Err(SpecError::ShortcutsRequireEntrypoint);
            }
        }
        if !self.install.requires.is_empty() {
            if self.schema_version < REQUIREMENTS_SCHEMA_VERSION {
                return Err(SpecError::RequirementsRequireSchema {
                    found: self.schema_version,
                    required: REQUIREMENTS_SCHEMA_VERSION,
                });
            }
            self.install.requires.validate(self.target.os)?;
        }
        if self.install.finish_links.len() > MAX_FINISH_LINKS {
            return Err(SpecError::TooManyFinishLinks(
                self.install.finish_links.len(),
            ));
        }
        for link in &self.install.finish_links {
            validate_text(
                "install.finish_links.label",
                &link.label,
                MAX_FINISH_LINK_LABEL_CHARS,
            )?;
            if link.label.chars().any(is_bidi_control) || !valid_https_url(&link.url) {
                return Err(SpecError::InvalidFinishLinkUrl);
            }
        }
        if self.files.is_empty() {
            return Err(SpecError::EmptyPayload);
        }
        if self.files.len() > MAX_PAYLOAD_FILES {
            return Err(SpecError::TooManyFiles(self.files.len()));
        }

        let mut paths = HashSet::with_capacity(self.files.len());
        let mut total_size = 0_u64;
        for file in &self.files {
            if file.size > MAX_PAYLOAD_FILE_BYTES {
                return Err(SpecError::FileTooLarge {
                    path: file.path.to_string(),
                    size: file.size,
                });
            }
            if !paths.insert(file.path.collision_key()) {
                return Err(SpecError::DuplicatePath(file.path.to_string()));
            }
            total_size = total_size
                .checked_add(file.size)
                .ok_or(SpecError::PayloadTooLarge)?;
            if total_size > MAX_PAYLOAD_BYTES {
                return Err(SpecError::PayloadTooLarge);
            }
        }
        for path in &paths {
            for (index, _) in path.match_indices('/') {
                if paths.contains(&path[..index]) {
                    return Err(SpecError::DuplicatePath(path.clone()));
                }
            }
        }
        validate_entrypoint(
            self.target.os,
            self.install.entrypoint.as_ref(),
            &self.files,
        )?;
        validate_product_icon(self.target.os, self.package.icon.as_ref(), &self.files)?;
        Ok(())
    }

    pub fn payload_size(&self) -> u64 {
        self.files.iter().map(|file| file.size).sum()
    }
}

const fn legacy_schema_version() -> u32 {
    1
}

fn is_legacy_schema_version(version: &u32) -> bool {
    *version == legacy_schema_version()
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn validate_text(field: &'static str, value: &str, max: usize) -> Result<(), SpecError> {
    let length = value.chars().count();
    // Every one of these strings is display-bound, so bidi overrides are rejected here for the
    // same reason shortcut display names and finish-link labels reject them.
    if length == 0
        || length > max
        || value
            .chars()
            .any(|character| character.is_control() || is_bidi_control(character))
    {
        return Err(SpecError::InvalidText { field, max });
    }
    Ok(())
}

fn validate_license(value: &str) -> Result<(), SpecError> {
    let valid_control = |character: char| matches!(character, '\n' | '\t');
    if value.trim().is_empty()
        || value.chars().count() > MAX_LICENSE_CHARS
        || value.chars().any(|character| {
            (character.is_control() && !valid_control(character)) || is_bidi_control(character)
        })
    {
        return Err(SpecError::InvalidText {
            field: "package.license",
            max: MAX_LICENSE_CHARS,
        });
    }
    Ok(())
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

fn valid_https_url(value: &str) -> bool {
    if value.len() > MAX_FINISH_LINK_URL_BYTES
        || value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || is_bidi_control(character)
        })
        || value.contains('\\')
    {
        return false;
    }
    let Some(remainder) = value.strip_prefix("https://") else {
        return false;
    };
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') || !authority.is_ascii() {
        return false;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.len() > 253
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return false;
    }
    port.is_none_or(|port| port.parse::<u16>().is_ok_and(|port| port != 0))
}

fn validate_product_url(field: &'static str, value: &str) -> Result<(), SpecError> {
    if valid_https_url(value) {
        Ok(())
    } else {
        Err(SpecError::InvalidProductUrl { field })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub id: PackageId,
    pub name: String,
    pub version: Version,
    pub publisher: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<PackagePath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support: Option<String>,
}

impl Package {
    pub const fn has_native_identity_metadata(&self) -> bool {
        self.icon.is_some() || self.homepage.is_some() || self.support.is_some()
    }

    pub fn product_metadata(&self, files: &[FileEntry]) -> ProductMetadata {
        ProductMetadata {
            package_id: self.id.clone(),
            name: self.name.clone(),
            version: self.version.clone(),
            publisher: self.publisher.clone(),
            description: self.description.clone(),
            icon: self.icon.as_ref().and_then(|path| {
                files
                    .iter()
                    .find(|file| file.path == *path)
                    .map(|file| ProductIcon {
                        path: file.path.clone(),
                        size: file.size,
                        sha256: file.sha256.clone(),
                    })
            }),
            homepage: self.homepage.clone(),
            support: self.support.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductMetadata {
    pub package_id: PackageId,
    pub name: String,
    pub version: Version,
    pub publisher: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<ProductIcon>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support: Option<String>,
}

impl ProductMetadata {
    pub fn from_package(package: &Package, files: &[FileEntry]) -> Self {
        package.product_metadata(files)
    }

    pub fn validate(&self, target: OperatingSystem) -> Result<(), SpecError> {
        validate_text("product_metadata.name", &self.name, 128)?;
        validate_text("product_metadata.publisher", &self.publisher, 128)?;
        if let Some(description) = &self.description {
            validate_text("product_metadata.description", description, 1024)?;
        }
        if let Some(homepage) = &self.homepage {
            validate_product_url("homepage", homepage)?;
        }
        if let Some(support) = &self.support {
            validate_product_url("support", support)?;
        }
        if let Some(icon) = &self.icon {
            validate_icon_identity(target, icon)?;
        }
        Ok(())
    }

    pub fn validate_against_files(
        &self,
        target: OperatingSystem,
        files: &[FileEntry],
    ) -> Result<(), SpecError> {
        self.validate(target)?;
        let Some(icon) = &self.icon else {
            return Ok(());
        };
        let file = files
            .iter()
            .find(|file| file.path == icon.path)
            .ok_or_else(|| SpecError::ProductIconMissingFile(icon.path.to_string()))?;
        if file.executable {
            return Err(SpecError::ProductIconExecutable(icon.path.to_string()));
        }
        if file.size != icon.size || file.sha256 != icon.sha256 {
            return Err(SpecError::ProductIconIdentityMismatch(
                icon.path.to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductIcon {
    pub path: PackagePath,
    pub size: u64,
    pub sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct PackageId(String);

impl PackageId {
    pub fn parse(value: impl Into<String>) -> Result<Self, SpecError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || value.starts_with('.')
            || value.ends_with('.')
            || !value.contains('.')
            || value.split('.').any(|part| {
                part.is_empty()
                    || part.starts_with('-')
                    || part.ends_with('-')
                    || !part.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(SpecError::InvalidPackageId(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_reserved_native_identity(&self) -> bool {
        self.0 == RESERVED_NATIVE_ID
            || self
                .0
                .strip_prefix(RESERVED_NATIVE_ID)
                .is_some_and(|suffix| suffix.starts_with('.'))
    }
}

fn validate_product_icon(
    target: OperatingSystem,
    icon: Option<&PackagePath>,
    files: &[FileEntry],
) -> Result<(), SpecError> {
    let Some(icon) = icon else {
        return Ok(());
    };
    let file = files
        .iter()
        .find(|file| file.path == *icon)
        .ok_or_else(|| SpecError::ProductIconMissingFile(icon.to_string()))?;
    if file.executable {
        return Err(SpecError::ProductIconExecutable(icon.to_string()));
    }
    validate_icon_identity(
        target,
        &ProductIcon {
            path: file.path.clone(),
            size: file.size,
            sha256: file.sha256.clone(),
        },
    )
}

fn validate_icon_identity(target: OperatingSystem, icon: &ProductIcon) -> Result<(), SpecError> {
    if icon.size == 0 || icon.size > MAX_PRODUCT_ICON_BYTES {
        return Err(SpecError::ProductIconTooLarge {
            path: icon.path.to_string(),
            size: icon.size,
            limit: MAX_PRODUCT_ICON_BYTES,
        });
    }
    let (extension, target_name, expected) = match target {
        OperatingSystem::Windows => ("ico", "Windows", ".ico"),
        OperatingSystem::Linux => ("png", "Linux", ".png"),
        OperatingSystem::Macos => ("icns", "macOS", ".icns"),
    };
    if !icon
        .path
        .as_str()
        .rsplit_once('.')
        .is_some_and(|(_, found)| found.eq_ignore_ascii_case(extension))
    {
        return Err(SpecError::ProductIconWrongFormat {
            path: icon.path.to_string(),
            target: target_name,
            expected,
        });
    }
    Ok(())
}

impl fmt::Display for PackageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PackageId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Windows,
    Linux,
    Macos,
}

impl OperatingSystem {
    #[cfg(target_os = "windows")]
    const HOST: Self = Self::Windows;
    #[cfg(target_os = "linux")]
    const HOST: Self = Self::Linux;
    #[cfg(target_os = "macos")]
    const HOST: Self = Self::Macos;

    pub const fn host() -> Self {
        Self::HOST
    }
}

impl fmt::Display for OperatingSystem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Macos => "macos",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

impl Architecture {
    #[cfg(target_arch = "x86_64")]
    const HOST: Self = Self::X86_64;
    #[cfg(target_arch = "aarch64")]
    const HOST: Self = Self::Aarch64;

    pub const fn host() -> Self {
        Self::HOST
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub os: OperatingSystem,
    pub arch: Architecture,
}

impl Target {
    pub const fn host() -> Self {
        Self {
            os: OperatingSystem::host(),
            arch: Architecture::host(),
        }
    }

    pub fn matches_host(&self) -> bool {
        *self == Self::host()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallScope {
    User,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPolicy {
    pub scope: InstallScope,
    pub directory: InstallDirectory,
    #[serde(default)]
    pub allow_downgrade: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<PackagePath>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub show_install_log: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finish_links: Vec<FinishLink>,
    #[serde(default, skip_serializing_if = "ShortcutPolicy::is_disabled")]
    pub shortcuts: ShortcutPolicy,
    #[serde(default, skip_serializing_if = "HostRequirements::is_empty")]
    pub requires: HostRequirements,
}

/// Declarative host requirements evaluated read-only before any mutation. Each predicate is
/// target-scoped on purpose: one OS cannot honestly answer another OS's version question.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRequirements {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_minimum_version: Option<WindowsVersion>,
}

impl HostRequirements {
    pub const fn is_empty(&self) -> bool {
        self.windows_minimum_version.is_none()
    }

    fn validate(&self, target: OperatingSystem) -> Result<(), SpecError> {
        if self.windows_minimum_version.is_some() && target != OperatingSystem::Windows {
            return Err(SpecError::RequirementTargetMismatch {
                field: "windows_minimum_version",
                expected: "windows",
            });
        }
        Ok(())
    }
}

/// A `major.minor.build` Windows version, the exact triple `RtlGetVersion` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WindowsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}

impl WindowsVersion {
    pub const fn new(major: u32, minor: u32, build: u32) -> Self {
        Self {
            major,
            minor,
            build,
        }
    }

    pub fn parse(value: &str) -> Result<Self, SpecError> {
        let invalid = || SpecError::InvalidWindowsVersion(value.to_owned());
        let mut parts = value.split('.');
        let mut next = || {
            parts
                .next()
                .filter(|part| !part.is_empty() && part.len() <= 10)
                .filter(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
                .filter(|part| *part == "0" || !part.starts_with('0'))
                .and_then(|part| part.parse::<u32>().ok())
                .ok_or_else(invalid)
        };
        let version = Self::new(next()?, next()?, next()?);
        if parts.next().is_some() {
            return Err(invalid());
        }
        Ok(version)
    }
}

impl fmt::Display for WindowsVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

impl<'de> Deserialize<'de> for WindowsVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

impl Serialize for WindowsVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// Portable, bounded desktop-integration intent. The target is always the
/// manifest's exact entrypoint; packages cannot provide arguments or paths.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShortcutPolicy {
    #[serde(default, skip_serializing_if = "is_false")]
    pub application_menu: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub desktop: bool,
}

impl ShortcutPolicy {
    pub const fn enabled(self) -> bool {
        self.application_menu || self.desktop
    }

    pub const fn is_disabled(&self) -> bool {
        !self.enabled()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishLink {
    pub label: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub path: PackagePath,
    pub size: u64,
    pub sha256: Sha256Digest,
    #[serde(default)]
    pub executable: bool,
}

/// Validate one optional installed entrypoint against the exact owned file table.
/// Receipts reuse this rule so launch policy cannot drift from manifest validation.
pub fn validate_entrypoint(
    target_os: OperatingSystem,
    entrypoint: Option<&PackagePath>,
    files: &[FileEntry],
) -> Result<(), SpecError> {
    let Some(entrypoint) = entrypoint else {
        return Ok(());
    };
    let file = files
        .iter()
        .find(|file| &file.path == entrypoint)
        .ok_or_else(|| SpecError::EntrypointMissingFile(entrypoint.to_string()))?;
    match target_os {
        OperatingSystem::Windows => {
            let path = entrypoint.as_str().as_bytes();
            if path.len() < 4 || !path[path.len() - 4..].eq_ignore_ascii_case(b".exe") {
                return Err(SpecError::WindowsEntrypointNotExecutable(
                    entrypoint.to_string(),
                ));
            }
        }
        OperatingSystem::Linux | OperatingSystem::Macos if !file.executable => {
            return Err(SpecError::EntrypointNotExecutable(entrypoint.to_string()));
        }
        OperatingSystem::Linux | OperatingSystem::Macos => {}
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, SpecError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || hex::decode(&value).is_err() {
            return Err(SpecError::InvalidDigest(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Sha256Digest {
    type Err = SpecError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> Manifest {
        Manifest {
            format_version: FORMAT_VERSION,
            schema_version: 1,
            package: Package {
                id: PackageId::parse("dev.luxury.demo").unwrap(),
                name: "Luxury Demo".into(),
                version: Version::new(1, 0, 0),
                publisher: "Luxury Software".into(),
                description: Some("Test package".into()),
                license: None,
                icon: None,
                homepage: None,
                support: None,
            },
            target: Target::host(),
            install: InstallPolicy {
                scope: InstallScope::User,
                directory: InstallDirectory::parse("Luxury Demo").unwrap(),
                allow_downgrade: false,
                entrypoint: None,
                show_install_log: false,
                finish_links: Vec::new(),
                shortcuts: ShortcutPolicy::default(),
                requires: Default::default(),
            },
            publisher_rotation: None,
            files: vec![FileEntry {
                path: PackagePath::parse("bin/demo.txt").unwrap(),
                size: 4,
                sha256: Sha256Digest::parse(
                    "81dc9bdb52d04dc20036dbd8313ed055de6b0f2f8f17b7f2a1d4c3c8a3f52c3f",
                )
                .unwrap(),
                executable: false,
            }],
        }
    }

    #[test]
    fn round_trips_toml() {
        let manifest = valid_manifest();
        let encoded = manifest.to_toml().unwrap();
        assert!(!encoded.contains("schema_version"));
        assert!(!encoded.contains("entrypoint"));
        assert!(!encoded.contains("show_install_log"));
        assert!(!encoded.contains("finish_links"));
        assert!(!encoded.contains("shortcuts"));
        let decoded = Manifest::from_toml(&encoded).unwrap();
        assert_eq!(decoded, manifest);

        let mut signed = valid_manifest();
        signed.format_version = SIGNED_FORMAT_VERSION;
        assert_eq!(
            Manifest::from_toml(&signed.to_toml().unwrap()).unwrap(),
            signed
        );
    }

    #[test]
    fn validates_optional_install_log_and_https_finish_links() {
        let mut manifest = valid_manifest();
        manifest.install.show_install_log = true;
        manifest.install.finish_links = vec![FinishLink {
            label: "Документация".into(),
            url: "https://example.com/docs?from=installer#start".into(),
        }];
        let encoded = manifest.to_toml().unwrap();
        assert!(encoded.contains("show_install_log = true"));
        assert!(encoded.contains("[[install.finish_links]]"));
        assert_eq!(Manifest::from_toml(&encoded).unwrap(), manifest);

        for url in [
            "http://example.com",
            "https://user@example.com",
            "https://example.com\\payload",
            "https://example.com/hidden\u{202e}txt",
            "https://bad_host.example",
            "https://example.com:0",
        ] {
            manifest.install.finish_links[0].url = url.into();
            assert_eq!(manifest.validate(), Err(SpecError::InvalidFinishLinkUrl));
        }
        manifest.install.finish_links = (0..=MAX_FINISH_LINKS)
            .map(|index| FinishLink {
                label: format!("Link {index}"),
                url: format!("https://example.com/{index}"),
            })
            .collect();
        assert_eq!(
            manifest.validate(),
            Err(SpecError::TooManyFinishLinks(MAX_FINISH_LINKS + 1))
        );
    }

    #[test]
    fn rejects_unsupported_schema_and_schema_one_entrypoint() {
        let mut manifest = valid_manifest();
        manifest.schema_version = MANIFEST_SCHEMA_VERSION + 1;
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::UnsupportedSchema {
                found,
                supported: MANIFEST_SCHEMA_VERSION
            }) if found == MANIFEST_SCHEMA_VERSION + 1
        ));

        manifest.schema_version = 1;
        manifest.install.entrypoint = Some(manifest.files[0].path.clone());
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::EntrypointRequiresSchema {
                found: 1,
                required: ENTRYPOINT_SCHEMA_VERSION
            })
        ));

        manifest.schema_version = ENTRYPOINT_SCHEMA_VERSION;
        manifest.target.os = OperatingSystem::Linux;
        manifest.files[0].executable = true;
        manifest.validate().unwrap();
    }

    #[test]
    fn license_requires_schema_three_and_bounded_plain_text() {
        let mut manifest = valid_manifest();
        manifest.package.license = Some("First line.\nSecond line.".into());
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::LicenseRequiresSchema {
                found: 1,
                required: LICENSE_SCHEMA_VERSION
            })
        ));

        manifest.schema_version = LICENSE_SCHEMA_VERSION;
        manifest.validate().unwrap();

        for invalid in [
            "",
            " \n\t",
            "invalid\0license",
            "invalid\rlicense",
            "hidden\u{202e}text",
        ] {
            manifest.package.license = Some(invalid.into());
            assert!(matches!(
                manifest.validate(),
                Err(SpecError::InvalidText {
                    field: "package.license",
                    max: MAX_LICENSE_CHARS
                })
            ));
        }

        manifest.package.license = Some("x".repeat(MAX_LICENSE_CHARS + 1));
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::InvalidText {
                field: "package.license",
                max: MAX_LICENSE_CHARS
            })
        ));
    }

    #[test]
    fn shortcuts_require_schema_four_and_an_exact_entrypoint() {
        let mut manifest = valid_manifest();
        manifest.install.shortcuts.application_menu = true;
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::ShortcutsRequireSchema {
                found: 1,
                required: SHORTCUT_SCHEMA_VERSION
            })
        ));

        manifest.schema_version = SHORTCUT_SCHEMA_VERSION;
        assert_eq!(
            manifest.validate(),
            Err(SpecError::ShortcutsRequireEntrypoint)
        );

        manifest.install.entrypoint = Some(manifest.files[0].path.clone());
        if manifest.target.os != OperatingSystem::Windows {
            manifest.files[0].executable = true;
        } else {
            manifest.files[0].path = PackagePath::parse("bin/demo.exe").unwrap();
            manifest.install.entrypoint = Some(manifest.files[0].path.clone());
        }
        manifest.validate().unwrap();
        let encoded = manifest.to_toml().unwrap();
        assert!(encoded.contains("[install.shortcuts]"));
        assert!(encoded.contains("application_menu = true"));
        assert!(!encoded.contains("desktop = false"));
        assert_eq!(Manifest::from_toml(&encoded).unwrap(), manifest);
    }

    #[test]
    fn package_description_is_bounded_plain_text() {
        let mut manifest = valid_manifest();
        manifest.package.description = Some("Human-facing summary".into());
        manifest.validate().unwrap();

        for invalid in ["", "bad\0description"] {
            manifest.package.description = Some(invalid.into());
            assert!(matches!(
                manifest.validate(),
                Err(SpecError::InvalidText {
                    field: "package.description",
                    max: 1024,
                })
            ));
        }
        manifest.package.description = Some("x".repeat(1025));
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::InvalidText {
                field: "package.description",
                max: 1024,
            })
        ));
    }

    #[test]
    fn host_requirements_are_schema_gated_target_scoped_and_exactly_parsed() {
        let mut manifest = valid_manifest();
        manifest.target.os = OperatingSystem::Windows;
        manifest.install.requires.windows_minimum_version = Some(WindowsVersion::new(10, 0, 19045));
        assert_eq!(
            manifest.validate(),
            Err(SpecError::RequirementsRequireSchema {
                found: 1,
                required: REQUIREMENTS_SCHEMA_VERSION,
            })
        );

        manifest.schema_version = REQUIREMENTS_SCHEMA_VERSION;
        manifest.validate().unwrap();
        let encoded = manifest.to_toml().unwrap();
        assert!(encoded.contains("windows_minimum_version = \"10.0.19045\""));
        assert_eq!(Manifest::from_toml(&encoded).unwrap(), manifest);

        // One OS cannot honestly answer another OS's version question.
        manifest.target.os = OperatingSystem::Linux;
        assert_eq!(
            manifest.validate(),
            Err(SpecError::RequirementTargetMismatch {
                field: "windows_minimum_version",
                expected: "windows",
            })
        );

        for value in [
            "10",
            "10.0",
            "10.0.0.0",
            "10.0.019045",
            "10.0.-1",
            "",
            "a.b.c",
        ] {
            assert!(
                WindowsVersion::parse(value).is_err(),
                "`{value}` must not parse"
            );
        }
        assert_eq!(
            WindowsVersion::parse("10.0.19045").unwrap(),
            WindowsVersion::new(10, 0, 19045)
        );
        assert!(WindowsVersion::new(10, 0, 19045) > WindowsVersion::new(10, 0, 19044));
        assert!(WindowsVersion::new(11, 0, 1) > WindowsVersion::new(10, 9, 99999));
    }

    #[test]
    fn product_identity_requires_schema_five_and_round_trips() {
        let mut manifest = valid_manifest();
        manifest.target.os = OperatingSystem::Linux;
        manifest.package.icon = Some(PackagePath::parse("branding/app.png").unwrap());
        manifest.package.homepage = Some("https://example.com/product".into());
        manifest.package.support = Some("https://support.example.com/help".into());
        manifest.files.push(FileEntry {
            path: manifest.package.icon.clone().unwrap(),
            size: 128,
            sha256: Sha256Digest::parse("a".repeat(64)).unwrap(),
            executable: false,
        });
        assert_eq!(
            manifest.validate(),
            Err(SpecError::ProductIdentityRequiresSchema {
                found: 1,
                required: PRODUCT_IDENTITY_SCHEMA_VERSION,
            })
        );

        manifest.schema_version = PRODUCT_IDENTITY_SCHEMA_VERSION;
        manifest.validate().unwrap();
        let encoded = manifest.to_toml().unwrap();
        assert!(encoded.contains("icon = \"branding/app.png\""));
        assert!(encoded.contains("homepage = \"https://example.com/product\""));
        assert!(encoded.contains("support = \"https://support.example.com/help\""));
        assert_eq!(Manifest::from_toml(&encoded).unwrap(), manifest);

        let metadata = manifest.package.product_metadata(&manifest.files);
        metadata.validate(manifest.target.os).unwrap();
        let icon = metadata.icon.unwrap();
        assert_eq!(icon.path.as_str(), "branding/app.png");
        assert_eq!(icon.size, 128);
    }

    #[test]
    fn product_identity_rejects_unsafe_urls_icons_and_owned_namespace() {
        let mut manifest = valid_manifest();
        manifest.schema_version = PRODUCT_IDENTITY_SCHEMA_VERSION;
        manifest.target.os = OperatingSystem::Windows;

        for value in [
            "http://example.com",
            "https://user@example.com",
            "https://example.com\\help",
            "https://example.com/hidden\u{202e}txt",
            "https://bad_host.example",
            "https://example.com:0",
        ] {
            manifest.package.homepage = Some(value.into());
            assert_eq!(
                manifest.validate(),
                Err(SpecError::InvalidProductUrl { field: "homepage" })
            );
        }
        manifest.package.homepage = None;

        manifest.package.icon = Some(PackagePath::parse("branding/app.png").unwrap());
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::ProductIconMissingFile(_))
        ));
        manifest.files.push(FileEntry {
            path: manifest.package.icon.clone().unwrap(),
            size: 1,
            sha256: Sha256Digest::parse("b".repeat(64)).unwrap(),
            executable: false,
        });
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::ProductIconWrongFormat {
                expected: ".ico",
                ..
            })
        ));
        manifest.files.last_mut().unwrap().path = PackagePath::parse("branding/app.ico").unwrap();
        manifest.package.icon = Some(manifest.files.last().unwrap().path.clone());
        manifest.files.last_mut().unwrap().executable = true;
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::ProductIconExecutable(_))
        ));
        manifest.files.last_mut().unwrap().executable = false;
        manifest.files.last_mut().unwrap().size = MAX_PRODUCT_ICON_BYTES + 1;
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::ProductIconTooLarge { .. })
        ));

        manifest.package.icon = None;
        manifest.files.pop();
        manifest.package.id = PackageId::parse("software.luxury.installer.product").unwrap();
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::ReservedNativePackageId(_))
        ));

        // The reserved namespace is not an opt-in of schema 5: legacy schemas write the same
        // receipt product identity, so they must be refused too.
        manifest.schema_version = SHORTCUT_SCHEMA_VERSION;
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::ReservedNativePackageId(_))
        ));
        manifest.package.id = PackageId::parse("dev.luxury.demo").unwrap();
        assert!(
            manifest.validate().is_ok(),
            "legacy schema remains readable"
        );

        // Display-bound identity text rejects bidi overrides at every schema version.
        manifest.package.name = "Setup\u{202e}drowssap".into();
        assert_eq!(
            manifest.validate(),
            Err(SpecError::InvalidText {
                field: "package.name",
                max: 128,
            })
        );
    }

    #[test]
    fn entrypoint_must_name_an_exact_manifest_file() {
        let mut manifest = valid_manifest();
        manifest.schema_version = MANIFEST_SCHEMA_VERSION;
        manifest.target.os = OperatingSystem::Linux;
        manifest.install.entrypoint = Some(PackagePath::parse("bin/missing").unwrap());
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::EntrypointMissingFile(path)) if path == "bin/missing"
        ));

        manifest.install.entrypoint = Some(PackagePath::parse("BIN/DEMO.TXT").unwrap());
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::EntrypointMissingFile(path)) if path == "BIN/DEMO.TXT"
        ));
    }

    #[test]
    fn windows_entrypoint_requires_case_insensitive_exe_suffix() {
        let mut manifest = valid_manifest();
        manifest.schema_version = MANIFEST_SCHEMA_VERSION;
        manifest.target.os = OperatingSystem::Windows;
        manifest.files[0].path = PackagePath::parse("bin/demo.EXE").unwrap();
        manifest.install.entrypoint = Some(manifest.files[0].path.clone());
        manifest.validate().unwrap();

        manifest.files[0].path = PackagePath::parse("bin/demo.exe.bak").unwrap();
        manifest.install.entrypoint = Some(manifest.files[0].path.clone());
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::WindowsEntrypointNotExecutable(path))
                if path == "bin/demo.exe.bak"
        ));
    }

    #[test]
    fn linux_and_macos_entrypoints_require_executable_files() {
        for target_os in [OperatingSystem::Linux, OperatingSystem::Macos] {
            let mut manifest = valid_manifest();
            manifest.schema_version = MANIFEST_SCHEMA_VERSION;
            manifest.target.os = target_os;
            manifest.files[0].path = PackagePath::parse("bin/demo").unwrap();
            manifest.install.entrypoint = Some(manifest.files[0].path.clone());
            assert!(matches!(
                manifest.validate(),
                Err(SpecError::EntrypointNotExecutable(path)) if path == "bin/demo"
            ));

            manifest.files[0].executable = true;
            manifest.validate().unwrap();
        }
    }

    #[test]
    fn rotation_metadata_is_version_gated() {
        let rotation = PublisherRotation {
            next_public_key: crate::PublisherPublicKey::from_bytes([1; 32]),
            proof: crate::PublisherRotationProof::from_bytes([2; 64]),
        };

        let mut manifest = valid_manifest();
        manifest.format_version = PUBLISHER_ROTATION_FORMAT_VERSION;
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::PublisherRotationRequired)
        ));
        manifest.publisher_rotation = Some(rotation);
        assert_eq!(
            Manifest::from_toml(&manifest.to_toml().unwrap()).unwrap(),
            manifest
        );

        for format_version in [FORMAT_VERSION, SIGNED_FORMAT_VERSION] {
            manifest.format_version = format_version;
            assert!(matches!(
                manifest.validate(),
                Err(SpecError::PublisherRotationForbidden { format_version: found })
                    if found == format_version
            ));
        }
    }

    #[test]
    fn rejects_case_colliding_paths() {
        let mut manifest = valid_manifest();
        manifest.files.push(FileEntry {
            path: PackagePath::parse("BIN/DEMO.TXT").unwrap(),
            size: 4,
            sha256: manifest.files[0].sha256.clone(),
            executable: false,
        });
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::DuplicatePath(_))
        ));
    }

    #[test]
    fn rejects_file_directory_prefix_conflicts() {
        let mut manifest = valid_manifest();
        manifest.files[0].path = PackagePath::parse("bin").unwrap();
        manifest.files.push(FileEntry {
            path: PackagePath::parse("bin/demo.txt").unwrap(),
            size: 4,
            sha256: manifest.files[0].sha256.clone(),
            executable: false,
        });
        assert!(matches!(
            manifest.validate(),
            Err(SpecError::DuplicatePath(_))
        ));
    }

    #[test]
    fn rejects_unknown_fields() {
        let source = valid_manifest().to_toml().unwrap() + "\nunknown = true\n";
        assert!(Manifest::from_toml(&source).is_err());
    }

    #[test]
    fn invalid_manifest_toml_does_not_echo_source_material() {
        let secret = concat!("-----BEGIN PRIVATE ", "KEY-----SECRET-MARKER");
        let error = Manifest::from_toml(&format!("not_valid = \"{secret}\"")).unwrap_err();
        let rendered = format!("{error}\n{error:?}");
        assert!(error.to_string().contains("unknown field"));
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("PRIVATE KEY"));
    }
}
