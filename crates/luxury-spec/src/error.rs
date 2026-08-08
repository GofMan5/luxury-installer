use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SpecError {
    #[error("invalid package id: {0}")]
    InvalidPackageId(String),
    #[error("invalid package path `{path}`: {reason}")]
    InvalidPath { path: String, reason: &'static str },
    #[error("invalid install directory `{0}`")]
    InvalidInstallDirectory(String),
    #[error("invalid SHA-256 digest `{0}`")]
    InvalidDigest(String),
    #[error("invalid publisher key id")]
    InvalidPublisherKeyId,
    #[error("invalid publisher public key")]
    InvalidPublisherPublicKey,
    #[error("invalid publisher rotation proof")]
    InvalidPublisherRotationProof,
    #[error("publisher rotation metadata is required for manifest format 3")]
    PublisherRotationRequired,
    #[error("publisher rotation metadata is forbidden for manifest format {format_version}")]
    PublisherRotationForbidden { format_version: u32 },
    #[error("unsupported manifest format {found}; latest supported format is {supported}")]
    UnsupportedFormat { found: u32, supported: u32 },
    #[error("unsupported manifest schema {found}; latest supported schema is {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error(
        "manifest schema {found} does not support install.entrypoint; schema {required} is required"
    )]
    EntrypointRequiresSchema { found: u32, required: u32 },
    #[error(
        "manifest schema {found} does not support package.license; schema {required} is required"
    )]
    LicenseRequiresSchema { found: u32, required: u32 },
    #[error(
        "manifest schema {found} does not support install.shortcuts; schema {required} is required"
    )]
    ShortcutsRequireSchema { found: u32, required: u32 },
    #[error("install.shortcuts requires an exact receipt-owned entrypoint")]
    ShortcutsRequireEntrypoint,
    #[error("install entrypoint `{0}` is not an exact manifest file")]
    EntrypointMissingFile(String),
    #[error("Windows install entrypoint `{0}` must have an .exe suffix")]
    WindowsEntrypointNotExecutable(String),
    #[error("Unix install entrypoint `{0}` must be marked executable")]
    EntrypointNotExecutable(String),
    #[error("install.finish_links contains too many links: {0}; limit is 4")]
    TooManyFinishLinks(usize),
    #[error("install.finish_links URL must be a bounded HTTPS URL without credentials")]
    InvalidFinishLinkUrl,
    #[error("manifest must contain at least one file")]
    EmptyPayload,
    #[error("manifest contains too many files: {0}")]
    TooManyFiles(usize),
    #[error("manifest contains duplicate or case-colliding path `{0}`")]
    DuplicatePath(String),
    #[error("file `{path}` is too large: {size} bytes")]
    FileTooLarge { path: String, size: u64 },
    #[error("manifest payload size exceeds the supported limit")]
    PayloadTooLarge,
    #[error("{field} must be between 1 and {max} characters")]
    InvalidText { field: &'static str, max: usize },
    #[error("manifest TOML is invalid: {0}")]
    InvalidToml(String),
    #[error("manifest serialization failed: {0}")]
    Serialization(String),
}
