//! Stable package schema and trust-boundary validation.

mod error;
mod manifest;
mod path;
mod publisher;

pub use error::SpecError;
pub use manifest::{
    Architecture, FileEntry, FinishLink, InstallPolicy, InstallScope, MAX_PAYLOAD_BYTES,
    MAX_PAYLOAD_FILE_BYTES, MAX_PAYLOAD_FILES, Manifest, OperatingSystem, Package, PackageId,
    Sha256Digest, Target, validate_entrypoint,
};
pub use path::{InstallDirectory, PackagePath};
pub use publisher::{
    PublisherKeyId, PublisherPublicKey, PublisherRotation, PublisherRotationProof,
};

/// Unsigned development package format.
pub const FORMAT_VERSION: u32 = 1;
/// Publisher-authenticated package format.
pub const SIGNED_FORMAT_VERSION: u32 = 2;
/// Publisher key-rotation package format.
pub const PUBLISHER_ROTATION_FORMAT_VERSION: u32 = 3;

/// Manifest revision that introduced an exact installed entrypoint.
pub const ENTRYPOINT_SCHEMA_VERSION: u32 = 2;
/// Manifest revision that introduced a signed plain-text license agreement.
pub const LICENSE_SCHEMA_VERSION: u32 = 3;
/// Latest manifest schema revision. This is independent of the package trust format.
pub const MANIFEST_SCHEMA_VERSION: u32 = LICENSE_SCHEMA_VERSION;
