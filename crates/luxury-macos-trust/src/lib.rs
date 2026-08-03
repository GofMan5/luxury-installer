//! macOS audit-token and code-signing identity checks for the privileged boundary.

#![deny(unsafe_code)]

use std::{fmt, path::PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeRole {
    App,
    Helper,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPeer {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub code_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustError {
    Unsupported,
    InvalidConfiguration,
    PeerIdentity,
    CodeSignature,
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unsupported => "macOS code trust is unavailable on this platform",
            Self::InvalidConfiguration => "macOS signing configuration is invalid",
            Self::PeerIdentity => "macOS peer identity could not be verified",
            Self::CodeSignature => "macOS code signature did not match the required identity",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for TrustError {}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{verify_path, verify_peer, verify_self};

#[cfg(not(target_os = "macos"))]
pub fn verify_self(_: CodeRole) -> Result<PathBuf, TrustError> {
    Err(TrustError::Unsupported)
}

#[cfg(not(target_os = "macos"))]
pub fn verify_path(_: &std::path::Path, _: CodeRole) -> Result<(), TrustError> {
    Err(TrustError::Unsupported)
}
