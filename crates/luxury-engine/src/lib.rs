//! Installer use cases and their platform-facing ports.

#![forbid(unsafe_code)]

pub mod install;
pub mod launch;
pub mod uninstall;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortErrorKind {
    Integrity,
    Collision,
    Permission,
    Capacity,
    Busy,
    Recovery,
    State,
    Unsupported,
    Io,
    Other,
}

/// A stable error boundary between the engine and platform adapters.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct PortError {
    kind: PortErrorKind,
    message: String,
}

impl PortError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            kind: PortErrorKind::Other,
            message: message.into(),
        }
    }

    pub fn with_kind(kind: PortErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> PortErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}
