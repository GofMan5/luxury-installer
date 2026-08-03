use std::{error::Error, fmt, path::Path};

#[cfg(windows)]
mod windows;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticodeSigner([u8; 32]);

impl AuthenticodeSigner {
    pub const fn certificate_sha256(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum TrustError {
    Unsupported,
    InvalidPath,
    VerificationFailed(i32),
    MalformedProviderState,
    StateCloseFailed(i32),
    ExecutableUnavailable(u32),
    ProcessImageMismatch(i32),
    SignerMismatch,
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => formatter.write_str("Authenticode is supported only on Windows"),
            Self::InvalidPath => formatter.write_str("Authenticode path is invalid"),
            Self::VerificationFailed(status) => {
                write!(
                    formatter,
                    "Windows rejected the Authenticode signature (0x{status:08x})"
                )
            }
            Self::MalformedProviderState => {
                formatter.write_str("Windows returned malformed Authenticode provider state")
            }
            Self::StateCloseFailed(status) => {
                write!(
                    formatter,
                    "Windows could not close Authenticode state (0x{status:08x})"
                )
            }
            Self::ExecutableUnavailable(error) => {
                write!(
                    formatter,
                    "Windows could not open or query the executable ({error})"
                )
            }
            Self::ProcessImageMismatch(status) => {
                write!(
                    formatter,
                    "the opened file is not the running process image (0x{status:08x})"
                )
            }
            Self::SignerMismatch => {
                formatter.write_str("Authenticode signer certificates do not match")
            }
        }
    }
}

#[cfg(windows)]
pub fn verify_process_authenticode_signer(
    process: std::os::windows::io::BorrowedHandle<'_>,
) -> Result<AuthenticodeSigner, TrustError> {
    windows::verify_process(process)
}

#[cfg(windows)]
pub fn verify_same_process_authenticode_signer(
    first: std::os::windows::io::BorrowedHandle<'_>,
    second: std::os::windows::io::BorrowedHandle<'_>,
) -> Result<AuthenticodeSigner, TrustError> {
    let first = verify_process_authenticode_signer(first)?;
    if first != verify_process_authenticode_signer(second)? {
        return Err(TrustError::SignerMismatch);
    }
    Ok(first)
}

impl Error for TrustError {}

pub fn verify_authenticode_signer(path: &Path) -> Result<AuthenticodeSigner, TrustError> {
    #[cfg(windows)]
    {
        windows::verify(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(TrustError::Unsupported)
    }
}

pub fn verify_same_authenticode_signer(
    first: &Path,
    second: &Path,
) -> Result<AuthenticodeSigner, TrustError> {
    let first = verify_authenticode_signer(first)?;
    if first != verify_authenticode_signer(second)? {
        return Err(TrustError::SignerMismatch);
    }
    Ok(first)
}
