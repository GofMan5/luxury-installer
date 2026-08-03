use std::{
    ffi::{OsString, c_void},
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    slice,
};

use sha2::{Digest, Sha256};
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessImageFileMapping};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
    WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTD_UICONTEXT_EXECUTE, WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_EXECUTE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        GetFileInformationByHandle, OPEN_EXISTING, SYNCHRONIZE,
    },
    System::Threading::QueryFullProcessImageNameW,
};

use super::{AuthenticodeSigner, TrustError};

const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;

pub(super) fn verify(path: &Path) -> Result<AuthenticodeSigner, TrustError> {
    let _locked = open_executable(path)?;
    verify_file(path)
}

pub(super) fn verify_process(
    process: BorrowedHandle<'_>,
) -> Result<AuthenticodeSigner, TrustError> {
    let path = process_image_path(process)?;
    let file = open_executable(&path)?;
    bind_process_image(process, file.as_handle())?;
    let signer = verify_file(&path)?;
    bind_process_image(process, file.as_handle())?;
    Ok(signer)
}

fn verify_file(path: &Path) -> Result<AuthenticodeSigner, TrustError> {
    if !path.is_absolute() {
        return Err(TrustError::InvalidPath);
    }
    let mut path = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if path.contains(&0) {
        return Err(TrustError::InvalidPath);
    }
    path.push(0);

    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: the action GUID and WINTRUST_DATA graph remain valid for the synchronous call.
    let status = unsafe {
        WinVerifyTrust(
            null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    let result = if status == 0 {
        // SAFETY: successful verification owns provider state until WTD_STATEACTION_CLOSE below.
        unsafe { signer_from_state(data.hWVTStateData) }
    } else {
        Err(TrustError::VerificationFailed(status))
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: this closes the state created by the verification call using the same data graph.
    let close_status = unsafe {
        WinVerifyTrust(
            null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    if close_status != 0 && result.is_ok() {
        return Err(TrustError::StateCloseFailed(close_status));
    }
    result
}

fn process_image_path(process: BorrowedHandle<'_>) -> Result<PathBuf, TrustError> {
    const CAPACITY: usize = 32_768;
    let mut buffer = vec![0_u16; CAPACITY];
    let mut length = CAPACITY as u32;
    if unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle() as HANDLE,
            0,
            buffer.as_mut_ptr(),
            &mut length,
        )
    } == 0
    {
        return Err(TrustError::ExecutableUnavailable(unsafe { GetLastError() }));
    }
    let length = length as usize;
    if length == 0 || length >= CAPACITY {
        return Err(TrustError::InvalidPath);
    }
    let path = PathBuf::from(OsString::from_wide(&buffer[..length]));
    if !path.is_absolute() {
        return Err(TrustError::InvalidPath);
    }
    Ok(path)
}

fn open_executable(path: &Path) -> Result<OwnedHandle, TrustError> {
    if !path.is_absolute() {
        return Err(TrustError::InvalidPath);
    }
    let mut path = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if path.contains(&0) {
        return Err(TrustError::InvalidPath);
    }
    path.push(0);
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | FILE_EXECUTE | SYNCHRONIZE,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(TrustError::ExecutableUnavailable(unsafe { GetLastError() }));
    }
    let file = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) } == 0
    {
        return Err(TrustError::ExecutableUnavailable(unsafe { GetLastError() }));
    }
    if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || information.nNumberOfLinks != 1
    {
        return Err(TrustError::InvalidPath);
    }
    Ok(file)
}

fn bind_process_image(
    process: BorrowedHandle<'_>,
    file: BorrowedHandle<'_>,
) -> Result<(), TrustError> {
    let mut file_handle = file.as_raw_handle() as HANDLE;
    let mut returned = 0_u32;
    let status = unsafe {
        NtQueryInformationProcess(
            process.as_raw_handle() as HANDLE,
            ProcessImageFileMapping,
            (&mut file_handle as *mut HANDLE).cast(),
            size_of::<HANDLE>() as u32,
            &mut returned,
        )
    };
    if status != 0 {
        return Err(TrustError::ProcessImageMismatch(status));
    }
    Ok(())
}

unsafe fn signer_from_state(
    state: windows_sys::Win32::Foundation::HANDLE,
) -> Result<AuthenticodeSigner, TrustError> {
    if state.is_null() {
        return Err(TrustError::MalformedProviderState);
    }
    // SAFETY: `state` came from a successful WinVerifyTrust call and remains open.
    let provider = unsafe { WTHelperProvDataFromStateData(state) };
    if provider.is_null() {
        return Err(TrustError::MalformedProviderState);
    }
    // SAFETY: provider index zero is the primary code signer from the verified state.
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
    if signer.is_null() {
        return Err(TrustError::MalformedProviderState);
    }
    // SAFETY: certificate index zero is the verified signer's leaf certificate.
    let provider_certificate = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    if provider_certificate.is_null() {
        return Err(TrustError::MalformedProviderState);
    }
    // SAFETY: all provider pointers remain valid until the caller closes WinTrust state.
    let certificate = unsafe { (*provider_certificate).pCert.as_ref() }
        .ok_or(TrustError::MalformedProviderState)?;
    let length = certificate.cbCertEncoded as usize;
    if certificate.pbCertEncoded.is_null() || !(1..=MAX_CERTIFICATE_BYTES).contains(&length) {
        return Err(TrustError::MalformedProviderState);
    }
    // SAFETY: CERT_CONTEXT exposes exactly `cbCertEncoded` bytes for the open provider state.
    let encoded = unsafe { slice::from_raw_parts(certificate.pbCertEncoded, length) };
    Ok(AuthenticodeSigner(Sha256::digest(encoded).into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::windows::process::CommandExt,
        process::{Command, Stdio},
    };
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    #[test]
    fn unsigned_test_binary_is_rejected() {
        let error = verify(&std::env::current_exe().unwrap()).unwrap_err();
        assert!(matches!(error, TrustError::VerificationFailed(_)));
    }

    #[test]
    fn locked_process_image_cannot_be_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("signed.exe");
        let moved = temp.path().join("signed.moved.exe");
        fs::copy(signed_system_executable(), &path).unwrap();
        let original = fs::read(&path).unwrap();
        let file = open_executable(&path).unwrap();

        let rename = fs::rename(&path, &moved);

        assert!(rename.is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!moved.exists());
        drop(file);
    }

    #[test]
    fn process_binding_rejects_a_file_replaced_after_launch() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("peer.exe");
        let moved = temp.path().join("peer.moved.exe");
        fs::copy(signed_system_executable(), &path).unwrap();
        let mut child = Command::new(&path)
            .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"not an executable").unwrap();

        let replacement = open_executable(&path).unwrap();
        let result = bind_process_image(child.as_handle(), replacement.as_handle());
        let _ = child.kill();
        let _ = child.wait();

        assert!(
            matches!(result, Err(TrustError::ProcessImageMismatch(_))),
            "{result:?}"
        );
    }

    fn signed_system_executable() -> PathBuf {
        PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe")
    }
}
