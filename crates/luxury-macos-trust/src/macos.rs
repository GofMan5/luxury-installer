use std::{
    ffi::c_void,
    mem::size_of,
    os::fd::{AsRawFd, BorrowedFd},
    path::PathBuf,
};

use core_foundation::{base::TCFType, data::CFData};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
};

use super::{CodeRole, TrustError, VerifiedPeer};

const SOL_LOCAL: libc::c_int = 0;
const LOCAL_PEERTOKEN: libc::c_int = 0x006;
const APP_IDENTIFIER: &str = "software.luxury.installer";
const HELPER_IDENTIFIER: &str = "software.luxury.installer.helper";

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditToken {
    value: [u32; 8],
}

pub fn verify_peer(socket: BorrowedFd<'_>, role: CodeRole) -> Result<VerifiedPeer, TrustError> {
    let token = peer_audit_token(socket)?;
    let pid = token.value[5];
    let uid = token.value[1];
    let gid = token.value[2];
    if pid == 0 {
        return Err(TrustError::PeerIdentity);
    }
    let mut peer_uid = 0;
    let mut peer_gid = 0;
    // SAFETY: the connected local socket is live and both outputs are writable.
    if unsafe { getpeereid(socket.as_raw_fd(), &mut peer_uid, &mut peer_gid) } != 0
        || peer_uid != uid
        || peer_gid != gid
    {
        return Err(TrustError::PeerIdentity);
    }

    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&token as *const AuditToken).cast::<u8>(),
            size_of::<AuditToken>(),
        )
    };
    let data = CFData::from_buffer(bytes);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(data.as_concrete_TypeRef());
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| TrustError::CodeSignature)?;
    check_code(&code, role)?;
    let code_path = code
        .path(Flags::NONE)
        .map_err(|_| TrustError::CodeSignature)?
        .to_path()
        .ok_or(TrustError::CodeSignature)?;
    let code_path = static_role_path(&code_path, role)?;
    verify_path(&code_path, role)?;
    Ok(VerifiedPeer {
        pid,
        uid,
        gid,
        code_path,
    })
}

pub fn verify_self(role: CodeRole) -> Result<PathBuf, TrustError> {
    let code = SecCode::for_self(Flags::NONE).map_err(|_| TrustError::CodeSignature)?;
    check_code(&code, role)?;
    let path = code
        .path(Flags::NONE)
        .map_err(|_| TrustError::CodeSignature)?
        .to_path()
        .ok_or(TrustError::CodeSignature)?;
    let path = static_role_path(&path, role)?;
    verify_path(&path, role)?;
    Ok(path)
}

pub fn verify_path(path: &std::path::Path, role: CodeRole) -> Result<(), TrustError> {
    let url = core_foundation::url::CFURL::from_path(path, path.is_dir())
        .ok_or(TrustError::CodeSignature)?;
    let code =
        SecStaticCode::from_path(&url, Flags::NONE).map_err(|_| TrustError::CodeSignature)?;
    let requirement: SecRequirement = requirement(role)?
        .parse()
        .map_err(|_| TrustError::InvalidConfiguration)?;
    code.check_validity(validation_flags(), &requirement)
        .map_err(|_| TrustError::CodeSignature)
}

fn check_code(code: &SecCode, role: CodeRole) -> Result<(), TrustError> {
    let requirement: SecRequirement = requirement(role)?
        .parse()
        .map_err(|_| TrustError::InvalidConfiguration)?;
    code.check_validity(validation_flags(), &requirement)
        .map_err(|_| TrustError::CodeSignature)
}

fn validation_flags() -> Flags {
    Flags::STRICT_VALIDATE | Flags::CHECK_ALL_ARCHITECTURES | Flags::CHECK_NESTED_CODE
}

fn static_role_path(path: &std::path::Path, role: CodeRole) -> Result<PathBuf, TrustError> {
    match role {
        CodeRole::App => path
            .ancestors()
            .find(|candidate| candidate.extension() == Some(std::ffi::OsStr::new("app")))
            .map(std::path::Path::to_path_buf)
            .ok_or(TrustError::CodeSignature),
        CodeRole::Helper => Ok(path.to_path_buf()),
    }
}

fn requirement(role: CodeRole) -> Result<String, TrustError> {
    let identifier = match role {
        CodeRole::App => APP_IDENTIFIER,
        CodeRole::Helper => HELPER_IDENTIFIER,
    };
    Ok(format!(
        "anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{}\"",
        team_id().ok_or(TrustError::InvalidConfiguration)?
    ))
}

fn team_id() -> Option<&'static str> {
    option_env!("LUXURY_APPLE_TEAM_ID").filter(|value| {
        value.len() == 10
            && value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

fn peer_audit_token(socket: BorrowedFd<'_>) -> Result<AuditToken, TrustError> {
    let mut token = AuditToken { value: [0; 8] };
    let mut length = size_of::<AuditToken>() as libc::socklen_t;
    // SAFETY: the connected local socket is live; token and length expose exact writable sizes.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            (&mut token as *mut AuditToken).cast::<c_void>(),
            &mut length,
        )
    } != 0
        || length as usize != size_of::<AuditToken>()
    {
        return Err(TrustError::PeerIdentity);
    }
    Ok(token)
}

unsafe extern "C" {
    fn getpeereid(socket: libc::c_int, uid: *mut libc::uid_t, gid: *mut libc::gid_t)
    -> libc::c_int;
}
