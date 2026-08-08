use std::{
    ffi::{OsString, c_void},
    fs::{File, OpenOptions},
    io,
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr::{null, null_mut},
    slice,
};

use luxury_spec::InstallScope;
use windows_sys::{
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
            },
            CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, DuplicateTokenEx, GetAce,
            GetAclInformation, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            GetSecurityDescriptorOwner, GetTokenInformation, INHERITED_ACE, IsValidSid,
            OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
            SecurityImpersonation, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION,
            TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenPrimary, TokenUser,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, DELETE, FILE_ADD_FILE,
            FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
            FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_ID_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FileDispositionInfoEx, FileIdInfo, GetDiskFreeSpaceExW, GetDiskFreeSpaceW,
            GetFileInformationByHandle, GetFileInformationByHandleEx, GetVolumePathNameW,
            MOVEFILE_WRITE_THROUGH, MoveFileExW, READ_CONTROL, SetFileInformationByHandle,
            WRITE_DAC, WRITE_OWNER,
        },
        System::{
            Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
            Threading::{
                CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithTokenW,
                GetCurrentProcess, LOGON_WITH_PROFILE, OpenProcessToken, PROCESS_INFORMATION,
                STARTUPINFOW, TerminateProcess, WaitForSingleObject,
            },
        },
    },
    core::PWSTR,
};

const MAX_WIDE_PATH_UNITS: usize = 32_768;
const MAX_SID_STRING_UNITS: usize = 256;

struct LocalAllocation(*mut c_void);

impl LocalAllocation {
    fn new(pointer: *mut c_void, label: &str) -> io::Result<Self> {
        if pointer.is_null() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Windows returned a null {label}"),
            ))
        } else {
            Ok(Self(pointer))
        }
    }
}

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: this wrapper is constructed only for memory returned by LocalAlloc-family APIs.
        unsafe {
            LocalFree(self.0 as HLOCAL);
        }
    }
}

struct EnvironmentBlock(*mut c_void);

impl Drop for EnvironmentBlock {
    fn drop(&mut self) {
        // SAFETY: this pointer is returned by CreateEnvironmentBlock and remains owned here.
        unsafe {
            DestroyEnvironmentBlock(self.0);
        }
    }
}

struct SecurityDescriptor {
    allocation: LocalAllocation,
    dacl: *mut ACL,
    owner: PSID,
}

pub(super) fn require_private_authority(scope: InstallScope) -> io::Result<()> {
    if scope == InstallScope::System && !current_token_is_elevated()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "system-private state requires an elevated Windows token",
        ));
    }
    Ok(())
}

pub(super) fn create_private_directory(path: &Path, scope: InstallScope) -> io::Result<()> {
    require_private_authority(scope)?;
    let (path, _parent_guards) = open_real_parent_chain(path)?;
    let descriptor = private_security_descriptor(scope, true)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.allocation.0,
        bInheritHandle: 0,
    };
    let path = extended_wide_path(&path)?;
    // SAFETY: the path is NUL-terminated and the descriptor outlives this synchronous call.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn set_private_directory(path: &Path, scope: InstallScope) -> io::Result<()> {
    set_private_security(path, true, scope)
}

pub(super) fn set_private_file(path: &Path, scope: InstallScope) -> io::Result<()> {
    set_private_security(path, false, scope)
}

pub(super) fn validate_private_directory(path: &Path, scope: InstallScope) -> io::Result<()> {
    validate_private_security(path, true, scope)
}

pub(super) fn validate_private_file(path: &Path, scope: InstallScope) -> io::Result<()> {
    validate_private_security(path, false, scope)
}

fn validate_private_security(path: &Path, directory: bool, scope: InstallScope) -> io::Result<()> {
    require_private_authority(scope)?;
    let user = current_user_sid_string()?;
    let file = open_acl_target(path, directory, false, scope, false)?;
    validate_trusted_owner(&file, scope, &user)?;
    validate_private_dacl(&file, scope, directory, &user)
}

fn set_private_security(path: &Path, directory: bool, scope: InstallScope) -> io::Result<()> {
    require_private_authority(scope)?;
    let user = current_user_sid_string()?;
    let descriptor = private_security_descriptor_for_scope(scope, directory, &user)?;
    let file = open_security_target(path, directory, scope)?;
    validate_trusted_owner(&file, scope, &user)?;
    apply_security(&file, &descriptor, scope)
}

fn open_security_target(path: &Path, directory: bool, scope: InstallScope) -> io::Result<File> {
    open_acl_target(path, directory, true, scope, true)
}

fn open_acl_target(
    path: &Path,
    directory: bool,
    require_unique_file: bool,
    scope: InstallScope,
    write: bool,
) -> io::Result<File> {
    let (path, _parent_guards) = open_real_parent_chain(path)?;
    let mut options = OpenOptions::new();
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let file = options
        .access_mode(
            READ_CONTROL
                | if write { WRITE_DAC } else { 0 }
                | if write && scope == InstallScope::System {
                    WRITE_OWNER
                } else {
                    0
                },
        )
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(flags)
        .open(path)?;
    let information = file_information(&file)?;
    let attributes = information.dwFileAttributes;
    let found_directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || found_directory != directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private ACL target changed type or is a reparse point",
        ));
    }
    if !directory && require_unique_file && information.nNumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private ACL target has multiple hard links",
        ));
    }
    Ok(file)
}

pub(super) fn open_real_parent_chain(path: &Path) -> io::Result<(PathBuf, Vec<File>)> {
    let absolute = absolute_local_path(path)?;
    let parent = absolute.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows filesystem path has no parent directory",
        )
    })?;
    let mut current = PathBuf::new();
    let mut guards = Vec::new();
    let mut rooted = false;
    for component in parent.components() {
        current.push(component.as_os_str());
        match component {
            Component::Prefix(_) => {}
            Component::RootDir => {
                rooted = true;
                guards.push(open_real_directory(&current)?);
            }
            Component::Normal(_) if rooted => {
                guards.push(open_real_directory(&current)?);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Windows filesystem path contains an unsupported component",
                ));
            }
        }
    }
    if !rooted {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows filesystem path is not rooted",
        ));
    }
    Ok((absolute, guards))
}

fn absolute_local_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let prefix = match absolute.components().next() {
        Some(Component::Prefix(prefix)) => prefix.kind(),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "filesystem path has no Windows prefix",
            ));
        }
    };
    if !matches!(
        prefix,
        Prefix::Disk(_) | Prefix::UNC(_, _) | Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _)
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows filesystem path uses a device namespace",
        ));
    }
    if absolute
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows filesystem path contains a parent component",
        ));
    }
    Ok(absolute)
}

fn apply_security(
    file: &File,
    descriptor: &SecurityDescriptor,
    scope: InstallScope,
) -> io::Result<()> {
    let information = DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION
        | if scope == InstallScope::System {
            OWNER_SECURITY_INFORMATION
        } else {
            0
        };
    // SAFETY: the file owns a valid handle and descriptor pointers remain alive for the call.
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            information,
            descriptor.owner,
            null_mut(),
            descriptor.dacl,
            null(),
        )
    };
    win32_result(result)
}

fn private_security_descriptor(
    scope: InstallScope,
    directory: bool,
) -> io::Result<SecurityDescriptor> {
    let user = current_user_sid_string()?;
    private_security_descriptor_for_scope(scope, directory, &user)
}

fn private_security_descriptor_for_scope(
    scope: InstallScope,
    directory: bool,
    user: &str,
) -> io::Result<SecurityDescriptor> {
    let descriptor = security_descriptor(&private_security_sddl(scope, directory, user))?;
    if scope == InstallScope::System && descriptor.owner.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system-private security descriptor has no owner",
        ));
    }
    Ok(descriptor)
}

fn private_security_sddl(scope: InstallScope, directory: bool, user: &str) -> String {
    let inheritance = if directory { "OICI" } else { "" };
    match scope {
        InstallScope::User => format!(
            "D:P(A;{inheritance};FA;;;{user})(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)"
        ),
        InstallScope::System => {
            format!("O:BAD:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)")
        }
    }
}

fn validate_trusted_owner(file: &File, scope: InstallScope, user: &str) -> io::Result<()> {
    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the file owns a valid READ_CONTROL handle and both requested outputs are writable.
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    win32_result(result)?;
    let _descriptor = LocalAllocation::new(descriptor, "owner security descriptor")?;
    // SAFETY: a successful GetSecurityInfo owner pointer aliases the live descriptor.
    if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private ACL target has an invalid owner SID",
        ));
    }
    let owner = sid_string(owner)?;
    if trusted_owner_sid(scope, &owner, user) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private ACL target is owned by an untrusted principal",
        ))
    }
}

fn validate_private_dacl(
    file: &File,
    scope: InstallScope,
    directory: bool,
    user: &str,
) -> io::Result<()> {
    let mut dacl = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the file owns a READ_CONTROL handle and both requested outputs are writable.
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    win32_result(result)?;
    let _descriptor = LocalAllocation::new(descriptor, "private DACL descriptor")?;
    if dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private state has a null DACL",
        ));
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: the descriptor is valid and both outputs are writable.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private state DACL is not protected",
        ));
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: the DACL is valid and `information` is writable for its declared size.
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut expected = match scope {
        InstallScope::User => vec![
            user.to_owned(),
            "S-1-5-18".to_owned(),
            "S-1-5-32-544".to_owned(),
        ],
        InstallScope::System => {
            vec!["S-1-5-18".to_owned(), "S-1-5-32-544".to_owned()]
        }
    };
    let expected_flags = if directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    if information.AceCount as usize != expected.len() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private state DACL has an unexpected ACE count",
        ));
    }
    for index in 0..information.AceCount {
        let mut raw_ace = null_mut();
        // SAFETY: the index is within the count returned by GetAclInformation.
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce returned a valid ACE pointer for the descriptor lifetime.
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Header.AceType != 0
            || usize::from(ace.Header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
            || ace.Mask != FILE_ALL_ACCESS
            || u32::from(ace.Header.AceFlags) != expected_flags
            || u32::from(ace.Header.AceFlags) & INHERITED_ACE != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private state DACL contains an unexpected ACE",
            ));
        }
        let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
        // SAFETY: the SID starts at SidStart in an ACCESS_ALLOWED_ACE.
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private state DACL contains an invalid SID",
            ));
        }
        let sid = sid_string(sid)?;
        let position = expected.iter().position(|candidate| candidate == &sid);
        let Some(position) = position else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private state DACL contains an unexpected principal",
            ));
        };
        expected.swap_remove(position);
    }
    if !expected.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private state DACL is missing a required principal",
        ));
    }
    Ok(())
}

fn trusted_owner_sid(scope: InstallScope, owner: &str, user: &str) -> bool {
    owner == "S-1-5-18" || owner == "S-1-5-32-544" || (scope == InstallScope::User && owner == user)
}

fn security_descriptor(sddl: &str) -> io::Result<SecurityDescriptor> {
    let mut sddl = sddl.encode_utf16().collect::<Vec<_>>();
    sddl.push(0);
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let mut descriptor_size = 0_u32;
    // SAFETY: the SDDL is NUL-terminated and both output pointers are writable.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut descriptor_size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let allocation = LocalAllocation::new(descriptor, "security descriptor")?;
    let mut dacl = null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    // SAFETY: the descriptor is valid and every output points to writable storage.
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private security descriptor has no DACL",
        ));
    }
    let mut owner = null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: the descriptor is valid and both owner outputs are writable.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(SecurityDescriptor {
        allocation,
        dacl,
        owner,
    })
}

fn current_token_is_elevated() -> io::Result<bool> {
    let mut raw_token: HANDLE = null_mut();
    // SAFETY: the current-process pseudo handle is valid and `raw_token` is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned an owned real handle on success.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    token_is_elevated(token.as_raw_handle() as HANDLE)
}

fn token_is_elevated(token: HANDLE) -> io::Result<bool> {
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0_u32;
    // SAFETY: the output is writable for its exact size and the token remains open.
    if unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned != size_of::<TOKEN_ELEVATION>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned malformed token elevation data",
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
}

pub(super) fn launch_with_process_token(
    parent_process: BorrowedHandle<'_>,
    executable: &Path,
    current_directory: &Path,
) -> io::Result<()> {
    let mut raw_parent_token: HANDLE = null_mut();
    // SAFETY: the authenticated parent process handle is live and the output is writable.
    if unsafe {
        OpenProcessToken(
            parent_process.as_raw_handle() as HANDLE,
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut raw_parent_token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned one owned token handle.
    let parent_token = unsafe { OwnedHandle::from_raw_handle(raw_parent_token) };
    if token_is_elevated(parent_token.as_raw_handle() as HANDLE)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "interactive parent token is elevated",
        ));
    }

    let mut raw_primary_token: HANDLE = null_mut();
    // SAFETY: the source token is live, optional attributes are null, and output is writable.
    if unsafe {
        DuplicateTokenEx(
            parent_token.as_raw_handle() as HANDLE,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut raw_primary_token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: DuplicateTokenEx returned one owned primary token handle.
    let primary_token = unsafe { OwnedHandle::from_raw_handle(raw_primary_token) };
    if token_is_elevated(primary_token.as_raw_handle() as HANDLE)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "duplicated interactive token is elevated",
        ));
    }

    let mut raw_environment = null_mut();
    // SAFETY: the token is live and `raw_environment` is writable.
    if unsafe {
        CreateEnvironmentBlock(
            &mut raw_environment,
            primary_token.as_raw_handle() as HANDLE,
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if raw_environment.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an empty user environment block",
        ));
    }
    let environment = EnvironmentBlock(raw_environment);
    let application = extended_wide_path(executable)?;
    let current_directory = extended_wide_path(current_directory)?;
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: all path/environment/startup pointers remain valid for the synchronous call.
    if unsafe {
        CreateProcessWithTokenW(
            primary_token.as_raw_handle() as HANDLE,
            LOGON_WITH_PROFILE,
            application.as_ptr(),
            null_mut(),
            CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP,
            environment.0,
            current_directory.as_ptr(),
            &startup,
            &mut process,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if process.hProcess.is_null() || process.hThread.is_null() {
        if !process.hProcess.is_null() {
            terminate_process_and_wait(process.hProcess);
            // SAFETY: CreateProcessWithTokenW returned this owned process handle.
            drop(unsafe { OwnedHandle::from_raw_handle(process.hProcess) });
        }
        if !process.hThread.is_null() {
            // SAFETY: CreateProcessWithTokenW returned this owned thread handle.
            drop(unsafe { OwnedHandle::from_raw_handle(process.hThread) });
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned incomplete launched-process handles",
        ));
    }
    // SAFETY: CreateProcessWithTokenW returned two owned handles.
    let launched_process = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
    // SAFETY: CreateProcessWithTokenW returned one owned primary-thread handle.
    let launched_thread = unsafe { OwnedHandle::from_raw_handle(process.hThread) };
    drop(launched_thread);
    drop(launched_process);
    Ok(())
}

fn terminate_process_and_wait(process: HANDLE) {
    // SAFETY: the handle is a live process returned by CreateProcessWithTokenW.
    unsafe {
        TerminateProcess(process, 1);
        let _ = WaitForSingleObject(process, 15_000);
    }
}

fn current_user_sid_string() -> io::Result<String> {
    let mut raw_token: HANDLE = null_mut();
    // SAFETY: the pseudo-process handle is valid and `raw_token` is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned an owned real handle on success.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut required = 0_u32;
    // SAFETY: a null buffer with zero length is the documented size-query form.
    let queried = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            null_mut(),
            0,
            &mut required,
        )
    };
    if queried != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || required < size_of::<TOKEN_USER>() as u32
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid TokenUser size",
        ));
    }
    let required = usize::try_from(required)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "TokenUser size overflow"))?;
    let mut buffer = vec![0_usize; required.div_ceil(size_of::<usize>())];
    let buffer_bytes = u32::try_from(buffer.len() * size_of::<usize>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "TokenUser buffer overflow"))?;
    let mut returned = 0_u32;
    // SAFETY: the aligned buffer is writable for `buffer_bytes` and the token remains open.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            buffer_bytes,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned < size_of::<TOKEN_USER>() as u32 || returned > buffer_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned malformed TokenUser data",
        ));
    }
    // SAFETY: GetTokenInformation initialized an aligned TOKEN_USER at the buffer start.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    // SAFETY: the SID pointer belongs to the live TokenUser buffer.
    if user.User.Sid.is_null() || unsafe { IsValidSid(user.User.Sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid user SID",
        ));
    }
    sid_string(user.User.Sid)
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text: PWSTR = null_mut();
    // SAFETY: the SID is valid for the call and `text` is writable.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalAllocation::new(text.cast(), "SID string")?;
    for length in 0..MAX_SID_STRING_UNITS {
        // SAFETY: ConvertSidToStringSidW returned a NUL-terminated LocalAlloc string.
        if unsafe { *text.add(length) } == 0 {
            // SAFETY: the preceding loop established a readable terminator within the bound.
            let units = unsafe { slice::from_raw_parts(text, length) };
            return String::from_utf16(units).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "user SID is not valid UTF-16")
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Windows returned an unterminated SID string",
    ))
}

fn win32_result(result: u32) -> io::Result<()> {
    if result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}

pub(super) fn open_nofollow(options: &mut OpenOptions, path: &Path) -> io::Result<File> {
    options
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

pub(super) fn open_sync_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

pub(super) fn open_movable_sync_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

pub(super) fn open_pinned_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

pub(super) fn open_launch_guards_nofollow(path: &Path) -> io::Result<(File, File)> {
    let write_guard = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let delete_guard = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    Ok((write_guard, delete_guard))
}

pub(super) fn number_of_links(file: &File) -> io::Result<u32> {
    Ok(file_information(file)?.nNumberOfLinks)
}

pub(super) fn directory_identity(path: &Path) -> io::Result<(u64, [u8; 16])> {
    let file = open_real_directory(path)?;
    file_identity(&file)
}

pub(super) fn volume_space(path: &Path) -> io::Result<(u64, u64, u64)> {
    let directory = open_real_directory(path)?;
    let (volume_id, _) = file_identity(&directory)?;
    let (volume_root, volume_root_wide) = volume_path(path)?;
    let volume_root_file = open_real_directory(&volume_root)?;
    if file_identity(&volume_root_file)?.0 != volume_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory volume changed while querying free space",
        ));
    }

    let mut available_bytes = 0_u64;
    let mut total_bytes = 0_u64;
    let mut total_free_bytes = 0_u64;
    // SAFETY: the volume path is NUL-terminated and each output points to writable storage.
    let free_space_ok = unsafe {
        GetDiskFreeSpaceExW(
            volume_root_wide.as_ptr(),
            &mut available_bytes,
            &mut total_bytes,
            &mut total_free_bytes,
        )
    };
    if free_space_ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if available_bytes > total_bytes || available_bytes > total_free_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "available volume bytes exceed reported capacity",
        ));
    }

    let mut sectors_per_cluster = 0_u32;
    let mut bytes_per_sector = 0_u32;
    let mut free_clusters = 0_u32;
    let mut total_clusters = 0_u32;
    // SAFETY: the volume path is NUL-terminated and each output points to writable storage.
    let geometry_ok = unsafe {
        GetDiskFreeSpaceW(
            volume_root_wide.as_ptr(),
            &mut sectors_per_cluster,
            &mut bytes_per_sector,
            &mut free_clusters,
            &mut total_clusters,
        )
    };
    if geometry_ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if sectors_per_cluster == 0
        || bytes_per_sector == 0
        || total_clusters == 0
        || free_clusters > total_clusters
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "volume returned an invalid allocation geometry",
        ));
    }
    let allocation_unit = u64::from(sectors_per_cluster)
        .checked_mul(u64::from(bytes_per_sector))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "volume allocation unit overflow",
            )
        })?;
    Ok((volume_id, available_bytes, allocation_unit))
}

fn open_real_directory(path: &Path) -> io::Result<File> {
    // Omitting FILE_SHARE_DELETE pins this component while the returned handle is alive.
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let attributes = file_information(&file)?.dwFileAttributes;
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "path is not a real directory",
        ));
    }
    Ok(file)
}

pub(super) fn check_directory_write_access(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .access_mode(FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let attributes = file_information(&file)?.dwFileAttributes;
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "path is not a real directory",
        ));
    }
    Ok(())
}

fn volume_path(path: &Path) -> io::Result<(PathBuf, Vec<u16>)> {
    let input = wide_path(path)?;
    let mut output = vec![0_u16; MAX_WIDE_PATH_UNITS];
    // SAFETY: input is NUL-terminated and output is writable for the declared length.
    let succeeded = unsafe {
        GetVolumePathNameW(
            input.as_ptr(),
            output.as_mut_ptr(),
            MAX_WIDE_PATH_UNITS as u32,
        )
    };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = output
        .iter()
        .position(|unit| *unit == 0)
        .filter(|end| *end > 0)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "volume path is not terminated")
        })?;
    let path = PathBuf::from(OsString::from_wide(&output[..end]));
    output.truncate(end + 1);
    Ok((path, output))
}

pub(super) fn file_identity(file: &File) -> io::Result<(u64, [u8; 16])> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: the file owns a valid handle and `information` is writable for its exact size.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    (succeeded != 0)
        .then_some((
            information.VolumeSerialNumber,
            information.FileId.Identifier,
        ))
        .ok_or_else(io::Error::last_os_error)
}

pub(super) fn open_delete_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .access_mode(FILE_GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

pub(super) fn delete_opened(file: File) -> io::Result<()> {
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: `file` owns a live DELETE-capable handle and `disposition` is readable for its
    // exact size. The handle remains owned until this synchronous call returns.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn file_information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file owns a valid handle and `information` is writable for the call.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) };
    if succeeded == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(information)
    }
}

pub(super) fn rename_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    let source = wide_path(source)?;
    let destination = wide_path(destination)?;
    // SAFETY: both buffers are NUL-terminated and remain alive for the call. Omitting
    // MOVEFILE_REPLACE_EXISTING makes an existing destination fail closed.
    let succeeded = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if succeeded == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn extended_wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let absolute = absolute_local_path(path)?;
    let mut path = absolute.as_os_str().encode_wide().collect::<Vec<_>>();
    if path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows paths cannot contain NUL",
        ));
    }
    for unit in &mut path {
        if *unit == b'/' as u16 {
            *unit = b'\\' as u16;
        }
    }

    const VERBATIM: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const DEVICE: &[u16] = &[b'\\' as u16, b'\\' as u16, b'.' as u16, b'\\' as u16];
    const UNC: &[u16] = &[b'\\' as u16, b'\\' as u16];
    let mut extended = if path.starts_with(VERBATIM) {
        path
    } else if path.starts_with(DEVICE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows device paths are not private filesystem paths",
        ));
    } else if path.starts_with(UNC) {
        let mut extended = VERBATIM.to_vec();
        extended.extend("UNC\\".encode_utf16());
        extended.extend_from_slice(&path[UNC.len()..]);
        extended
    } else {
        let mut extended = VERBATIM.to_vec();
        extended.extend(path);
        extended
    };
    if extended.len() >= MAX_WIDE_PATH_UNITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path exceeds the extended-length limit",
        ));
    }
    extended.push(0);
    Ok(extended)
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows paths cannot contain NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, io::Read, os::windows::fs::symlink_dir};

    use tempfile::tempdir;
    use windows_sys::Win32::{
        Security::{
            ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, AclSizeInformation, CONTAINER_INHERIT_ACE,
            GetAce, GetAclInformation, GetSecurityDescriptorControl, INHERITED_ACE,
            OBJECT_INHERIT_ACE, SE_DACL_PROTECTED,
        },
        Storage::FileSystem::FILE_ALL_ACCESS,
    };

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct AceSnapshot {
        sid: String,
        mask: u32,
        flags: u32,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct DaclSnapshot {
        protected: bool,
        aces: Vec<AceSnapshot>,
    }

    #[test]
    fn delete_opened_removes_verified_object_not_replacement_path() {
        let temp = tempdir().unwrap();
        let parent = temp.path().join("parent");
        let displaced = temp.path().join("displaced.bin");
        fs::create_dir(&parent).unwrap();
        let owned = parent.join("owned.bin");
        fs::write(&owned, b"owned").unwrap();
        let mut opened = open_delete_nofollow(&owned).unwrap();
        let mut verified = Vec::new();
        opened.read_to_end(&mut verified).unwrap();
        assert_eq!(verified, b"owned");

        fs::rename(&owned, &displaced).unwrap();
        let replacement = parent.join("owned.bin");
        fs::write(&replacement, b"foreign").unwrap();

        delete_opened(opened).unwrap();

        assert!(!displaced.exists());
        assert_eq!(fs::read(replacement).unwrap(), b"foreign");
    }

    #[test]
    fn live_temp_volume_reports_stable_identity_and_nonzero_allocation_unit() {
        let temp = tempdir().unwrap();
        let directory = fs::canonicalize(temp.path()).unwrap();
        let expected_volume = directory_identity(&directory).unwrap().0;

        let (volume_id, _available_bytes, allocation_unit) = volume_space(&directory).unwrap();

        assert_eq!(volume_id, expected_volume);
        assert!(allocation_unit > 0);
    }

    #[test]
    fn real_parent_chain_guards_deny_replacement_until_drop() {
        let temp = tempdir().unwrap();
        let parent = temp.path().join("parent");
        let moved = temp.path().join("moved");
        fs::create_dir(&parent).unwrap();
        let (_, guards) = open_real_parent_chain(&parent.join("entry.exe")).unwrap();

        assert!(fs::rename(&parent, &moved).is_err());
        drop(guards);
        fs::rename(&parent, &moved).unwrap();
        fs::rename(&moved, &parent).unwrap();
    }

    #[test]
    fn private_acl_replaces_broad_inheritance_and_propagates_only_the_allowlist() {
        let temp = tempdir().unwrap();
        let broad = security_descriptor("D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;BU)").unwrap();
        let parent = open_security_target(temp.path(), true, InstallScope::User).unwrap();
        apply_security(&parent, &broad, InstallScope::User).unwrap();
        validate_private_directory(temp.path(), InstallScope::User)
            .expect_err("a broad DACL must not be accepted as private state");

        let private = temp.path().join("private");
        create_private_directory(&private, InstallScope::User).unwrap();
        assert_explicit_private_acl(&private, true);
        validate_private_directory(&private, InstallScope::User).unwrap();

        let inherited_directory = private.join("inherited-directory");
        let inherited_file = private.join("inherited.bin");
        fs::create_dir(&inherited_directory).unwrap();
        fs::write(&inherited_file, b"private").unwrap();
        assert_safe_inherited_acl(&inherited_directory, true);
        assert_safe_inherited_acl(&inherited_file, false);
        validate_private_directory(&inherited_directory, InstallScope::User)
            .expect_err("an inherited DACL must not be accepted as explicit private state");

        set_private_directory(&inherited_directory, InstallScope::User).unwrap();
        set_private_file(&inherited_file, InstallScope::User).unwrap();
        assert_explicit_private_acl(&inherited_directory, true);
        assert_explicit_private_acl(&inherited_file, false);
        validate_private_directory(&inherited_directory, InstallScope::User).unwrap();
        validate_private_file(&inherited_file, InstallScope::User).unwrap();
    }

    #[test]
    fn private_acl_rejects_a_directory_symlink_without_touching_its_target() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("target");
        create_private_directory(&target, InstallScope::User).unwrap();
        let before = dacl_snapshot(&target, true).unwrap();
        let linked = temp.path().join("linked");
        if let Err(error) = symlink_dir(&target, &linked) {
            if error.raw_os_error() == Some(1314) {
                return;
            }
            panic!("creating directory symlink failed: {error}");
        }

        set_private_directory(&linked, InstallScope::User)
            .expect_err("a reparse point must be rejected");

        assert_eq!(dacl_snapshot(&target, true).unwrap(), before);
        assert!(linked.symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn private_acl_rejects_an_intermediate_directory_link() {
        let temp = tempdir().unwrap();
        let external = temp.path().join("external");
        let nested = external.join("nested");
        let root = temp.path().join("root");
        create_private_directory(&external, InstallScope::User).unwrap();
        create_private_directory(&nested, InstallScope::User).unwrap();
        create_private_directory(&root, InstallScope::User).unwrap();
        let broad = security_descriptor("D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;BU)").unwrap();
        let external_handle = open_security_target(&nested, true, InstallScope::User).unwrap();
        apply_security(&external_handle, &broad, InstallScope::User).unwrap();
        let before = dacl_snapshot(&nested, true).unwrap();
        let sentinel = nested.join("sentinel.bin");
        fs::write(&sentinel, b"external").unwrap();
        let linked = root.join("linked");
        if let Err(error) = symlink_dir(&external, &linked) {
            if error.raw_os_error() == Some(1314) {
                return;
            }
            panic!("creating intermediate directory symlink failed: {error}");
        }

        set_private_directory(&linked.join("nested"), InstallScope::User)
            .expect_err("an intermediate reparse point must be rejected");
        create_private_directory(&linked.join("created"), InstallScope::User)
            .expect_err("creation through a reparse point must be rejected");

        assert_eq!(dacl_snapshot(&nested, true).unwrap(), before);
        assert_eq!(fs::read(sentinel).unwrap(), b"external");
        assert!(!external.join("created").exists());
    }

    #[test]
    fn private_file_rejects_a_hard_link_without_changing_its_peer_acl() {
        let temp = tempdir().unwrap();
        let original = temp.path().join("original.bin");
        let alias = temp.path().join("alias.bin");
        fs::write(&original, b"private").unwrap();
        set_private_file(&original, InstallScope::User).unwrap();
        let before = dacl_snapshot(&original, false).unwrap();
        fs::hard_link(&original, &alias).unwrap();

        set_private_file(&alias, InstallScope::User)
            .expect_err("a multiply-linked private file must be rejected");

        assert_eq!(dacl_snapshot(&original, false).unwrap(), before);
        assert_eq!(dacl_snapshot(&alias, false).unwrap(), before);
        assert_eq!(fs::read(&original).unwrap(), b"private");
        assert_eq!(fs::read(&alias).unwrap(), b"private");
    }

    #[test]
    fn private_path_prefix_allowlist_rejects_device_namespaces() {
        for allowed in [
            r"C:\private",
            r"\\server\share\private",
            r"\\?\C:\private",
            r"\\?\UNC\server\share\private",
        ] {
            assert!(absolute_local_path(Path::new(allowed)).is_ok(), "{allowed}");
        }
        for denied in [
            r"\\.\PhysicalDrive0",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\private",
            r"\\?\PIPE\luxury-private",
        ] {
            assert!(absolute_local_path(Path::new(denied)).is_err(), "{denied}");
        }
    }

    #[test]
    fn private_owner_allowlist_rejects_broad_principals() {
        let user = current_user_sid_string().unwrap();
        assert!(trusted_owner_sid(InstallScope::User, &user, &user));
        assert!(trusted_owner_sid(InstallScope::User, "S-1-5-18", &user));
        assert!(trusted_owner_sid(
            InstallScope::System,
            "S-1-5-32-544",
            &user
        ));
        assert!(!trusted_owner_sid(InstallScope::System, &user, &user));
        assert!(!trusted_owner_sid(InstallScope::System, "S-1-1-0", &user));
        assert!(!trusted_owner_sid(
            InstallScope::System,
            "S-1-5-32-545",
            &user
        ));
    }

    #[test]
    fn system_private_descriptor_has_only_system_and_administrators() {
        let user = "S-1-5-21-1-2-3-1001";
        assert_eq!(
            private_security_sddl(InstallScope::System, true, user),
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        );
        assert_eq!(
            private_security_sddl(InstallScope::System, false, user),
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        );
        assert!(
            private_security_sddl(InstallScope::User, false, user).contains(user),
            "user-private state must retain its explicit user principal"
        );
    }

    #[test]
    fn private_directory_supports_an_extended_length_path() {
        let temp = tempdir().unwrap();
        let mut path = temp.path().to_path_buf();
        let mut index = 0_u32;
        while path.as_os_str().encode_wide().count() <= 280 {
            path.push(format!("private-segment-{index:04}"));
            create_private_directory(&path, InstallScope::User).unwrap();
            index += 1;
        }

        assert!(path.as_os_str().encode_wide().count() > 260);
        set_private_directory(&path, InstallScope::User).unwrap();
        assert_explicit_private_acl(&path, true);
    }

    fn assert_explicit_private_acl(path: &Path, directory: bool) {
        let snapshot = dacl_snapshot(path, directory).unwrap();
        assert!(snapshot.protected, "private DACL must be protected");
        assert_eq!(snapshot.aces.len(), 3);
        let inheritance = if directory {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        assert_allowlist(&snapshot.aces, inheritance, false);
    }

    fn assert_safe_inherited_acl(path: &Path, directory: bool) {
        let snapshot = dacl_snapshot(path, directory).unwrap();
        assert!(
            !snapshot.protected,
            "an inherited child is not explicitly protected"
        );
        assert_eq!(snapshot.aces.len(), 3);
        assert_allowlist(&snapshot.aces, 0, true);
    }

    fn assert_allowlist(aces: &[AceSnapshot], exact_flags: u32, inherited: bool) {
        let mut expected = BTreeSet::from([
            current_user_sid_string().unwrap(),
            "S-1-5-18".to_owned(),
            "S-1-5-32-544".to_owned(),
        ]);
        for ace in aces {
            assert_eq!(ace.mask, FILE_ALL_ACCESS);
            if inherited {
                assert_ne!(ace.flags & INHERITED_ACE, 0);
            } else {
                assert_eq!(ace.flags, exact_flags);
            }
            assert!(
                expected.remove(&ace.sid),
                "unexpected or duplicate SID {}",
                ace.sid
            );
        }
        assert!(
            expected.is_empty(),
            "missing private ACL principals: {expected:?}"
        );
    }

    fn dacl_snapshot(path: &Path, directory: bool) -> io::Result<DaclSnapshot> {
        let file = open_acl_target(path, directory, false, InstallScope::User, false)?;
        let mut dacl = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: the file owns a valid handle and both requested outputs are writable.
        let result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        win32_result(result)?;
        let _descriptor = LocalAllocation::new(descriptor, "queried security descriptor")?;
        if dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "queried security descriptor has a null DACL",
            ));
        }

        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: the descriptor is valid and both outputs are writable.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut information = ACL_SIZE_INFORMATION::default();
        // SAFETY: the DACL is valid and `information` is writable for its declared size.
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut aces = Vec::with_capacity(information.AceCount as usize);
        for index in 0..information.AceCount {
            let mut raw_ace = null_mut();
            // SAFETY: the index is within the count reported by GetAclInformation.
            if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: GetAce returned a valid ACE pointer for the lifetime of the descriptor.
            let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
            if ace.Header.AceType != 0
                || usize::from(ace.Header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "private DACL contains an unexpected ACE type",
                ));
            }
            let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
            // SAFETY: the SID begins at SidStart in an ACCESS_ALLOWED_ACE.
            if unsafe { IsValidSid(sid) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "private DACL contains an invalid SID",
                ));
            }
            aces.push(AceSnapshot {
                sid: sid_string(sid)?,
                mask: ace.Mask,
                flags: u32::from(ace.Header.AceFlags),
            });
        }
        Ok(DaclSnapshot {
            protected: control & SE_DACL_PROTECTED != 0,
            aces,
        })
    }
}
