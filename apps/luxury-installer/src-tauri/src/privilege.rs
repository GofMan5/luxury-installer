#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos;
#[cfg(windows)]
mod windows;

use std::{
    io,
    sync::{Arc, atomic::AtomicBool, mpsc, mpsc::Receiver},
};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::backend::{BackendError, BackendEvent, MAX_SAFE_INTEGER, OperationMessage};

const SYSTEM_PROTOCOL_VERSION: u8 = 2;

struct SystemPreparation(Value);

impl Default for SystemPreparation {
    fn default() -> Self {
        Self(Value::Null)
    }
}

impl<'de> Deserialize<'de> for SystemPreparation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Value::deserialize(deserializer).map(Self)
    }
}

pub(crate) struct SystemOperation {
    pub(crate) operation_id: String,
    receiver: Receiver<OperationMessage>,
    cancel: Arc<AtomicBool>,
}

impl SystemOperation {
    pub(crate) fn recv(&self) -> Result<OperationMessage, BackendError> {
        self.receiver.recv().map_err(|_| {
            BackendError::new("backend_unavailable", "system operation channel closed")
        })
    }

    pub(crate) fn cancellation(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum SystemOperationFrame {
    #[serde(rename = "installPhase")]
    Phase {
        protocol_version: u8,
        operation_id: String,
        phase: crate::backend::InstallPhase,
    },
    #[serde(rename = "installAction")]
    Action {
        protocol_version: u8,
        operation_id: String,
        action: crate::backend::InstallResultAction,
    },
    #[serde(rename = "installProgress")]
    Progress {
        protocol_version: u8,
        operation_id: String,
        completed_files: u64,
        total_files: u64,
        completed_bytes: u64,
        total_bytes: u64,
    },
    #[serde(rename = "installComplete")]
    Complete {
        protocol_version: u8,
        operation_id: String,
        action: crate::backend::InstallResultAction,
        package_id: String,
        install_directory: String,
        installed_files: u64,
        installed_bytes: u64,
        #[serde(default)]
        system_preparation: SystemPreparation,
    },
    #[serde(rename = "installFailed")]
    Failed {
        protocol_version: u8,
        operation_id: String,
        code: String,
    },
    #[serde(rename = "uninstallPhase")]
    UninstallPhase {
        protocol_version: u8,
        operation_id: String,
        phase: crate::backend::UninstallPhase,
    },
    #[serde(rename = "uninstallProgress")]
    UninstallProgress {
        protocol_version: u8,
        operation_id: String,
        processed_files: u64,
        total_files: u64,
    },
    #[serde(rename = "uninstallComplete")]
    UninstallComplete {
        protocol_version: u8,
        operation_id: String,
        status: String,
        package_id: String,
        removed_files: u64,
        missing_files: u64,
        preserved_modified_files: u64,
        #[serde(default)]
        system_preparation: SystemPreparation,
    },
    #[serde(rename = "uninstallFailed")]
    UninstallFailed {
        protocol_version: u8,
        operation_id: String,
        code: String,
    },
    #[serde(rename = "launchComplete")]
    LaunchComplete {
        protocol_version: u8,
        operation_id: String,
        status: String,
        package_id: String,
    },
    #[serde(rename = "launchFailed")]
    LaunchFailed {
        protocol_version: u8,
        operation_id: String,
        code: String,
    },
}

fn forward_system_operation_frame(
    frame: SystemOperationFrame,
    expected_action: &str,
    expected_operation_id: &str,
    expected_package_id: &str,
    sender: &mpsc::Sender<OperationMessage>,
) -> io::Result<Option<OperationMessage>> {
    if system_frame_action(&frame) != expected_action {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system helper returned a frame for another action",
        ));
    }
    match frame {
        SystemOperationFrame::Phase {
            protocol_version,
            operation_id,
            phase,
        } => {
            require_system_frame(protocol_version, &operation_id, expected_operation_id)?;
            send_operation(
                sender,
                OperationMessage::Event(BackendEvent::InstallPhase {
                    operation_id,
                    phase,
                }),
            )?;
            Ok(None)
        }
        SystemOperationFrame::Action {
            protocol_version,
            operation_id,
            action,
        } => {
            require_system_frame(protocol_version, &operation_id, expected_operation_id)?;
            send_operation(
                sender,
                OperationMessage::Event(BackendEvent::Action {
                    operation_id,
                    action,
                }),
            )?;
            Ok(None)
        }
        SystemOperationFrame::Progress {
            protocol_version,
            operation_id,
            completed_files,
            total_files,
            completed_bytes,
            total_bytes,
        } => {
            require_system_frame(protocol_version, &operation_id, expected_operation_id)?;
            if completed_files > total_files
                || completed_bytes > total_bytes
                || [completed_files, total_files, completed_bytes, total_bytes]
                    .into_iter()
                    .any(|value| value > MAX_SAFE_INTEGER)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "system install progress exceeded its bounds",
                ));
            }
            send_operation(
                sender,
                OperationMessage::Event(BackendEvent::Progress {
                    operation_id,
                    completed_files,
                    total_files,
                    completed_bytes,
                    total_bytes,
                }),
            )?;
            Ok(None)
        }
        SystemOperationFrame::Complete {
            protocol_version,
            operation_id,
            action,
            package_id,
            install_directory,
            installed_files,
            installed_bytes,
            system_preparation,
        } => {
            require_system_frame(protocol_version, &operation_id, expected_operation_id)?;
            if package_id != expected_package_id
                || installed_files > MAX_SAFE_INTEGER
                || installed_bytes > MAX_SAFE_INTEGER
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "system install completion did not match the reviewed package",
                ));
            }
            Ok(Some(OperationMessage::Complete(Ok(json!({
                "action": action,
                "packageId": package_id,
                "installedFiles": installed_files,
                "installedBytes": installed_bytes,
                "installDirectory": install_directory,
                "systemPreparation": system_preparation.0,
            })))))
        }
        SystemOperationFrame::Failed {
            protocol_version,
            operation_id,
            code,
        } => {
            require_system_frame(protocol_version, &operation_id, expected_operation_id)?;
            require_error_code(&code, "system install")?;
            Ok(Some(OperationMessage::Complete(Err(BackendError::new(
                code,
                "system install failed",
            )))))
        }
        SystemOperationFrame::UninstallPhase {
            protocol_version,
            operation_id,
            phase,
        } => {
            require_system_frame(protocol_version, &operation_id, expected_operation_id)?;
            send_operation(
                sender,
                OperationMessage::Event(BackendEvent::UninstallPhase {
                    operation_id,
                    phase,
                }),
            )?;
            Ok(None)
        }
        SystemOperationFrame::UninstallProgress {
            protocol_version,
            operation_id,
            processed_files,
            total_files,
        } => {
            require_system_frame(protocol_version, &operation_id, expected_operation_id)?;
            if processed_files > total_files || total_files > MAX_SAFE_INTEGER {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "system uninstall progress exceeded its bounds",
                ));
            }
            send_operation(
                sender,
                OperationMessage::Event(BackendEvent::Progress {
                    operation_id,
                    completed_files: processed_files,
                    total_files,
                    completed_bytes: 0,
                    total_bytes: 0,
                }),
            )?;
            Ok(None)
        }
        SystemOperationFrame::UninstallComplete {
            protocol_version,
            operation_id,
            status,
            package_id,
            removed_files,
            missing_files,
            preserved_modified_files,
            system_preparation,
        } => {
            require_system_frame(protocol_version, &operation_id, expected_operation_id)?;
            if package_id != expected_package_id
                || [removed_files, missing_files, preserved_modified_files]
                    .into_iter()
                    .any(|value| value > MAX_SAFE_INTEGER)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "system uninstall completion did not match the reviewed package",
                ));
            }
            let result = match status.as_str() {
                "notInstalled"
                    if removed_files == 0
                        && missing_files == 0
                        && preserved_modified_files == 0 =>
                {
                    json!({
                        "status": "notInstalled",
                        "packageId": package_id,
                        "systemPreparation": system_preparation.0,
                    })
                }
                "uninstalled" => json!({
                    "status": "uninstalled",
                    "packageId": package_id,
                    "removedFiles": removed_files,
                    "missingFiles": missing_files,
                    "preservedModifiedFiles": preserved_modified_files,
                    "systemPreparation": system_preparation.0,
                }),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "system uninstall returned an invalid terminal status",
                    ));
                }
            };
            Ok(Some(OperationMessage::Complete(Ok(result))))
        }
        SystemOperationFrame::UninstallFailed {
            protocol_version,
            operation_id,
            code,
        } => {
            require_system_frame(protocol_version, &operation_id, expected_operation_id)?;
            require_error_code(&code, "system uninstall")?;
            Ok(Some(OperationMessage::Complete(Err(BackendError::new(
                code,
                "system uninstall failed",
            )))))
        }
        SystemOperationFrame::LaunchComplete {
            protocol_version,
            operation_id,
            status,
            package_id,
        } => {
            require_system_frame(protocol_version, &operation_id, expected_operation_id)?;
            if status != "launched" || package_id != expected_package_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "system launch completion did not match the reviewed package",
                ));
            }
            Ok(Some(OperationMessage::Complete(Ok(json!({
                "status": "launched",
                "packageId": package_id,
            })))))
        }
        SystemOperationFrame::LaunchFailed {
            protocol_version,
            operation_id,
            code,
        } => {
            require_system_frame(protocol_version, &operation_id, expected_operation_id)?;
            require_error_code(&code, "system launch")?;
            Ok(Some(OperationMessage::Complete(Err(BackendError::new(
                code,
                "system launch failed",
            )))))
        }
    }
}

const fn system_frame_action(frame: &SystemOperationFrame) -> &'static str {
    match frame {
        SystemOperationFrame::Phase { .. }
        | SystemOperationFrame::Action { .. }
        | SystemOperationFrame::Progress { .. }
        | SystemOperationFrame::Complete { .. }
        | SystemOperationFrame::Failed { .. } => "install",
        SystemOperationFrame::UninstallPhase { .. }
        | SystemOperationFrame::UninstallProgress { .. }
        | SystemOperationFrame::UninstallComplete { .. }
        | SystemOperationFrame::UninstallFailed { .. } => "uninstall",
        SystemOperationFrame::LaunchComplete { .. } | SystemOperationFrame::LaunchFailed { .. } => {
            "launch"
        }
    }
}

fn require_error_code(code: &str, action: &str) -> io::Result<()> {
    if !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{action} returned an invalid error code"),
        ))
    }
}

fn require_system_frame(found: u8, operation_id: &str, expected: &str) -> io::Result<()> {
    if found == SYSTEM_PROTOCOL_VERSION && operation_id == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system frame was not bound to this operation",
        ))
    }
}

fn send_operation(
    sender: &mpsc::Sender<OperationMessage>,
    message: OperationMessage,
) -> io::Result<()> {
    sender.send(message).map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "system operation receiver was closed",
        )
    })
}
#[cfg(windows)]
pub(crate) fn is_elevated() -> std::io::Result<bool> {
    windows::is_elevated()
}

#[cfg(windows)]
pub(crate) fn verify_backend_transport(path: &std::path::Path) -> std::io::Result<()> {
    windows::verify_backend_transport(path)
}

#[cfg(windows)]
pub(crate) fn verify_elevated_backend_transport(path: &std::path::Path) -> std::io::Result<()> {
    windows::verify_elevated_backend_transport(path)
}

#[cfg(windows)]
pub(crate) fn verify_authenticated_backend_transport(
    path: &std::path::Path,
) -> std::io::Result<()> {
    windows::verify_authenticated_backend_transport(path)
}

#[cfg(windows)]
pub(crate) fn verify_container_parent() -> std::io::Result<()> {
    windows::verify_container_parent()
}

#[cfg(windows)]
pub(crate) fn authorize_system_install(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
) -> std::io::Result<crate::backend::PrepareInstallResult> {
    windows::authorize_system_install(executable, package, package_id, package_fingerprint)
}

#[cfg(windows)]
pub(crate) fn start_system_install(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
    allow_unsigned: bool,
    accept_license: bool,
    allow_publisher_migration: bool,
) -> std::io::Result<SystemOperation> {
    windows::start_system_install(
        executable,
        package,
        package_id,
        package_fingerprint,
        allow_unsigned,
        accept_license,
        allow_publisher_migration,
    )
}

#[cfg(windows)]
pub(crate) fn start_system_uninstall(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
) -> std::io::Result<SystemOperation> {
    windows::start_system_uninstall(executable, package, package_id, package_fingerprint)
}

#[cfg(windows)]
pub(crate) fn start_system_launch(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
) -> std::io::Result<SystemOperation> {
    windows::start_system_launch(executable, package, package_id, package_fingerprint)
}

pub(crate) const fn desktop_runtime_allowed(elevated: bool, verify_requested: bool) -> bool {
    verify_requested || !elevated
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn is_elevated() -> std::io::Result<bool> {
    Ok(rustix::process::geteuid().is_root())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn verify_backend_transport(_: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn verify_elevated_backend_transport(_: &std::path::Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "elevated transport verification is supported only on Windows",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn verify_authenticated_backend_transport(_: &std::path::Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "authenticated transport verification is supported only on Windows",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn verify_container_parent() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "container parent verification is supported only on Windows",
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn authorize_system_install(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
) -> std::io::Result<crate::backend::PrepareInstallResult> {
    linux::authorize_system_install(executable, package, package_id, package_fingerprint)
}

#[cfg(target_os = "linux")]
pub(crate) fn start_system_install(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
    allow_unsigned: bool,
    accept_license: bool,
    allow_publisher_migration: bool,
) -> std::io::Result<SystemOperation> {
    linux::start_system_install(
        executable,
        package,
        package_id,
        package_fingerprint,
        allow_unsigned,
        accept_license,
        allow_publisher_migration,
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn start_system_uninstall(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
) -> std::io::Result<SystemOperation> {
    linux::start_system_uninstall(executable, package, package_id, package_fingerprint)
}

#[cfg(target_os = "linux")]
pub(crate) fn start_system_launch(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
) -> std::io::Result<SystemOperation> {
    linux::start_system_launch(executable, package, package_id, package_fingerprint)
}

#[cfg(target_os = "macos")]
pub(crate) fn authorize_system_install(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
) -> std::io::Result<crate::backend::PrepareInstallResult> {
    macos::authorize_system_install(executable, package, package_id, package_fingerprint)
}

#[cfg(target_os = "macos")]
pub(crate) fn start_system_install(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
    allow_unsigned: bool,
    accept_license: bool,
    allow_publisher_migration: bool,
) -> std::io::Result<SystemOperation> {
    macos::start_system_install(
        executable,
        package,
        package_id,
        package_fingerprint,
        allow_unsigned,
        accept_license,
        allow_publisher_migration,
    )
}

#[cfg(target_os = "macos")]
pub(crate) fn start_system_uninstall(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
) -> std::io::Result<SystemOperation> {
    macos::start_system_uninstall(executable, package, package_id, package_fingerprint)
}

#[cfg(target_os = "macos")]
pub(crate) fn start_system_launch(
    executable: &std::path::Path,
    package: &std::path::Path,
    package_id: &str,
    package_fingerprint: &str,
) -> std::io::Result<SystemOperation> {
    macos::start_system_launch(executable, package, package_id, package_fingerprint)
}

#[cfg(test)]
mod tests {
    use super::{desktop_runtime_allowed, is_elevated};

    #[test]
    fn desktop_runtime_never_runs_elevated_but_headless_verification_can() {
        assert!(desktop_runtime_allowed(false, false));
        assert!(!desktop_runtime_allowed(true, false));
        assert!(desktop_runtime_allowed(false, true));
        assert!(desktop_runtime_allowed(true, true));
    }

    #[test]
    fn current_process_privilege_probe_is_available() {
        is_elevated().unwrap();
    }
}
