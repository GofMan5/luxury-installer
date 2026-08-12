use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const PROTOCOL_VERSION: u64 = luxury_spec::JSONL_PROTOCOL_VERSION as u64;
pub(crate) const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_PUBLIC_URL_BYTES: usize = 2_048;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub(crate) enum BackendLine {
    #[serde(rename = "result")]
    Result {
        #[serde(rename = "protocolVersion")]
        protocol_version: u64,
        id: String,
        result: Value,
    },
    #[serde(rename = "error")]
    Error {
        #[serde(rename = "protocolVersion")]
        protocol_version: u64,
        id: Option<String>,
        error: ErrorPayload,
    },
    #[serde(rename = "event")]
    Event {
        #[serde(rename = "protocolVersion")]
        protocol_version: u64,
        id: String,
        event: String,
        data: Value,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErrorPayload {
    pub(crate) code: String,
    pub(crate) message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BackendRequest<'a> {
    pub(crate) protocol_version: u64,
    pub(crate) id: &'a str,
    pub(crate) method: &'a str,
    pub(crate) params: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OperationKind {
    Install,
    Uninstall,
}

#[derive(Clone, Debug)]
pub(crate) enum BackendEvent {
    Action {
        operation_id: String,
        action: InstallResultAction,
    },
    InstallPhase {
        operation_id: String,
        phase: InstallPhase,
    },
    UninstallPhase {
        operation_id: String,
        phase: UninstallPhase,
    },
    Progress {
        operation_id: String,
        completed_files: u64,
        total_files: u64,
        completed_bytes: u64,
        total_bytes: u64,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum InstallResultAction {
    Install,
    Update,
    Repair,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum InstallPhase {
    Validating,
    Recovering,
    Verifying,
    Planning,
    Applying,
    Committing,
    RollingBack,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum UninstallPhase {
    Recovering,
    LoadingReceipt,
    Removing,
    Committing,
    RollingBack,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionData {
    action: InstallResultAction,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallPhaseData {
    phase: InstallPhase,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UninstallPhaseData {
    phase: UninstallPhase,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProgressData {
    completed_files: u64,
    total_files: u64,
    completed_bytes: u64,
    total_bytes: u64,
}

pub(crate) fn parse_event(
    kind: OperationKind,
    operation_id: String,
    event: &str,
    data: Value,
) -> Result<BackendEvent, String> {
    match (kind, event) {
        (OperationKind::Install, "action") => {
            let data: ActionData = strict_value(data, "install action")?;
            Ok(BackendEvent::Action {
                operation_id,
                action: data.action,
            })
        }
        (OperationKind::Install, "phase") => {
            let data: InstallPhaseData = strict_value(data, "install phase")?;
            Ok(BackendEvent::InstallPhase {
                operation_id,
                phase: data.phase,
            })
        }
        (OperationKind::Uninstall, "phase") => {
            let data: UninstallPhaseData = strict_value(data, "uninstall phase")?;
            Ok(BackendEvent::UninstallPhase {
                operation_id,
                phase: data.phase,
            })
        }
        (_, "progress") => {
            let data: ProgressData = strict_value(data, "operation progress")?;
            if data.completed_files > data.total_files
                || data.completed_bytes > data.total_bytes
                || [
                    data.completed_files,
                    data.total_files,
                    data.completed_bytes,
                    data.total_bytes,
                ]
                .into_iter()
                .any(|value| value > MAX_SAFE_INTEGER)
            {
                return Err("backend progress exceeds its declared totals".into());
            }
            Ok(BackendEvent::Progress {
                operation_id,
                completed_files: data.completed_files,
                total_files: data.total_files,
                completed_bytes: data.completed_bytes,
                total_bytes: data.total_bytes,
            })
        }
        _ => Err("backend emitted an event incompatible with its operation".into()),
    }
}

pub(crate) fn strict_value<T: for<'de> Deserialize<'de>>(
    value: Value,
    label: &str,
) -> Result<T, String> {
    serde_json::from_value(value).map_err(|_| format!("backend returned invalid {label}"))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DefaultsResult {
    pub(crate) install_base: String,
    pub(crate) state_root: String,
    pub(crate) target: Target,
    pub(crate) backend_version: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InspectResult {
    pub(crate) format_version: u8,
    pub(crate) schema_version: u8,
    pub(crate) package_fingerprint: String,
    pub(crate) trust: PackageTrust,
    pub(crate) publisher_rotation: Option<PublisherRotation>,
    pub(crate) package: PackageIdentity,
    pub(crate) target: Target,
    pub(crate) install: InstallPolicy,
    pub(crate) payload: Payload,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProjectResult {
    pub(crate) format_version: u8,
    pub(crate) schema_version: u8,
    pub(crate) package: PackageIdentity,
    pub(crate) target: Target,
    pub(crate) install: InstallPolicy,
    pub(crate) payload: Payload,
    pub(crate) authoring: ProjectAuthoring,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedPayloadPath {
    pub(crate) path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum PrepareInstallResult {
    Ready {
        action: PreparedAction,
        #[serde(rename = "installedVersion")]
        installed_version: Option<String>,
        #[serde(rename = "publisherMigrationRequired")]
        publisher_migration_required: bool,
    },
    InsufficientSpace {
        action: PreparedAction,
        #[serde(rename = "installedVersion")]
        installed_version: Option<String>,
        #[serde(rename = "publisherMigrationRequired")]
        publisher_migration_required: bool,
    },
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum PreparedAction {
    Install,
    Update,
    Repair,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstallResult {
    pub(crate) action: InstallResultAction,
    pub(crate) package_id: String,
    pub(crate) installed_files: u64,
    pub(crate) installed_bytes: u64,
    pub(crate) install_directory: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum UninstallResult {
    NotInstalled {
        #[serde(rename = "packageId")]
        package_id: String,
    },
    Uninstalled {
        #[serde(rename = "packageId")]
        package_id: String,
        #[serde(rename = "removedFiles")]
        removed_files: u64,
        #[serde(rename = "missingFiles")]
        missing_files: u64,
        #[serde(rename = "preservedModifiedFiles")]
        preserved_modified_files: u64,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LaunchResult {
    pub(crate) status: String,
    pub(crate) package_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CancelResult {
    pub(crate) request_id: String,
    pub(crate) accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) os: TargetOs,
    pub(crate) arch: TargetArch,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum TargetOs {
    Windows,
    Linux,
    Macos,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum TargetArch {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PackageIdentity {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) publisher: String,
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) license: Option<String>,
    #[serde(default)]
    pub(crate) icon: Option<ProductIcon>,
    #[serde(default)]
    pub(crate) homepage: Option<String>,
    #[serde(default)]
    pub(crate) support: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProductIcon {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) sha256: String,
}

impl ProductIcon {
    /// Re-checks the backend's icon identity against the target's native format and the payload it
    /// must live inside. Both shells validate every backend field before trusting it.
    pub(crate) fn is_valid_for(&self, target: TargetOs, payload_bytes: u64) -> bool {
        valid_native_icon_path(&self.path, target)
            && (1..=luxury_spec::MAX_PRODUCT_ICON_BYTES).contains(&self.size)
            && self.size <= payload_bytes
            && self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    }
}

pub(crate) fn valid_native_icon_path(value: &str, target: TargetOs) -> bool {
    let extension = match target {
        TargetOs::Windows => "ico",
        TargetOs::Linux => "png",
        TargetOs::Macos => "icns",
    };
    luxury_spec::PackagePath::parse(value).is_ok()
        && value
            .rsplit_once('.')
            .is_some_and(|(_, found)| found.eq_ignore_ascii_case(extension))
}

/// Bounded credential-free HTTPS policy shared by finish links and product homepage/support.
pub(crate) fn valid_public_https_url(value: &str) -> bool {
    if value.len() > MAX_PUBLIC_URL_BYTES
        || value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
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
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
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
        && port.is_none_or(|port| port.parse::<u16>().is_ok_and(|port| port != 0))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstallPolicy {
    pub(crate) scope: InstallScope,
    pub(crate) directory: String,
    pub(crate) has_entrypoint: bool,
    #[serde(default)]
    pub(crate) show_install_log: bool,
    #[serde(default)]
    pub(crate) finish_links: Vec<FinishLink>,
    #[serde(default)]
    pub(crate) shortcuts: ShortcutPolicy,
    #[serde(default)]
    pub(crate) requires: HostRequirements,
}

/// Declarative host requirements. Each predicate is target-scoped, so the shell validates the
/// pairing exactly like the backend does instead of trusting the reported combination.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HostRequirements {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) windows_minimum_version: Option<String>,
}

impl HostRequirements {
    pub(crate) fn is_empty(&self) -> bool {
        self.windows_minimum_version.is_none()
    }

    pub(crate) fn is_valid_for(&self, target: TargetOs) -> bool {
        match &self.windows_minimum_version {
            None => true,
            Some(version) => {
                target == TargetOs::Windows && luxury_spec::WindowsVersion::parse(version).is_ok()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ShortcutPolicy {
    #[serde(default)]
    pub(crate) application_menu: bool,
    #[serde(default)]
    pub(crate) desktop: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinishLink {
    pub(crate) label: String,
    pub(crate) url: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum InstallScope {
    User,
    System,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Payload {
    pub(crate) files: u64,
    pub(crate) bytes: u64,
    #[serde(default)]
    pub(crate) install_log: Option<InstallLog>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProjectAuthoring {
    pub(crate) allow_downgrade: bool,
    pub(crate) entrypoint: Option<String>,
    pub(crate) executable_files: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstallLog {
    pub(crate) files: Vec<String>,
    pub(crate) omitted_files: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum PackageTrust {
    #[serde(rename = "unsigned")]
    Unsigned {},
    #[serde(rename = "trustedPublisher")]
    TrustedPublisher {
        #[serde(rename = "keyId")]
        key_id: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublisherRotation {
    pub(crate) signer_key_id: String,
    pub(crate) next_key_id: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn backend_line_rejects_unknown_fields() {
        let line = serde_json::to_vec(&json!({
            "protocolVersion": PROTOCOL_VERSION,
            "type": "result",
            "id": "one",
            "result": {},
            "extra": true,
        }))
        .unwrap();
        assert!(serde_json::from_slice::<BackendLine>(&line).is_err());
    }

    #[test]
    fn progress_rejects_completed_work_beyond_totals() {
        let error = parse_event(
            OperationKind::Install,
            "one".into(),
            "progress",
            json!({
                "completedFiles": 2,
                "totalFiles": 1,
                "completedBytes": 0,
                "totalBytes": 0
            }),
        )
        .unwrap_err();
        assert!(error.contains("exceeds"));

        assert!(
            parse_event(
                OperationKind::Install,
                "one".into(),
                "progress",
                json!({
                    "completedFiles": 0,
                    "totalFiles": 1,
                    "completedBytes": 0,
                    "totalBytes": MAX_SAFE_INTEGER + 1
                }),
            )
            .is_err()
        );
    }

    #[test]
    fn package_trust_rejects_unknown_fields() {
        assert!(
            serde_json::from_value::<PackageTrust>(json!({
                "kind": "unsigned",
                "keyId": "a".repeat(64)
            }))
            .is_err()
        );
    }

    #[test]
    fn operation_kind_rejects_sibling_phase_vocabulary() {
        assert!(
            parse_event(
                OperationKind::Uninstall,
                "one".into(),
                "phase",
                json!({ "phase": "validating" }),
            )
            .is_err()
        );
    }
}
