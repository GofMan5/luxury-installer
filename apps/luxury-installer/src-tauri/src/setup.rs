use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::{
    app::{
        AppMode, AppState, ExclusiveGuard, PublicError, valid_install_directory, valid_license,
        valid_package_id, valid_text,
    },
    backend::{
        BackendEvent, DefaultsResult, FinishLink, InspectResult, InstallLog, InstallResult,
        InstallResultAction, InstallScope, LaunchResult, MAX_SAFE_INTEGER, OperationKind,
        OperationMessage, PackageTrust, PrepareInstallResult, PreparedAction, PublisherRotation,
        ShortcutPolicy, Target, TargetArch, TargetOs, UninstallResult, strict_value,
    },
};

#[repr(C)]
struct BuildPackageBinding {
    prefix: [u8; 16],
    fingerprint: [u8; 64],
    suffix: [u8; 16],
}

const fn build_fingerprint_bytes(value: Option<&str>) -> [u8; 64] {
    let mut output = [0_u8; 64];
    let Some(value) = value else {
        return output;
    };
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() && index < output.len() {
        output[index] = bytes[index];
        index += 1;
    }
    output
}

#[used]
static BUILD_PACKAGE_BINDING: BuildPackageBinding = BuildPackageBinding {
    prefix: luxury_spec::SETUP_BINDING_PREFIX,
    fingerprint: build_fingerprint_bytes(option_env!("LUXURY_BOUND_PACKAGE_FINGERPRINT")),
    suffix: luxury_spec::SETUP_BINDING_SUFFIX,
};

const OPERATION_EVENT: &str = "luxury://operation-event";
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MAX_FINISH_LINKS: usize = 4;
const MAX_FINISH_LINK_LABEL_CHARS: usize = 48;
const MAX_FINISH_LINK_URL_BYTES: usize = 2_048;
const MAX_INSTALL_LOG_FILES: usize = 128;

#[derive(Clone)]
pub(crate) struct SetupContext {
    package: BoundPackage,
    selection: Arc<Mutex<Option<SetupSelection>>>,
    active: Arc<Mutex<Option<ActiveOperation>>>,
    starting: Arc<AtomicBool>,
    last_install_path: Arc<Mutex<Option<PathBuf>>>,
    install_completed: Arc<AtomicBool>,
}

#[derive(Clone)]
struct BoundPackage {
    path: PathBuf,
    fingerprint: String,
    id: String,
    summary: PackageSummary,
}

#[derive(Clone)]
struct SetupSelection {
    install_base: PathBuf,
    state_root: PathBuf,
    preparation: PrepareInstallResult,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveKind {
    Install,
    Uninstall,
}

#[derive(Clone)]
struct ActiveOperation {
    operation_id: String,
    kind: ActiveKind,
    system_cancel: Option<Arc<AtomicBool>>,
    completion: Arc<(Mutex<bool>, Condvar)>,
}

enum SetupOperation {
    User(crate::backend::BackendOperation),
    System(crate::privilege::SystemOperation),
}

struct SetupOperationMessage {
    message: OperationMessage,
    system_preparation: Option<PrepareInstallResult>,
}

impl SetupOperation {
    fn operation_id(&self) -> &str {
        match self {
            Self::User(operation) => &operation.operation_id,
            Self::System(operation) => &operation.operation_id,
        }
    }

    fn system_cancellation(&self) -> Option<Arc<AtomicBool>> {
        match self {
            Self::User(_) => None,
            Self::System(operation) => Some(operation.cancellation()),
        }
    }

    fn recv(&self) -> Result<SetupOperationMessage, crate::backend::BackendError> {
        match self {
            Self::User(operation) => operation.recv().map(|message| SetupOperationMessage {
                message,
                system_preparation: None,
            }),
            Self::System(operation) => operation.recv().and_then(system_operation_message),
        }
    }
}

fn system_operation_message(
    message: OperationMessage,
) -> Result<SetupOperationMessage, crate::backend::BackendError> {
    let OperationMessage::Complete(Ok(Value::Object(mut result))) = message else {
        return Ok(SetupOperationMessage {
            message,
            system_preparation: None,
        });
    };
    let system_preparation = result
        .remove("systemPreparation")
        .and_then(|preparation| serde_json::from_value(preparation).ok())
        .flatten();
    Ok(SetupOperationMessage {
        message: OperationMessage::Complete(Ok(Value::Object(result))),
        system_preparation,
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PackageSummary {
    name: String,
    publisher: String,
    version: String,
    description: Option<String>,
    license: Option<String>,
    target_os: TargetOs,
    target_arch: TargetArch,
    install_directory: String,
    scope: InstallScope,
    has_entrypoint: bool,
    install_log: Option<InstallLog>,
    finish_links: Vec<FinishLink>,
    shortcuts: ShortcutPolicy,
    files: u64,
    bytes: u64,
    trust: PackageTrust,
    publisher_rotation: Option<PublisherRotation>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallerDestination {
    install_base: String,
    install_path: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstallerReview {
    package: PackageSummary,
    destination: Option<InstallerDestination>,
    action: SetupAction,
    installed_version: Option<String>,
    publisher_migration_required: bool,
    space_available: bool,
    can_uninstall: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
enum SetupAction {
    Install,
    Update,
    Repair,
    Recover,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartInstallInput {
    allow_unsigned: bool,
    accept_license: bool,
    allow_publisher_migration: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnattendedCommand {
    Help,
    InfoJson,
    Install {
        allow_unsigned: bool,
        accept_license: bool,
        allow_publisher_migration: bool,
    },
    Uninstall,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BoundPackageInfo {
    schema_version: u8,
    package: BoundPackageInfoPackage,
    target: Target,
    install: BoundPackageInfoInstall,
    payload: BoundPackageInfoPayload,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BoundPackageInfoPackage {
    id: String,
    fingerprint: String,
    name: String,
    publisher: String,
    version: String,
    description: Option<String>,
    trust: PackageTrust,
    requires_license: bool,
    publisher_rotation: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BoundPackageInfoInstall {
    scope: InstallScope,
    directory: String,
    has_entrypoint: bool,
    show_install_log: bool,
    finish_links: usize,
    shortcuts: ShortcutPolicy,
}

#[derive(Debug, Serialize)]
struct BoundPackageInfoPayload {
    files: u64,
    bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OperationStarted {
    operation_id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum SetupEvent {
    Action {
        operation_id: String,
        action: InstallResultAction,
    },
    Phase {
        operation_id: String,
        phase: crate::backend::InstallPhase,
    },
    Progress {
        operation_id: String,
        completed_files: u64,
        total_files: u64,
        completed_bytes: u64,
        total_bytes: u64,
    },
    Complete {
        operation_id: String,
        action: InstallResultAction,
        installed_files: u64,
        installed_bytes: u64,
        review: Option<Box<InstallerReview>>,
    },
    UninstallPhase {
        operation_id: String,
        phase: crate::backend::UninstallPhase,
    },
    UninstallProgress {
        operation_id: String,
        processed_files: u64,
        total_files: u64,
    },
    UninstallComplete {
        operation_id: String,
        removed_files: u64,
        missing_files: u64,
        preserved_modified_files: u64,
        review: Option<Box<InstallerReview>>,
    },
    Error {
        operation_id: String,
        code: String,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        review: Option<Box<InstallerReview>>,
    },
}

#[tauri::command]
pub(crate) async fn get_bootstrap(
    state: State<'_, AppState>,
) -> Result<InstallerReview, PublicError> {
    state.require_mode(AppMode::Setup)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || bootstrap_review(&state))
        .await
        .map_err(|_| PublicError::new("internal_error", "Запуск Setup прерван."))?
}

#[tauri::command]
pub(crate) async fn choose_directory(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<InstallerReview>, PublicError> {
    state.require_mode(AppMode::Setup)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let context = setup_context(&state)?;
        let _starting = acquire_idle(&state, &context)?;
        if context.package.summary.scope == InstallScope::System {
            return Err(PublicError::new(
                "unsupported_scope",
                "Системная установка использует защищённую папку ОС.",
            ));
        }
        let current = selection(&context)?;
        let _dialog = ExclusiveGuard::acquire(
            &state.dialog_open,
            "dialog_busy",
            "Другой системный диалог уже открыт.",
        )?;
        let selected = app
            .dialog()
            .file()
            .set_parent(&window)
            .set_title("Выберите папку")
            .set_directory(&current.install_base)
            .blocking_pick_folder()
            .map(|path| {
                path.into_path().map_err(|_| {
                    PublicError::new(
                        "invalid_install_path",
                        "Выбран недопустимый путь установки.",
                    )
                })
            })
            .transpose()?;
        let Some(selected) = selected else {
            return Ok(None);
        };
        let next = prepare_selection(&state, &context.package, selected, current.state_root)?;
        *context
            .selection
            .lock()
            .map_err(|_| PublicError::new("internal_error", "Состояние Setup недоступно."))? =
            Some(next);
        review(&context).map(Some)
    })
    .await
    .map_err(|_| PublicError::new("internal_error", "Выбор папки прерван."))?
}

#[tauri::command]
pub(crate) async fn start_install(
    input: StartInstallInput,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<OperationStarted, PublicError> {
    state.require_mode(AppMode::Setup)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || start_install_sync(input, app, state))
        .await
        .map_err(|_| PublicError::new("internal_error", "Запуск установки прерван."))?
}

#[tauri::command]
pub(crate) async fn start_uninstall(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<OperationStarted, PublicError> {
    state.require_mode(AppMode::Setup)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || start_uninstall_sync(app, state))
        .await
        .map_err(|_| PublicError::new("internal_error", "Запуск удаления прерван."))?
}

#[tauri::command]
pub(crate) async fn cancel_operation(state: State<'_, AppState>) -> Result<(), PublicError> {
    state.require_mode(AppMode::Setup)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let context = setup_context(&state)?;
        let active = context
            .active
            .lock()
            .map_err(|_| PublicError::new("internal_error", "Состояние операции недоступно."))?
            .clone();
        let Some(active) = active else {
            return Ok(());
        };
        if let Some(cancel) = active.system_cancel {
            cancel.store(true, Ordering::Release);
            return Ok(());
        }
        match state
            .backend()
            .map_err(PublicError::from)?
            .cancel(&active.operation_id)
        {
            Ok(()) => Ok(()),
            Err(error) if error.code == "cancel_rejected" => Ok(()),
            Err(error) => Err(PublicError::from(error)),
        }
    })
    .await
    .map_err(|_| PublicError::new("internal_error", "Отмена операции прервана."))?
}

pub(crate) fn shutdown_operation(state: &AppState) -> Result<(), PublicError> {
    shutdown_operation_with_timeout(state, SHUTDOWN_TIMEOUT)
}

fn shutdown_operation_with_timeout(state: &AppState, timeout: Duration) -> Result<(), PublicError> {
    if state.mode != AppMode::Setup {
        return Ok(());
    }
    let deadline = Instant::now() + timeout;
    let timed_out = || {
        PublicError::new(
            "shutdown_timeout",
            "Операция ещё выполняет безопасный откат. Повторите закрытие позже.",
        )
    };
    let context = loop {
        match state.setup.try_lock() {
            Ok(context) => break context.clone(),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(TryLockError::WouldBlock) => return Err(timed_out()),
            Err(TryLockError::Poisoned(_)) => {
                return Err(PublicError::new(
                    "internal_error",
                    "Состояние Setup недоступно.",
                ));
            }
        }
    };
    let Some(context) = context else {
        return Ok(());
    };
    let active = loop {
        let active = context
            .active
            .lock()
            .map_err(|_| PublicError::new("internal_error", "Состояние операции недоступно."))?
            .clone();
        if let Some(active) = active {
            break active;
        }
        if !context.starting.load(Ordering::Acquire) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        thread::sleep(Duration::from_millis(10));
    };
    if let Some(cancel) = &active.system_cancel {
        cancel.store(true, Ordering::Release);
    } else {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        match state
            .backend()
            .map_err(PublicError::from)?
            .cancel_with_timeout(&active.operation_id, remaining)
        {
            Ok(()) => {}
            Err(error) if error.code == "cancel_rejected" => {}
            Err(error) => return Err(PublicError::from(error)),
        }
    }
    let (completed, changed) = &*active.completion;
    let completed = completed
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Состояние завершения недоступно."))?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let (completed, _) = changed
        .wait_timeout_while(completed, remaining, |completed| !*completed)
        .map_err(|_| PublicError::new("internal_error", "Состояние завершения недоступно."))?;
    if *completed { Ok(()) } else { Err(timed_out()) }
}

#[tauri::command]
pub(crate) async fn launch_installed(state: State<'_, AppState>) -> Result<(), PublicError> {
    state.require_mode(AppMode::Setup)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let context = setup_context(&state)?;
        let _starting = acquire_idle(&state, &context)?;
        if !context.package.summary.has_entrypoint {
            return Err(PublicError::new(
                "launch_not_available",
                "Точка запуска недоступна.",
            ));
        }
        let result: LaunchResult = match context.package.summary.scope {
            InstallScope::User => {
                let selection = selection(&context)?;
                state
                    .backend()
                    .map_err(PublicError::from)?
                    .request(
                        "launch",
                        json!({
                            "packageId": context.package.id,
                            "installBase": path_text(&selection.install_base)?,
                            "stateRoot": path_text(&selection.state_root)?,
                        }),
                        None,
                    )
                    .map_err(PublicError::from)?
            }
            InstallScope::System => {
                state.verify_privilege_transport()?;
                let backend = state.backend().map_err(PublicError::from)?;
                let executable = backend.executable().map_err(PublicError::from)?;
                let operation = crate::privilege::start_system_launch(
                    executable,
                    &context.package.path,
                    &context.package.id,
                    &context.package.fingerprint,
                )
                .map_err(|_| {
                    PublicError::new(
                        "system_authorization_failed",
                        "Не удалось запустить системный компонент запуска.",
                    )
                })?;
                let value = match operation.recv().map_err(PublicError::from)? {
                    OperationMessage::Complete(result) => result.map_err(PublicError::from)?,
                    OperationMessage::Event(_) => {
                        return Err(PublicError::new(
                            "invalid_backend_output",
                            "Системный компонент запуска вернул лишнее событие.",
                        ));
                    }
                };
                strict_value(value, "system launch result").map_err(|_| {
                    PublicError::new(
                        "invalid_backend_output",
                        "Системный компонент запуска вернул неверный результат.",
                    )
                })?
            }
        };
        if result.status != "launched" || result.package_id != context.package.id {
            return Err(PublicError::new(
                "invalid_backend_output",
                "Компонент запуска вернул другой пакет.",
            ));
        }
        Ok(())
    })
    .await
    .map_err(|_| PublicError::new("internal_error", "Запуск приложения прерван."))?
}

#[tauri::command]
pub(crate) fn reveal_installed(state: State<'_, AppState>) -> Result<(), PublicError> {
    state.require_mode(AppMode::Setup)?;
    let context = setup_context(state.inner())?;
    let _starting = acquire_idle(state.inner(), &context)?;
    let path = installed_reveal_path(&context)?;
    tauri_plugin_opener::open_path(path, None::<&str>)
        .map_err(|_| PublicError::new("reveal_failed", "Не удалось открыть папку приложения."))
}

fn installed_reveal_path(context: &SetupContext) -> Result<PathBuf, PublicError> {
    if !context.install_completed.load(Ordering::Acquire) {
        return Err(PublicError::new(
            "nothing_to_reveal",
            "Папка приложения станет доступна после установки.",
        ));
    }
    if context.package.summary.scope == InstallScope::User {
        return context
            .last_install_path
            .lock()
            .map_err(|_| PublicError::new("internal_error", "Путь приложения недоступен."))?
            .clone()
            .ok_or_else(|| PublicError::new("nothing_to_reveal", "Папка приложения недоступна."));
    }

    let (install_base, _) = luxury_system_roots::get().map_err(|_| {
        PublicError::new(
            "nothing_to_reveal",
            "Системная папка приложения недоступна.",
        )
    })?;
    let path = install_base.join(&context.package.summary.install_directory);
    if path.parent() != Some(install_base.as_path()) {
        return Err(PublicError::new(
            "nothing_to_reveal",
            "Системная папка приложения недоступна.",
        ));
    }
    Ok(path)
}

#[tauri::command]
pub(crate) fn open_finish_link(
    index: usize,
    state: State<'_, AppState>,
) -> Result<(), PublicError> {
    state.require_mode(AppMode::Setup)?;
    let context = setup_context(state.inner())?;
    let _starting = acquire_idle(state.inner(), &context)?;
    if !context.install_completed.load(Ordering::Acquire) {
        return Err(PublicError::new(
            "finish_link_not_available",
            "Ссылка станет доступна после завершения установки.",
        ));
    }
    let link = context
        .package
        .summary
        .finish_links
        .get(index)
        .ok_or_else(|| PublicError::new("finish_link_not_available", "Ссылка недоступна."))?;
    tauri_plugin_opener::open_url(&link.url, None::<&str>)
        .map_err(|_| PublicError::new("open_link_failed", "Не удалось открыть ссылку."))
}

fn setup_context(state: &AppState) -> Result<SetupContext, PublicError> {
    let mut stored = state
        .setup
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Состояние Setup недоступно."))?;
    if let Some(context) = stored.clone() {
        return Ok(context);
    }
    let (package, defaults) = load_bound_package(state)?;
    let context = build_setup_context(state, package, defaults)?;
    *stored = Some(context.clone());
    Ok(context)
}

fn bootstrap_review(state: &AppState) -> Result<InstallerReview, PublicError> {
    let existing = state
        .setup
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Состояние Setup недоступно."))?
        .clone();
    if let Some(context) = existing {
        let _starting = acquire_idle(state, &context)?;
        let previous = context
            .selection
            .lock()
            .map_err(|_| PublicError::new("internal_error", "Состояние Setup недоступно."))?
            .clone();
        let previous = match previous {
            Some(previous) => previous,
            None => {
                let defaults = state.defaults()?;
                SetupSelection {
                    install_base: absolute_path(&defaults.install_base)?,
                    state_root: absolute_path(&defaults.state_root)?,
                    preparation: PrepareInstallResult::RecoveryRequired,
                }
            }
        };
        return refresh_selection(state, &context, previous);
    }
    review(&setup_context(state)?)
}

fn build_setup_context(
    state: &AppState,
    package: BoundPackage,
    defaults: DefaultsResult,
) -> Result<SetupContext, PublicError> {
    let install_base = absolute_path(&defaults.install_base)?;
    let state_root = absolute_path(&defaults.state_root)?;
    let selection = prepare_selection(state, &package, install_base, state_root)?;
    Ok(SetupContext {
        package,
        selection: Arc::new(Mutex::new(Some(selection))),
        active: Arc::new(Mutex::new(None)),
        starting: Arc::new(AtomicBool::new(false)),
        last_install_path: Arc::new(Mutex::new(None)),
        install_completed: Arc::new(AtomicBool::new(false)),
    })
}

fn load_bound_package(state: &AppState) -> Result<(BoundPackage, DefaultsResult), PublicError> {
    let package_path = state
        .package_path
        .clone()
        .filter(|path| path.is_absolute())
        .ok_or_else(|| PublicError::new("payload_missing", "Пакет приложения отсутствует."))?;
    let backend = state.backend().map_err(PublicError::from)?;
    let defaults = state.defaults()?;
    let inspected: InspectResult = backend
        .request_operation(
            "inspect",
            json!({ "packagePath": path_text(&package_path)? }),
        )
        .map_err(PublicError::from)?;
    if inspected.target != defaults.target {
        return Err(PublicError::new(
            "invalid_backend_output",
            "Пакет и backend вернули разные платформы.",
        ));
    }
    Ok((
        BoundPackage::from_backend(package_path, inspected)?,
        defaults,
    ))
}

pub(crate) fn bound_package_info(state: &AppState) -> Result<BoundPackageInfo, PublicError> {
    state.require_mode(AppMode::Setup)?;
    let (package, defaults) = load_bound_package(state)?;
    Ok(package_info(package, defaults.target))
}

fn package_info(package: BoundPackage, target: Target) -> BoundPackageInfo {
    let BoundPackage {
        path: _,
        fingerprint,
        id,
        summary,
    } = package;
    BoundPackageInfo {
        schema_version: 2,
        package: BoundPackageInfoPackage {
            id,
            fingerprint,
            name: summary.name,
            publisher: summary.publisher,
            version: summary.version,
            description: summary.description,
            requires_license: summary.license.is_some(),
            trust: summary.trust,
            publisher_rotation: summary.publisher_rotation.is_some(),
        },
        target,
        install: BoundPackageInfoInstall {
            scope: summary.scope,
            directory: summary.install_directory,
            has_entrypoint: summary.has_entrypoint,
            show_install_log: summary.install_log.is_some(),
            finish_links: summary.finish_links.len(),
            shortcuts: summary.shortcuts,
        },
        payload: BoundPackageInfoPayload {
            files: summary.files,
            bytes: summary.bytes,
        },
    }
}

fn start_install_sync(
    input: StartInstallInput,
    app: AppHandle,
    state: AppState,
) -> Result<OperationStarted, PublicError> {
    let context = setup_context(&state)?;
    let starting = acquire_idle(&state, &context)?;
    let selection = selection(&context)?;
    let operation = create_install_operation(&input, &state, &context, &selection)?;
    let operation_id = operation.operation_id().to_owned();
    let system_cancel = operation.system_cancellation();
    *context
        .active
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Состояние операции недоступно."))? =
        Some(ActiveOperation {
            operation_id: operation_id.clone(),
            kind: ActiveKind::Install,
            system_cancel: system_cancel.clone(),
            completion: Arc::new((Mutex::new(false), Condvar::new())),
        });
    drop(starting);
    if let Err(error) =
        spawn_install_completion(app, state.clone(), context.clone(), selection, operation)
    {
        clear_active(&context, &operation_id);
        if let Some(cancel) = system_cancel {
            cancel.store(true, Ordering::Release);
        } else if let Ok(backend) = state.backend() {
            let _ = backend.cancel(&operation_id);
        }
        return Err(error);
    }
    Ok(OperationStarted { operation_id })
}

fn create_install_operation(
    input: &StartInstallInput,
    state: &AppState,
    context: &SetupContext,
    selection: &SetupSelection,
) -> Result<SetupOperation, PublicError> {
    let (space_available, migration_required) = match &selection.preparation {
        PrepareInstallResult::Ready {
            publisher_migration_required,
            ..
        } => (true, *publisher_migration_required),
        PrepareInstallResult::InsufficientSpace { .. } => (false, false),
        PrepareInstallResult::RecoveryRequired => (true, false),
    };
    if !space_available {
        return Err(PublicError::new(
            "insufficient_space",
            "Недостаточно свободного места.",
        ));
    }
    if input.allow_publisher_migration && !migration_required {
        return Err(PublicError::new(
            "publisher_migration_not_offered",
            "Подтверждение смены издателя не запрашивалось.",
        ));
    }
    if migration_required && !input.allow_publisher_migration {
        return Err(PublicError::new(
            "publisher_migration_required",
            "Требуется подтверждение смены издателя.",
        ));
    }
    if matches!(context.package.summary.trust, PackageTrust::Unsigned {}) && !input.allow_unsigned {
        return Err(PublicError::new(
            "unsigned_not_allowed",
            "Подтвердите установку неподписанного пакета.",
        ));
    }
    require_license_consent(
        context.package.summary.license.as_deref(),
        input.accept_license,
    )?;
    context.install_completed.store(false, Ordering::Release);
    Ok(match context.package.summary.scope {
        InstallScope::User => SetupOperation::User(
            state
                .backend()
                .map_err(PublicError::from)?
                .start_operation(
                    "install",
                    json!({
                        "packagePath": path_text(&context.package.path)?,
                        "installBase": path_text(&selection.install_base)?,
                        "stateRoot": path_text(&selection.state_root)?,
                        "allowUnsigned": matches!(context.package.summary.trust, PackageTrust::Unsigned {}) && input.allow_unsigned,
                        "acceptLicense": context.package.summary.license.is_some() && input.accept_license,
                        "allowPublisherMigration": input.allow_publisher_migration,
                        "expectedFingerprint": context.package.fingerprint,
                    }),
                    OperationKind::Install,
                )
                .map_err(PublicError::from)?,
        ),
        InstallScope::System => {
            state.verify_privilege_transport()?;
            let backend = state.backend().map_err(PublicError::from)?;
            let executable = backend.executable().map_err(PublicError::from)?;
            SetupOperation::System(
                crate::privilege::start_system_install(
                    executable,
                    &context.package.path,
                    &context.package.id,
                    &context.package.fingerprint,
                    matches!(context.package.summary.trust, PackageTrust::Unsigned {})
                        && input.allow_unsigned,
                    context.package.summary.license.is_some() && input.accept_license,
                    input.allow_publisher_migration,
                )
                .map_err(|_| {
                    PublicError::new(
                        "system_authorization_failed",
                        "Не удалось запустить системный компонент установки.",
                    )
                })?,
            )
        }
    })
}

fn require_license_consent(license: Option<&str>, accepted: bool) -> Result<(), PublicError> {
    match (license.is_some(), accepted) {
        (true, false) => {
            return Err(PublicError::new(
                "license_not_accepted",
                "Примите лицензионное соглашение для продолжения.",
            ));
        }
        (false, true) => {
            return Err(PublicError::new(
                "license_not_offered",
                "Лицензионное соглашение для этого пакета не запрашивалось.",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn start_uninstall_sync(app: AppHandle, state: AppState) -> Result<OperationStarted, PublicError> {
    let context = setup_context(&state)?;
    let starting = acquire_idle(&state, &context)?;
    let selection = selection(&context)?;
    if !review(&context)?.can_uninstall {
        return Err(PublicError::new(
            "uninstall_not_available",
            "Приложение не установлено.",
        ));
    }
    let operation = create_uninstall_operation(&state, &context, &selection)?;
    let operation_id = operation.operation_id().to_owned();
    let system_cancel = operation.system_cancellation();
    *context
        .active
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Состояние операции недоступно."))? =
        Some(ActiveOperation {
            operation_id: operation_id.clone(),
            kind: ActiveKind::Uninstall,
            system_cancel: system_cancel.clone(),
            completion: Arc::new((Mutex::new(false), Condvar::new())),
        });
    drop(starting);
    if let Err(error) =
        spawn_uninstall_completion(app, state.clone(), context.clone(), selection, operation)
    {
        clear_active(&context, &operation_id);
        if let Some(cancel) = system_cancel {
            cancel.store(true, Ordering::Release);
        } else if let Ok(backend) = state.backend() {
            let _ = backend.cancel(&operation_id);
        }
        return Err(error);
    }
    Ok(OperationStarted { operation_id })
}

fn create_uninstall_operation(
    state: &AppState,
    context: &SetupContext,
    selection: &SetupSelection,
) -> Result<SetupOperation, PublicError> {
    Ok(match context.package.summary.scope {
        InstallScope::User => SetupOperation::User(
            state
                .backend()
                .map_err(PublicError::from)?
                .start_operation(
                    "uninstall",
                    json!({
                        "packageId": context.package.id,
                        "installBase": path_text(&selection.install_base)?,
                        "stateRoot": path_text(&selection.state_root)?,
                    }),
                    OperationKind::Uninstall,
                )
                .map_err(PublicError::from)?,
        ),
        InstallScope::System => {
            state.verify_privilege_transport()?;
            let backend = state.backend().map_err(PublicError::from)?;
            let executable = backend.executable().map_err(PublicError::from)?;
            SetupOperation::System(
                crate::privilege::start_system_uninstall(
                    executable,
                    &context.package.path,
                    &context.package.id,
                    &context.package.fingerprint,
                )
                .map_err(|_| {
                    PublicError::new(
                        "system_authorization_failed",
                        "Не удалось запустить системный компонент удаления.",
                    )
                })?,
            )
        }
    })
}

pub(crate) fn run_unattended(
    state: &AppState,
    command: UnattendedCommand,
) -> Result<(), PublicError> {
    state.require_mode(AppMode::Setup)?;
    match command {
        UnattendedCommand::Help => return Ok(()),
        UnattendedCommand::InfoJson => return bound_package_info(state).map(drop),
        UnattendedCommand::Install { .. } | UnattendedCommand::Uninstall => {}
    }
    let context = setup_context(state)?;
    let starting = acquire_idle(state, &context)?;
    let selection = selection(&context)?;
    match command {
        UnattendedCommand::Help | UnattendedCommand::InfoJson => Ok(()),
        UnattendedCommand::Install {
            allow_unsigned,
            accept_license,
            allow_publisher_migration,
        } => {
            let operation = create_install_operation(
                &StartInstallInput {
                    allow_unsigned,
                    accept_license,
                    allow_publisher_migration,
                },
                state,
                &context,
                &selection,
            )?;
            drop(starting);
            wait_unattended_install(&context, &selection, operation)
        }
        UnattendedCommand::Uninstall => {
            let operation = create_uninstall_operation(state, &context, &selection)?;
            drop(starting);
            wait_unattended_uninstall(&context, operation)
        }
    }
}

fn wait_unattended_install(
    context: &SetupContext,
    selection: &SetupSelection,
    operation: SetupOperation,
) -> Result<(), PublicError> {
    loop {
        match operation.recv().map_err(PublicError::from)?.message {
            OperationMessage::Event(_) => {}
            OperationMessage::Complete(result) => {
                let value = result.map_err(PublicError::from)?;
                let result =
                    strict_value::<InstallResult>(value, "install result").map_err(|_| {
                        PublicError::new(
                            "invalid_backend_output",
                            "Компонент установки вернул неверный результат.",
                        )
                    })?;
                validate_install_result(context, selection, result)?;
                return Ok(());
            }
        }
    }
}

fn wait_unattended_uninstall(
    context: &SetupContext,
    operation: SetupOperation,
) -> Result<(), PublicError> {
    loop {
        match operation.recv().map_err(PublicError::from)?.message {
            OperationMessage::Event(_) => {}
            OperationMessage::Complete(result) => {
                let value = result.map_err(PublicError::from)?;
                let result =
                    strict_value::<UninstallResult>(value, "uninstall result").map_err(|_| {
                        PublicError::new(
                            "invalid_backend_output",
                            "Компонент удаления вернул неверный результат.",
                        )
                    })?;
                validate_uninstall_result(context, result)?;
                return Ok(());
            }
        }
    }
}

fn spawn_install_completion(
    app: AppHandle,
    state: AppState,
    context: SetupContext,
    selection: SetupSelection,
    operation: SetupOperation,
) -> Result<(), PublicError> {
    let operation_id = operation.operation_id().to_owned();
    thread::Builder::new()
        .name("luxury-install-completion".into())
        .spawn(move || {
            loop {
                match operation.recv() {
                    Ok(SetupOperationMessage {
                        message: OperationMessage::Event(event),
                        ..
                    }) => emit_backend_event(&app, &context, event),
                    Ok(SetupOperationMessage {
                        message: OperationMessage::Complete(result),
                        system_preparation,
                    }) => {
                        finish_install(
                            &app,
                            &state,
                            &context,
                            &selection,
                            &operation_id,
                            result,
                            system_preparation,
                        );
                        return;
                    }
                    Err(error) => {
                        finish_install(
                            &app,
                            &state,
                            &context,
                            &selection,
                            &operation_id,
                            Err(error),
                            None,
                        );
                        return;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|_| PublicError::new("internal_error", "Не удалось следить за установкой."))
}

fn spawn_uninstall_completion(
    app: AppHandle,
    state: AppState,
    context: SetupContext,
    selection: SetupSelection,
    operation: SetupOperation,
) -> Result<(), PublicError> {
    let operation_id = operation.operation_id().to_owned();
    thread::Builder::new()
        .name("luxury-uninstall-completion".into())
        .spawn(move || {
            loop {
                match operation.recv() {
                    Ok(SetupOperationMessage {
                        message: OperationMessage::Event(event),
                        ..
                    }) => emit_backend_event(&app, &context, event),
                    Ok(SetupOperationMessage {
                        message: OperationMessage::Complete(result),
                        system_preparation,
                    }) => {
                        finish_uninstall(
                            &app,
                            &state,
                            &context,
                            &selection,
                            &operation_id,
                            result,
                            system_preparation,
                        );
                        return;
                    }
                    Err(error) => {
                        finish_uninstall(
                            &app,
                            &state,
                            &context,
                            &selection,
                            &operation_id,
                            Err(error),
                            None,
                        );
                        return;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|_| PublicError::new("internal_error", "Не удалось следить за удалением."))
}

fn finish_install(
    app: &AppHandle,
    state: &AppState,
    context: &SetupContext,
    selection: &SetupSelection,
    operation_id: &str,
    result: Result<Value, crate::backend::BackendError>,
    system_preparation: Option<PrepareInstallResult>,
) {
    if !is_active(context, operation_id, ActiveKind::Install) {
        return;
    }
    match result
        .map_err(PublicError::from)
        .and_then(|value| {
            strict_value::<InstallResult>(value, "install result").map_err(|_| {
                PublicError::new(
                    "invalid_backend_output",
                    "Компонент установки вернул неверный результат.",
                )
            })
        })
        .and_then(|result| validate_install_result(context, selection, result))
    {
        Ok(result) => {
            if context.package.summary.scope == InstallScope::User {
                let install_path = selection.install_base.join(&result.install_directory);
                if let Ok(mut last) = context.last_install_path.lock() {
                    *last = Some(install_path);
                }
            }
            let review = cache_completed_selection(
                context,
                selection,
                system_preparation,
                PreparedAction::Repair,
            );
            clear_active(context, operation_id);
            context.install_completed.store(true, Ordering::Release);
            emit(
                app,
                SetupEvent::Complete {
                    operation_id: operation_id.into(),
                    action: result.action,
                    installed_files: result.installed_files,
                    installed_bytes: result.installed_bytes,
                    review: review.map(Box::new),
                },
            );
        }
        Err(error) => {
            let review = if !state.close_started.load(Ordering::Acquire)
                && matches!(
                    error.code.as_str(),
                    "cancelled"
                        | "rollback_failed"
                        | "state_conflict"
                        | "publisher_migration_required"
                        | "insufficient_space"
                ) {
                refresh_selection(state, context, selection.clone()).ok()
            } else {
                None
            };
            clear_active(context, operation_id);
            emit_error(app, operation_id, error, review);
        }
    }
}

fn cache_completed_selection(
    context: &SetupContext,
    previous: &SetupSelection,
    system_preparation: Option<PrepareInstallResult>,
    user_action: PreparedAction,
) -> Option<InstallerReview> {
    let preparation = match (context.package.summary.scope, system_preparation) {
        (InstallScope::System, Some(preparation)) => preparation,
        (InstallScope::System, None) => {
            *context.selection.lock().ok()? = None;
            return None;
        }
        (InstallScope::User, _) => PrepareInstallResult::Ready {
            action: user_action,
            installed_version: (user_action != PreparedAction::Install)
                .then(|| context.package.summary.version.clone()),
            publisher_migration_required: false,
        },
    };
    let next = SetupSelection {
        install_base: previous.install_base.clone(),
        state_root: previous.state_root.clone(),
        preparation,
    };
    if validate_preparation(&next.preparation).is_err() {
        *context.selection.lock().ok()? = None;
        return None;
    }
    *context.selection.lock().ok()? = Some(next);
    review(context).ok()
}

fn finish_uninstall(
    app: &AppHandle,
    state: &AppState,
    context: &SetupContext,
    selection: &SetupSelection,
    operation_id: &str,
    result: Result<Value, crate::backend::BackendError>,
    system_preparation: Option<PrepareInstallResult>,
) {
    if !is_active(context, operation_id, ActiveKind::Uninstall) {
        return;
    }
    match result
        .map_err(PublicError::from)
        .and_then(|value| {
            strict_value::<UninstallResult>(value, "uninstall result").map_err(|_| {
                PublicError::new(
                    "invalid_backend_output",
                    "Компонент удаления вернул неверный результат.",
                )
            })
        })
        .and_then(|result| validate_uninstall_result(context, result))
    {
        Ok((removed, missing, preserved)) => {
            context.install_completed.store(false, Ordering::Release);
            if let Ok(mut last) = context.last_install_path.lock() {
                *last = None;
            }
            let next = if context.package.summary.scope == InstallScope::System {
                system_preparation.and_then(|preparation| {
                    validate_preparation(&preparation).ok()?;
                    Some(SetupSelection {
                        install_base: selection.install_base.clone(),
                        state_root: selection.state_root.clone(),
                        preparation,
                    })
                })
            } else {
                prepare_selection(
                    state,
                    &context.package,
                    selection.install_base.clone(),
                    selection.state_root.clone(),
                )
                .ok()
            };
            if let Ok(mut current) = context.selection.lock() {
                *current = next;
            }
            let review = review(context).ok();
            clear_active(context, operation_id);
            emit(
                app,
                SetupEvent::UninstallComplete {
                    operation_id: operation_id.into(),
                    removed_files: removed,
                    missing_files: missing,
                    preserved_modified_files: preserved,
                    review: review.map(Box::new),
                },
            );
        }
        Err(error) => {
            clear_active(context, operation_id);
            emit_error(app, operation_id, error, None);
        }
    }
}

fn emit_backend_event(app: &AppHandle, context: &SetupContext, event: BackendEvent) {
    let event = match event {
        BackendEvent::Action {
            operation_id,
            action,
        } if is_active(context, &operation_id, ActiveKind::Install) => SetupEvent::Action {
            operation_id,
            action,
        },
        BackendEvent::InstallPhase {
            operation_id,
            phase,
        } if is_active(context, &operation_id, ActiveKind::Install) => SetupEvent::Phase {
            operation_id,
            phase,
        },
        BackendEvent::UninstallPhase {
            operation_id,
            phase,
        } if is_active(context, &operation_id, ActiveKind::Uninstall) => {
            SetupEvent::UninstallPhase {
                operation_id,
                phase,
            }
        }
        BackendEvent::Progress {
            operation_id,
            completed_files,
            total_files,
            completed_bytes,
            total_bytes,
        } if is_active(context, &operation_id, ActiveKind::Install) => SetupEvent::Progress {
            operation_id,
            completed_files,
            total_files,
            completed_bytes,
            total_bytes,
        },
        BackendEvent::Progress {
            operation_id,
            completed_files,
            total_files,
            ..
        } if is_active(context, &operation_id, ActiveKind::Uninstall) => {
            SetupEvent::UninstallProgress {
                operation_id,
                processed_files: completed_files,
                total_files,
            }
        }
        _ => return,
    };
    emit(app, event);
}

fn emit(app: &AppHandle, event: SetupEvent) {
    let _ = app.emit(OPERATION_EVENT, event);
}

fn emit_error(
    app: &AppHandle,
    operation_id: &str,
    error: PublicError,
    review: Option<InstallerReview>,
) {
    emit(
        app,
        SetupEvent::Error {
            operation_id: operation_id.into(),
            code: error.code,
            message: error.message,
            review: review.map(Box::new),
        },
    );
}

fn prepare_selection(
    state: &AppState,
    package: &BoundPackage,
    install_base: PathBuf,
    state_root: PathBuf,
) -> Result<SetupSelection, PublicError> {
    if !install_base.is_absolute() || !state_root.is_absolute() {
        return Err(PublicError::new(
            "invalid_install_path",
            "Путь установки должен быть абсолютным.",
        ));
    }
    let preparation: PrepareInstallResult = match package.summary.scope {
        InstallScope::User => state
            .backend()
            .map_err(PublicError::from)?
            .request_operation(
                "prepareInstall",
                json!({
                    "packagePath": path_text(&package.path)?,
                    "installBase": path_text(&install_base)?,
                    "stateRoot": path_text(&state_root)?,
                    "expectedFingerprint": package.fingerprint,
                }),
            )
            .map_err(PublicError::from)?,
        InstallScope::System => {
            state.verify_privilege_transport()?;
            let backend = state.backend().map_err(PublicError::from)?;
            let executable = backend.executable().map_err(PublicError::from)?;
            crate::privilege::authorize_system_install(
                executable,
                &package.path,
                &package.id,
                &package.fingerprint,
            )
            .map_err(|_| {
                PublicError::new(
                    "system_authorization_failed",
                    "Не удалось проверить состояние системной установки.",
                )
            })?
        }
    };
    validate_preparation(&preparation)?;
    Ok(SetupSelection {
        install_base,
        state_root,
        preparation,
    })
}

fn refresh_selection(
    state: &AppState,
    context: &SetupContext,
    previous: SetupSelection,
) -> Result<InstallerReview, PublicError> {
    let next = prepare_selection(
        state,
        &context.package,
        previous.install_base,
        previous.state_root,
    )?;
    *context
        .selection
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Состояние Setup недоступно."))? =
        Some(next);
    review(context)
}

fn review(context: &SetupContext) -> Result<InstallerReview, PublicError> {
    let selection = selection(context)?;
    let destination = if context.package.summary.scope == InstallScope::System {
        None
    } else {
        let install_path = selection
            .install_base
            .join(&context.package.summary.install_directory);
        if install_path.parent() != Some(selection.install_base.as_path()) {
            return Err(PublicError::new(
                "invalid_install_path",
                "Пакет вернул недопустимую папку.",
            ));
        }
        Some(InstallerDestination {
            install_base: path_text(&selection.install_base)?.into(),
            install_path: path_text(&install_path)?.into(),
        })
    };
    let (action, installed_version, migration, space, can_uninstall) = match selection.preparation {
        PrepareInstallResult::Ready {
            action,
            installed_version,
            publisher_migration_required,
        } => (
            setup_action(action),
            installed_version.clone(),
            publisher_migration_required,
            true,
            installed_version.is_some(),
        ),
        PrepareInstallResult::InsufficientSpace {
            action,
            installed_version,
            publisher_migration_required,
        } => (
            setup_action(action),
            installed_version.clone(),
            publisher_migration_required,
            false,
            installed_version.is_some(),
        ),
        PrepareInstallResult::RecoveryRequired => (SetupAction::Recover, None, false, true, false),
    };
    Ok(InstallerReview {
        package: context.package.summary.clone(),
        destination,
        action,
        installed_version,
        publisher_migration_required: migration,
        space_available: space,
        can_uninstall,
    })
}

fn selection(context: &SetupContext) -> Result<SetupSelection, PublicError> {
    context
        .selection
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Состояние Setup недоступно."))?
        .clone()
        .ok_or_else(|| PublicError::new("busy", "Состояние Setup обновляется."))
}

fn acquire_idle<'a>(
    state: &AppState,
    context: &'a SetupContext,
) -> Result<ExclusiveGuard<'a>, PublicError> {
    let starting = ExclusiveGuard::acquire(
        &context.starting,
        "busy",
        "Другая операция уже выполняется.",
    )?;
    if state.close_started.load(Ordering::Acquire) {
        return Err(PublicError::new("busy", "Установщик закрывается."));
    }
    if state.dialog_open.load(Ordering::Acquire)
        || context
            .active
            .lock()
            .map_err(|_| PublicError::new("internal_error", "Состояние операции недоступно."))?
            .is_some()
    {
        Err(PublicError::new("busy", "Другая операция уже выполняется."))
    } else {
        Ok(starting)
    }
}

fn is_active(context: &SetupContext, operation_id: &str, kind: ActiveKind) -> bool {
    context.active.lock().ok().is_some_and(|active| {
        active
            .as_ref()
            .is_some_and(|active| active.operation_id == operation_id && active.kind == kind)
    })
}

fn clear_active(context: &SetupContext, operation_id: &str) {
    let completion = context.active.lock().ok().and_then(|mut active| {
        active
            .as_ref()
            .is_some_and(|active| active.operation_id == operation_id)
            .then(|| active.take().map(|active| active.completion))
            .flatten()
    });
    if let Some(completion) = completion {
        let (completed, changed) = &*completion;
        let mut completed = completed.lock().unwrap_or_else(|error| error.into_inner());
        *completed = true;
        changed.notify_all();
    }
}

pub(crate) fn verify_runner(state: &AppState) -> Result<(), PublicError> {
    state.require_mode(AppMode::Setup)?;
    let (package, defaults) = load_bound_package(state)?;
    if package.summary.scope == InstallScope::User {
        review(&build_setup_context(state, package, defaults)?)?;
    }
    state.verify_privilege_transport()?;
    Ok(())
}

pub(crate) fn verify_system_authorization(state: &AppState) -> Result<(), PublicError> {
    state.require_mode(AppMode::Setup)?;
    let (package, _) = load_bound_package(state)?;
    if package.summary.scope != InstallScope::System {
        return Err(PublicError::new(
            "wrong_install_scope",
            "Проверка системной установки требует пакет с областью system.",
        ));
    }
    state.verify_privilege_transport()?;
    let backend = state.backend().map_err(PublicError::from)?;
    let executable = backend.executable().map_err(PublicError::from)?;
    let _ = crate::privilege::authorize_system_install(
        executable,
        &package.path,
        &package.id,
        &package.fingerprint,
    )
    .map_err(|_| {
        PublicError::new(
            "system_authorization_failed",
            "Системный компонент не подтвердил пакет и полномочия установки.",
        )
    })?;
    Ok(())
}

impl BoundPackage {
    fn from_backend(path: PathBuf, inspected: InspectResult) -> Result<Self, PublicError> {
        if cfg!(feature = "setup")
            && !cfg!(debug_assertions)
            && !compiled_binding_matches(
                build_bound_package_fingerprint(),
                &inspected.package_fingerprint,
            )
        {
            return Err(PublicError::new(
                "invalid_bound_package",
                "Пакет не совпадает с защищённой сборкой установщика.",
            ));
        }
        let signed = matches!(inspected.trust, PackageTrust::TrustedPublisher { .. });
        let trust_valid = match &inspected.trust {
            PackageTrust::Unsigned {} => true,
            PackageTrust::TrustedPublisher { key_id } => valid_hash(key_id),
        };
        let rotation_valid = match (&inspected.trust, &inspected.publisher_rotation) {
            (PackageTrust::TrustedPublisher { key_id }, Some(rotation)) => {
                inspected.format_version == 3
                    && rotation.signer_key_id == *key_id
                    && rotation.signer_key_id != rotation.next_key_id
                    && valid_hash(&rotation.signer_key_id)
                    && valid_hash(&rotation.next_key_id)
            }
            (_, None) => inspected.format_version != 3,
            _ => false,
        };
        if !matches!(inspected.format_version, 1..=3)
            || !(1..=luxury_spec::MANIFEST_SCHEMA_VERSION as u8).contains(&inspected.schema_version)
            || (inspected.schema_version == 1 && inspected.install.has_entrypoint)
            || (inspected.schema_version < 3 && inspected.package.license.is_some())
            || (inspected.install.shortcuts.application_menu || inspected.install.shortcuts.desktop)
                && (!inspected.install.has_entrypoint
                    || inspected.schema_version < luxury_spec::SHORTCUT_SCHEMA_VERSION as u8)
            || (inspected.format_version == 1) == signed
            || !trust_valid
            || !rotation_valid
            || !valid_hash(&inspected.package_fingerprint)
            || !valid_package_id(&inspected.package.id)
            || !valid_text(&inspected.package.name)
            || !valid_text(&inspected.package.publisher)
            || !valid_text(&inspected.package.version)
            || inspected
                .package
                .description
                .as_deref()
                .is_some_and(|description| !valid_text(description))
            || inspected
                .package
                .license
                .as_deref()
                .is_some_and(|license| !valid_license(license))
            || !valid_install_directory(&inspected.install.directory)
            || inspected.install.finish_links.len() > MAX_FINISH_LINKS
            || inspected.install.finish_links.iter().any(|link| {
                link.label.chars().count() > MAX_FINISH_LINK_LABEL_CHARS
                    || !valid_text(&link.label)
                    || link.label.chars().any(|character| {
                        matches!(
                            character,
                            '\u{061c}'
                                | '\u{200e}'
                                | '\u{200f}'
                                | '\u{202a}'..='\u{202e}'
                                | '\u{2066}'..='\u{2069}'
                        )
                    })
                    || !valid_https_url(&link.url)
            })
            || !valid_install_log(
                inspected.install.show_install_log,
                inspected.payload.install_log.as_ref(),
                inspected.payload.files,
            )
            || inspected.payload.files > MAX_SAFE_INTEGER
            || inspected.payload.bytes > MAX_SAFE_INTEGER
        {
            return Err(PublicError::new(
                "invalid_backend_output",
                "Компонент установщика вернул недопустимый пакет.",
            ));
        }
        Ok(Self {
            path,
            fingerprint: inspected.package_fingerprint,
            id: inspected.package.id,
            summary: PackageSummary {
                name: inspected.package.name,
                publisher: inspected.package.publisher,
                version: inspected.package.version,
                description: inspected.package.description,
                license: inspected.package.license,
                target_os: inspected.target.os,
                target_arch: inspected.target.arch,
                install_directory: inspected.install.directory,
                scope: inspected.install.scope,
                has_entrypoint: inspected.install.has_entrypoint,
                install_log: inspected.payload.install_log,
                finish_links: inspected.install.finish_links,
                shortcuts: inspected.install.shortcuts,
                files: inspected.payload.files,
                bytes: inspected.payload.bytes,
                trust: inspected.trust,
                publisher_rotation: inspected.publisher_rotation,
            },
        })
    }
}

fn compiled_binding_matches(expected: Option<&str>, actual: &str) -> bool {
    expected.is_some_and(|expected| valid_hash(expected) && expected == actual)
}

fn build_bound_package_fingerprint() -> Option<&'static str> {
    std::str::from_utf8(&BUILD_PACKAGE_BINDING.fingerprint)
        .ok()
        .filter(|value| valid_hash(value))
}

fn validate_preparation(preparation: &PrepareInstallResult) -> Result<(), PublicError> {
    let valid = match preparation {
        PrepareInstallResult::Ready {
            action,
            installed_version,
            ..
        }
        | PrepareInstallResult::InsufficientSpace {
            action,
            installed_version,
            ..
        } => {
            matches!(action, PreparedAction::Install) == installed_version.is_none()
                && installed_version.as_deref().is_none_or(valid_text)
        }
        PrepareInstallResult::RecoveryRequired => true,
    };
    if valid {
        Ok(())
    } else {
        Err(PublicError::new(
            "invalid_backend_output",
            "Компонент установки вернул несогласованный план.",
        ))
    }
}

fn validate_install_result(
    context: &SetupContext,
    selection: &SetupSelection,
    result: InstallResult,
) -> Result<InstallResult, PublicError> {
    let action_matches = match &selection.preparation {
        PrepareInstallResult::Ready { action, .. }
        | PrepareInstallResult::InsufficientSpace { action, .. } => {
            result.action
                == match action {
                    PreparedAction::Install => InstallResultAction::Install,
                    PreparedAction::Update => InstallResultAction::Update,
                    PreparedAction::Repair => InstallResultAction::Repair,
                }
        }
        PrepareInstallResult::RecoveryRequired => true,
    };
    if action_matches
        && result.package_id == context.package.id
        && result.install_directory == context.package.summary.install_directory
        && result.installed_files == context.package.summary.files
        && result.installed_bytes == context.package.summary.bytes
    {
        Ok(result)
    } else {
        Err(PublicError::new(
            "invalid_backend_output",
            "Компонент установки вернул другой пакет.",
        ))
    }
}

fn validate_uninstall_result(
    context: &SetupContext,
    result: UninstallResult,
) -> Result<(u64, u64, u64), PublicError> {
    match result {
        UninstallResult::NotInstalled { package_id } if package_id == context.package.id => {
            Ok((0, 0, 0))
        }
        UninstallResult::Uninstalled {
            package_id,
            removed_files,
            missing_files,
            preserved_modified_files,
        } if package_id == context.package.id
            && removed_files
                .checked_add(missing_files)
                .and_then(|total| total.checked_add(preserved_modified_files))
                .is_some_and(|total| total <= MAX_SAFE_INTEGER) =>
        {
            Ok((removed_files, missing_files, preserved_modified_files))
        }
        _ => Err(PublicError::new(
            "invalid_backend_output",
            "Компонент удаления вернул другой пакет.",
        )),
    }
}

fn setup_action(action: PreparedAction) -> SetupAction {
    match action {
        PreparedAction::Install => SetupAction::Install,
        PreparedAction::Update => SetupAction::Update,
        PreparedAction::Repair => SetupAction::Repair,
    }
}

fn absolute_path(value: &str) -> Result<PathBuf, PublicError> {
    let path = PathBuf::from(value);
    if path.is_absolute() && !value.contains('\0') {
        Ok(path)
    } else {
        Err(PublicError::new(
            "invalid_backend_output",
            "Компонент установщика вернул относительный путь.",
        ))
    }
}

fn path_text(path: &Path) -> Result<&str, PublicError> {
    path.to_str()
        .filter(|value| !value.contains('\0'))
        .ok_or_else(|| {
            PublicError::new("invalid_install_path", "Системный путь не поддерживается.")
        })
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_install_log(show: bool, log: Option<&InstallLog>, total_files: u64) -> bool {
    match (show, log) {
        (false, None) => true,
        (true, Some(log)) => {
            log.files.len() <= MAX_INSTALL_LOG_FILES
                && log.files.iter().all(|path| valid_install_log_path(path))
                && u64::try_from(log.files.len())
                    .ok()
                    .and_then(|shown| shown.checked_add(log.omitted_files))
                    == Some(total_files)
        }
        _ => false,
    }
}

fn valid_install_log_path(value: &str) -> bool {
    luxury_spec::PackagePath::parse(value).is_ok()
}

fn valid_https_url(value: &str) -> bool {
    if value.len() > MAX_FINISH_LINK_URL_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.contains(['\\', '\u{061c}', '\u{200e}', '\u{200f}'])
        || value
            .chars()
            .any(|character| matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::backend::{InstallPolicy, PackageIdentity, Payload, Target};

    fn inspected() -> InspectResult {
        InspectResult {
            format_version: 1,
            schema_version: 1,
            package_fingerprint: "a".repeat(64),
            trust: PackageTrust::Unsigned {},
            publisher_rotation: None,
            package: PackageIdentity {
                id: "dev.luxury.demo".into(),
                name: "Luxury Demo".into(),
                publisher: "Luxury Software".into(),
                version: "1.0.0".into(),
                description: None,
                license: None,
            },
            target: Target {
                os: TargetOs::Windows,
                arch: TargetArch::X86_64,
            },
            install: InstallPolicy {
                scope: InstallScope::User,
                directory: "Luxury Demo".into(),
                has_entrypoint: false,
                show_install_log: false,
                finish_links: Vec::new(),
                shortcuts: crate::backend::ShortcutPolicy::default(),
            },
            payload: Payload {
                files: 1,
                bytes: 29,
                install_log: None,
            },
        }
    }

    #[test]
    fn setup_events_use_exact_renderer_field_names() {
        let value = serde_json::to_value(SetupEvent::Progress {
            operation_id: "tauri-1-1".into(),
            completed_files: 1,
            total_files: 2,
            completed_bytes: 3,
            total_bytes: 4,
        })
        .unwrap();
        assert_eq!(
            value,
            json!({
                "kind": "progress",
                "operationId": "tauri-1-1",
                "completedFiles": 1,
                "totalFiles": 2,
                "completedBytes": 3,
                "totalBytes": 4
            })
        );
    }

    #[test]
    fn bound_package_info_is_one_line_and_omits_authority_and_private_content() {
        let mut inspected = inspected();
        inspected.schema_version = luxury_spec::SHORTCUT_SCHEMA_VERSION as u8;
        inspected.package.description = Some("Desktop application".into());
        inspected.package.license = Some("private license body".into());
        inspected.install.has_entrypoint = true;
        inspected.install.show_install_log = true;
        inspected.install.shortcuts.application_menu = true;
        inspected.install.finish_links = vec![FinishLink {
            label: "Support".into(),
            url: "https://example.com/private".into(),
        }];
        inspected.payload.install_log = Some(InstallLog {
            files: vec!["hello.txt".into()],
            omitted_files: 0,
        });
        let target = inspected.target.clone();
        let package =
            BoundPackage::from_backend("private/package.luxpkg".into(), inspected).unwrap();
        let output = serde_json::to_string(&package_info(package, target)).unwrap();

        assert!(!output.contains('\n'));
        assert_eq!(
            serde_json::from_str::<Value>(&output).unwrap(),
            json!({
                "schemaVersion": 2,
                "package": {
                    "id": "dev.luxury.demo",
                    "fingerprint": "a".repeat(64),
                    "name": "Luxury Demo",
                    "publisher": "Luxury Software",
                    "version": "1.0.0",
                    "description": "Desktop application",
                    "trust": {"kind": "unsigned"},
                    "requiresLicense": true,
                    "publisherRotation": false
                },
                "target": {"os": "windows", "arch": "x86_64"},
                "install": {
                    "scope": "user",
                    "directory": "Luxury Demo",
                    "hasEntrypoint": true,
                    "showInstallLog": true,
                    "finishLinks": 1,
                    "shortcuts": {"applicationMenu": true, "desktop": false}
                },
                "payload": {"files": 1, "bytes": 29}
            })
        );
        assert!(!output.contains("private license body"));
        assert!(!output.contains("example.com"));
        assert!(!output.contains("package.luxpkg"));
    }

    #[test]
    fn install_presentation_metadata_is_bounded_and_cross_checked() {
        let mut value = inspected();
        value.package.description = Some("Human-facing application summary.".into());
        value.install.show_install_log = true;
        value.install.finish_links = vec![FinishLink {
            label: "Документация".into(),
            url: "https://example.com/docs".into(),
        }];
        value.payload.install_log = Some(InstallLog {
            files: vec!["hello.txt".into()],
            omitted_files: 0,
        });
        let package = BoundPackage::from_backend("payload.luxpkg".into(), value.clone()).unwrap();
        assert_eq!(
            package.summary.description.as_deref(),
            Some("Human-facing application summary.")
        );
        assert_eq!(package.summary.finish_links.len(), 1);
        assert_eq!(package.summary.install_log.unwrap().files, ["hello.txt"]);

        let mut unsafe_url = value.clone();
        unsafe_url.install.finish_links[0].url = "file:///etc/passwd".into();
        assert!(BoundPackage::from_backend("payload.luxpkg".into(), unsafe_url).is_err());

        let mut mismatched = value.clone();
        mismatched
            .payload
            .install_log
            .as_mut()
            .unwrap()
            .omitted_files = 1;
        assert!(BoundPackage::from_backend("payload.luxpkg".into(), mismatched).is_err());

        let mut invalid_description = value.clone();
        invalid_description.package.description = Some("bad\ndescription".into());
        assert!(BoundPackage::from_backend("payload.luxpkg".into(), invalid_description).is_err());

        let mut unicode_description = value.clone();
        unicode_description.package.description = Some("я".repeat(1024));
        assert!(BoundPackage::from_backend("payload.luxpkg".into(), unicode_description).is_ok());

        value.payload.install_log.as_mut().unwrap().files[0] = "../escape".into();
        assert!(BoundPackage::from_backend("payload.luxpkg".into(), value).is_err());
    }

    #[test]
    fn install_result_must_match_the_inspected_payload_totals() {
        let package = BoundPackage::from_backend("payload.luxpkg".into(), inspected()).unwrap();
        let context = SetupContext {
            package,
            selection: Arc::new(Mutex::new(None)),
            active: Arc::new(Mutex::new(None)),
            starting: Arc::new(AtomicBool::new(false)),
            last_install_path: Arc::new(Mutex::new(None)),
            install_completed: Arc::new(AtomicBool::new(false)),
        };
        let result = InstallResult {
            action: InstallResultAction::Install,
            package_id: context.package.id.clone(),
            installed_files: context.package.summary.files,
            installed_bytes: context.package.summary.bytes,
            install_directory: context.package.summary.install_directory.clone(),
        };
        let selection = SetupSelection {
            install_base: PathBuf::from(r"C:\Programs"),
            state_root: PathBuf::from(r"C:\State"),
            preparation: PrepareInstallResult::Ready {
                action: PreparedAction::Install,
                installed_version: None,
                publisher_migration_required: false,
            },
        };

        assert!(validate_install_result(&context, &selection, result.clone()).is_ok());
        let mut wrong_files = result.clone();
        wrong_files.installed_files += 1;
        assert!(validate_install_result(&context, &selection, wrong_files).is_err());
        let mut wrong_bytes = result.clone();
        wrong_bytes.installed_bytes += 1;
        assert!(validate_install_result(&context, &selection, wrong_bytes).is_err());
        let mut wrong_action = result;
        wrong_action.action = InstallResultAction::Update;
        assert!(validate_install_result(&context, &selection, wrong_action).is_err());

        let update = SetupSelection {
            preparation: PrepareInstallResult::Ready {
                action: PreparedAction::Update,
                installed_version: Some("0.9.0".into()),
                publisher_migration_required: false,
            },
            ..selection
        };
        let update_result = InstallResult {
            action: InstallResultAction::Update,
            package_id: context.package.id.clone(),
            installed_files: context.package.summary.files,
            installed_bytes: context.package.summary.bytes,
            install_directory: context.package.summary.install_directory.clone(),
        };
        assert!(validate_install_result(&context, &update, update_result).is_ok());
    }

    #[test]
    fn uninstall_result_totals_must_fit_one_renderer_safe_integer() {
        let context = SetupContext {
            package: BoundPackage::from_backend("payload.luxpkg".into(), inspected()).unwrap(),
            selection: Arc::new(Mutex::new(None)),
            active: Arc::new(Mutex::new(None)),
            starting: Arc::new(AtomicBool::new(false)),
            last_install_path: Arc::new(Mutex::new(None)),
            install_completed: Arc::new(AtomicBool::new(false)),
        };
        let result =
            |removed_files, missing_files, preserved_modified_files| UninstallResult::Uninstalled {
                package_id: context.package.id.clone(),
                removed_files,
                missing_files,
                preserved_modified_files,
            };

        assert!(validate_uninstall_result(&context, result(1, 0, 0)).is_ok());
        assert!(validate_uninstall_result(&context, result(MAX_SAFE_INTEGER, 1, 0)).is_err());
    }

    #[test]
    fn shutdown_cancels_system_operation_and_waits_for_terminal_cleanup() {
        let completion = Arc::new((Mutex::new(false), Condvar::new()));
        let cancel = Arc::new(AtomicBool::new(false));
        let context = SetupContext {
            package: BoundPackage::from_backend("payload.luxpkg".into(), inspected()).unwrap(),
            selection: Arc::new(Mutex::new(None)),
            active: Arc::new(Mutex::new(Some(ActiveOperation {
                operation_id: "tauri-shutdown-test".into(),
                kind: ActiveKind::Install,
                system_cancel: Some(cancel.clone()),
                completion,
            }))),
            starting: Arc::new(AtomicBool::new(false)),
            last_install_path: Arc::new(Mutex::new(None)),
            install_completed: Arc::new(AtomicBool::new(false)),
        };
        let state = AppState {
            mode: AppMode::Setup,
            backend: Err(crate::backend::BackendError::new("unused", "unused")),
            package_path: None,
            packager_path: None,
            studio: Arc::new(crate::studio::StudioState::default()),
            dialog_open: Arc::new(AtomicBool::new(false)),
            setup: Arc::new(Mutex::new(Some(context.clone()))),
            close_started: Arc::new(AtomicBool::new(false)),
            close_ready: Arc::new(AtomicBool::new(false)),
        };
        let waiter = thread::spawn(move || shutdown_operation(&state));
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !cancel.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(cancel.load(Ordering::Acquire));

        clear_active(&context, "tauri-shutdown-test");

        assert!(waiter.join().unwrap().is_ok());
    }

    #[test]
    fn shutdown_timeout_includes_a_busy_setup_bootstrap_lock() {
        let state = AppState {
            mode: AppMode::Setup,
            backend: Err(crate::backend::BackendError::new("unused", "unused")),
            package_path: None,
            packager_path: None,
            studio: Arc::new(crate::studio::StudioState::default()),
            dialog_open: Arc::new(AtomicBool::new(false)),
            setup: Arc::new(Mutex::new(None)),
            close_started: Arc::new(AtomicBool::new(true)),
            close_ready: Arc::new(AtomicBool::new(false)),
        };
        let setup = Arc::clone(&state.setup);
        let _busy = setup.lock().unwrap();

        let error = shutdown_operation_with_timeout(&state, Duration::from_millis(20)).unwrap_err();

        assert_eq!(error.code, "shutdown_timeout");
    }

    #[test]
    fn shutdown_waits_for_starting_operation_then_cancels_and_waits_for_terminal_cleanup() {
        let completion = Arc::new((Mutex::new(false), Condvar::new()));
        let cancel = Arc::new(AtomicBool::new(false));
        let context = SetupContext {
            package: BoundPackage::from_backend("payload.luxpkg".into(), inspected()).unwrap(),
            selection: Arc::new(Mutex::new(None)),
            active: Arc::new(Mutex::new(None)),
            starting: Arc::new(AtomicBool::new(true)),
            last_install_path: Arc::new(Mutex::new(None)),
            install_completed: Arc::new(AtomicBool::new(false)),
        };
        let state = AppState {
            mode: AppMode::Setup,
            backend: Err(crate::backend::BackendError::new("unused", "unused")),
            package_path: None,
            packager_path: None,
            studio: Arc::new(crate::studio::StudioState::default()),
            dialog_open: Arc::new(AtomicBool::new(false)),
            setup: Arc::new(Mutex::new(Some(context.clone()))),
            close_started: Arc::new(AtomicBool::new(true)),
            close_ready: Arc::new(AtomicBool::new(false)),
        };
        let waiter = thread::spawn(move || shutdown_operation(&state));

        thread::sleep(Duration::from_millis(20));
        assert!(!waiter.is_finished());
        *context.active.lock().unwrap() = Some(ActiveOperation {
            operation_id: "tauri-starting-shutdown-test".into(),
            kind: ActiveKind::Install,
            system_cancel: Some(cancel.clone()),
            completion,
        });
        context.starting.store(false, Ordering::Release);

        let deadline = Instant::now() + Duration::from_secs(1);
        while !cancel.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(cancel.load(Ordering::Acquire));
        clear_active(&context, "tauri-starting-shutdown-test");
        assert!(waiter.join().unwrap().is_ok());
    }

    #[test]
    fn closing_state_cannot_enter_a_new_setup_action() {
        let context = SetupContext {
            package: BoundPackage::from_backend("payload.luxpkg".into(), inspected()).unwrap(),
            selection: Arc::new(Mutex::new(None)),
            active: Arc::new(Mutex::new(None)),
            starting: Arc::new(AtomicBool::new(false)),
            last_install_path: Arc::new(Mutex::new(None)),
            install_completed: Arc::new(AtomicBool::new(false)),
        };
        let state = AppState {
            mode: AppMode::Setup,
            backend: Err(crate::backend::BackendError::new("unused", "unused")),
            package_path: None,
            packager_path: None,
            studio: Arc::new(crate::studio::StudioState::default()),
            dialog_open: Arc::new(AtomicBool::new(false)),
            setup: Arc::new(Mutex::new(Some(context.clone()))),
            close_started: Arc::new(AtomicBool::new(true)),
            close_ready: Arc::new(AtomicBool::new(false)),
        };

        assert_eq!(acquire_idle(&state, &context).err().unwrap().code, "busy");
        assert!(!context.starting.load(Ordering::Acquire));
    }

    #[test]
    fn bound_package_rejects_schema_and_signer_drift() {
        let inspected = inspected();
        assert!(BoundPackage::from_backend("payload.luxpkg".into(), inspected.clone()).is_ok());

        let mut licensed = inspected.clone();
        licensed.schema_version = 3;
        licensed.package.license = Some("Demo license terms.".into());
        let package = BoundPackage::from_backend("payload.luxpkg".into(), licensed).unwrap();
        assert_eq!(
            package.summary.license.as_deref(),
            Some("Demo license terms.")
        );

        let mut invalid_license_schema = inspected.clone();
        invalid_license_schema.package.license = Some("Demo license terms.".into());
        assert!(
            BoundPackage::from_backend("payload.luxpkg".into(), invalid_license_schema).is_err()
        );

        let mut invalid_license_text = inspected.clone();
        invalid_license_text.schema_version = 3;
        invalid_license_text.package.license = Some("invalid\0license".into());
        assert!(BoundPackage::from_backend("payload.luxpkg".into(), invalid_license_text).is_err());

        let mut invalid_schema = inspected.clone();
        invalid_schema.install.has_entrypoint = true;
        assert!(BoundPackage::from_backend("payload.luxpkg".into(), invalid_schema).is_err());

        let mut legacy_shortcut = inspected.clone();
        legacy_shortcut.schema_version = 3;
        legacy_shortcut.install.has_entrypoint = true;
        legacy_shortcut.install.shortcuts.application_menu = true;
        assert!(BoundPackage::from_backend("payload.luxpkg".into(), legacy_shortcut).is_err());

        let mut shortcut_without_entrypoint = inspected.clone();
        shortcut_without_entrypoint.schema_version = luxury_spec::SHORTCUT_SCHEMA_VERSION as u8;
        shortcut_without_entrypoint.install.shortcuts.desktop = true;
        assert!(
            BoundPackage::from_backend("payload.luxpkg".into(), shortcut_without_entrypoint)
                .is_err()
        );

        let mut invalid_signer = inspected;
        invalid_signer.format_version = 2;
        invalid_signer.trust = PackageTrust::TrustedPublisher {
            key_id: "not-a-key-id".into(),
        };
        assert!(BoundPackage::from_backend("payload.luxpkg".into(), invalid_signer).is_err());
    }

    #[test]
    fn compiled_package_binding_is_exact_and_canonical() {
        let fingerprint = "a".repeat(64);
        assert!(compiled_binding_matches(Some(&fingerprint), &fingerprint));
        assert!(!compiled_binding_matches(None, &fingerprint));
        assert!(!compiled_binding_matches(
            Some(&"b".repeat(64)),
            &fingerprint
        ));
        assert!(!compiled_binding_matches(
            Some(&"A".repeat(64)),
            &"A".repeat(64)
        ));
    }

    #[test]
    fn license_consent_is_required_and_cannot_be_unsolicited() {
        assert!(require_license_consent(None, false).is_ok());
        assert!(require_license_consent(Some("Terms"), true).is_ok());
        assert_eq!(
            require_license_consent(Some("Terms"), false)
                .unwrap_err()
                .code,
            "license_not_accepted"
        );
        assert_eq!(
            require_license_consent(None, true).unwrap_err().code,
            "license_not_offered"
        );
    }

    #[test]
    fn successful_user_install_caches_maintenance_review() {
        let package = BoundPackage::from_backend("payload.luxpkg".into(), inspected()).unwrap();
        let previous = SetupSelection {
            install_base: PathBuf::from(r"C:\Programs"),
            state_root: PathBuf::from(r"C:\State"),
            preparation: PrepareInstallResult::Ready {
                action: PreparedAction::Install,
                installed_version: None,
                publisher_migration_required: false,
            },
        };
        let context = SetupContext {
            package,
            selection: Arc::new(Mutex::new(Some(previous.clone()))),
            active: Arc::new(Mutex::new(None)),
            starting: Arc::new(AtomicBool::new(false)),
            last_install_path: Arc::new(Mutex::new(None)),
            install_completed: Arc::new(AtomicBool::new(false)),
        };

        let review =
            cache_completed_selection(&context, &previous, None, PreparedAction::Repair).unwrap();
        assert!(matches!(review.action, SetupAction::Repair));
        assert_eq!(review.installed_version.as_deref(), Some("1.0.0"));
        assert!(review.can_uninstall);
    }

    #[test]
    fn successful_system_install_uses_only_terminal_preparation() {
        let mut inspected = inspected();
        inspected.install.scope = InstallScope::System;
        let previous = SetupSelection {
            install_base: PathBuf::from(r"C:\Programs"),
            state_root: PathBuf::from(r"C:\State"),
            preparation: PrepareInstallResult::Ready {
                action: PreparedAction::Install,
                installed_version: None,
                publisher_migration_required: false,
            },
        };
        let context = SetupContext {
            package: BoundPackage::from_backend("payload.luxpkg".into(), inspected).unwrap(),
            selection: Arc::new(Mutex::new(Some(previous.clone()))),
            active: Arc::new(Mutex::new(None)),
            starting: Arc::new(AtomicBool::new(false)),
            last_install_path: Arc::new(Mutex::new(None)),
            install_completed: Arc::new(AtomicBool::new(false)),
        };

        let review = cache_completed_selection(
            &context,
            &previous,
            Some(PrepareInstallResult::RecoveryRequired),
            PreparedAction::Repair,
        )
        .unwrap();
        assert!(matches!(review.action, SetupAction::Recover));
        assert!(!review.can_uninstall);

        assert!(
            cache_completed_selection(&context, &previous, None, PreparedAction::Repair).is_none()
        );
        assert!(context.selection.lock().unwrap().is_none());
    }

    #[test]
    fn system_terminal_treats_missing_preparation_as_an_uncached_success() {
        let result = system_operation_message(OperationMessage::Complete(Ok(json!({
            "status": "uninstalled",
            "packageId": "dev.luxury.demo",
            "removedFiles": 1,
            "missingFiles": 0,
            "preservedModifiedFiles": 0,
        }))));
        let result = result.unwrap();
        assert!(result.system_preparation.is_none());

        let result = system_operation_message(OperationMessage::Complete(Ok(json!({
            "status": "uninstalled",
            "packageId": "dev.luxury.demo",
            "removedFiles": 1,
            "missingFiles": 0,
            "preservedModifiedFiles": 0,
            "systemPreparation": { "status": "recoveryRequired" },
        }))));
        let result = result.unwrap();
        assert!(matches!(
            result.system_preparation,
            Some(PrepareInstallResult::RecoveryRequired)
        ));
        let OperationMessage::Complete(Ok(Value::Object(result))) = result.message else {
            panic!("system terminal was not preserved");
        };
        assert!(result.get("systemPreparation").is_none());
    }

    #[test]
    fn system_uninstall_event_exposes_only_the_authoritative_terminal_review() {
        let mut inspected = inspected();
        inspected.install.scope = InstallScope::System;
        let selection = SetupSelection {
            install_base: PathBuf::from(r"C:\Programs"),
            state_root: PathBuf::from(r"C:\State"),
            preparation: PrepareInstallResult::Ready {
                action: PreparedAction::Repair,
                installed_version: Some("1.0.0".into()),
                publisher_migration_required: false,
            },
        };
        let context = SetupContext {
            package: BoundPackage::from_backend("payload.luxpkg".into(), inspected).unwrap(),
            selection: Arc::new(Mutex::new(Some(selection.clone()))),
            active: Arc::new(Mutex::new(None)),
            starting: Arc::new(AtomicBool::new(false)),
            last_install_path: Arc::new(Mutex::new(None)),
            install_completed: Arc::new(AtomicBool::new(false)),
        };

        let next = Some(SetupSelection {
            install_base: selection.install_base,
            state_root: selection.state_root,
            preparation: PrepareInstallResult::Ready {
                action: PreparedAction::Install,
                installed_version: None,
                publisher_migration_required: false,
            },
        });
        *context.selection.lock().unwrap() = next;
        let event = SetupEvent::UninstallComplete {
            operation_id: "system-uninstall".into(),
            removed_files: 1,
            missing_files: 0,
            preserved_modified_files: 0,
            review: review(&context).ok().map(Box::new),
        };
        let value = serde_json::to_value(event).unwrap();

        assert_eq!(value["review"]["package"]["scope"], "system");
        assert_eq!(value["review"]["action"], "install");
        assert_eq!(value["review"]["canUninstall"], false);
        assert!(value["review"]["destination"].is_null());
    }

    #[test]
    fn system_review_is_pathless_and_exposes_only_bound_maintenance_intent() {
        let mut system = inspected();
        system.install.scope = InstallScope::System;
        let package = BoundPackage::from_backend("payload.luxpkg".into(), system).unwrap();
        let selection = SetupSelection {
            install_base: PathBuf::from(r"C:\Users\demo\Programs"),
            state_root: PathBuf::from(r"C:\Users\demo\State"),
            preparation: PrepareInstallResult::Ready {
                action: PreparedAction::Repair,
                installed_version: Some("1.0.0".into()),
                publisher_migration_required: false,
            },
        };
        let untrusted_selection_base = selection.install_base.clone();
        let context = SetupContext {
            package,
            selection: Arc::new(Mutex::new(Some(selection))),
            active: Arc::new(Mutex::new(None)),
            starting: Arc::new(AtomicBool::new(false)),
            last_install_path: Arc::new(Mutex::new(None)),
            install_completed: Arc::new(AtomicBool::new(false)),
        };

        let review = review(&context).unwrap();
        assert!(review.destination.is_none());
        assert!(review.can_uninstall);
        assert_eq!(
            installed_reveal_path(&context).unwrap_err().code,
            "nothing_to_reveal"
        );

        context.install_completed.store(true, Ordering::Release);
        let path = installed_reveal_path(&context).unwrap();
        let (system_base, _) = luxury_system_roots::get().unwrap();
        assert_eq!(
            path,
            system_base.join(&context.package.summary.install_directory)
        );
        assert!(!path.starts_with(untrusted_selection_base));
    }
}
