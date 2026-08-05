use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use luxury_process::ChildContainment;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use tempfile::{Builder, NamedTempFile, TempDir};

use crate::{
    app::{
        AppMode, AppState, ExclusiveGuard, PublicError, valid_install_directory, valid_license,
        valid_package_id, valid_text,
    },
    backend::{
        FinishLink, InstallScope, MAX_SAFE_INTEGER, ProjectResult, ResolvedPayloadPath, TargetArch,
        TargetOs, guard_executable,
    },
};

pub(crate) struct StudioState {
    busy: AtomicBool,
    build_active: AtomicBool,
    build_cancel: AtomicBool,
    active: Mutex<Option<ActiveProject>>,
    last_output: Mutex<Option<PathBuf>>,
    recent_path: Option<PathBuf>,
    recent: Mutex<Vec<RecentProject>>,
}

const MAX_RECENT_PROJECTS: usize = 6;
const MAX_RECENT_FILE_BYTES: u64 = 64 * 1024;

impl StudioState {
    pub(crate) fn new(recent_path: Option<PathBuf>) -> Self {
        let recent = recent_path
            .as_deref()
            .map(load_recent_projects)
            .unwrap_or_default();
        Self {
            busy: AtomicBool::new(false),
            build_active: AtomicBool::new(false),
            build_cancel: AtomicBool::new(false),
            active: Mutex::new(None),
            last_output: Mutex::new(None),
            recent_path,
            recent: Mutex::new(recent),
        }
    }
}

impl Default for StudioState {
    fn default() -> Self {
        Self::new(None)
    }
}

#[derive(Clone)]
struct ActiveProject {
    path: PathBuf,
    summary: StudioProject,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecentProject {
    project_path: String,
    name: String,
    publisher: String,
    version: String,
    target_os: TargetOs,
    target_arch: TargetArch,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecentProjectStore {
    schema_version: u8,
    projects: Vec<RecentProject>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioProject {
    project_path: String,
    format_version: u8,
    schema_version: u8,
    package_id: String,
    name: String,
    publisher: String,
    version: String,
    description: Option<String>,
    license: Option<String>,
    has_license: bool,
    target_os: TargetOs,
    target_arch: TargetArch,
    install_directory: String,
    scope: InstallScope,
    allow_downgrade: bool,
    entrypoint: Option<String>,
    has_entrypoint: bool,
    show_install_log: bool,
    finish_links: Vec<FinishLink>,
    executable_files: u64,
    files: u64,
    bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StudioProjectUpdate {
    package_id: String,
    name: String,
    publisher: String,
    version: String,
    description: Option<String>,
    license: Option<String>,
    target_os: TargetOs,
    target_arch: TargetArch,
    install_directory: String,
    scope: InstallScope,
    allow_downgrade: bool,
    entrypoint: Option<String>,
    show_install_log: bool,
    finish_links: Vec<FinishLink>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioBuildResult {
    output_path: String,
    project: StudioProject,
}

#[tauri::command]
pub(crate) async fn create_project(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<StudioProject>, PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || create_project_sync(&app, &window, &state))
        .await
        .map_err(|_| PublicError::new("internal_error", "Операция Studio прервана."))?
}

#[tauri::command]
pub(crate) async fn open_project(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<StudioProject>, PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || open_project_sync(&app, &window, &state))
        .await
        .map_err(|_| PublicError::new("internal_error", "Операция Studio прервана."))?
}

#[tauri::command]
pub(crate) fn get_recent_projects(
    state: State<'_, AppState>,
) -> Result<Vec<RecentProject>, PublicError> {
    state.require_mode(AppMode::Studio)?;
    state
        .studio
        .recent
        .lock()
        .map(|projects| projects.clone())
        .map_err(|_| PublicError::new("internal_error", "Недавние проекты недоступны."))
}

#[tauri::command]
pub(crate) async fn open_recent_project(
    index: u8,
    state: State<'_, AppState>,
) -> Result<StudioProject, PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || open_recent_project_sync(index, &state))
        .await
        .map_err(|_| PublicError::new("internal_error", "Открытие проекта прервано."))?
}

#[tauri::command]
pub(crate) async fn reload_project(
    state: State<'_, AppState>,
) -> Result<StudioProject, PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || reload_project_sync(&state))
        .await
        .map_err(|_| PublicError::new("internal_error", "Проверка Studio прервана."))?
}

#[tauri::command]
pub(crate) async fn update_project(
    input: StudioProjectUpdate,
    state: State<'_, AppState>,
) -> Result<StudioProject, PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || update_project_sync(&state, input))
        .await
        .map_err(|_| PublicError::new("internal_error", "Сохранение Studio прервано."))?
}

#[tauri::command]
pub(crate) async fn import_project_files(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<StudioProject>, PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || import_project_files_sync(&app, &window, &state))
        .await
        .map_err(|_| PublicError::new("internal_error", "Импорт файлов Studio прерван."))?
}

#[tauri::command]
pub(crate) async fn import_project_directory(
    replace: bool,
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<StudioProject>, PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        import_project_directory_sync(&app, &window, &state, replace)
    })
    .await
    .map_err(|_| PublicError::new("internal_error", "Импорт папки Studio прерван."))?
}

#[tauri::command]
pub(crate) async fn choose_project_entrypoint(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<String>, PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        choose_project_entrypoint_sync(&app, &window, &state)
    })
    .await
    .map_err(|_| PublicError::new("internal_error", "Выбор точки запуска прерван."))?
}

#[tauri::command]
pub(crate) async fn reveal_project(state: State<'_, AppState>) -> Result<(), PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || reveal_project_sync(&state))
        .await
        .map_err(|_| PublicError::new("internal_error", "Открытие папки Studio прервано."))?
}

#[tauri::command]
pub(crate) async fn reveal_build_output(state: State<'_, AppState>) -> Result<(), PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || reveal_build_output_sync(&state))
        .await
        .map_err(|_| PublicError::new("internal_error", "Открытие результата сборки прервано."))?
}

#[tauri::command]
pub(crate) async fn build_project(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<StudioBuildResult>, PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || build_project_sync(&app, &window, &state))
        .await
        .map_err(|_| PublicError::new("internal_error", "Сборка Studio прервана."))?
}

pub(crate) fn verify_studio(state: &AppState) -> Result<(), PublicError> {
    state.require_mode(AppMode::Studio)?;
    state.defaults()?;
    state.verify_privilege_transport()?;
    Ok(())
}

pub(crate) fn shutdown(state: &AppState) -> Result<(), PublicError> {
    if state.mode != AppMode::Studio {
        return Ok(());
    }
    state.studio.build_cancel.store(true, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(10);
    while state.studio.build_active.load(Ordering::Acquire) {
        if Instant::now() >= deadline {
            return Err(PublicError::new(
                "project_build_failed",
                "Native-сборка не завершила отмену вовремя.",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}

fn create_project_sync(
    app: &AppHandle,
    window: &WebviewWindow,
    state: &AppState,
) -> Result<Option<StudioProject>, PublicError> {
    let _busy = ExclusiveGuard::acquire(
        &state.studio.busy,
        "busy",
        "Другая операция Studio уже выполняется.",
    )?;
    let Some(path) = choose_directory(app, window, state, "Создать проект")? else {
        return Ok(None);
    };
    let backend = state.backend().map_err(PublicError::from)?;
    let project: ProjectResult = backend
        .request_operation("initProject", json!({ "projectPath": path_text(&path)? }))
        .map_err(PublicError::from)?;
    let summary = StudioProject::from_backend(&path, project)?;
    set_active_project(state, path, &summary)?;
    Ok(Some(summary))
}

fn open_project_sync(
    app: &AppHandle,
    window: &WebviewWindow,
    state: &AppState,
) -> Result<Option<StudioProject>, PublicError> {
    let _busy = ExclusiveGuard::acquire(
        &state.studio.busy,
        "busy",
        "Другая операция Studio уже выполняется.",
    )?;
    let Some(path) = choose_directory(app, window, state, "Открыть проект")? else {
        return Ok(None);
    };
    let backend = state.backend().map_err(PublicError::from)?;
    let project: ProjectResult = backend
        .request_operation(
            "validateProject",
            json!({ "projectPath": path_text(&path)? }),
        )
        .map_err(PublicError::from)?;
    let summary = StudioProject::from_backend(&path, project)?;
    set_active_project(state, path, &summary)?;
    Ok(Some(summary))
}

fn open_recent_project_sync(index: u8, state: &AppState) -> Result<StudioProject, PublicError> {
    let _busy = ExclusiveGuard::acquire(
        &state.studio.busy,
        "busy",
        "Другая операция Studio уже выполняется.",
    )?;
    let path = state
        .studio
        .recent
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Недавние проекты недоступны."))?
        .get(usize::from(index))
        .map(|project| PathBuf::from(&project.project_path))
        .ok_or_else(|| PublicError::new("project_not_open", "Недавний проект не найден."))?;
    let backend = state.backend().map_err(PublicError::from)?;
    let project: ProjectResult = match backend.request_operation(
        "validateProject",
        json!({ "projectPath": path_text(&path)? }),
    ) {
        Ok(project) => project,
        Err(error) => {
            if error.code == "project_validation_failed" {
                remove_recent_project(state, &path);
            }
            return Err(PublicError::from(error));
        }
    };
    let summary = StudioProject::from_backend(&path, project)?;
    set_active_project(state, path, &summary)?;
    Ok(summary)
}

fn reload_project_sync(state: &AppState) -> Result<StudioProject, PublicError> {
    let _busy = ExclusiveGuard::acquire(
        &state.studio.busy,
        "busy",
        "Другая операция Studio уже выполняется.",
    )?;
    let active = active_project(state)?;
    let backend = state.backend().map_err(PublicError::from)?;
    let project: ProjectResult = backend
        .request_operation(
            "validateProject",
            json!({ "projectPath": path_text(&active.path)? }),
        )
        .map_err(PublicError::from)?;
    let summary = StudioProject::from_backend(&active.path, project)?;
    set_active_project(state, active.path, &summary)?;
    Ok(summary)
}

fn update_project_sync(
    state: &AppState,
    input: StudioProjectUpdate,
) -> Result<StudioProject, PublicError> {
    let _busy = ExclusiveGuard::acquire(
        &state.studio.busy,
        "busy",
        "Другая операция Studio уже выполняется.",
    )?;
    let active = active_project(state)?;
    if active.summary.format_version != 1 {
        return Err(PublicError::new(
            "project_update_failed",
            "Подписанные проекты редактируются через CLI.",
        ));
    }
    validate_project_update(&input)?;
    let backend = state.backend().map_err(PublicError::from)?;
    let project: ProjectResult = backend
        .request_operation(
            "updateProject",
            json!({
                "projectPath": path_text(&active.path)?,
                "package": {
                    "id": input.package_id,
                    "name": input.name,
                    "version": input.version,
                    "publisher": input.publisher,
                    "description": input.description,
                    "license": input.license,
                },
                "target": {
                    "os": input.target_os,
                    "arch": input.target_arch,
                },
                "install": {
                    "scope": input.scope,
                    "directory": input.install_directory,
                    "allowDowngrade": input.allow_downgrade,
                    "entrypoint": input.entrypoint,
                    "showInstallLog": input.show_install_log,
                    "finishLinks": input.finish_links,
                },
            }),
        )
        .map_err(PublicError::from)?;
    let summary = StudioProject::from_backend(&active.path, project)?;
    set_active_project(state, active.path, &summary)?;
    Ok(summary)
}

fn import_project_files_sync(
    app: &AppHandle,
    window: &WebviewWindow,
    state: &AppState,
) -> Result<Option<StudioProject>, PublicError> {
    import_project_payload_sync(app, window, state, false, false)
}

fn import_project_directory_sync(
    app: &AppHandle,
    window: &WebviewWindow,
    state: &AppState,
    replace: bool,
) -> Result<Option<StudioProject>, PublicError> {
    import_project_payload_sync(app, window, state, true, replace)
}

fn import_project_payload_sync(
    app: &AppHandle,
    window: &WebviewWindow,
    state: &AppState,
    directory: bool,
    replace: bool,
) -> Result<Option<StudioProject>, PublicError> {
    let _busy = ExclusiveGuard::acquire(
        &state.studio.busy,
        "busy",
        "Другая операция Studio уже выполняется.",
    )?;
    let active = active_project(state)?;
    if active.summary.format_version != 1 {
        return Err(PublicError::new(
            "project_import_failed",
            "Подписанные проекты изменяются через CLI.",
        ));
    }
    let _dialog = ExclusiveGuard::acquire(
        &state.dialog_open,
        "dialog_busy",
        "Другой системный диалог уже открыт.",
    )?;
    let dialog = app
        .dialog()
        .file()
        .set_parent(window)
        .set_title(if replace {
            "Заменить файлы приложения содержимым папки"
        } else if directory {
            "Добавить папку в пакет"
        } else {
            "Добавить файлы в пакет"
        });
    let selected = if directory {
        dialog.blocking_pick_folder().map(|path| vec![path])
    } else {
        dialog.blocking_pick_files()
    };
    let Some(selected) = selected else {
        return Ok(None);
    };
    let source_paths = selected
        .into_iter()
        .map(|path| {
            path.into_path().map_err(|_| {
                PublicError::new("invalid_import_path", "Выбран недопустимый путь импорта.")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source_paths = source_paths
        .iter()
        .map(|path| path_text(path))
        .collect::<Result<Vec<_>, _>>()?;
    let backend = state.backend().map_err(PublicError::from)?;
    let project: ProjectResult = backend
        .request_operation(
            "importPayload",
            json!({
                "projectPath": path_text(&active.path)?,
                "sourcePaths": source_paths,
                "replace": replace,
            }),
        )
        .map_err(PublicError::from)?;
    let summary = StudioProject::from_backend(&active.path, project)?;
    set_active_project(state, active.path, &summary)?;
    Ok(Some(summary))
}

fn choose_project_entrypoint_sync(
    app: &AppHandle,
    window: &WebviewWindow,
    state: &AppState,
) -> Result<Option<String>, PublicError> {
    let _busy = ExclusiveGuard::acquire(
        &state.studio.busy,
        "busy",
        "Другая операция Studio уже выполняется.",
    )?;
    let active = active_project(state)?;
    if active.summary.format_version != 1 {
        return Err(PublicError::new(
            "payload_path_invalid",
            "Подписанные проекты изменяются через CLI.",
        ));
    }
    let _dialog = ExclusiveGuard::acquire(
        &state.dialog_open,
        "dialog_busy",
        "Другой системный диалог уже открыт.",
    )?;
    let payload = active.path.join("payload");
    let start = if payload.is_dir() {
        payload.as_path()
    } else {
        active.path.as_path()
    };
    let selected = app
        .dialog()
        .file()
        .set_parent(window)
        .set_title("Выбрать точку запуска")
        .set_directory(start)
        .blocking_pick_file()
        .map(|path| {
            path.into_path().map_err(|_| {
                PublicError::new("invalid_import_path", "Выбран недопустимый путь файла.")
            })
        })
        .transpose()?;
    let Some(selected) = selected else {
        return Ok(None);
    };
    let backend = state.backend().map_err(PublicError::from)?;
    let resolved: ResolvedPayloadPath = backend
        .request_operation(
            "resolvePayloadPath",
            json!({
                "projectPath": path_text(&active.path)?,
                "selectedPath": path_text(&selected)?,
            }),
        )
        .map_err(PublicError::from)?;
    if !valid_portable_path(&resolved.path) {
        return Err(PublicError::new(
            "invalid_backend_output",
            "Компонент Studio вернул недопустимую точку запуска.",
        ));
    }
    Ok(Some(resolved.path))
}

fn reveal_project_sync(state: &AppState) -> Result<(), PublicError> {
    let _busy = ExclusiveGuard::acquire(
        &state.studio.busy,
        "busy",
        "Другая операция Studio уже выполняется.",
    )?;
    let project = active_project(state)?;
    tauri_plugin_opener::open_path(project.path, None::<&str>)
        .map_err(|_| PublicError::new("project_reveal_failed", "Не удалось открыть папку проекта."))
}

fn reveal_build_output_sync(state: &AppState) -> Result<(), PublicError> {
    let output = state
        .studio
        .last_output
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Результат сборки недоступен."))?
        .clone()
        .ok_or_else(|| PublicError::new("build_output_missing", "Сначала соберите установщик."))?;
    let metadata = fs::symlink_metadata(&output).map_err(|_| {
        PublicError::new(
            "build_output_missing",
            "Собранный установщик больше не найден в выбранной папке.",
        )
    })?;
    if metadata.is_dir() {
        tauri_plugin_opener::open_path(output, None::<&str>)
    } else if metadata.is_file() {
        tauri_plugin_opener::reveal_item_in_dir(output)
    } else {
        return Err(PublicError::new(
            "build_output_missing",
            "Результат сборки имеет неподдерживаемый тип.",
        ));
    }
    .map_err(|_| {
        PublicError::new(
            "build_output_reveal_failed",
            "Не удалось показать собранный установщик.",
        )
    })
}

fn build_project_sync(
    app: &AppHandle,
    window: &WebviewWindow,
    state: &AppState,
) -> Result<Option<StudioBuildResult>, PublicError> {
    let _busy = ExclusiveGuard::acquire(
        &state.studio.busy,
        "busy",
        "Другая операция Studio уже выполняется.",
    )?;
    let project = active_project(state)?;
    if project.summary.format_version != 1 {
        return Err(PublicError::new(
            "project_build_failed",
            "Подписанные пакеты собираются только через CLI.",
        ));
    }
    let host = state.defaults()?.target;
    if project.summary.target_os != host.os || project.summary.target_arch != host.arch {
        return Err(PublicError::new(
            "project_build_failed",
            "Соберите проект на выбранной целевой системе или через native build matrix.",
        ));
    }
    let version = project
        .summary
        .version
        .chars()
        .take(48)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let _dialog = ExclusiveGuard::acquire(
        &state.dialog_open,
        "dialog_busy",
        "Другой системный диалог уже открыт.",
    )?;
    let directory = project.path.parent().unwrap_or(Path::new("."));
    let output = match host.os {
        TargetOs::Windows => app
            .dialog()
            .file()
            .set_parent(window)
            .set_title("Собрать Windows Setup")
            .set_directory(directory)
            .set_file_name(format!(
                "{}-{version}-Setup.exe",
                project.summary.package_id
            ))
            .add_filter("Windows installer", &["exe"])
            .blocking_save_file()
            .map(file_path)
            .transpose()?,
        TargetOs::Linux => app
            .dialog()
            .file()
            .set_parent(window)
            .set_title("Выберите папку для Linux installers")
            .set_directory(directory)
            .blocking_pick_folder()
            .map(file_path)
            .transpose()?
            .map(|parent| {
                parent.join(format!(
                    "{}-{version}-linux-{}",
                    project.summary.package_id,
                    match host.arch {
                        TargetArch::X86_64 => "x86_64",
                        TargetArch::Aarch64 => "aarch64",
                    }
                ))
            }),
        TargetOs::Macos => app
            .dialog()
            .file()
            .set_parent(window)
            .set_title("Собрать macOS DMG")
            .set_directory(directory)
            .set_file_name(format!("{}-{version}.dmg", project.summary.package_id))
            .add_filter("macOS installer", &["dmg"])
            .blocking_save_file()
            .map(file_path)
            .transpose()?,
    };
    let Some(output) = output else {
        return Ok(None);
    };
    drop(_dialog);
    let output_path = path_text(&output)?.to_owned();
    let packager = state.packager_path.as_deref().ok_or_else(|| {
        PublicError::new("project_build_failed", "Компонент native-сборки не найден.")
    })?;
    if state.close_started.load(Ordering::Acquire) {
        return Err(PublicError::new(
            "project_build_cancelled",
            "Сборка отменена при закрытии Studio.",
        ));
    }
    let _build_active = ExclusiveGuard::acquire(
        &state.studio.build_active,
        "busy",
        "Другая native-сборка уже выполняется.",
    )?;
    state.studio.build_cancel.store(false, Ordering::Release);
    if state.close_started.load(Ordering::Acquire) {
        return Err(PublicError::new(
            "project_build_cancelled",
            "Сборка отменена при закрытии Studio.",
        ));
    }
    run_native_packager(packager, &project.path, &output, &state.studio.build_cancel)?;
    drop(_build_active);
    let backend = state.backend().map_err(PublicError::from)?;
    let project_result: ProjectResult = backend
        .request_operation(
            "validateProject",
            json!({ "projectPath": path_text(&project.path)? }),
        )
        .map_err(PublicError::from)?;
    let summary = StudioProject::from_backend(&project.path, project_result)?;
    set_active_project(state, project.path, &summary)?;
    *state
        .studio
        .last_output
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Результат сборки недоступен."))? =
        Some(output.clone());
    Ok(Some(StudioBuildResult {
        output_path,
        project: summary,
    }))
}

fn file_path(path: tauri_plugin_dialog::FilePath) -> Result<PathBuf, PublicError> {
    path.into_path().map_err(|_| {
        PublicError::new(
            "invalid_package_path",
            "Выбран недопустимый путь установщика.",
        )
    })
}

fn run_native_packager(
    executable: &Path,
    project: &Path,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<(), PublicError> {
    const BUILD_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
    if cancel.load(Ordering::Acquire) {
        return Err(PublicError::new(
            "project_build_cancelled",
            "Сборка отменена.",
        ));
    }
    let _guard = guard_executable(executable).map_err(|_| {
        PublicError::new(
            "project_build_failed",
            "Компонент native-сборки недоступен.",
        )
    })?;
    let output_parent = output.parent().ok_or_else(|| {
        PublicError::new(
            "project_build_failed",
            "Папка для native-сборки недоступна.",
        )
    })?;
    let work = Builder::new()
        .prefix(".luxury-studio-build-")
        .tempdir_in(output_parent)
        .map_err(|_| {
            PublicError::new(
                "project_build_failed",
                "Не удалось подготовить временную папку native-сборки.",
            )
        })?;
    let mut command = Command::new(executable);
    command
        .arg("__managed-project-installer")
        .arg(project)
        .arg(output)
        .arg(work.path())
        .current_dir(executable.parent().ok_or_else(|| {
            PublicError::new(
                "project_build_failed",
                "Компонент native-сборки расположен неверно.",
            )
        })?);
    let result = supervise_native_packager(command, cancel, BUILD_TIMEOUT);
    finish_managed_native_build(result, work)
}

fn finish_managed_native_build(
    result: Result<(), PublicError>,
    work: TempDir,
) -> Result<(), PublicError> {
    let cleanup = cleanup_native_build_work(work);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

fn cleanup_native_build_work(work: TempDir) -> Result<(), PublicError> {
    const ATTEMPTS: usize = 20;
    for attempt in 0..ATTEMPTS {
        match fs::remove_dir_all(work.path()) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error)
                if cfg!(windows)
                    && error.kind() == std::io::ErrorKind::PermissionDenied
                    && attempt + 1 < ATTEMPTS =>
            {
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }
    Err(PublicError::new(
        "project_build_failed",
        "Не удалось очистить временные файлы native-сборки.",
    ))
}

fn supervise_native_packager(
    mut command: Command,
    cancel: &AtomicBool,
    timeout: Duration,
) -> Result<(), PublicError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let (mut child, mut containment) = ChildContainment::spawn_hidden(&mut command, timeout)
        .map_err(|_| {
            PublicError::new(
                "project_build_failed",
                "Не удалось запустить native-сборку.",
            )
        })?;
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            finish_native_packager(&mut child, &mut containment, false)?;
            return Err(PublicError::new(
                "project_build_failed",
                "Native-сборка не открыла защищённый канал диагностики.",
            ));
        }
    };
    let (diagnostics_tx, diagnostics) = mpsc::sync_channel(1);
    if thread::Builder::new()
        .name("native-packager-stderr".into())
        .spawn(move || {
            let _ = diagnostics_tx.send(drain_native_diagnostics(stderr));
        })
        .is_err()
    {
        finish_native_packager(&mut child, &mut containment, false)?;
        return Err(PublicError::new(
            "project_build_failed",
            "Не удалось запустить защищённый канал диагностики native-сборки.",
        ));
    }
    loop {
        if cancel.load(Ordering::Acquire) {
            finish_native_packager(&mut child, &mut containment, false)?;
            return Err(PublicError::new(
                "project_build_cancelled",
                "Сборка отменена.",
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let timed_out = containment.timed_out();
                finish_native_packager(&mut child, &mut containment, true)?;
                if timed_out {
                    return Err(PublicError::new(
                        "project_build_failed",
                        "Native-сборка превысила лимит времени.",
                    ));
                }
                if status.success() {
                    return Ok(());
                }
                let diagnostics = diagnostics
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap_or_default();
                return Err(native_packager_error(
                    &diagnostics,
                    "Native-сборка завершилась с ошибкой.",
                ));
            }
            Ok(None) if containment.timed_out() => {
                finish_native_packager(&mut child, &mut containment, false)?;
                return Err(PublicError::new(
                    "project_build_failed",
                    "Native-сборка превысила лимит времени.",
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                finish_native_packager(&mut child, &mut containment, false)?;
                return Err(PublicError::new(
                    "project_build_failed",
                    "Не удалось дождаться native-сборки.",
                ));
            }
        }
    }
}

fn finish_native_packager(
    child: &mut std::process::Child,
    containment: &mut ChildContainment,
    primary_exited: bool,
) -> Result<(), PublicError> {
    let termination = if primary_exited {
        containment.terminate_after_primary_exit(child)
    } else {
        containment.terminate()
    };
    if termination.is_err() && !primary_exited {
        // Best-effort primary fallback only; the containment error still makes the build fail.
        let _ = child.kill();
    }
    let waited = child.wait();
    containment.disarm();
    if termination.is_err() || waited.is_err() {
        Err(PublicError::new(
            "project_build_failed",
            "Не удалось завершить все процессы native-сборки.",
        ))
    } else {
        Ok(())
    }
}

fn drain_native_diagnostics(mut source: impl Read) -> Vec<u8> {
    const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;
    let mut tail = Vec::with_capacity(MAX_DIAGNOSTIC_BYTES);
    let mut buffer = [0_u8; 4 * 1024];
    while let Ok(read) = source.read(&mut buffer) {
        if read == 0 {
            break;
        }
        if read >= MAX_DIAGNOSTIC_BYTES {
            tail.clear();
            tail.extend_from_slice(&buffer[read - MAX_DIAGNOSTIC_BYTES..read]);
            continue;
        }
        let overflow = tail
            .len()
            .saturating_add(read)
            .saturating_sub(MAX_DIAGNOSTIC_BYTES);
        if overflow != 0 {
            tail.drain(..overflow);
        }
        tail.extend_from_slice(&buffer[..read]);
    }
    tail
}

fn native_packager_error(diagnostics: &[u8], fallback: &str) -> PublicError {
    let detail = String::from_utf8_lossy(diagnostics)
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| {
            line.chars()
                .filter(|character| {
                    !character.is_control()
                        && !matches!(
                            character,
                            '\u{061c}'
                                | '\u{200e}'
                                | '\u{200f}'
                                | '\u{202a}'..='\u{202e}'
                                | '\u{2066}'..='\u{2069}'
                        )
                })
                .take(512)
                .collect::<String>()
        })
        .filter(|line| !line.is_empty());
    PublicError::new(
        "project_build_failed",
        detail.map_or_else(
            || fallback.to_owned(),
            |detail| format!("{fallback} {detail}"),
        ),
    )
}

fn active_project(state: &AppState) -> Result<ActiveProject, PublicError> {
    state
        .studio
        .active
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Состояние Studio недоступно."))?
        .clone()
        .ok_or_else(|| PublicError::new("project_not_open", "Сначала откройте проект."))
}

fn set_active_project(
    state: &AppState,
    path: PathBuf,
    summary: &StudioProject,
) -> Result<(), PublicError> {
    let recent_path = path.clone();
    *state
        .studio
        .active
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Состояние Studio недоступно."))? =
        Some(ActiveProject {
            path,
            summary: summary.clone(),
        });
    record_recent_project(state, &recent_path, summary);
    Ok(())
}

fn record_recent_project(state: &AppState, path: &Path, summary: &StudioProject) {
    let Ok(mut recent) = state.studio.recent.lock() else {
        return;
    };
    recent.retain(|project| Path::new(&project.project_path) != path);
    recent.insert(
        0,
        RecentProject {
            project_path: summary.project_path.clone(),
            name: summary.name.clone(),
            publisher: summary.publisher.clone(),
            version: summary.version.clone(),
            target_os: summary.target_os,
            target_arch: summary.target_arch,
        },
    );
    recent.truncate(MAX_RECENT_PROJECTS);
    let snapshot = recent.clone();
    drop(recent);
    if let Some(path) = state.studio.recent_path.as_deref() {
        let _ = persist_recent_projects(path, &snapshot);
    }
}

fn remove_recent_project(state: &AppState, path: &Path) {
    let Ok(mut recent) = state.studio.recent.lock() else {
        return;
    };
    recent.retain(|project| Path::new(&project.project_path) != path);
    let snapshot = recent.clone();
    drop(recent);
    if let Some(path) = state.studio.recent_path.as_deref() {
        let _ = persist_recent_projects(path, &snapshot);
    }
}

fn load_recent_projects(path: &Path) -> Vec<RecentProject> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Vec::new();
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_RECENT_FILE_BYTES
    {
        return Vec::new();
    }
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    let Ok(store) = serde_json::from_slice::<RecentProjectStore>(&bytes) else {
        return Vec::new();
    };
    if store.schema_version != 1 || store.projects.len() > MAX_RECENT_PROJECTS {
        return Vec::new();
    }
    store
        .projects
        .into_iter()
        .filter(valid_recent_project)
        .collect()
}

fn valid_recent_project(project: &RecentProject) -> bool {
    Path::new(&project.project_path).is_absolute()
        && !project.project_path.contains('\0')
        && valid_text(&project.name)
        && valid_text(&project.publisher)
        && valid_text(&project.version)
}

fn persist_recent_projects(path: &Path, projects: &[RecentProject]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "recent project store has no parent".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create recent project directory: {error}"))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("could not inspect recent project directory: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("recent project directory is not a real directory".into());
    }
    let mut bytes = serde_json::to_vec_pretty(&RecentProjectStore {
        schema_version: 1,
        projects: projects.to_vec(),
    })
    .map_err(|error| format!("could not serialize recent projects: {error}"))?;
    bytes.push(b'\n');
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| format!("could not create recent project staging file: {error}"))?;
    temporary
        .write_all(&bytes)
        .map_err(|error| format!("could not write recent projects: {error}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("could not sync recent projects: {error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("could not publish recent projects: {}", error.error))?;
    #[cfg(unix)]
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("could not sync recent project directory: {error}"))?;
    Ok(())
}

fn choose_directory(
    app: &AppHandle,
    window: &WebviewWindow,
    state: &AppState,
    title: &'static str,
) -> Result<Option<PathBuf>, PublicError> {
    let _dialog = ExclusiveGuard::acquire(
        &state.dialog_open,
        "dialog_busy",
        "Другой системный диалог уже открыт.",
    )?;
    app.dialog()
        .file()
        .set_parent(window)
        .set_title(title)
        .blocking_pick_folder()
        .map(|path| {
            path.into_path().map_err(|_| {
                PublicError::new("invalid_package_path", "Выбран недопустимый путь проекта.")
            })
        })
        .transpose()
}

impl StudioProject {
    fn from_backend(path: &Path, project: ProjectResult) -> Result<Self, PublicError> {
        if !path.is_absolute()
            || !matches!(project.format_version, 1..=3)
            || !matches!(project.schema_version, 1..=3)
            || (project.schema_version < 3 && project.package.license.is_some())
            || !valid_package_id(&project.package.id)
            || !valid_text(&project.package.name)
            || !valid_text(&project.package.publisher)
            || !valid_text(&project.package.version)
            || project
                .package
                .description
                .as_deref()
                .is_some_and(|description| !valid_text(description))
            || project
                .package
                .license
                .as_deref()
                .is_some_and(|license| !valid_license(license))
            || !valid_install_directory(&project.install.directory)
            || project
                .authoring
                .entrypoint
                .as_deref()
                .is_some_and(|path| !valid_portable_path(path))
            || project.authoring.executable_files > project.payload.files
            || project.payload.files > MAX_SAFE_INTEGER
            || project.payload.bytes > MAX_SAFE_INTEGER
        {
            return Err(PublicError::new(
                "invalid_backend_output",
                "Компонент Studio вернул недопустимый проект.",
            ));
        }
        Ok(Self {
            project_path: path_text(path)?.into(),
            format_version: project.format_version,
            schema_version: project.schema_version,
            package_id: project.package.id,
            name: project.package.name,
            publisher: project.package.publisher,
            version: project.package.version,
            description: project.package.description,
            license: project.package.license.clone(),
            has_license: project.package.license.is_some(),
            target_os: project.target.os,
            target_arch: project.target.arch,
            install_directory: project.install.directory,
            scope: project.install.scope,
            allow_downgrade: project.authoring.allow_downgrade,
            entrypoint: project.authoring.entrypoint,
            has_entrypoint: project.install.has_entrypoint,
            show_install_log: project.install.show_install_log,
            finish_links: project.install.finish_links,
            executable_files: project.authoring.executable_files,
            files: project.payload.files,
            bytes: project.payload.bytes,
        })
    }
}

fn validate_project_update(input: &StudioProjectUpdate) -> Result<(), PublicError> {
    let optional_text_valid = |value: Option<&str>| value.is_none_or(valid_text);
    if !valid_package_id(&input.package_id)
        || !valid_text(&input.name)
        || !valid_text(&input.publisher)
        || !valid_text(&input.version)
        || !optional_text_valid(input.description.as_deref())
        || input
            .license
            .as_deref()
            .is_some_and(|license| !valid_license(license))
        || !valid_install_directory(&input.install_directory)
        || input
            .entrypoint
            .as_deref()
            .is_some_and(|path| !valid_portable_path(path))
        || input.finish_links.len() > 4
        || input.finish_links.iter().any(|link| {
            !valid_text(&link.label)
                || link.label.chars().count() > 48
                || link.url.len() > 2_048
                || !link.url.starts_with("https://")
                || link.url.contains(['\\', '\0'])
        })
    {
        return Err(PublicError::new(
            "project_update_failed",
            "Проверьте поля проекта и повторите сохранение.",
        ));
    }
    Ok(())
}

fn valid_portable_path(value: &str) -> bool {
    luxury_spec::PackagePath::parse(value).is_ok()
}

fn path_text(path: &Path) -> Result<&str, PublicError> {
    path.to_str()
        .filter(|value| !value.contains('\0'))
        .ok_or_else(|| {
            PublicError::new("invalid_package_path", "Системный путь не поддерживается.")
        })
}

#[cfg(test)]
mod tests {
    use std::{env, sync::Arc};

    use super::*;
    use crate::backend::{
        InstallPolicy, InstallScope, PackageIdentity, Payload, ProjectAuthoring, Target,
        TargetArch, TargetOs,
    };

    fn project(schema_version: u8, license: Option<&str>) -> ProjectResult {
        ProjectResult {
            format_version: 1,
            schema_version,
            package: PackageIdentity {
                id: "dev.luxury.demo".into(),
                name: "Luxury Demo".into(),
                publisher: "Luxury Software".into(),
                version: "1.0.0".into(),
                description: None,
                license: license.map(str::to_owned),
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
            },
            payload: Payload {
                files: 1,
                bytes: 29,
                install_log: None,
            },
            authoring: ProjectAuthoring {
                allow_downgrade: false,
                entrypoint: None,
                executable_files: 0,
            },
        }
    }

    #[test]
    fn studio_exposes_only_valid_schema_three_license_state() {
        let path = std::env::temp_dir().join("luxury-studio-project");
        let licensed =
            StudioProject::from_backend(&path, project(3, Some("First line.\nSecond line.")))
                .unwrap();
        assert!(licensed.has_license);
        assert!(StudioProject::from_backend(&path, project(2, Some("Terms"))).is_err());
        assert!(StudioProject::from_backend(&path, project(3, Some("bad\0text"))).is_err());
    }

    #[test]
    fn recent_projects_persist_strict_bounded_display_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recent.json");
        let recent = RecentProject {
            project_path: temp.path().join("demo").to_string_lossy().into_owned(),
            name: "Luxury Demo".into(),
            publisher: "Luxury Software".into(),
            version: "1.0.0".into(),
            target_os: TargetOs::Windows,
            target_arch: TargetArch::X86_64,
        };
        persist_recent_projects(&path, std::slice::from_ref(&recent)).unwrap();
        assert_eq!(load_recent_projects(&path), vec![recent]);

        let updated = RecentProject {
            version: "2.0.0".into(),
            ..load_recent_projects(&path).pop().unwrap()
        };
        persist_recent_projects(&path, std::slice::from_ref(&updated)).unwrap();
        assert_eq!(load_recent_projects(&path), vec![updated]);

        fs::write(
            &path,
            br#"{"schemaVersion":1,"projects":[{"projectPath":"relative","name":"Demo","publisher":"Publisher","version":"1.0.0","targetOs":"windows","targetArch":"x86_64"}]}"#,
        )
        .unwrap();
        assert!(load_recent_projects(&path).is_empty());
    }

    #[test]
    fn pre_cancelled_native_build_never_opens_the_packager() {
        let cancel = AtomicBool::new(true);
        let error = run_native_packager(
            Path::new("missing-packager"),
            Path::new("missing-project"),
            Path::new("missing-output"),
            &cancel,
        )
        .unwrap_err();
        assert_eq!(error.code, "project_build_cancelled");
    }

    #[test]
    fn managed_native_work_is_removed_after_build_cancellation() {
        let parent = tempfile::tempdir().unwrap();
        let work = Builder::new()
            .prefix(".luxury-studio-build-")
            .tempdir_in(parent.path())
            .unwrap();
        let path = work.path().to_owned();
        let nested = path.join(".luxury-assemble-child");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("partial"), b"partial").unwrap();

        let error = finish_managed_native_build(
            Err(PublicError::new(
                "project_build_cancelled",
                "Сборка отменена.",
            )),
            work,
        )
        .unwrap_err();
        assert_eq!(error.code, "project_build_cancelled");
        assert!(!path.exists());
    }

    #[test]
    fn cancelled_native_build_terminates_packager_descendants() {
        const MODE: &str = "LUXURY_NATIVE_PACKAGER_HELPER";
        match env::var(MODE).as_deref() {
            Ok("parent") => return native_packager_parent(),
            Ok("grandchild") => return native_packager_grandchild(),
            Ok("empty") => return,
            _ => {}
        }

        let temp = tempfile::tempdir().unwrap();
        let ready = temp.path().join("descendant-ready");
        let sentinel = temp.path().join("descendant-survived");
        let executable = env::current_exe().unwrap();
        let test_name = native_packager_test_name();
        let mut command = Command::new(executable);
        command
            .args(["--exact", &test_name, "--nocapture"])
            .env(MODE, "parent")
            .env("LUXURY_NATIVE_PACKAGER_READY", &ready)
            .env("LUXURY_NATIVE_PACKAGER_SENTINEL", &sentinel);
        let cancel = Arc::new(AtomicBool::new(false));
        let cancellation = Arc::clone(&cancel);
        let ready_signal = ready.clone();
        let request_cancel = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready_signal.is_file() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            cancellation.store(true, Ordering::Release);
        });

        let error =
            supervise_native_packager(command, &cancel, Duration::from_secs(10)).unwrap_err();
        request_cancel.join().unwrap();
        thread::sleep(Duration::from_millis(1_200));

        assert!(ready.is_file(), "packager descendant never started");
        assert_eq!(error.code, "project_build_cancelled");
        assert!(
            !sentinel.exists(),
            "packager descendant survived cancellation"
        );
    }

    #[test]
    fn completed_native_build_reaps_its_empty_process_tree() {
        let executable = env::current_exe().unwrap();
        let test_name = native_packager_test_name();
        let mut command = Command::new(executable);
        command
            .args(["--exact", &test_name, "--nocapture"])
            .env("LUXURY_NATIVE_PACKAGER_HELPER", "empty");

        supervise_native_packager(command, &AtomicBool::new(false), Duration::from_secs(10))
            .unwrap();
    }

    fn native_packager_parent() {
        thread::sleep(Duration::from_millis(75));
        let executable = env::current_exe().unwrap();
        let test_name = native_packager_test_name();
        let mut grandchild = Command::new(executable)
            .args(["--exact", &test_name, "--nocapture"])
            .env("LUXURY_NATIVE_PACKAGER_HELPER", "grandchild")
            .env(
                "LUXURY_NATIVE_PACKAGER_READY",
                env::var_os("LUXURY_NATIVE_PACKAGER_READY").unwrap(),
            )
            .env(
                "LUXURY_NATIVE_PACKAGER_SENTINEL",
                env::var_os("LUXURY_NATIVE_PACKAGER_SENTINEL").unwrap(),
            )
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_secs(5));
        let _ = grandchild.kill();
        let _ = grandchild.wait();
    }

    fn native_packager_grandchild() {
        fs::write(
            env::var_os("LUXURY_NATIVE_PACKAGER_READY").unwrap(),
            b"ready",
        )
        .unwrap();
        thread::sleep(Duration::from_millis(800));
        fs::write(
            env::var_os("LUXURY_NATIVE_PACKAGER_SENTINEL").unwrap(),
            b"survived",
        )
        .unwrap();
        thread::sleep(Duration::from_secs(5));
    }

    fn native_packager_test_name() -> String {
        let module = module_path!()
            .strip_prefix(concat!(env!("CARGO_CRATE_NAME"), "::"))
            .unwrap_or(module_path!());
        format!("{module}::cancelled_native_build_terminates_packager_descendants")
    }

    #[test]
    fn native_build_failure_exposes_only_the_bounded_last_diagnostic() {
        let source = format!(
            "{}\nignored\nerror: {}\u{7}\u{202e}\n",
            "z".repeat(20_000),
            "x".repeat(800)
        );
        let diagnostics = drain_native_diagnostics(source.as_bytes());
        assert!(diagnostics.len() <= 16 * 1024);
        let error = native_packager_error(&diagnostics, "build failed");
        assert_eq!(error.code, "project_build_failed");
        assert!(error.message.starts_with("build failed error: "));
        assert!(!error.message.contains('\u{7}'));
        assert!(!error.message.contains('\u{202e}'));
        assert!(error.message.chars().count() <= 525);
    }
}
