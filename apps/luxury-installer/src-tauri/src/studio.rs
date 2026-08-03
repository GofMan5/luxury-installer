use std::{
    path::{Path, PathBuf},
    sync::{Mutex, atomic::AtomicBool},
};

use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::{
    app::{
        AppMode, AppState, ExclusiveGuard, PublicError, valid_install_directory, valid_license,
        valid_package_id, valid_text,
    },
    backend::{
        FinishLink, InstallScope, MAX_SAFE_INTEGER, ProjectBuildResult, ProjectResult,
        ResolvedPayloadPath, TargetArch, TargetOs,
    },
};

#[derive(Default)]
pub(crate) struct StudioState {
    busy: AtomicBool,
    active: Mutex<Option<ActiveProject>>,
}

#[derive(Clone)]
struct ActiveProject {
    path: PathBuf,
    summary: StudioProject,
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
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<StudioProject>, PublicError> {
    state.require_mode(AppMode::Studio)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        import_project_directory_sync(&app, &window, &state)
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
    import_project_payload_sync(app, window, state, false)
}

fn import_project_directory_sync(
    app: &AppHandle,
    window: &WebviewWindow,
    state: &AppState,
) -> Result<Option<StudioProject>, PublicError> {
    import_project_payload_sync(app, window, state, true)
}

fn import_project_payload_sync(
    app: &AppHandle,
    window: &WebviewWindow,
    state: &AppState,
    directory: bool,
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
        .set_title(if directory {
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
    let version = project
        .summary
        .version
        .chars()
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
    let output = app
        .dialog()
        .file()
        .set_parent(window)
        .set_title("Собрать пакет")
        .set_directory(project.path.parent().unwrap_or(Path::new(".")))
        .set_file_name(format!("{}-{version}.luxpkg", project.summary.package_id))
        .add_filter("Luxury package", &["luxpkg"])
        .blocking_save_file()
        .map(|path| {
            path.into_path().map_err(|_| {
                PublicError::new("invalid_package_path", "Выбран недопустимый путь пакета.")
            })
        })
        .transpose()?;
    let Some(output) = output else {
        return Ok(None);
    };
    let backend = state.backend().map_err(PublicError::from)?;
    let result: ProjectBuildResult = backend
        .request_operation(
            "buildProject",
            json!({
                "projectPath": path_text(&project.path)?,
                "outputPath": path_text(&output)?,
            }),
        )
        .map_err(PublicError::from)?;
    if Path::new(&result.output_path) != output {
        return Err(PublicError::new(
            "invalid_backend_output",
            "Компонент Studio вернул другой путь сборки.",
        ));
    }
    let project_result = ProjectResult {
        format_version: result.format_version,
        schema_version: result.schema_version,
        package: result.package,
        target: result.target,
        install: result.install,
        payload: result.payload,
        authoring: result.authoring,
    };
    let summary = StudioProject::from_backend(&project.path, project_result)?;
    set_active_project(state, project.path, &summary)?;
    Ok(Some(StudioBuildResult {
        output_path: path_text(&output)?.into(),
        project: summary,
    }))
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
    *state
        .studio
        .active
        .lock()
        .map_err(|_| PublicError::new("internal_error", "Состояние Studio недоступно."))? =
        Some(ActiveProject {
            path,
            summary: summary.clone(),
        });
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
    !value.is_empty()
        && value.len() <= 4_096
        && !value.starts_with(['/', '\\'])
        && !value.contains(['\\', ':', '\0'])
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."))
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
}
