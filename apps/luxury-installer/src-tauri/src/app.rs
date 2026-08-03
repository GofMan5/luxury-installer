use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use serde::Serialize;
use serde_json::json;
use tauri::{AppHandle, Manager, Runtime};

use crate::{
    backend::{BackendClient, BackendError, DefaultsResult, TargetArch, TargetOs},
    studio::StudioState,
};

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum AppMode {
    Studio,
    Setup,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PublicError {
    pub(crate) code: String,
    pub(crate) message: String,
}

impl From<BackendError> for PublicError {
    fn from(error: BackendError) -> Self {
        let (code, message) = public_backend_message(&error.code);
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }
}

impl PublicError {
    pub(crate) fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

pub(crate) struct ExclusiveGuard<'a>(&'a AtomicBool);

impl<'a> ExclusiveGuard<'a> {
    pub(crate) fn acquire(
        flag: &'a AtomicBool,
        code: &'static str,
        message: &'static str,
    ) -> Result<Self, PublicError> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self(flag))
            .map_err(|_| PublicError::new(code, message))
    }
}

impl Drop for ExclusiveGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) mode: AppMode,
    pub(crate) backend: Result<BackendClient, BackendError>,
    pub(crate) package_path: Option<PathBuf>,
    pub(crate) studio: Arc<StudioState>,
    pub(crate) dialog_open: Arc<AtomicBool>,
    pub(crate) setup: Arc<Mutex<Option<crate::setup::SetupContext>>>,
    pub(crate) close_started: Arc<AtomicBool>,
    pub(crate) close_ready: Arc<AtomicBool>,
}

impl AppState {
    pub(crate) fn new<R: Runtime>(app: &AppHandle<R>) -> Self {
        let package_requested = package_requested();
        let (arguments, argument_error) = match parse_arguments() {
            Ok(arguments) => (arguments, None),
            Err(error) => (Arguments::default(), Some(error)),
        };
        let setup_build = cfg!(feature = "setup");
        let development_setup = cfg!(debug_assertions) && package_requested;
        let mode = if setup_build || development_setup {
            AppMode::Setup
        } else {
            AppMode::Studio
        };
        let resources = (setup_build || !cfg!(debug_assertions))
            .then(|| app.path().resource_dir().ok())
            .flatten();
        let package_path = if setup_build {
            resources
                .as_ref()
                .map(|resources| resources.join("payload").join("package.luxpkg"))
        } else {
            arguments.package_path
        };
        let executable = if setup_build || !cfg!(debug_assertions) {
            resources.as_ref().map(|resources| {
                resources.join("backend").join(if cfg!(windows) {
                    "luxury.exe"
                } else {
                    "luxury"
                })
            })
        } else {
            arguments.backend_path.or_else(|| {
                workspace_root().map(|root| {
                    root.join("target").join("debug").join(if cfg!(windows) {
                        "luxury.exe"
                    } else {
                        "luxury"
                    })
                })
            })
        };
        let backend = argument_error.map_or_else(
            || {
                executable
                    .ok_or_else(|| {
                        BackendError::new("invalid_backend_path", "backend path is unavailable")
                    })
                    .and_then(|path| BackendClient::new(path, arguments.trusted_publisher_key))
            },
            Err,
        );
        Self {
            mode,
            backend,
            package_path,
            studio: Arc::new(StudioState::default()),
            dialog_open: Arc::new(AtomicBool::new(false)),
            setup: Arc::new(Mutex::new(None)),
            close_started: Arc::new(AtomicBool::new(false)),
            close_ready: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn backend(&self) -> Result<BackendClient, BackendError> {
        self.backend.clone()
    }

    pub(crate) fn require_mode(&self, expected: AppMode) -> Result<(), PublicError> {
        if self.mode == expected {
            Ok(())
        } else {
            Err(PublicError::new(
                "wrong_app_mode",
                "Эта операция недоступна в текущем режиме.",
            ))
        }
    }

    pub(crate) fn defaults(&self) -> Result<DefaultsResult, PublicError> {
        let defaults: DefaultsResult = self
            .backend()
            .map_err(PublicError::from)?
            .request_short("defaults", json!({}))
            .map_err(PublicError::from)?;
        if !Path::new(&defaults.install_base).is_absolute()
            || !Path::new(&defaults.state_root).is_absolute()
            || defaults.backend_version != env!("CARGO_PKG_VERSION")
            || defaults.target.os != host_os()
            || defaults.target.arch != host_arch()
        {
            return Err(PublicError::new(
                "invalid_backend_output",
                "Компонент установщика вернул неверные параметры по умолчанию.",
            ));
        }
        Ok(defaults)
    }

    pub(crate) fn verify_privilege_transport(&self) -> Result<(), PublicError> {
        let backend = self.backend().map_err(PublicError::from)?;
        let executable = backend.executable().map_err(PublicError::from)?;
        crate::privilege::verify_backend_transport(executable).map_err(|_| {
            PublicError::new(
                "privilege_transport_failed",
                "Защищённый канал повышения прав не прошёл проверку.",
            )
        })
    }

    pub(crate) fn verify_elevated_privilege_transport(&self) -> Result<(), PublicError> {
        let backend = self.backend().map_err(PublicError::from)?;
        let executable = backend.executable().map_err(PublicError::from)?;
        crate::privilege::verify_elevated_backend_transport(executable).map_err(|_| {
            PublicError::new(
                "elevated_privilege_transport_failed",
                "Проверка канала с повышенными правами не пройдена или отменена.",
            )
        })
    }

    pub(crate) fn verify_authenticated_privilege_transport(&self) -> Result<(), PublicError> {
        let backend = self.backend().map_err(PublicError::from)?;
        let executable = backend.executable().map_err(PublicError::from)?;
        crate::privilege::verify_authenticated_backend_transport(executable).map_err(|_| {
            PublicError::new(
                "authenticated_privilege_transport_failed",
                "Подписи приложения и компонента с повышенными правами не прошли проверку.",
            )
        })
    }

    pub(crate) fn verify_container_parent(&self) -> Result<(), PublicError> {
        crate::privilege::verify_container_parent().map_err(|_| {
            PublicError::new(
                "container_parent_failed",
                "Подпись контейнера установщика не совпала с подписью приложения.",
            )
        })
    }
}

pub(crate) fn package_requested() -> bool {
    env::args_os().any(|argument| {
        argument == "--package"
            || argument
                .to_str()
                .is_some_and(|argument| argument.starts_with("--package="))
    })
}

pub(crate) fn valid_package_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.contains('.')
        && value.split('.').all(|part| {
            !part.is_empty()
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

pub(crate) fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

pub(crate) fn valid_install_directory(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !matches!(value, "." | "..")
        && !value.contains(['/', '\\', ':', '\0'])
        && !value.ends_with(['.', ' '])
}

#[derive(Default)]
struct Arguments {
    package_path: Option<PathBuf>,
    trusted_publisher_key: Option<PathBuf>,
    backend_path: Option<PathBuf>,
}

fn parse_arguments() -> Result<Arguments, BackendError> {
    let package_path = if cfg!(debug_assertions) {
        one_absolute_argument("--package", "invalid_package_path")?
    } else {
        None
    };
    let trusted_publisher_key = if cfg!(debug_assertions) {
        one_absolute_argument(
            "--trusted-publisher-key",
            "invalid_trusted_publisher_key_path",
        )?
    } else {
        None
    };
    let backend_path = if cfg!(debug_assertions) {
        match env::var_os("LUXURY_BACKEND_PATH").map(PathBuf::from) {
            Some(path) if path.is_absolute() => Some(path),
            Some(_) => {
                return Err(BackendError::new(
                    "invalid_backend_path",
                    "LUXURY_BACKEND_PATH must be absolute",
                ));
            }
            None => None,
        }
    } else {
        None
    };
    Ok(Arguments {
        package_path,
        trusted_publisher_key,
        backend_path,
    })
}

fn host_os() -> TargetOs {
    if cfg!(target_os = "windows") {
        TargetOs::Windows
    } else if cfg!(target_os = "macos") {
        TargetOs::Macos
    } else {
        TargetOs::Linux
    }
}

fn host_arch() -> TargetArch {
    if cfg!(target_arch = "aarch64") {
        TargetArch::Aarch64
    } else {
        TargetArch::X86_64
    }
}

fn one_absolute_argument(
    name: &str,
    error_code: &'static str,
) -> Result<Option<PathBuf>, BackendError> {
    let arguments = env::args_os().collect::<Vec<_>>();
    let prefix = format!("{name}=");
    let mut value: Option<OsString> = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == name {
            if value.is_some() {
                return Err(BackendError::new(error_code, "argument was repeated"));
            }
            index += 1;
            value = Some(
                arguments
                    .get(index)
                    .cloned()
                    .ok_or_else(|| BackendError::new(error_code, "argument has no value"))?,
            );
        } else if let Some(argument) = argument.to_str()
            && let Some(inline) = argument.strip_prefix(&prefix)
        {
            if value.is_some() {
                return Err(BackendError::new(error_code, "argument was repeated"));
            }
            value = Some(inline.into());
        }
        index += 1;
    }
    match value.map(PathBuf::from) {
        Some(path) if path.is_absolute() => Ok(Some(path)),
        Some(_) => Err(BackendError::new(
            error_code,
            "argument path must be absolute",
        )),
        None => Ok(None),
    }
}

fn workspace_root() -> Option<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .parent()
        .map(Path::to_path_buf)
}

fn public_backend_message(code: &str) -> (&str, &'static str) {
    let message = match code {
        "backend_timeout" => "Компонент установщика не ответил вовремя.",
        "busy" => "Другая операция уже выполняется.",
        "cancel_rejected" => "Операцию уже нельзя отменить.",
        "cancelled" => "Операция отменена.",
        "dialog_busy" => "Другой системный диалог уже открыт.",
        "downgrade_denied" => "Установка более старой версии запрещена.",
        "insufficient_space" => "Недостаточно свободного места.",
        "invalid_backend_path"
        | "backend_missing"
        | "backend_spawn_failed"
        | "backend_unavailable" => "Не удалось запустить защищённый компонент установщика.",
        "invalid_backend_output" | "unsupported_protocol" => "Компоненты установщика несовместимы.",
        "invalid_install_path" | "invalid_package_path" | "package_changed" => {
            "Проверенные данные установщика изменились или недействительны."
        }
        "launch_failed" => "Не удалось запустить установленное приложение.",
        "launch_not_available" => "Точка запуска недоступна.",
        "license_not_accepted" => "Примите лицензионное соглашение для продолжения.",
        "license_not_offered" => "Лицензионное соглашение для этого пакета не запрашивалось.",
        "nothing_to_reveal" => "Папка установленного приложения недоступна.",
        "operation_not_active" => "Операция уже завершена.",
        "payload_missing" | "payload_unavailable" | "package_open_failed" => {
            "Пакет приложения недоступен."
        }
        "permission_denied" => {
            "Недостаточно прав для этой папки. Выберите другую папку в профиле пользователя."
        }
        "project_build_failed" => "Не удалось собрать проект.",
        "project_init_failed" => "Не удалось создать проект.",
        "project_not_open" => "Сначала откройте проект.",
        "project_validation_failed" => "Проверка проекта не пройдена.",
        "publisher_migration_not_offered" => "Подтверждение смены издателя сейчас недоступно.",
        "publisher_migration_required" => "Требуется подтверждение смены привязки издателя.",
        "publisher_mismatch"
        | "publisher_rotation_denied"
        | "publisher_rotation_invalid"
        | "publisher_untrusted" => "Не удалось подтвердить издателя пакета.",
        "recovery_required" => "Требуется восстановление незавершённой установки.",
        "reinstall_mismatch" => "Установленная версия содержит другой набор файлов.",
        "reveal_failed" => "Не удалось открыть папку приложения.",
        "rollback_failed" => "Не удалось полностью отменить изменения.",
        "signature_invalid" | "signature_missing" => "Подпись пакета недействительна.",
        "invalid_state" | "state_conflict" | "state_error" => {
            "Состояние установки изменилось или повреждено."
        }
        "too_many_requests" => "Установщик обрабатывает слишком много операций.",
        "unsigned_not_allowed" => "Подтвердите установку неподписанного пакета.",
        "uninstall_failed" => "Удаление приложения не выполнено.",
        "uninstall_not_available" => "Приложение не установлено в выбранной папке.",
        "unsupported" | "unsupported_scope" | "unsupported_target" => {
            "Операция не поддерживается этой системой."
        }
        "wrong_app_mode" => "Операция недоступна в текущем режиме.",
        _ => return ("internal_error", "Операция Luxury Installer не выполнена."),
    };
    (code, message)
}

pub(crate) fn valid_license(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 64 * 1024
        && value.chars().count() <= 16_384
        && !value.chars().any(|character| {
            (character.is_control() && !matches!(character, '\n' | '\t'))
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::{public_backend_message, valid_license, valid_package_id};

    #[test]
    fn package_id_contract_matches_core_hyphen_rules() {
        assert!(valid_package_id("dev.foo--bar"));
        assert!(!valid_package_id("devfoo"));
        assert!(!valid_package_id("dev.foo-"));
        assert!(!valid_package_id("dev..foo"));
    }

    #[test]
    fn invalid_state_keeps_its_public_code() {
        assert_eq!(public_backend_message("invalid_state").0, "invalid_state");
        assert_eq!(
            public_backend_message("private_backend_detail").0,
            "internal_error"
        );
    }

    #[test]
    fn license_text_rejects_controls_bidi_and_oversize() {
        assert!(valid_license("First line.\nSecond line."));
        assert!(!valid_license("bad\0text"));
        assert!(!valid_license("bad\rtext"));
        assert!(!valid_license("hidden\u{202e}text"));
        assert!(!valid_license(&"x".repeat(16_385)));
    }
}
