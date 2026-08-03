#![deny(unsafe_code)]

use tauri::{Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
compile_error!("Luxury Installer supports only Windows, Linux, and macOS");
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Luxury Installer supports only x86_64 and aarch64");

#[cfg(all(feature = "studio", feature = "setup"))]
compile_error!("features `studio` and `setup` are mutually exclusive");
#[cfg(not(any(feature = "studio", feature = "setup")))]
compile_error!("one of features `studio` or `setup` must be enabled");

mod app;
mod backend;
#[allow(unsafe_code)]
mod privilege;
mod setup;
mod studio;

use app::{AppMode, AppState, PublicError};

const NO_REQUESTED_EXIT: i32 = i32::MIN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloseRequestDisposition {
    Allow,
    Wait,
    Start,
}

const fn close_request_disposition(started: bool, ready: bool) -> CloseRequestDisposition {
    if started && ready {
        CloseRequestDisposition::Allow
    } else if started {
        CloseRequestDisposition::Wait
    } else {
        CloseRequestDisposition::Start
    }
}

const fn container_parent_mode_valid(requested: bool, runner: bool, authenticated: bool) -> bool {
    !requested || (runner && authenticated)
}

const fn final_exit_code(runtime: i32, requested: i32) -> i32 {
    if requested == NO_REQUESTED_EXIT {
        runtime
    } else {
        requested
    }
}

#[tauri::command]
fn get_app_mode(state: State<'_, AppState>) -> AppMode {
    state.mode
}

#[tauri::command]
fn minimize_window(window: WebviewWindow) -> Result<(), PublicError> {
    window
        .minimize()
        .map_err(|_| PublicError::new("internal_error", "Не удалось свернуть окно."))
}

#[tauri::command]
fn toggle_maximize_window(window: WebviewWindow) -> Result<(), PublicError> {
    let maximized = window
        .is_maximized()
        .map_err(|_| PublicError::new("internal_error", "Не удалось определить размер окна."))?;
    let result = if maximized {
        window.unmaximize()
    } else {
        window.maximize()
    };
    result.map_err(|_| PublicError::new("internal_error", "Не удалось изменить размер окна."))
}

#[tauri::command]
async fn close_window(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<(), PublicError> {
    close_window_inner(window, state.inner().clone()).await
}

async fn close_window_inner(window: WebviewWindow, state: AppState) -> Result<(), PublicError> {
    if state
        .close_started
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        return Ok(());
    }
    let shutdown_state = state.clone();
    let shutdown = match tauri::async_runtime::spawn_blocking(move || {
        setup::shutdown_operation(&shutdown_state)?;
        if let Ok(backend) = shutdown_state.backend() {
            backend.close();
        }
        Ok::<_, PublicError>(())
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(PublicError::new(
            "internal_error",
            "Не удалось закрыть установщик.",
        )),
    };
    if let Err(error) = shutdown {
        state
            .close_ready
            .store(false, std::sync::atomic::Ordering::Release);
        state
            .close_started
            .store(false, std::sync::atomic::Ordering::Release);
        return Err(error);
    }
    state
        .close_ready
        .store(true, std::sync::atomic::Ordering::Release);
    let result = window
        .close()
        .map_err(|_| PublicError::new("internal_error", "Не удалось закрыть окно."));
    if result.is_err() {
        state
            .close_ready
            .store(false, std::sync::atomic::Ordering::Release);
        state
            .close_started
            .store(false, std::sync::atomic::Ordering::Release);
    }
    result
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let verify_runner = std::env::args_os().any(|argument| argument == "--verify-runner");
    let verify_studio = std::env::args_os().any(|argument| argument == "--verify-studio");
    let verify_elevated_transport =
        std::env::args_os().any(|argument| argument == "--verify-elevated-transport");
    let verify_authenticated_transport =
        std::env::args_os().any(|argument| argument == "--verify-authenticated-transport");
    let verify_container_parent =
        std::env::args_os().any(|argument| argument == "--verify-container-parent");
    let verify_system_authorization =
        std::env::args_os().any(|argument| argument == "--verify-system-authorization");
    let verify_requested = verify_runner || verify_studio;
    let startup_error = if verify_requested {
        None
    } else {
        match privilege::is_elevated() {
            Ok(elevated) if privilege::desktop_runtime_allowed(elevated, false) => None,
            Ok(_) => Some((
                "elevated_ui_forbidden",
                "Luxury Installer не запускает web-интерфейс с повышенными правами.",
            )),
            Err(_) => Some((
                "privilege_check_failed",
                "Не удалось безопасно определить уровень прав процесса.",
            )),
        }
    };
    let development_setup = cfg!(debug_assertions) && app::package_requested();
    let setup_mode = cfg!(feature = "setup") || development_setup;
    let mut context = tauri::generate_context!();
    if verify_requested || startup_error.is_some() {
        context.config_mut().app.windows.clear();
    }
    let requested_exit_code =
        std::sync::Arc::new(std::sync::atomic::AtomicI32::new(NO_REQUESTED_EXIT));
    let setup_exit_code = std::sync::Arc::clone(&requested_exit_code);
    let mut builder = tauri::Builder::default();
    if !verify_requested && startup_error.is_none() && !setup_mode {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = tauri::Manager::get_webview_window(app, "main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }));
    }
    let app = builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(move |app| {
            if let Some((code, message)) = startup_error {
                app.dialog()
                    .message(message)
                    .title("Luxury Installer")
                    .blocking_show();
                eprintln!("[{code}] {message}");
                setup_exit_code.store(1, std::sync::atomic::Ordering::Release);
                app.handle().exit(1);
                return Ok(());
            }
            let state = AppState::new(app.handle());
            app.manage(state.clone());
            if verify_requested {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
                let privilege_mode_count = [
                    verify_elevated_transport,
                    verify_authenticated_transport,
                    verify_system_authorization,
                ]
                .into_iter()
                .filter(|enabled| *enabled)
                .count();
                let valid_container_parent = container_parent_mode_valid(
                    verify_container_parent,
                    verify_runner,
                    verify_authenticated_transport,
                );
                let mut result = match (
                    verify_runner,
                    verify_studio,
                    verify_system_authorization,
                    privilege_mode_count <= 1 && valid_container_parent,
                ) {
                    (true, false, true, true) => setup::verify_system_authorization(&state),
                    (true, false, false, true) => setup::verify_runner(&state),
                    (false, true, false, true) => studio::verify_studio(&state),
                    _ => Err(PublicError::new(
                        "invalid_arguments",
                        "Выберите один artifact verifier и не более одного режима повышенных прав.",
                    )),
                };
                if result.is_ok() && verify_authenticated_transport {
                    result = state.verify_authenticated_privilege_transport();
                } else if result.is_ok() && verify_elevated_transport {
                    result = state.verify_elevated_privilege_transport();
                }
                if result.is_ok() && verify_container_parent {
                    result = state.verify_container_parent();
                }
                if let Ok(backend) = state.backend() {
                    backend.close();
                }
                match result {
                    Ok(()) => {
                        if verify_system_authorization {
                            println!("{{\"systemAuthorizationVerified\":true}}");
                        } else if verify_container_parent {
                            println!("{{\"containerParentVerified\":true}}");
                        } else if verify_authenticated_transport {
                            println!("{{\"authenticatedTransportVerified\":true}}");
                        } else if verify_elevated_transport {
                            println!("{{\"elevatedTransportVerified\":true}}");
                        } else if verify_studio {
                            println!("{{\"studioVerified\":true}}");
                        } else {
                            println!("{{\"verified\":true}}");
                        }
                        setup_exit_code.store(0, std::sync::atomic::Ordering::Release);
                        app.handle().exit(0);
                    }
                    Err(error) => {
                        eprintln!("[{}] {}", error.code, error.message);
                        setup_exit_code.store(1, std::sync::atomic::Ordering::Release);
                        app.handle().exit(1);
                    }
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_mode,
            studio::create_project,
            studio::open_project,
            studio::reload_project,
            studio::reveal_project,
            studio::build_project,
            setup::get_bootstrap,
            setup::choose_directory,
            setup::start_install,
            setup::start_uninstall,
            setup::cancel_operation,
            setup::launch_installed,
            setup::reveal_installed,
            setup::open_finish_link,
            minimize_window,
            toggle_maximize_window,
            close_window,
        ])
        .build(context)
        .expect("Luxury Installer Tauri runtime failed");
    let exit_code = app.run_return(|app, event| {
        if let tauri::RunEvent::WindowEvent {
            label,
            event: tauri::WindowEvent::CloseRequested { api, .. },
            ..
        } = &event
            && let Some(state) = app.try_state::<AppState>()
            && let Some(window) = app.get_webview_window(label)
        {
            match close_request_disposition(
                state
                    .close_started
                    .load(std::sync::atomic::Ordering::Acquire),
                state.close_ready.load(std::sync::atomic::Ordering::Acquire),
            ) {
                CloseRequestDisposition::Allow => {}
                CloseRequestDisposition::Wait => api.prevent_close(),
                CloseRequestDisposition::Start => {
                    api.prevent_close();
                    let state = state.inner().clone();
                    tauri::async_runtime::spawn(async move {
                        let _ = close_window_inner(window, state).await;
                    });
                }
            }
        }
        if matches!(event, tauri::RunEvent::Exit)
            && let Some(state) = app.try_state::<AppState>()
            && let Ok(backend) = state.backend()
        {
            backend.close();
        }
    });
    let requested = requested_exit_code.load(std::sync::atomic::Ordering::Acquire);
    std::process::exit(final_exit_code(exit_code, requested));
}

#[cfg(test)]
mod tests {
    use super::{
        CloseRequestDisposition, NO_REQUESTED_EXIT, close_request_disposition,
        container_parent_mode_valid, final_exit_code,
    };

    #[test]
    fn explicit_headless_exit_code_wins_over_runtime_default() {
        assert_eq!(final_exit_code(0, 1), 1);
        assert_eq!(final_exit_code(1, 0), 0);
        assert_eq!(final_exit_code(7, NO_REQUESTED_EXIT), 7);
    }

    #[test]
    fn container_parent_requires_runner_and_authenticated_transport() {
        assert!(container_parent_mode_valid(false, false, false));
        assert!(container_parent_mode_valid(true, true, true));
        assert!(!container_parent_mode_valid(true, true, false));
        assert!(!container_parent_mode_valid(true, false, true));
    }

    #[test]
    fn repeated_close_waits_for_terminal_shutdown_before_native_close() {
        assert_eq!(
            close_request_disposition(false, false),
            CloseRequestDisposition::Start
        );
        assert_eq!(
            close_request_disposition(true, false),
            CloseRequestDisposition::Wait
        );
        assert_eq!(
            close_request_disposition(true, true),
            CloseRequestDisposition::Allow
        );
        assert_eq!(
            close_request_disposition(false, true),
            CloseRequestDisposition::Start
        );
    }
}
