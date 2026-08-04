#![deny(unsafe_code)]

use tauri::{LogicalSize, Manager, State, WebviewWindow};
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
const DEFAULT_WINDOW_WIDTH: f64 = 1080.0;
const DEFAULT_WINDOW_HEIGHT: f64 = 720.0;
const WINDOW_WORK_AREA_MARGIN: f64 = 32.0;

#[derive(Clone, Copy, Debug, PartialEq)]
struct FixedWindowSize {
    width: f64,
    height: f64,
}

fn fixed_window_size(work_width: u32, work_height: u32, scale_factor: f64) -> FixedWindowSize {
    if work_width == 0 || work_height == 0 || !scale_factor.is_finite() || scale_factor <= 0.0 {
        return FixedWindowSize {
            width: DEFAULT_WINDOW_WIDTH,
            height: DEFAULT_WINDOW_HEIGHT,
        };
    }
    let available_width = (f64::from(work_width) / scale_factor - WINDOW_WORK_AREA_MARGIN).max(1.0);
    let available_height =
        (f64::from(work_height) / scale_factor - WINDOW_WORK_AREA_MARGIN).max(1.0);
    let fit = (available_width / DEFAULT_WINDOW_WIDTH)
        .min(available_height / DEFAULT_WINDOW_HEIGHT)
        .min(1.0);
    FixedWindowSize {
        width: (DEFAULT_WINDOW_WIDTH * fit).floor().max(1.0),
        height: (DEFAULT_WINDOW_HEIGHT * fit).floor().max(1.0),
    }
}

fn configure_main_window(window: &WebviewWindow) -> tauri::Result<()> {
    let size = window
        .current_monitor()?
        .or(window.primary_monitor()?)
        .map(|monitor| {
            let work_area = monitor.work_area();
            fixed_window_size(
                work_area.size.width,
                work_area.size.height,
                monitor.scale_factor(),
            )
        })
        .unwrap_or(FixedWindowSize {
            width: DEFAULT_WINDOW_WIDTH,
            height: DEFAULT_WINDOW_HEIGHT,
        });
    let logical = LogicalSize::new(size.width, size.height);
    window.set_min_size(None::<LogicalSize<f64>>)?;
    window.set_max_size(None::<LogicalSize<f64>>)?;
    window.set_size(logical)?;
    window.set_min_size(Some(logical))?;
    window.set_max_size(Some(logical))?;
    window.set_resizable(false)?;
    window.set_maximizable(false)?;
    window.center()
}

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
        studio::shutdown(&shutdown_state)?;
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
            if let Some(window) = app.get_webview_window("main") {
                configure_main_window(&window)?;
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
            studio::get_recent_projects,
            studio::open_recent_project,
            studio::reload_project,
            studio::update_project,
            studio::import_project_files,
            studio::import_project_directory,
            studio::choose_project_entrypoint,
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
        CloseRequestDisposition, DEFAULT_WINDOW_HEIGHT, DEFAULT_WINDOW_WIDTH, NO_REQUESTED_EXIT,
        close_request_disposition, container_parent_mode_valid, final_exit_code, fixed_window_size,
    };

    #[test]
    fn fixed_window_fits_the_monitor_work_area_at_any_scale() {
        let large = fixed_window_size(3840, 2080, 2.0);
        assert_eq!(large.width, DEFAULT_WINDOW_WIDTH);
        assert_eq!(large.height, DEFAULT_WINDOW_HEIGHT);

        let compact = fixed_window_size(1366, 728, 1.25);
        assert!(compact.width <= 1366.0 / 1.25);
        assert!(compact.height <= 728.0 / 1.25);
        assert!(compact.width < DEFAULT_WINDOW_WIDTH);
        assert_eq!((compact.width / compact.height * 100.0).round(), 150.0);

        let fallback = fixed_window_size(0, 0, f64::NAN);
        assert_eq!(fallback.width, DEFAULT_WINDOW_WIDTH);
        assert_eq!(fallback.height, DEFAULT_WINDOW_HEIGHT);
    }

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
