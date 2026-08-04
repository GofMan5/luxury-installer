fn main() {
    const COMMANDS: &[&str] = &[
        "get_app_mode",
        "get_bootstrap",
        "create_project",
        "open_project",
        "get_recent_projects",
        "open_recent_project",
        "reload_project",
        "update_project",
        "import_project_files",
        "import_project_directory",
        "choose_project_entrypoint",
        "reveal_project",
        "reveal_build_output",
        "build_project",
        "choose_directory",
        "start_install",
        "start_uninstall",
        "cancel_operation",
        "launch_installed",
        "reveal_installed",
        "open_finish_link",
        "minimize_window",
        "close_window",
    ];
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to build Tauri permissions and resources")
}
