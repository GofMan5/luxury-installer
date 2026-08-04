use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, BufRead, BufWriter, Read, Write},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use luxury_bundle::{
    Bundle, BundleError, PackageTrust, SIGNATURE_ENTRY, TrustedPublisherKey,
    open_bundle_file_cancellable,
};
use luxury_engine::{
    PortErrorKind,
    install::{
        InstallAction, InstallCommand, InstallError, InstallEvent, InstallOutcome, InstallPhase,
        InstallPrepareOutcome, install, prepare_install,
    },
    launch::{LaunchCommand, LaunchError, launch},
    uninstall::{
        UninstallCommand, UninstallError, UninstallEvent, UninstallOutcome, UninstallPhase,
        uninstall,
    },
};
use luxury_platform::{
    LocalInstallAdapter, LocalLaunchAdapter, LocalUninstallAdapter, default_user_roots,
};
use luxury_spec::{
    Architecture, FinishLink, InstallDirectory, InstallPolicy, InstallScope, Manifest,
    OperatingSystem, Package, PackageId, PackagePath, Target,
};
use semver::Version;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

const PROTOCOL_VERSION: u32 = luxury_spec::JSONL_PROTOCOL_VERSION;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_PATH_BYTES: usize = 32_768;
const MAX_MESSAGE_BYTES: usize = 1024;
const MAX_TRUSTED_KEY_BYTES: u64 = 16 * 1024;
const CHANNEL_CAPACITY: usize = 64;
const PROGRESS_INTERVAL: Duration = Duration::from_millis(16);
const MAX_INSTALL_LOG_FILES: usize = 128;

pub(super) fn run(args: &[OsString]) {
    std::panic::set_hook(Box::new(|_| {}));
    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    let trusted_key = match load_trusted_publisher_key(args) {
        Ok(trusted_key) => trusted_key,
        Err(error) => {
            let _ = write_error(&mut output, None, error);
            return;
        }
    };

    let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let input_sender = sender.clone();
    if let Err(error) = thread::Builder::new()
        .name("luxury-stdio-input".into())
        .spawn(move || {
            let stdin = io::stdin();
            read_input(stdin.lock(), input_sender);
        })
    {
        let _ = write_error(
            &mut output,
            None,
            WireError::new(
                "internal_error",
                format!("starting input reader failed: {error}"),
            ),
        );
        return;
    }

    serve(receiver, sender, &mut output, trusted_key);
}

fn load_trusted_publisher_key(args: &[OsString]) -> Result<Option<TrustedPublisherKey>, WireError> {
    if args.is_empty() {
        return Ok(None);
    }
    if args.len() != 2 || args[0].as_os_str() != OsStr::new("--trusted-publisher-key") {
        return Err(WireError::new(
            "invalid_request",
            "stdio accepts only --trusted-publisher-key <absolute SPKI PEM path>",
        ));
    }

    let path = PathBuf::from(&args[1]);
    if !path.is_absolute() {
        return Err(WireError::new(
            "invalid_request",
            "trusted publisher key path must be absolute",
        ));
    }
    let file = File::open(&path).map_err(|error| {
        WireError::new(
            "trusted_publisher_key_invalid",
            format!("opening trusted publisher key failed: {error}"),
        )
    })?;
    if !file
        .metadata()
        .map_err(|error| {
            WireError::new(
                "trusted_publisher_key_invalid",
                format!("reading trusted publisher key metadata failed: {error}"),
            )
        })?
        .is_file()
    {
        return Err(WireError::new(
            "trusted_publisher_key_invalid",
            "trusted publisher key must be a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_TRUSTED_KEY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            WireError::new(
                "trusted_publisher_key_invalid",
                format!("reading trusted publisher key failed: {error}"),
            )
        })?;
    if bytes.len() as u64 > MAX_TRUSTED_KEY_BYTES {
        return Err(WireError::new(
            "trusted_publisher_key_invalid",
            format!("trusted publisher key exceeds {MAX_TRUSTED_KEY_BYTES} bytes"),
        ));
    }
    let pem = std::str::from_utf8(&bytes).map_err(|_| {
        WireError::new(
            "trusted_publisher_key_invalid",
            "trusted publisher key must be UTF-8 SPKI PEM",
        )
    })?;
    TrustedPublisherKey::from_public_key_pem(pem)
        .map(Some)
        .map_err(|error| WireError::new("trusted_publisher_key_invalid", error.to_string()))
}

fn serve<W: Write>(
    receiver: Receiver<ServerMessage>,
    sender: SyncSender<ServerMessage>,
    output: &mut W,
    trusted_key: Option<TrustedPublisherKey>,
) {
    let mut active_mutation: Option<ActiveMutation> = None;
    let mut active_operation: Option<ActiveOperation> = None;
    let mut shutting_down = false;
    let mut output_failed = false;

    while let Ok(message) = receiver.recv() {
        let output_ok = match message {
            ServerMessage::Request(request) if !shutting_down => handle_request(
                request,
                &sender,
                &mut active_mutation,
                &mut active_operation,
                output,
                trusted_key,
            ),
            ServerMessage::Request(_) => true,
            ServerMessage::InputError(error) => {
                shutting_down = true;
                request_shutdown(active_mutation.as_ref(), active_operation.as_ref());
                write_error(output, None, WireError::new("input_error", error))
            }
            ServerMessage::InputClosed => {
                shutting_down = true;
                request_shutdown(active_mutation.as_ref(), active_operation.as_ref());
                true
            }
            ServerMessage::MutationEvent { id, event } => {
                if active_mutation
                    .as_ref()
                    .is_some_and(|mutation| mutation.id == id)
                    && !output_failed
                {
                    write_mutation_event(output, &id, event)
                } else {
                    true
                }
            }
            ServerMessage::MutationDone { id, result } => {
                let Some(mutation) = active_mutation.take().filter(|mutation| mutation.id == id)
                else {
                    continue;
                };
                let _ = mutation.worker.join();
                if output_failed {
                    true
                } else {
                    match result {
                        Ok(result) => write_result(output, &id, result),
                        Err(error) => write_error(output, Some(&id), error),
                    }
                }
            }
            ServerMessage::OperationDone { id, result } => {
                let Some(operation) = active_operation
                    .take()
                    .filter(|operation| operation.id == id)
                else {
                    continue;
                };
                let _ = operation.worker.join();
                if output_failed {
                    true
                } else {
                    match result {
                        Ok(result) => write_result(output, &id, result),
                        Err(error) => write_error(output, Some(&id), error),
                    }
                }
            }
        };

        if !output_ok {
            shutting_down = true;
            output_failed = true;
            request_shutdown(active_mutation.as_ref(), active_operation.as_ref());
        }
        if shutting_down && active_mutation.is_none() && active_operation.is_none() {
            break;
        }
    }
}

fn handle_request<W: Write>(
    request: Result<Request, ProtocolIssue>,
    sender: &SyncSender<ServerMessage>,
    active_mutation: &mut Option<ActiveMutation>,
    active_operation: &mut Option<ActiveOperation>,
    output: &mut W,
    trusted_key: Option<TrustedPublisherKey>,
) -> bool {
    let request = match request {
        Ok(request) => request,
        Err(issue) => return write_error(output, issue.id.as_deref(), issue.error),
    };
    if request.protocol_version != PROTOCOL_VERSION {
        return write_error(
            output,
            Some(&request.id),
            WireError::new(
                "unsupported_protocol",
                format!(
                    "protocolVersion {} is not supported; expected {PROTOCOL_VERSION}",
                    request.protocol_version
                ),
            ),
        );
    }
    if active_mutation
        .as_ref()
        .is_some_and(|mutation| mutation.id == request.id)
        || active_operation
            .as_ref()
            .is_some_and(|operation| operation.id == request.id)
    {
        return write_error(
            output,
            Some(&request.id),
            WireError::new("duplicate_id", "request id is already active"),
        );
    }

    match request.method.as_str() {
        "defaults" => match decode_params::<EmptyParams>(&request).and_then(|_| defaults()) {
            Ok(result) => write_result(output, &request.id, result),
            Err(error) => write_error(output, Some(&request.id), error),
        },
        "initProject" => {
            if active_mutation.is_some() || active_operation.is_some() {
                return write_busy(output, &request.id);
            }
            match decode_params::<ProjectParams>(&request)
                .and_then(|params| absolute_path(params.project_path, "projectPath"))
            {
                Ok(path) => {
                    match start_operation(request.id.clone(), sender.clone(), move |cancel| {
                        initialize_project(path, cancel)
                    }) {
                        Ok(operation) => {
                            *active_operation = Some(operation);
                            true
                        }
                        Err(error) => write_error(output, Some(&request.id), error),
                    }
                }
                Err(error) => write_error(output, Some(&request.id), error),
            }
        }
        "validateProject" => {
            if active_mutation.is_some() || active_operation.is_some() {
                return write_busy(output, &request.id);
            }
            match decode_params::<ProjectParams>(&request)
                .and_then(|params| absolute_path(params.project_path, "projectPath"))
            {
                Ok(path) => {
                    match start_operation(request.id.clone(), sender.clone(), move |cancel| {
                        validate_project(path, cancel)
                    }) {
                        Ok(operation) => {
                            *active_operation = Some(operation);
                            true
                        }
                        Err(error) => write_error(output, Some(&request.id), error),
                    }
                }
                Err(error) => write_error(output, Some(&request.id), error),
            }
        }
        "updateProject" => {
            if active_mutation.is_some() || active_operation.is_some() {
                return write_busy(output, &request.id);
            }
            match decode_params::<UpdateProjectParams>(&request) {
                Ok(params) => {
                    match start_operation(request.id.clone(), sender.clone(), move |cancel| {
                        update_project(params, cancel)
                    }) {
                        Ok(operation) => {
                            *active_operation = Some(operation);
                            true
                        }
                        Err(error) => write_error(output, Some(&request.id), error),
                    }
                }
                Err(error) => write_error(output, Some(&request.id), error),
            }
        }
        "importPayload" => {
            if active_mutation.is_some() || active_operation.is_some() {
                return write_busy(output, &request.id);
            }
            match decode_params::<ImportPayloadParams>(&request) {
                Ok(params) => {
                    match start_operation(request.id.clone(), sender.clone(), move |cancel| {
                        import_payload(params, cancel)
                    }) {
                        Ok(operation) => {
                            *active_operation = Some(operation);
                            true
                        }
                        Err(error) => write_error(output, Some(&request.id), error),
                    }
                }
                Err(error) => write_error(output, Some(&request.id), error),
            }
        }
        "resolvePayloadPath" => {
            if active_mutation.is_some() || active_operation.is_some() {
                return write_busy(output, &request.id);
            }
            match decode_params::<ResolvePayloadPathParams>(&request) {
                Ok(params) => {
                    match start_operation(request.id.clone(), sender.clone(), move |_| {
                        resolve_payload_path(params)
                    }) {
                        Ok(operation) => {
                            *active_operation = Some(operation);
                            true
                        }
                        Err(error) => write_error(output, Some(&request.id), error),
                    }
                }
                Err(error) => write_error(output, Some(&request.id), error),
            }
        }
        "buildProject" => {
            if active_mutation.is_some() || active_operation.is_some() {
                return write_busy(output, &request.id);
            }
            match decode_params::<BuildProjectParams>(&request) {
                Ok(params) => {
                    match start_operation(request.id.clone(), sender.clone(), move |cancel| {
                        build_project(params, cancel)
                    }) {
                        Ok(operation) => {
                            *active_operation = Some(operation);
                            true
                        }
                        Err(error) => write_error(output, Some(&request.id), error),
                    }
                }
                Err(error) => write_error(output, Some(&request.id), error),
            }
        }
        "inspect" => {
            if active_mutation.is_some() || active_operation.is_some() {
                return write_busy(output, &request.id);
            }
            match decode_params::<InspectParams>(&request)
                .and_then(|params| absolute_path(params.package_path, "packagePath"))
            {
                Ok(path) => {
                    match start_operation(request.id.clone(), sender.clone(), move |cancel| {
                        inspect_package(path, trusted_key.as_ref(), cancel)
                    }) {
                        Ok(operation) => {
                            *active_operation = Some(operation);
                            true
                        }
                        Err(error) => write_error(output, Some(&request.id), error),
                    }
                }
                Err(error) => write_error(output, Some(&request.id), error),
            }
        }
        "prepareInstall" => {
            if active_mutation.is_some() || active_operation.is_some() {
                return write_busy(output, &request.id);
            }
            match decode_params::<PrepareInstallParams>(&request)
                .and_then(validate_prepare_install_params)
            {
                Ok(params) => {
                    match start_operation(request.id.clone(), sender.clone(), move |cancel| {
                        prepare_install_package(params, trusted_key.as_ref(), cancel)
                    }) {
                        Ok(operation) => {
                            *active_operation = Some(operation);
                            true
                        }
                        Err(error) => write_error(output, Some(&request.id), error),
                    }
                }
                Err(error) => write_error(output, Some(&request.id), error),
            }
        }
        "install" => {
            if active_mutation.is_some() || active_operation.is_some() {
                return write_busy(output, &request.id);
            }
            match decode_params::<InstallParams>(&request).and_then(validate_install_params) {
                Ok(params) => {
                    match start_install(request.id.clone(), params, sender.clone(), trusted_key) {
                        Ok(mutation) => {
                            *active_mutation = Some(mutation);
                            true
                        }
                        Err(error) => write_error(output, Some(&request.id), error),
                    }
                }
                Err(error) => write_error(output, Some(&request.id), error),
            }
        }
        "uninstall" => {
            if active_mutation.is_some() || active_operation.is_some() {
                return write_busy(output, &request.id);
            }
            match decode_params::<UninstallParams>(&request).and_then(validate_uninstall_params) {
                Ok(params) => match start_uninstall(request.id.clone(), params, sender.clone()) {
                    Ok(mutation) => {
                        *active_mutation = Some(mutation);
                        true
                    }
                    Err(error) => write_error(output, Some(&request.id), error),
                },
                Err(error) => write_error(output, Some(&request.id), error),
            }
        }
        "launch" => {
            if active_mutation.is_some() || active_operation.is_some() {
                return write_busy(output, &request.id);
            }
            match decode_params::<UninstallParams>(&request).and_then(validate_uninstall_params) {
                Ok(params) => match start_launch(request.id.clone(), params, sender.clone()) {
                    Ok(mutation) => {
                        *active_mutation = Some(mutation);
                        true
                    }
                    Err(error) => write_error(output, Some(&request.id), error),
                },
                Err(error) => write_error(output, Some(&request.id), error),
            }
        }
        "cancel" => match decode_params::<CancelParams>(&request).and_then(|params| {
            if valid_request_id(&params.request_id) {
                Ok(params)
            } else {
                Err(WireError::new(
                    "invalid_params",
                    "requestId must be a valid request id",
                ))
            }
        }) {
            Ok(params) => write_result(
                output,
                &request.id,
                CancelResult {
                    accepted: request_cancellation(
                        active_mutation.as_ref(),
                        active_operation.as_ref(),
                        &params.request_id,
                    ),
                    request_id: params.request_id,
                },
            ),
            Err(error) => write_error(output, Some(&request.id), error),
        },
        _ => write_error(
            output,
            Some(&request.id),
            WireError::new(
                "unknown_method",
                format!("unknown method `{}`", request.method),
            ),
        ),
    }
}

fn defaults() -> Result<DefaultsResult, WireError> {
    let (install_base, state_root) = default_user_roots()
        .map_err(|error| WireError::new("defaults_failed", error.to_string()))?;
    Ok(DefaultsResult {
        install_base: path_text(&install_base, "default install base")?,
        state_root: path_text(&state_root, "default state root")?,
        target: TargetResult::from(Target::host()),
        backend_version: env!("CARGO_PKG_VERSION"),
    })
}

fn initialize_project(path: PathBuf, cancel: &AtomicBool) -> Result<ProjectResult, WireError> {
    if cancel.load(Ordering::Acquire) {
        return Err(WireError::new("cancelled", "operation cancelled"));
    }
    luxury_compiler::init_project(&path)
        .map_err(|error| WireError::new("project_init_failed", error.to_string()))?;
    let manifest = luxury_compiler::validate_project_cancellable(path, cancel).map_err(
        |error| match error {
            luxury_compiler::CompilerError::Cancelled => WireError::new(
                "cancelled",
                "project is initialized; validation was cancelled; open or retry it",
            ),
            error => compiler_error(error, "project_init_failed"),
        },
    )?;
    ProjectResult::from_manifest(&manifest, "project_init_failed")
}

fn validate_project(path: PathBuf, cancel: &AtomicBool) -> Result<ProjectResult, WireError> {
    let manifest = luxury_compiler::validate_project_cancellable(path, cancel)
        .map_err(|error| compiler_error(error, "project_validation_failed"))?;
    ProjectResult::from_manifest(&manifest, "project_validation_failed")
}

fn update_project(
    params: UpdateProjectParams,
    cancel: &AtomicBool,
) -> Result<ProjectResult, WireError> {
    let project_path = absolute_path(params.project_path, "projectPath")?;
    let update = luxury_compiler::ProjectUpdate {
        package: Package {
            id: params.package.id,
            name: params.package.name,
            version: params.package.version,
            publisher: params.package.publisher,
            description: params.package.description,
            license: params.package.license,
        },
        target: Target {
            os: params.target.os,
            arch: params.target.arch,
        },
        install: InstallPolicy {
            scope: params.install.scope,
            directory: params.install.directory,
            allow_downgrade: params.install.allow_downgrade,
            entrypoint: params.install.entrypoint,
            show_install_log: params.install.show_install_log,
            finish_links: params.install.finish_links,
        },
        executable: params.executable,
    };
    let manifest = luxury_compiler::update_project_cancellable(project_path, update, cancel)
        .map_err(|error| compiler_error(error, "project_update_failed"))?;
    ProjectResult::from_manifest(&manifest, "project_update_failed")
}

fn import_payload(
    params: ImportPayloadParams,
    cancel: &AtomicBool,
) -> Result<ProjectResult, WireError> {
    let project_path = absolute_path(params.project_path, "projectPath")?;
    if params.replace && params.source_paths.len() != 1 {
        return Err(WireError::new(
            "invalid_params",
            "payload replacement requires exactly one source directory",
        ));
    }
    let source_paths = params
        .source_paths
        .into_iter()
        .map(|path| absolute_path(path, "sourcePaths"))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = if params.replace {
        luxury_compiler::replace_payload_cancellable(project_path, &source_paths[0], cancel)
    } else {
        luxury_compiler::import_payload_cancellable(project_path, &source_paths, cancel)
    }
    .map_err(|error| compiler_error(error, "project_import_failed"))?;
    ProjectResult::from_manifest(&manifest, "project_import_failed")
}

fn resolve_payload_path(
    params: ResolvePayloadPathParams,
) -> Result<ResolvePayloadPathResult, WireError> {
    let project_path = absolute_path(params.project_path, "projectPath")?;
    let selected_path = absolute_path(params.selected_path, "selectedPath")?;
    let path = luxury_compiler::resolve_payload_file(project_path, selected_path)
        .map_err(|error| compiler_error(error, "payload_path_invalid"))?;
    Ok(ResolvePayloadPathResult {
        path: path.to_string(),
    })
}

fn build_project(
    params: BuildProjectParams,
    cancel: &AtomicBool,
) -> Result<ProjectBuildResult, WireError> {
    let project_path = absolute_path(params.project_path, "projectPath")?;
    let output_text = params.output_path;
    let output_path = absolute_path(output_text.clone(), "outputPath")?;
    let manifest = luxury_compiler::compile_project_cancellable(project_path, output_path, cancel)
        .map_err(|error| compiler_error(error, "project_build_failed"))?;
    Ok(ProjectBuildResult {
        project: ProjectResult::from_manifest(&manifest, "project_build_failed")?,
        output_path: output_text,
    })
}

fn compiler_error(error: luxury_compiler::CompilerError, fallback: &'static str) -> WireError {
    let code = match &error {
        luxury_compiler::CompilerError::Cancelled => "cancelled",
        luxury_compiler::CompilerError::ProjectChanged => "state_conflict",
        luxury_compiler::CompilerError::ImportConflict(_) => "collision",
        luxury_compiler::CompilerError::Io { action, .. }
            if matches!(
                *action,
                "rolling back payload import"
                    | "restoring starter payload"
                    | "inspecting starter payload restore path"
                    | "rolling back replacement project payload"
                    | "restoring previous project payload"
            ) =>
        {
            "rollback_failed"
        }
        _ => fallback,
    };
    WireError::new(code, error.to_string())
}

fn inspect_package(
    path: PathBuf,
    trusted_key: Option<&TrustedPublisherKey>,
    cancel: &AtomicBool,
) -> Result<InspectResult, WireError> {
    let bundle = open_bundle_file_cancellable(path, trusted_key, cancel)
        .map_err(|error| bundle_error(error, "inspect_failed"))?;
    InspectResult::from_bundle(&bundle)
}

fn prepare_install_package(
    params: ValidPrepareInstallParams,
    trusted_key: Option<&TrustedPublisherKey>,
    cancel: &AtomicBool,
) -> Result<PrepareInstallResult, WireError> {
    let bundle = open_bundle_file_cancellable(&params.package_path, trusted_key, cancel)
        .map_err(|error| bundle_error(error, "package_open_failed"))?;
    if bundle.review_fingerprint() != params.expected_fingerprint {
        return Err(WireError::new(
            "package_changed",
            "package does not match the version reviewed by the user",
        ));
    }
    let manifest = bundle.manifest().clone();
    let mut adapter = LocalInstallAdapter::new(bundle, params.install_base, params.state_root);
    let outcome = prepare_install(manifest, &mut adapter).map_err(install_error)?;
    if cancel.load(Ordering::Acquire) {
        return Err(WireError::new("cancelled", "operation cancelled"));
    }
    PrepareInstallResult::from_outcome(outcome)
}

fn start_operation<T, F>(
    id: String,
    sender: SyncSender<ServerMessage>,
    operation: F,
) -> Result<ActiveOperation, WireError>
where
    T: Serialize + 'static,
    F: FnOnce(&AtomicBool) -> Result<T, WireError> + Send + 'static,
{
    let cancel = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    let worker_finished = Arc::clone(&finished);
    let worker_id = id.clone();
    let worker = thread::Builder::new()
        .name("luxury-operation".into())
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| operation(&worker_cancel)))
                .unwrap_or_else(|_| {
                    Err(WireError::new("internal_error", "operation worker failed"))
                })
                .and_then(|result| {
                    serde_json::to_value(result).map_err(|_| {
                        WireError::new("internal_error", "serializing operation result failed")
                    })
                });
            worker_finished.store(true, Ordering::Release);
            let _ = sender.send(ServerMessage::OperationDone {
                id: worker_id,
                result,
            });
        })
        .map_err(|error| {
            WireError::new(
                "internal_error",
                format!("starting operation worker failed: {error}"),
            )
        })?;
    Ok(ActiveOperation {
        id,
        cancel,
        finished,
        worker,
    })
}

fn start_install(
    id: String,
    params: ValidInstallParams,
    sender: SyncSender<ServerMessage>,
    trusted_key: Option<TrustedPublisherKey>,
) -> Result<ActiveMutation, WireError> {
    start_mutation(
        id,
        sender,
        "install",
        "install worker failed after transaction recovery",
        true,
        move |id, cancel, sender| install_package(id, params, trusted_key.as_ref(), cancel, sender),
    )
}

fn start_uninstall(
    id: String,
    params: ValidUninstallParams,
    sender: SyncSender<ServerMessage>,
) -> Result<ActiveMutation, WireError> {
    start_mutation(
        id,
        sender,
        "uninstall",
        "uninstall worker failed after transaction recovery",
        true,
        move |id, cancel, sender| uninstall_package(id, params, cancel, sender),
    )
}

fn start_launch(
    id: String,
    params: ValidUninstallParams,
    sender: SyncSender<ServerMessage>,
) -> Result<ActiveMutation, WireError> {
    start_mutation(
        id,
        sender,
        "launch",
        "launch worker failed",
        false,
        move |_id, cancel, _sender| launch_package(params, cancel),
    )
}

fn start_mutation<T, F>(
    id: String,
    sender: SyncSender<ServerMessage>,
    name: &'static str,
    panic_message: &'static str,
    cancellable: bool,
    mutation: F,
) -> Result<ActiveMutation, WireError>
where
    T: Serialize + 'static,
    F: FnOnce(&str, &AtomicBool, &SyncSender<ServerMessage>) -> Result<T, WireError>
        + Send
        + 'static,
{
    let cancel = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    let worker_finished = Arc::clone(&finished);
    let worker_id = id.clone();
    let worker = thread::Builder::new()
        .name(format!("luxury-{name}"))
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                mutation(&worker_id, &worker_cancel, &sender)
            }))
            .unwrap_or_else(|_| Err(WireError::new("internal_error", panic_message)))
            .and_then(|result| {
                serde_json::to_value(result).map_err(|_| {
                    WireError::new("internal_error", "serializing mutation result failed")
                })
            });
            worker_finished.store(true, Ordering::Release);
            let _ = sender.send(ServerMessage::MutationDone {
                id: worker_id,
                result,
            });
        })
        .map_err(|error| {
            WireError::new(
                "internal_error",
                format!("starting {name} worker failed: {error}"),
            )
        })?;
    Ok(ActiveMutation {
        id,
        cancel,
        cancellable,
        finished,
        worker,
    })
}

fn install_package(
    id: &str,
    params: ValidInstallParams,
    trusted_key: Option<&TrustedPublisherKey>,
    cancel: &AtomicBool,
    sender: &SyncSender<ServerMessage>,
) -> Result<InstallResult, WireError> {
    if cancel.load(Ordering::Acquire) {
        return Err(WireError::new("cancelled", "installation cancelled"));
    }
    let bundle = open_bundle_file_cancellable(&params.package_path, trusted_key, cancel)
        .map_err(|error| bundle_error(error, "package_open_failed"))?;
    if bundle.trust() == PackageTrust::Unsigned && !params.allow_unsigned {
        return Err(WireError::new(
            "unsigned_not_allowed",
            "allowUnsigned must be true to install an unsigned v1 package",
        ));
    }
    if bundle.review_fingerprint() != params.expected_fingerprint {
        return Err(WireError::new(
            "package_changed",
            "package does not match the version reviewed by the user",
        ));
    }
    let manifest = bundle.manifest().clone();
    let install_directory = manifest.install.directory.to_string();
    let mut adapter = LocalInstallAdapter::new(bundle, params.install_base, params.state_root);
    let mut events = MutationEvents::new(id, sender);
    let result = install(
        InstallCommand::new(manifest)
            .with_license_acceptance(params.accept_license)
            .with_downgrade_approval(params.allow_downgrade)
            .with_publisher_migration_approval(params.allow_publisher_migration),
        &mut adapter,
        || cancel.load(Ordering::Acquire),
        |event| events.emit(MutationEvent::Install(event)),
    );
    events.flush();
    result
        .map(|outcome| InstallResult::new(outcome, install_directory))
        .map_err(install_error)
}

fn uninstall_package(
    id: &str,
    params: ValidUninstallParams,
    cancel: &AtomicBool,
    sender: &SyncSender<ServerMessage>,
) -> Result<UninstallResult, WireError> {
    let package_id = params.package_id.to_string();
    let mut adapter = LocalUninstallAdapter::new(params.install_base, params.state_root);
    let mut events = MutationEvents::new(id, sender);
    let result = uninstall(
        UninstallCommand::new(params.package_id),
        &mut adapter,
        || cancel.load(Ordering::Acquire),
        |event| {
            if !matches!(event, UninstallEvent::PreservedModified(_)) {
                events.emit(MutationEvent::Uninstall(event));
            }
        },
    );
    events.flush();
    result
        .map(|outcome| UninstallResult::new(package_id, outcome))
        .map_err(uninstall_error)
}

fn launch_package(
    params: ValidUninstallParams,
    cancel: &AtomicBool,
) -> Result<LaunchResult, WireError> {
    if cancel.load(Ordering::Acquire) {
        return Err(WireError::new("cancelled", "launch cancelled"));
    }
    let package_id = params.package_id.to_string();
    let mut adapter = LocalLaunchAdapter::new(params.install_base, params.state_root);
    launch(LaunchCommand::new(params.package_id), &mut adapter)
        .map(|()| LaunchResult::Launched { package_id })
        .map_err(launch_error)
}

fn bundle_error(error: BundleError, fallback: &'static str) -> WireError {
    let code = match &error {
        BundleError::Cancelled => "cancelled",
        BundleError::MissingSignature => "signature_missing",
        BundleError::MalformedSignature { .. }
        | BundleError::InvalidSignature
        | BundleError::SignatureForbidden
        | BundleError::SignatureNotSecond(_) => "signature_invalid",
        BundleError::DuplicateEntry(path) if path == SIGNATURE_ENTRY => "signature_invalid",
        BundleError::ForbiddenEntryType { path, .. } if path == SIGNATURE_ENTRY => {
            "signature_invalid"
        }
        BundleError::InvalidPublisherRotationKey
        | BundleError::PublisherRotationToSameKey
        | BundleError::InvalidPublisherRotationProof => "publisher_rotation_invalid",
        BundleError::UntrustedPublisher { .. } => "publisher_untrusted",
        _ => fallback,
    };
    WireError::new(code, error.to_string())
}

fn install_error(error: InstallError) -> WireError {
    WireError::new(install_error_code(&error), error.to_string())
}

pub(crate) fn install_error_code(error: &InstallError) -> &'static str {
    match error {
        InstallError::InvalidManifest(_) => "invalid_package",
        InstallError::UnsupportedTarget { .. } => "unsupported_target",
        InstallError::UnsupportedScope { .. } => "unsupported_scope",
        InstallError::LicenseNotAccepted => "license_not_accepted",
        InstallError::InvalidReceipt(_) => "invalid_state",
        InstallError::ReceiptMismatch { .. } | InstallError::PathAliasChanged { .. } => {
            "state_conflict"
        }
        InstallError::PublisherMigrationDenied { .. } => "publisher_migration_required",
        InstallError::PublisherMismatch { .. } => "publisher_mismatch",
        InstallError::PublisherRotationDenied { .. } => "publisher_rotation_denied",
        InstallError::DowngradeDenied { .. } => "downgrade_denied",
        InstallError::ReinstallMismatch { .. } => "reinstall_mismatch",
        InstallError::Cancelled => "cancelled",
        InstallError::Rollback { .. } => "rollback_failed",
        InstallError::Port { source, .. } => match source.kind() {
            PortErrorKind::Integrity => "integrity_failed",
            PortErrorKind::Collision => "collision",
            PortErrorKind::Permission => "permission_denied",
            PortErrorKind::Capacity => "insufficient_space",
            PortErrorKind::Busy => "busy",
            PortErrorKind::Recovery => "recovery_required",
            PortErrorKind::State => "state_error",
            PortErrorKind::Unsupported => "unsupported",
            PortErrorKind::Io => "io_error",
            PortErrorKind::Other => "install_failed",
        },
    }
}

fn uninstall_error(error: UninstallError) -> WireError {
    let code = uninstall_error_code(&error);
    let message = match error {
        UninstallError::InvalidReceipt(_) => "installed state is invalid".into(),
        UninstallError::UnsupportedScope { .. } => {
            "installed scope requires privileged authority".into()
        }
        UninstallError::ReceiptPackageMismatch { .. } => {
            "installed state does not match the requested package".into()
        }
        UninstallError::Cancelled => "uninstallation cancelled".into(),
        UninstallError::Rollback { .. } => {
            "uninstallation failed and rollback could not complete".into()
        }
        UninstallError::Port { step, .. } => format!("uninstall step `{step}` failed"),
    };
    WireError::new(code, message)
}

pub(crate) fn uninstall_error_code(error: &UninstallError) -> &'static str {
    match error {
        UninstallError::InvalidReceipt(_) => "invalid_state",
        UninstallError::UnsupportedScope { .. } => "unsupported_scope",
        UninstallError::ReceiptPackageMismatch { .. } => "state_conflict",
        UninstallError::Cancelled => "cancelled",
        UninstallError::Rollback { .. } => "rollback_failed",
        UninstallError::Port { source, .. } => port_error_code(source.kind(), "uninstall_failed"),
    }
}

fn launch_error(error: LaunchError) -> WireError {
    let code = launch_error_code(&error);
    let message = match error {
        LaunchError::RecoveryPending { .. } => "installed state requires recovery",
        LaunchError::NotInstalled { .. } | LaunchError::MissingEntrypoint { .. } => {
            "installed entrypoint is not available"
        }
        LaunchError::InvalidReceipt(_)
        | LaunchError::ReceiptPackageMismatch { .. }
        | LaunchError::EntrypointNotOwned { .. } => "installed state is invalid",
        LaunchError::UnsupportedScope { .. } => "installed scope requires privileged authority",
        LaunchError::Port { source, .. } if source.kind() == PortErrorKind::Recovery => {
            "installed state requires recovery"
        }
        LaunchError::Port { source, .. }
            if matches!(
                source.kind(),
                PortErrorKind::Integrity | PortErrorKind::Collision | PortErrorKind::State
            ) =>
        {
            "installed state is invalid"
        }
        LaunchError::Port { .. } => "launching installed application failed",
    };
    WireError::new(code, message)
}

pub(crate) fn launch_error_code(error: &LaunchError) -> &'static str {
    match error {
        LaunchError::RecoveryPending { .. } => "recovery_required",
        LaunchError::NotInstalled { .. } | LaunchError::MissingEntrypoint { .. } => {
            "launch_not_available"
        }
        LaunchError::InvalidReceipt(_)
        | LaunchError::ReceiptPackageMismatch { .. }
        | LaunchError::EntrypointNotOwned { .. } => "invalid_state",
        LaunchError::UnsupportedScope { .. } => "unsupported_scope",
        LaunchError::Port { source, .. } if source.kind() == PortErrorKind::Recovery => {
            "recovery_required"
        }
        LaunchError::Port { source, .. }
            if matches!(
                source.kind(),
                PortErrorKind::Integrity | PortErrorKind::Collision | PortErrorKind::State
            ) =>
        {
            "invalid_state"
        }
        LaunchError::Port { .. } => "launch_failed",
    }
}

fn port_error_code(kind: PortErrorKind, fallback: &'static str) -> &'static str {
    match kind {
        PortErrorKind::Integrity => "integrity_failed",
        PortErrorKind::Collision => "collision",
        PortErrorKind::Permission => "permission_denied",
        PortErrorKind::Capacity => "insufficient_space",
        PortErrorKind::Busy => "busy",
        PortErrorKind::Recovery => "recovery_required",
        PortErrorKind::State => "state_error",
        PortErrorKind::Unsupported => "unsupported",
        PortErrorKind::Io => "io_error",
        PortErrorKind::Other => fallback,
    }
}

fn validate_prepare_install_params(
    params: PrepareInstallParams,
) -> Result<ValidPrepareInstallParams, WireError> {
    Ok(ValidPrepareInstallParams {
        package_path: absolute_path(params.package_path, "packagePath")?,
        install_base: absolute_path(params.install_base, "installBase")?,
        state_root: absolute_path(params.state_root, "stateRoot")?,
        expected_fingerprint: validate_fingerprint(params.expected_fingerprint)?,
    })
}

fn validate_install_params(params: InstallParams) -> Result<ValidInstallParams, WireError> {
    Ok(ValidInstallParams {
        package_path: absolute_path(params.package_path, "packagePath")?,
        install_base: absolute_path(params.install_base, "installBase")?,
        state_root: absolute_path(params.state_root, "stateRoot")?,
        allow_unsigned: params.allow_unsigned,
        accept_license: params.accept_license,
        allow_downgrade: params.allow_downgrade,
        allow_publisher_migration: params.allow_publisher_migration,
        expected_fingerprint: validate_fingerprint(params.expected_fingerprint)?,
    })
}

fn validate_uninstall_params(params: UninstallParams) -> Result<ValidUninstallParams, WireError> {
    let package_id = PackageId::parse(params.package_id)
        .map_err(|_| WireError::new("invalid_params", "packageId is invalid"))?;
    Ok(ValidUninstallParams {
        package_id,
        install_base: absolute_path(params.install_base, "installBase")?,
        state_root: absolute_path(params.state_root, "stateRoot")?,
    })
}

fn validate_fingerprint(value: String) -> Result<String, WireError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value)
    } else {
        Err(WireError::new(
            "invalid_params",
            "expectedFingerprint must be 64 lowercase hexadecimal characters",
        ))
    }
}

fn absolute_path(value: String, field: &str) -> Result<PathBuf, WireError> {
    if value.is_empty() || value.len() > MAX_PATH_BYTES || value.contains('\0') {
        return Err(WireError::new(
            "invalid_params",
            format!("{field} must be a non-empty local path of at most {MAX_PATH_BYTES} bytes"),
        ));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(WireError::new(
            "invalid_params",
            format!("{field} must be an absolute path"),
        ));
    }
    Ok(path)
}

fn path_text(path: &Path, label: &str) -> Result<String, WireError> {
    let text = path.to_str().ok_or_else(|| {
        WireError::new("defaults_failed", format!("{label} is not valid Unicode"))
    })?;
    if text.is_empty() || text.len() > MAX_PATH_BYTES {
        return Err(WireError::new(
            "defaults_failed",
            format!("{label} exceeds the protocol path limit"),
        ));
    }
    Ok(text.to_owned())
}

fn decode_params<T: DeserializeOwned>(request: &Request) -> Result<T, WireError> {
    serde_json::from_value(request.params.clone()).map_err(|error| {
        WireError::new(
            "invalid_params",
            format!("invalid params for `{}`: {error}", request.method),
        )
    })
}

fn request_cancellation(
    active_mutation: Option<&ActiveMutation>,
    active_operation: Option<&ActiveOperation>,
    request_id: &str,
) -> bool {
    if let Some(active) =
        active_mutation.filter(|active| active.id == request_id && active.cancellable)
    {
        if active.finished.load(Ordering::Acquire) {
            return false;
        }
        active.cancel.store(true, Ordering::Release);
        return true;
    }
    if let Some(active) = active_operation.filter(|active| active.id == request_id) {
        if active.finished.load(Ordering::Acquire) {
            return false;
        }
        active.cancel.store(true, Ordering::Release);
        return true;
    }
    false
}

fn request_shutdown(
    active_mutation: Option<&ActiveMutation>,
    active_operation: Option<&ActiveOperation>,
) {
    if let Some(active) = active_mutation {
        active.cancel.store(true, Ordering::Release);
    }
    if let Some(active) = active_operation {
        active.cancel.store(true, Ordering::Release);
    }
}

fn read_input<R: BufRead>(mut input: R, sender: SyncSender<ServerMessage>) {
    loop {
        match read_bounded_line(&mut input) {
            Ok(Some(BoundedLine::Bytes(bytes))) => {
                let request = if bytes.is_empty() {
                    Err(ProtocolIssue::new(None, "request line is empty"))
                } else {
                    parse_request(&bytes)
                };
                if sender.send(ServerMessage::Request(request)).is_err() {
                    return;
                }
            }
            Ok(Some(BoundedLine::Oversized)) => {
                if sender
                    .send(ServerMessage::Request(Err(ProtocolIssue::new(
                        None,
                        format!("request line exceeds {MAX_LINE_BYTES} bytes"),
                    ))))
                    .is_err()
                {
                    return;
                }
            }
            Ok(None) => break,
            Err(error) => {
                let _ = sender.send(ServerMessage::InputError(error.to_string()));
                break;
            }
        }
    }
    let _ = sender.send(ServerMessage::InputClosed);
}

fn read_bounded_line<R: BufRead>(input: &mut R) -> io::Result<Option<BoundedLine>> {
    let mut bytes = Vec::new();
    let mut oversized = false;
    let mut saw_input = false;
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            if !saw_input {
                return Ok(None);
            }
            break;
        }
        saw_input = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let content = newline.unwrap_or(available.len());
        if !oversized {
            if bytes.len().saturating_add(content) > MAX_LINE_BYTES {
                bytes.clear();
                oversized = true;
            } else {
                bytes.extend_from_slice(&available[..content]);
            }
        }
        let consumed = newline.map_or(available.len(), |index| index + 1);
        input.consume(consumed);
        if newline.is_some() {
            break;
        }
    }
    if oversized {
        return Ok(Some(BoundedLine::Oversized));
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Ok(Some(BoundedLine::Bytes(bytes)))
}

fn parse_request(bytes: &[u8]) -> Result<Request, ProtocolIssue> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| ProtocolIssue::new(None, format!("invalid JSON: {error}")))?;
    let id = value.get("id").and_then(Value::as_str).and_then(|id| {
        if valid_request_id(id) {
            Some(id.to_owned())
        } else {
            None
        }
    });
    let request: Request = serde_json::from_value(value).map_err(|error| ProtocolIssue {
        id: id.clone(),
        error: WireError::new("invalid_request", format!("invalid request: {error}")),
    })?;
    if !valid_request_id(&request.id) {
        return Err(ProtocolIssue::new(
            None,
            "id must be 1-128 ASCII letters, digits, `.`, `_`, `:`, or `-`",
        ));
    }
    Ok(request)
}

fn valid_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn write_mutation_event<W: Write>(output: &mut W, id: &str, event: MutationEvent) -> bool {
    match event {
        MutationEvent::Install(event) => write_install_event(output, id, event),
        MutationEvent::Uninstall(event) => write_uninstall_event(output, id, event),
    }
}

fn write_install_event<W: Write>(output: &mut W, id: &str, event: InstallEvent) -> bool {
    match event {
        InstallEvent::Phase(phase) => write_event(
            output,
            id,
            "phase",
            PhaseData {
                phase: phase_name(phase),
            },
        ),
        InstallEvent::Action(action) => write_event(
            output,
            id,
            "action",
            ActionData {
                action: install_action(action),
            },
        ),
        InstallEvent::Progress(progress) => write_event(
            output,
            id,
            "progress",
            ProgressData {
                completed_files: progress.completed_files,
                total_files: progress.total_files,
                completed_bytes: progress.completed_bytes,
                total_bytes: progress.total_bytes,
            },
        ),
    }
}

fn write_uninstall_event<W: Write>(output: &mut W, id: &str, event: UninstallEvent) -> bool {
    match event {
        UninstallEvent::Phase(phase) => write_event(
            output,
            id,
            "phase",
            PhaseData {
                phase: uninstall_phase_name(phase),
            },
        ),
        UninstallEvent::Progress(progress) => write_event(
            output,
            id,
            "progress",
            ProgressData {
                completed_files: progress.processed_files,
                total_files: progress.total_files,
                completed_bytes: 0,
                total_bytes: 0,
            },
        ),
        UninstallEvent::PreservedModified(_) => true,
    }
}

fn phase_name(phase: InstallPhase) -> &'static str {
    match phase {
        InstallPhase::Validating => "validating",
        InstallPhase::Recovering => "recovering",
        InstallPhase::Verifying => "verifying",
        InstallPhase::Planning => "planning",
        InstallPhase::Applying => "applying",
        InstallPhase::Committing => "committing",
        InstallPhase::RollingBack => "rollingBack",
        InstallPhase::Completed => "completed",
        InstallPhase::Cancelled => "cancelled",
        InstallPhase::Failed => "failed",
    }
}

fn uninstall_phase_name(phase: UninstallPhase) -> &'static str {
    match phase {
        UninstallPhase::Recovering => "recovering",
        UninstallPhase::LoadingReceipt => "loadingReceipt",
        UninstallPhase::Removing => "removing",
        UninstallPhase::Committing => "committing",
        UninstallPhase::RollingBack => "rollingBack",
        UninstallPhase::Completed => "completed",
        UninstallPhase::Cancelled => "cancelled",
        UninstallPhase::Failed => "failed",
    }
}

fn write_busy<W: Write>(output: &mut W, id: &str) -> bool {
    write_error(
        output,
        Some(id),
        WireError::new("busy", "another operation is already active"),
    )
}

fn write_result<W: Write, T: Serialize>(output: &mut W, id: &str, result: T) -> bool {
    write_line(
        output,
        &ResultLine {
            protocol_version: PROTOCOL_VERSION,
            kind: "result",
            id,
            result,
        },
    )
    .is_ok()
}

fn write_error<W: Write>(output: &mut W, id: Option<&str>, error: WireError) -> bool {
    write_line(
        output,
        &ErrorLine {
            protocol_version: PROTOCOL_VERSION,
            kind: "error",
            id,
            error,
        },
    )
    .is_ok()
}

fn write_event<W: Write, T: Serialize>(
    output: &mut W,
    id: &str,
    event: &'static str,
    data: T,
) -> bool {
    write_line(
        output,
        &EventLine {
            protocol_version: PROTOCOL_VERSION,
            kind: "event",
            id,
            event,
            data,
        },
    )
    .is_ok()
}

fn write_line<W: Write, T: Serialize>(output: &mut W, value: &T) -> io::Result<()> {
    serde_json::to_writer(&mut *output, value).map_err(io::Error::other)?;
    output.write_all(b"\n")?;
    output.flush()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    protocol_version: u32,
    id: String,
    method: String,
    params: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyParams {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectParams {
    project_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuildProjectParams {
    project_path: String,
    output_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateProjectParams {
    project_path: String,
    package: UpdatePackageParams,
    target: UpdateTargetParams,
    install: UpdateInstallParams,
    #[serde(default)]
    executable: Option<Vec<PackagePath>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportPayloadParams {
    project_path: String,
    source_paths: Vec<String>,
    #[serde(default)]
    replace: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResolvePayloadPathParams {
    project_path: String,
    selected_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdatePackageParams {
    id: PackageId,
    name: String,
    version: Version,
    publisher: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    license: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateTargetParams {
    os: OperatingSystem,
    arch: Architecture,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateInstallParams {
    scope: InstallScope,
    directory: InstallDirectory,
    #[serde(default)]
    allow_downgrade: bool,
    #[serde(default)]
    entrypoint: Option<PackagePath>,
    #[serde(default)]
    show_install_log: bool,
    #[serde(default)]
    finish_links: Vec<FinishLink>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InspectParams {
    package_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrepareInstallParams {
    package_path: String,
    install_base: String,
    state_root: String,
    expected_fingerprint: String,
}

#[derive(Debug)]
struct ValidPrepareInstallParams {
    package_path: PathBuf,
    install_base: PathBuf,
    state_root: PathBuf,
    expected_fingerprint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallParams {
    package_path: String,
    install_base: String,
    state_root: String,
    allow_unsigned: bool,
    #[serde(default)]
    accept_license: bool,
    #[serde(default)]
    allow_downgrade: bool,
    #[serde(default)]
    allow_publisher_migration: bool,
    expected_fingerprint: String,
}

#[derive(Debug)]
struct ValidInstallParams {
    package_path: PathBuf,
    install_base: PathBuf,
    state_root: PathBuf,
    allow_unsigned: bool,
    accept_license: bool,
    allow_downgrade: bool,
    allow_publisher_migration: bool,
    expected_fingerprint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UninstallParams {
    package_id: String,
    install_base: String,
    state_root: String,
}

#[derive(Debug)]
struct ValidUninstallParams {
    package_id: PackageId,
    install_base: PathBuf,
    state_root: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CancelParams {
    request_id: String,
}

#[derive(Debug)]
struct ProtocolIssue {
    id: Option<String>,
    error: WireError,
}

impl ProtocolIssue {
    fn new(id: Option<String>, message: impl Into<String>) -> Self {
        Self {
            id,
            error: WireError::new("invalid_request", message),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct WireError {
    code: &'static str,
    message: String,
}

impl WireError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        let message = message.into();
        let mut bounded = String::new();
        let mut bytes = 0;
        for character in message.chars() {
            let character = if character.is_control() {
                ' '
            } else {
                character
            };
            let next = bytes + character.len_utf8();
            if next > MAX_MESSAGE_BYTES {
                break;
            }
            bounded.push(character);
            bytes = next;
        }
        if bounded.trim().is_empty() {
            bounded.clear();
            bounded.push_str("operation failed");
        }
        Self {
            code,
            message: bounded,
        }
    }
}

enum BoundedLine {
    Bytes(Vec<u8>),
    Oversized,
}

enum ServerMessage {
    Request(Result<Request, ProtocolIssue>),
    InputError(String),
    InputClosed,
    MutationEvent {
        id: String,
        event: MutationEvent,
    },
    MutationDone {
        id: String,
        result: Result<Value, WireError>,
    },
    OperationDone {
        id: String,
        result: Result<Value, WireError>,
    },
}

enum MutationEvent {
    Install(InstallEvent),
    Uninstall(UninstallEvent),
}

impl MutationEvent {
    fn is_progress(&self) -> bool {
        matches!(
            self,
            Self::Install(InstallEvent::Progress(_)) | Self::Uninstall(UninstallEvent::Progress(_))
        )
    }
}

struct PendingMutationProgress {
    id: String,
    sender: SyncSender<ServerMessage>,
    event: Mutex<Option<MutationEvent>>,
}

impl PendingMutationProgress {
    fn replace(&self, event: MutationEvent) {
        *self.event.lock().unwrap_or_else(|error| error.into_inner()) = Some(event);
    }

    fn flush(&self) {
        let mut pending = self.event.lock().unwrap_or_else(|error| error.into_inner());
        let Some(event) = pending.take() else {
            return;
        };
        let _ = self.sender.send(ServerMessage::MutationEvent {
            id: self.id.clone(),
            event,
        });
    }

    fn send(&self, event: MutationEvent) {
        let _ = self.sender.send(ServerMessage::MutationEvent {
            id: self.id.clone(),
            event,
        });
    }
}

struct MutationEvents {
    pending: Arc<PendingMutationProgress>,
    stop: Arc<AtomicBool>,
    ticker: Option<JoinHandle<()>>,
}

impl MutationEvents {
    fn new(id: &str, sender: &SyncSender<ServerMessage>) -> Self {
        Self::with_interval(id, sender, PROGRESS_INTERVAL)
    }

    fn with_interval(id: &str, sender: &SyncSender<ServerMessage>, interval: Duration) -> Self {
        let pending = Arc::new(PendingMutationProgress {
            id: id.to_owned(),
            sender: sender.clone(),
            event: Mutex::new(None),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let ticker_pending = Arc::clone(&pending);
        let ticker_stop = Arc::clone(&stop);
        let ticker = thread::Builder::new()
            .name("luxury-progress".into())
            .spawn(move || {
                while !ticker_stop.load(Ordering::Acquire) {
                    thread::park_timeout(interval);
                    if ticker_stop.load(Ordering::Acquire) {
                        break;
                    }
                    ticker_pending.flush();
                }
            })
            .ok();
        Self {
            pending,
            stop,
            ticker,
        }
    }

    fn emit(&mut self, event: MutationEvent) {
        if !event.is_progress() {
            self.flush();
            self.pending.send(event);
            return;
        }
        self.pending.replace(event);
    }

    fn flush(&self) {
        self.pending.flush();
    }
}

impl Drop for MutationEvents {
    fn drop(&mut self) {
        self.flush();
        self.stop.store(true, Ordering::Release);
        if let Some(ticker) = self.ticker.take() {
            ticker.thread().unpark();
            let _ = ticker.join();
        }
    }
}

struct ActiveMutation {
    id: String,
    cancel: Arc<AtomicBool>,
    cancellable: bool,
    finished: Arc<AtomicBool>,
    worker: JoinHandle<()>,
}

struct ActiveOperation {
    id: String,
    cancel: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
    worker: JoinHandle<()>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultLine<'a, T> {
    protocol_version: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    id: &'a str,
    result: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorLine<'a> {
    protocol_version: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    id: Option<&'a str>,
    error: WireError,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EventLine<'a, T> {
    protocol_version: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    id: &'a str,
    event: &'static str,
    data: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DefaultsResult {
    install_base: String,
    state_root: String,
    target: TargetResult,
    backend_version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectResult {
    format_version: u32,
    schema_version: u32,
    package: PackageResult,
    target: TargetResult,
    install: InstallResultPolicy,
    payload: PayloadResult,
    authoring: ProjectAuthoringResult,
}

impl ProjectResult {
    fn from_manifest(manifest: &Manifest, error_code: &'static str) -> Result<Self, WireError> {
        let version = manifest.package.version.to_string();
        if version.len() > MAX_MESSAGE_BYTES {
            return Err(WireError::new(
                error_code,
                "package version exceeds the protocol text limit",
            ));
        }
        let install_log = manifest.install.show_install_log.then(|| {
            let files = manifest
                .files
                .iter()
                .take(MAX_INSTALL_LOG_FILES)
                .map(|file| file.path.to_string())
                .collect::<Vec<_>>();
            InstallLogResult {
                omitted_files: manifest.files.len() - files.len(),
                files,
            }
        });
        Ok(Self {
            format_version: manifest.format_version,
            schema_version: manifest.schema_version,
            package: PackageResult {
                id: manifest.package.id.to_string(),
                name: manifest.package.name.clone(),
                publisher: manifest.package.publisher.clone(),
                version,
                description: manifest.package.description.clone(),
                license: manifest.package.license.clone(),
            },
            target: TargetResult::from(manifest.target),
            install: InstallResultPolicy {
                scope: match manifest.install.scope {
                    InstallScope::User => "user",
                    InstallScope::System => "system",
                },
                directory: manifest.install.directory.to_string(),
                has_entrypoint: manifest.install.entrypoint.is_some(),
                show_install_log: manifest.install.show_install_log,
                finish_links: manifest.install.finish_links.clone(),
            },
            payload: PayloadResult {
                files: manifest.files.len(),
                bytes: manifest.payload_size(),
                install_log,
            },
            authoring: ProjectAuthoringResult {
                allow_downgrade: manifest.install.allow_downgrade,
                entrypoint: manifest
                    .install
                    .entrypoint
                    .as_ref()
                    .map(ToString::to_string),
                executable_files: manifest.files.iter().filter(|file| file.executable).count(),
            },
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectBuildResult {
    #[serde(flatten)]
    project: ProjectResult,
    output_path: String,
}

#[derive(Serialize)]
struct ResolvePayloadPathResult {
    path: String,
}

#[derive(Serialize)]
struct TargetResult {
    os: String,
    arch: String,
}

impl From<Target> for TargetResult {
    fn from(target: Target) -> Self {
        Self {
            os: target.os.to_string(),
            arch: target.arch.to_string(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InspectResult {
    format_version: u32,
    schema_version: u32,
    package_fingerprint: String,
    trust: TrustResult,
    publisher_rotation: Option<PublisherRotationResult>,
    package: PackageResult,
    target: TargetResult,
    install: InstallResultPolicy,
    payload: PayloadResult,
}

impl InspectResult {
    fn from_bundle(bundle: &Bundle) -> Result<Self, WireError> {
        let project = ProjectResult::from_manifest(bundle.manifest(), "inspect_failed")?;
        Ok(Self {
            format_version: project.format_version,
            schema_version: project.schema_version,
            package_fingerprint: bundle.review_fingerprint().to_owned(),
            trust: TrustResult::from(bundle.trust()),
            publisher_rotation: bundle.publisher_rotation().map(|rotation| {
                PublisherRotationResult {
                    signer_key_id: rotation.from_key_id.to_string(),
                    next_key_id: rotation.to_key_id.to_string(),
                }
            }),
            package: project.package,
            target: project.target,
            install: project.install,
            payload: project.payload,
        })
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PublisherRotationResult {
    signer_key_id: String,
    next_key_id: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind")]
enum TrustResult {
    #[serde(rename = "unsigned")]
    Unsigned,
    #[serde(rename = "trustedPublisher")]
    TrustedPublisher {
        #[serde(rename = "keyId")]
        key_id: String,
    },
}

impl From<PackageTrust> for TrustResult {
    fn from(trust: PackageTrust) -> Self {
        match trust {
            PackageTrust::Unsigned => Self::Unsigned,
            PackageTrust::TrustedPublisher { key_id } => Self::TrustedPublisher {
                key_id: key_id.to_string(),
            },
        }
    }
}

#[derive(Serialize)]
struct PackageResult {
    id: String,
    name: String,
    publisher: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallResultPolicy {
    scope: &'static str,
    directory: String,
    #[serde(rename = "hasEntrypoint")]
    has_entrypoint: bool,
    #[serde(skip_serializing_if = "is_false")]
    show_install_log: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    finish_links: Vec<FinishLink>,
}

#[derive(Serialize)]
struct PayloadResult {
    files: usize,
    bytes: u64,
    #[serde(rename = "installLog", skip_serializing_if = "Option::is_none")]
    install_log: Option<InstallLogResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectAuthoringResult {
    allow_downgrade: bool,
    entrypoint: Option<String>,
    executable_files: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallLogResult {
    files: Vec<String>,
    omitted_files: usize,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum PrepareInstallResult {
    Ready {
        action: &'static str,
        installed_version: Option<String>,
        publisher_migration_required: bool,
    },
    InsufficientSpace {
        action: &'static str,
        installed_version: Option<String>,
        publisher_migration_required: bool,
    },
    RecoveryRequired,
}

impl PrepareInstallResult {
    pub(crate) fn from_outcome(outcome: InstallPrepareOutcome) -> Result<Self, WireError> {
        match outcome {
            InstallPrepareOutcome::Ready {
                action,
                installed_version,
                publisher_migration_required,
            } => Ok(Self::Ready {
                action: prepare_action(action)?,
                installed_version: installed_version.map(|version| version.to_string()),
                publisher_migration_required,
            }),
            InstallPrepareOutcome::InsufficientSpace {
                action,
                installed_version,
                publisher_migration_required,
            } => Ok(Self::InsufficientSpace {
                action: prepare_action(action)?,
                installed_version: installed_version.map(|version| version.to_string()),
                publisher_migration_required,
            }),
            InstallPrepareOutcome::RecoveryRequired => Ok(Self::RecoveryRequired),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallResult {
    package_id: String,
    action: &'static str,
    installed_files: usize,
    installed_bytes: u64,
    install_directory: String,
}

impl InstallResult {
    fn new(outcome: InstallOutcome, install_directory: String) -> Self {
        Self {
            package_id: outcome.package_id.to_string(),
            action: install_action(outcome.action),
            installed_files: outcome.installed_files,
            installed_bytes: outcome.installed_bytes,
            install_directory,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum UninstallResult {
    NotInstalled {
        package_id: String,
    },
    Uninstalled {
        package_id: String,
        removed_files: usize,
        missing_files: usize,
        preserved_modified_files: usize,
    },
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum LaunchResult {
    Launched { package_id: String },
}

impl UninstallResult {
    fn new(package_id: String, outcome: UninstallOutcome) -> Self {
        match outcome {
            UninstallOutcome::NotInstalled => Self::NotInstalled { package_id },
            UninstallOutcome::Uninstalled {
                removed_files,
                missing_files,
                preserved_modified_files,
            } => Self::Uninstalled {
                package_id,
                removed_files,
                missing_files,
                preserved_modified_files,
            },
        }
    }
}

fn install_action(action: InstallAction) -> &'static str {
    match action {
        InstallAction::Install => "install",
        InstallAction::Update => "update",
        InstallAction::Repair => "repair",
        InstallAction::Downgrade => "downgrade",
    }
}

fn prepare_action(action: InstallAction) -> Result<&'static str, WireError> {
    match action {
        InstallAction::Install => Ok("install"),
        InstallAction::Update => Ok("update"),
        InstallAction::Repair => Ok("repair"),
        InstallAction::Downgrade => Err(WireError::new(
            "internal_error",
            "prepareInstall returned an unexpected downgrade action",
        )),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CancelResult {
    request_id: String,
    accepted: bool,
}

#[derive(Serialize)]
struct PhaseData {
    phase: &'static str,
}

#[derive(Serialize)]
struct ActionData {
    action: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressData {
    completed_files: usize,
    total_files: usize,
    completed_bytes: u64,
    total_bytes: u64,
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Cursor};

    use luxury_bundle::{PackageSigningKey, create_signed_bundle};
    use luxury_compiler::{compile_project, init_project};
    use luxury_engine::install::PackageIdentity;
    use luxury_engine::uninstall::ReceiptError;
    use luxury_spec::{FORMAT_VERSION, PackagePath, PublisherKeyId, SIGNED_FORMAT_VERSION};
    use semver::Version;
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    // Public deterministic test-only fixtures; never use these keys for production signing.
    const SIGNING_KEY_PEM: &str = concat!(
        "-----BEGIN PRIVATE ",
        "KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE ",
        "KEY-----\n"
    );
    const TRUSTED_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";
    const OTHER_SIGNING_KEY_PEM: &str = concat!(
        "-----BEGIN PRIVATE ",
        "KEY-----\nMC4CAQAwBQYDK2VwBCIEIEzNCJso/5banbbDRuwRTg9bijGfNaumJNqM9u1PuKb7\n-----END PRIVATE ",
        "KEY-----\n"
    );
    const OTHER_TRUSTED_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=\n-----END PUBLIC KEY-----\n";

    fn stdio_request(method: &str, params: Value) -> Value {
        stdio_request_version(PROTOCOL_VERSION, method, params)
    }

    fn stdio_request_version(protocol_version: u32, method: &str, params: Value) -> Value {
        let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let mut active_mutation = None;
        let mut active_operation = None;
        let mut output = Vec::new();
        assert!(handle_request(
            Ok(Request {
                protocol_version,
                id: "studio-1".into(),
                method: method.into(),
                params,
            }),
            &sender,
            &mut active_mutation,
            &mut active_operation,
            &mut output,
            None,
        ));
        assert!(active_mutation.is_none());
        if let Some(operation) = active_operation.take() {
            let ServerMessage::OperationDone { id, result } = receiver.recv().unwrap() else {
                panic!("operation worker returned an unexpected message");
            };
            assert_eq!(id, operation.id);
            operation.worker.join().unwrap();
            match result {
                Ok(result) => assert!(write_result(&mut output, &id, result)),
                Err(error) => assert!(write_error(&mut output, Some(&id), error)),
            }
        }
        serde_json::from_slice(output.strip_suffix(b"\n").unwrap()).unwrap()
    }

    fn stdio_mutation_request(method: &str, params: Value) -> Vec<Value> {
        let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let mut active_mutation = None;
        let mut active_operation = None;
        let mut output = Vec::new();
        assert!(handle_request(
            Ok(Request {
                protocol_version: PROTOCOL_VERSION,
                id: "mutation-1".into(),
                method: method.into(),
                params,
            }),
            &sender,
            &mut active_mutation,
            &mut active_operation,
            &mut output,
            None,
        ));
        assert!(active_operation.is_none());
        let mutation = active_mutation
            .take()
            .expect("mutation worker was not started");
        loop {
            match receiver.recv().unwrap() {
                ServerMessage::MutationEvent { id, event } => {
                    assert_eq!(id, mutation.id);
                    assert!(write_mutation_event(&mut output, &id, event));
                }
                ServerMessage::MutationDone { id, result } => {
                    assert_eq!(id, mutation.id);
                    mutation.worker.join().unwrap();
                    match result {
                        Ok(result) => assert!(write_result(&mut output, &id, result)),
                        Err(error) => assert!(write_error(&mut output, Some(&id), error)),
                    }
                    break;
                }
                _ => panic!("mutation worker returned an unexpected message"),
            }
        }
        output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    fn install_default_fixture(root: &Path) -> (String, PathBuf, PathBuf, PathBuf) {
        let project = root.join("project");
        let package = root.join("package.luxpkg");
        let install_base = root.join("install");
        let state_root = root.join("state");
        init_project(&project).unwrap();
        compile_project(&project, &package).unwrap();
        let inspected = inspect_package(package.clone(), None, &AtomicBool::new(false)).unwrap();
        let installed = install_base
            .join(&inspected.install.directory)
            .join("hello.txt");
        let package_id = inspected.package.id;
        let (sender, _receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        install_package(
            "fixture-install",
            ValidInstallParams {
                package_path: package,
                install_base: install_base.clone(),
                state_root: state_root.clone(),
                allow_unsigned: true,
                accept_license: false,
                allow_downgrade: false,
                allow_publisher_migration: false,
                expected_fingerprint: inspected.package_fingerprint,
            },
            None,
            &AtomicBool::new(false),
            &sender,
        )
        .unwrap();
        assert!(installed.is_file());
        (package_id, install_base, state_root, installed)
    }

    fn configure_rotation_project(project: &Path, rotation: &luxury_spec::PublisherRotation) {
        let config = project.join("luxury.toml");
        let source = fs::read_to_string(&config).unwrap().replacen(
            "format_version = 1",
            "format_version = 3",
            1,
        );
        fs::write(
            config,
            format!(
                "{source}\n[publisher_rotation]\nnext_public_key = \"{}\"\nproof = \"{}\"\n",
                rotation.next_public_key, rotation.proof
            ),
        )
        .unwrap();
    }

    #[test]
    fn request_contract_is_strict_and_ids_are_safe_to_echo() {
        let request = parse_request(
            br#"{"protocolVersion":3,"id":"request_1","method":"defaults","params":{}}"#,
        )
        .unwrap();
        assert_eq!(request.id, "request_1");

        let snake_case = parse_request(
            br#"{"protocol_version":3,"id":"request_2","method":"defaults","params":{}}"#,
        )
        .unwrap_err();
        assert_eq!(snake_case.id.as_deref(), Some("request_2"));
        assert_eq!(snake_case.error.code, "invalid_request");

        let unsafe_id = parse_request(
            br#"{"protocolVersion":3,"id":"bad id","method":"defaults","params":{}}"#,
        )
        .unwrap_err();
        assert_eq!(unsafe_id.id, None);

        let previous = stdio_request_version(2, "defaults", json!({}));
        assert_eq!(previous["error"]["code"], "unsupported_protocol");
    }

    #[test]
    fn studio_params_are_strict_and_paths_are_absolute() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let project_path = project.to_str().unwrap();

        let extra = stdio_request(
            "initProject",
            json!({"projectPath": project_path, "signingKey": "forbidden"}),
        );
        assert_eq!(extra["error"]["code"], "invalid_params");
        assert!(!project.exists());

        let relative = stdio_request(
            "validateProject",
            json!({"projectPath": "relative/project"}),
        );
        assert_eq!(relative["error"]["code"], "invalid_params");

        let missing = stdio_request("buildProject", json!({"projectPath": project_path}));
        assert_eq!(missing["error"]["code"], "invalid_params");

        let absent = temp.path().join("absent");
        let validation = stdio_request(
            "validateProject",
            json!({"projectPath": absent.to_str().unwrap()}),
        );
        assert_eq!(validation["error"]["code"], "project_validation_failed");

        let initialized = stdio_request("initProject", json!({"projectPath": project_path}));
        assert_eq!(initialized["type"], "result");
        let retry = stdio_request("initProject", json!({"projectPath": project_path}));
        assert_eq!(retry["result"], initialized["result"]);
    }

    #[test]
    fn studio_initializes_validates_and_builds_an_unsigned_project() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let output = temp.path().join("demo.luxpkg");
        let project_path = project.to_str().unwrap();
        let output_path = output.to_str().unwrap();

        let initialized = stdio_request("initProject", json!({"projectPath": project_path}));
        assert_eq!(initialized["type"], "result");
        let target = Target::host();
        let expected = json!({
            "formatVersion": FORMAT_VERSION,
            "schemaVersion": 1,
            "package": {
                "id": "dev.luxury.demo",
                "name": "Luxury Demo",
                "publisher": "Luxury Software",
                "version": "1.0.0"
            },
            "target": {
                "os": target.os.to_string(),
                "arch": target.arch.to_string()
            },
            "install": {
                "scope": "user",
                "directory": "Luxury Demo",
                "hasEntrypoint": false
            },
            "payload": {"files": 1, "bytes": 29},
            "authoring": {
                "allowDowngrade": false,
                "entrypoint": null,
                "executableFiles": 0
            }
        });
        assert_eq!(initialized["result"], expected);

        let validated = stdio_request("validateProject", json!({"projectPath": project_path}));
        assert_eq!(validated["result"], initialized["result"]);

        let built = stdio_request(
            "buildProject",
            json!({"projectPath": project_path, "outputPath": output_path}),
        );
        assert_eq!(built["type"], "result");
        let mut expected_build = expected;
        expected_build["outputPath"] = json!(output_path);
        assert_eq!(built["result"], expected_build);
        assert!(output.is_file());
    }

    #[test]
    fn studio_update_wire_is_strict_validated_and_returns_authoring_state() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let project_path = project.to_str().unwrap();
        assert_eq!(
            stdio_request("initProject", json!({"projectPath": project_path}))["type"],
            "result"
        );
        let target = Target::host();
        let params = json!({
            "projectPath": project_path,
            "package": {
                "id": "dev.human.app",
                "name": "Human App",
                "version": "2.1.0",
                "publisher": "Human Publisher",
                "description": "Release-ready app",
                "license": "Read these terms."
            },
            "target": {
                "os": target.os.to_string(),
                "arch": target.arch.to_string()
            },
            "install": {
                "scope": "user",
                "directory": "Human App",
                "allowDowngrade": true,
                "entrypoint": null,
                "showInstallLog": true,
                "finishLinks": [{
                    "label": "Документация",
                    "url": "https://example.com/docs"
                }]
            }
        });
        let updated = stdio_request("updateProject", params.clone());
        assert_eq!(updated["type"], "result");
        assert_eq!(
            updated["result"]["schemaVersion"],
            luxury_spec::LICENSE_SCHEMA_VERSION
        );
        assert_eq!(updated["result"]["package"]["id"], "dev.human.app");
        assert_eq!(
            updated["result"]["package"]["description"],
            "Release-ready app"
        );
        assert_eq!(updated["result"]["install"]["showInstallLog"], true);
        assert_eq!(updated["result"]["authoring"]["allowDowngrade"], true);

        let before = fs::read(project.join("luxury.toml")).unwrap();
        let mut extra = params;
        extra["unexpected"] = json!(true);
        let rejected = stdio_request("updateProject", extra);
        assert_eq!(rejected["error"]["code"], "invalid_params");
        assert_eq!(fs::read(project.join("luxury.toml")).unwrap(), before);
    }

    #[test]
    fn studio_import_wire_keeps_source_paths_out_of_results_and_rejects_overwrite() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let source = temp.path().join("app.bin");
        fs::write(&source, b"application").unwrap();
        let project_path = project.to_str().unwrap();
        let source_path = source.to_str().unwrap();
        assert_eq!(
            stdio_request("initProject", json!({"projectPath": project_path}))["type"],
            "result"
        );

        let imported = stdio_request(
            "importPayload",
            json!({"projectPath": project_path, "sourcePaths": [source_path]}),
        );
        assert_eq!(imported["type"], "result");
        assert_eq!(imported["result"]["payload"]["files"], 1);
        assert_eq!(imported["result"]["payload"]["bytes"], 11);
        assert!(!imported.to_string().contains(source_path));
        assert_eq!(
            fs::read(project.join("payload/app.bin")).unwrap(),
            b"application"
        );
        assert!(!project.join("payload/hello.txt").exists());
        let resolved = stdio_request(
            "resolvePayloadPath",
            json!({
                "projectPath": project_path,
                "selectedPath": project.join("payload/app.bin").to_str().unwrap()
            }),
        );
        assert_eq!(resolved["result"], json!({"path": "app.bin"}));
        let outside = stdio_request(
            "resolvePayloadPath",
            json!({"projectPath": project_path, "selectedPath": source_path}),
        );
        assert_eq!(outside["error"]["code"], "payload_path_invalid");

        fs::write(&source, b"replacement").unwrap();
        let rejected = stdio_request(
            "importPayload",
            json!({"projectPath": project_path, "sourcePaths": [source_path]}),
        );
        assert_eq!(rejected["error"]["code"], "collision");
        assert_eq!(
            fs::read(project.join("payload/app.bin")).unwrap(),
            b"application"
        );

        let replacement = temp.path().join("replacement");
        fs::create_dir(&replacement).unwrap();
        fs::write(replacement.join("app.bin"), b"replacement").unwrap();
        fs::write(replacement.join("next.bin"), b"next").unwrap();
        let replaced = stdio_request(
            "importPayload",
            json!({
                "projectPath": project_path,
                "sourcePaths": [replacement.to_str().unwrap()],
                "replace": true
            }),
        );
        assert_eq!(replaced["type"], "result");
        assert_eq!(replaced["result"]["payload"]["files"], 2);
        assert!(!replaced.to_string().contains(replacement.to_str().unwrap()));
        assert_eq!(
            fs::read(project.join("payload/app.bin")).unwrap(),
            b"replacement"
        );
        assert_eq!(fs::read(project.join("payload/next.bin")).unwrap(), b"next");

        let invalid_replacement = stdio_request(
            "importPayload",
            json!({
                "projectPath": project_path,
                "sourcePaths": [replacement.to_str().unwrap(), source_path],
                "replace": true
            }),
        );
        assert_eq!(invalid_replacement["error"]["code"], "invalid_params");
        assert_eq!(
            fs::read(project.join("payload/app.bin")).unwrap(),
            b"replacement"
        );

        let relative = stdio_request(
            "importPayload",
            json!({"projectPath": project_path, "sourcePaths": ["relative.bin"]}),
        );
        assert_eq!(relative["error"]["code"], "invalid_params");
    }

    #[test]
    fn project_wire_bounds_optional_install_log_and_finish_links() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let config = project.join("luxury.toml");
        let source = fs::read_to_string(&config).unwrap().replace(
            "directory = \"Luxury Demo\"",
            "directory = \"Luxury Demo\"\nshow_install_log = true\n\n[[install.finish_links]]\nlabel = \"Документация\"\nurl = \"https://example.com/docs\"",
        );
        fs::write(config, source).unwrap();

        let validated = stdio_request(
            "validateProject",
            json!({"projectPath": project.to_str().unwrap()}),
        );
        assert_eq!(validated["result"]["install"]["showInstallLog"], true);
        assert_eq!(
            validated["result"]["install"]["finishLinks"],
            json!([{"label": "Документация", "url": "https://example.com/docs"}])
        );
        assert_eq!(
            validated["result"]["payload"]["installLog"],
            json!({"files": ["hello.txt"], "omittedFiles": 0})
        );
    }

    #[test]
    fn studio_v2_validation_succeeds_but_unsigned_build_fails_without_output() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let output = temp.path().join("must-not-exist.luxpkg");
        init_project(&project).unwrap();
        let config = project.join("luxury.toml");
        fs::write(
            &config,
            fs::read_to_string(&config).unwrap().replacen(
                "format_version = 1",
                "format_version = 2",
                1,
            ),
        )
        .unwrap();
        let project_path = project.to_str().unwrap();
        let output_path = output.to_str().unwrap();

        let validated = stdio_request("validateProject", json!({"projectPath": project_path}));
        assert_eq!(validated["result"]["formatVersion"], SIGNED_FORMAT_VERSION);

        let built = stdio_request(
            "buildProject",
            json!({"projectPath": project_path, "outputPath": output_path}),
        );
        assert_eq!(built["error"]["code"], "project_build_failed");
        assert!(!output.exists());
    }

    #[test]
    fn studio_v3_validation_is_public_only_and_unsigned_build_stays_disabled() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let output = temp.path().join("must-not-exist-v3.luxpkg");
        init_project(&project).unwrap();
        let manifest = luxury_compiler::validate_project(&project).unwrap();
        let current = PackageSigningKey::from_pkcs8_pem(SIGNING_KEY_PEM).unwrap();
        let next = PackageSigningKey::from_pkcs8_pem(OTHER_SIGNING_KEY_PEM).unwrap();
        let rotation = next
            .create_publisher_rotation(
                &manifest.package.id,
                &manifest.package.version,
                current.key_id(),
            )
            .unwrap();
        configure_rotation_project(&project, &rotation);
        let project_path = project.to_str().unwrap();

        let validated = stdio_request("validateProject", json!({"projectPath": project_path}));
        assert_eq!(validated["result"]["formatVersion"], 3);
        assert!(validated["result"].get("publisherRotation").is_none());
        let encoded = serde_json::to_string(&validated).unwrap();
        assert!(!encoded.contains("PRIVATE KEY"));
        assert!(!encoded.contains(SIGNING_KEY_PEM));
        assert!(!encoded.contains(OTHER_SIGNING_KEY_PEM));

        let built = stdio_request(
            "buildProject",
            json!({"projectPath": project_path, "outputPath": output.to_str().unwrap()}),
        );
        assert_eq!(built["error"]["code"], "project_build_failed");
        assert!(!output.exists());
    }

    #[test]
    fn studio_rotation_parse_errors_do_not_echo_rejected_secret_material() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let config = project.join("luxury.toml");
        let secret = concat!("-----BEGIN PRIVATE ", "KEY-----SECRET-MARKER");
        let source = fs::read_to_string(&config).unwrap().replacen(
            "format_version = 1",
            "format_version = 3",
            1,
        );
        fs::write(
            config,
            format!(
                "{source}\n[publisher_rotation]\nnext_public_key = \"{secret}\"\nproof = \"{}\"\n",
                "0".repeat(128)
            ),
        )
        .unwrap();

        let response = stdio_request(
            "validateProject",
            json!({"projectPath": project.to_str().unwrap()}),
        );
        assert_eq!(response["error"]["code"], "project_validation_failed");
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(!encoded.contains(secret));
        assert!(!encoded.contains("PRIVATE KEY"));
    }

    #[test]
    fn stdio_shutdown_cancels_and_joins_active_operation_worker() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        File::create(project.join("payload/large.bin"))
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();

        let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        sender
            .send(ServerMessage::Request(Ok(Request {
                protocol_version: PROTOCOL_VERSION,
                id: "authoring-shutdown".into(),
                method: "validateProject".into(),
                params: json!({"projectPath": project.to_str().unwrap()}),
            })))
            .unwrap();
        sender.send(ServerMessage::InputClosed).unwrap();

        let mut output = Vec::new();
        serve(receiver, sender, &mut output, None);

        assert_eq!(
            serde_json::from_slice::<Value>(output.strip_suffix(b"\n").unwrap()).unwrap(),
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "type": "error",
                "id": "authoring-shutdown",
                "error": {"code": "cancelled", "message": "operation cancelled"}
            })
        );
    }

    #[test]
    fn stdio_eof_cancels_and_joins_active_uninstall_worker() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let package = temp.path().join("package.luxpkg");
        let install_base = temp.path().join("install");
        let state_root = temp.path().join("state");
        init_project(&project).unwrap();
        File::create(project.join("payload/hello.txt"))
            .unwrap()
            .set_len(8 * 1024 * 1024)
            .unwrap();
        compile_project(&project, &package).unwrap();
        let inspected = inspect_package(package.clone(), None, &AtomicBool::new(false)).unwrap();
        let installed = install_base
            .join(&inspected.install.directory)
            .join("hello.txt");
        let package_id = inspected.package.id;
        let (install_sender, _install_receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        install_package(
            "uninstall-eof-fixture",
            ValidInstallParams {
                package_path: package,
                install_base: install_base.clone(),
                state_root: state_root.clone(),
                allow_unsigned: true,
                accept_license: false,
                allow_downgrade: false,
                allow_publisher_migration: false,
                expected_fingerprint: inspected.package_fingerprint,
            },
            None,
            &AtomicBool::new(false),
            &install_sender,
        )
        .unwrap();
        assert!(installed.is_file());

        let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        sender
            .send(ServerMessage::Request(Ok(Request {
                protocol_version: PROTOCOL_VERSION,
                id: "uninstall-eof".into(),
                method: "uninstall".into(),
                params: json!({
                    "packageId": package_id,
                    "installBase": install_base,
                    "stateRoot": state_root,
                }),
            })))
            .unwrap();
        sender.send(ServerMessage::InputClosed).unwrap();

        let mut output = Vec::new();
        serve(receiver, sender, &mut output, None);

        let lines = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lines.last().unwrap()["type"], "error");
        assert_eq!(lines.last().unwrap()["id"], "uninstall-eof");
        assert_eq!(lines.last().unwrap()["error"]["code"], "cancelled");
        assert!(installed.is_file());
    }

    #[test]
    fn pre_cancelled_project_initialization_does_not_create_files() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let cancelled = AtomicBool::new(true);

        let Err(error) = initialize_project(project.clone(), &cancelled) else {
            panic!("pre-cancelled project initialization unexpectedly succeeded");
        };

        assert_eq!(error.code, "cancelled");
        assert!(!project.exists());
    }

    #[test]
    fn cancelled_project_initialization_is_reported_and_retryable() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let payload = project.join("payload");
        fs::create_dir_all(&payload).unwrap();
        let large = payload.join("large.bin");
        File::create(&large)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancelled);
        let config = project.join("luxury.toml");
        let canceller = thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !config.exists() {
                assert!(std::time::Instant::now() < deadline);
                thread::yield_now();
            }
            worker_cancel.store(true, Ordering::Release);
        });

        let Err(error) = initialize_project(project.clone(), cancelled.as_ref()) else {
            panic!("project validation unexpectedly completed before cancellation");
        };
        canceller.join().unwrap();

        assert_eq!(error.code, "cancelled");
        assert!(error.message.contains("project is initialized"));
        fs::remove_file(large).unwrap();
        cancelled.store(false, Ordering::Release);
        initialize_project(project, cancelled.as_ref()).unwrap();
    }

    #[test]
    fn oversized_lines_are_discarded_without_losing_the_next_request() {
        let mut source = vec![b'x'; MAX_LINE_BYTES + 1];
        source.extend_from_slice(b"\n{}\n");
        let mut input = Cursor::new(source);
        assert!(matches!(
            read_bounded_line(&mut input).unwrap(),
            Some(BoundedLine::Oversized)
        ));
        assert!(matches!(
            read_bounded_line(&mut input).unwrap(),
            Some(BoundedLine::Bytes(bytes)) if bytes == b"{}"
        ));
    }

    #[test]
    fn result_and_error_lines_match_the_jsonl_contract() {
        let unicode_error = WireError::new(
            "invalid_request",
            format!("bad\n{}", "💥".repeat(MAX_MESSAGE_BYTES)),
        );
        assert!(unicode_error.message.len() <= MAX_MESSAGE_BYTES);
        assert!(!unicode_error.message.chars().any(char::is_control));
        assert!(unicode_error.message.starts_with("bad "));
        assert_eq!(
            WireError::new("invalid_request", "\n\t").message,
            "operation failed"
        );
        let mut output = Vec::new();
        assert!(write_result(
            &mut output,
            "request-1",
            CancelResult {
                request_id: "install-1".into(),
                accepted: true,
            }
        ));
        assert!(write_error(
            &mut output,
            None,
            WireError::new("invalid_request", "bad line")
        ));
        let lines = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            lines[0],
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "type": "result",
                "id": "request-1",
                "result": {"requestId": "install-1", "accepted": true}
            })
        );
        assert_eq!(lines[1]["type"], "error");
        assert!(lines[1]["id"].is_null());
    }

    #[test]
    fn install_params_keep_unsigned_consent_until_the_bundle_is_opened() {
        let absolute = if cfg!(windows) {
            "C:\\Luxury\\package.luxpkg"
        } else {
            "/tmp/package.luxpkg"
        };
        let params = InstallParams {
            package_path: absolute.into(),
            install_base: absolute.into(),
            state_root: absolute.into(),
            allow_unsigned: false,
            accept_license: false,
            allow_downgrade: false,
            allow_publisher_migration: false,
            expected_fingerprint: "a".repeat(64),
        };
        let params = validate_install_params(params).unwrap();
        assert!(!params.allow_unsigned);
        assert!(!params.accept_license);
        assert!(!params.allow_downgrade);
        assert!(!params.allow_publisher_migration);

        let old_request: InstallParams = serde_json::from_value(json!({
            "packagePath": absolute,
            "installBase": absolute,
            "stateRoot": absolute,
            "allowUnsigned": false,
            "expectedFingerprint": "a".repeat(64),
        }))
        .unwrap();
        assert!(!old_request.allow_downgrade);
        assert!(!old_request.allow_publisher_migration);
        assert!(!old_request.accept_license);

        let approved: InstallParams = serde_json::from_value(json!({
            "packagePath": absolute,
            "installBase": absolute,
            "stateRoot": absolute,
            "allowUnsigned": false,
            "acceptLicense": true,
            "allowDowngrade": true,
            "allowPublisherMigration": true,
            "expectedFingerprint": "a".repeat(64),
        }))
        .unwrap();
        let approved = validate_install_params(approved).unwrap();
        assert!(approved.accept_license);
        assert!(approved.allow_downgrade);
        assert!(approved.allow_publisher_migration);
        assert_eq!(
            absolute_path("relative.luxpkg".into(), "packagePath")
                .unwrap_err()
                .code,
            "invalid_params"
        );
        assert_eq!(
            validate_fingerprint("A".repeat(64)).unwrap_err().code,
            "invalid_params"
        );
    }

    #[test]
    fn uninstall_params_are_strict_absolute_and_validate_package_id() {
        let absolute = std::env::current_dir()
            .unwrap()
            .join("uninstall")
            .to_string_lossy()
            .into_owned();
        let params: UninstallParams = serde_json::from_value(json!({
            "packageId": "dev.luxury.demo",
            "installBase": absolute,
            "stateRoot": absolute,
        }))
        .unwrap();
        let validated = validate_uninstall_params(params).unwrap();
        assert_eq!(validated.package_id.as_str(), "dev.luxury.demo");
        assert!(validated.install_base.is_absolute());
        assert!(validated.state_root.is_absolute());

        assert!(
            serde_json::from_value::<UninstallParams>(json!({
                "packageId": "dev.luxury.demo",
                "installBase": absolute,
                "stateRoot": absolute,
                "allowUnsigned": true,
            }))
            .is_err()
        );
        let relative: UninstallParams = serde_json::from_value(json!({
            "packageId": "dev.luxury.demo",
            "installBase": "relative",
            "stateRoot": absolute,
        }))
        .unwrap();
        assert_eq!(
            validate_uninstall_params(relative).unwrap_err().code,
            "invalid_params"
        );
        let invalid: UninstallParams = serde_json::from_value(json!({
            "packageId": "PRIVATE INVALID PACKAGE ID",
            "installBase": absolute,
            "stateRoot": absolute,
        }))
        .unwrap();
        let error = validate_uninstall_params(invalid).unwrap_err();
        assert_eq!(error.code, "invalid_params");
        assert!(!error.message.contains("PRIVATE"));
    }

    #[test]
    fn uninstall_wire_covers_installed_and_not_installed_lifecycle() {
        let temp = tempdir().unwrap();
        let (package_id, install_base, state_root, installed) =
            install_default_fixture(temp.path());
        let params = json!({
            "packageId": package_id,
            "installBase": install_base,
            "stateRoot": state_root,
        });

        let lines = stdio_mutation_request("uninstall", params.clone());
        let phases = lines
            .iter()
            .filter(|line| line["type"] == "event" && line["event"] == "phase")
            .map(|line| line["data"]["phase"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            [
                "recovering",
                "loadingReceipt",
                "removing",
                "committing",
                "completed",
            ]
        );
        assert_eq!(
            lines.last().unwrap(),
            &json!({
                "protocolVersion": PROTOCOL_VERSION,
                "type": "result",
                "id": "mutation-1",
                "result": {
                    "status": "uninstalled",
                    "packageId": "dev.luxury.demo",
                    "removedFiles": 1,
                    "missingFiles": 0,
                    "preservedModifiedFiles": 0,
                },
            })
        );
        assert!(!installed.exists());

        let lines = stdio_mutation_request("uninstall", params);
        assert_eq!(
            lines.last().unwrap()["result"],
            json!({
                "status": "notInstalled",
                "packageId": "dev.luxury.demo",
            })
        );
    }

    #[test]
    fn launch_wire_is_pathless_and_does_not_mutate_a_package_without_an_entrypoint() {
        let temp = tempdir().unwrap();
        let (package_id, install_base, state_root, installed) =
            install_default_fixture(temp.path());
        let installed_bytes = fs::read(&installed).unwrap();

        let lines = stdio_mutation_request(
            "launch",
            json!({
                "packageId": package_id,
                "installBase": install_base,
                "stateRoot": state_root,
            }),
        );

        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["type"], "error");
        assert_eq!(lines[0]["error"]["code"], "launch_not_available");
        assert_eq!(fs::read(installed).unwrap(), installed_bytes);
    }

    #[test]
    fn uninstall_progress_uses_zero_bytes_and_suppresses_modified_paths() {
        let temp = tempdir().unwrap();
        let (package_id, install_base, state_root, installed) =
            install_default_fixture(temp.path());
        fs::write(&installed, b"private modified contents").unwrap();

        let lines = stdio_mutation_request(
            "uninstall",
            json!({
                "packageId": package_id,
                "installBase": install_base,
                "stateRoot": state_root,
            }),
        );
        let progress = lines
            .iter()
            .filter(|line| line["type"] == "event" && line["event"] == "progress")
            .map(|line| line["data"].clone())
            .collect::<Vec<_>>();
        assert_eq!(
            progress,
            [
                json!({
                    "completedFiles": 0,
                    "totalFiles": 1,
                    "completedBytes": 0,
                    "totalBytes": 0,
                }),
                json!({
                    "completedFiles": 1,
                    "totalFiles": 1,
                    "completedBytes": 0,
                    "totalBytes": 0,
                }),
            ]
        );
        assert_eq!(
            lines.last().unwrap()["result"],
            json!({
                "status": "uninstalled",
                "packageId": "dev.luxury.demo",
                "removedFiles": 0,
                "missingFiles": 0,
                "preservedModifiedFiles": 1,
            })
        );
        let wire = serde_json::to_string(&lines).unwrap();
        assert!(!wire.contains("hello.txt"));
        assert!(!wire.contains("private modified contents"));
        assert_eq!(fs::read(installed).unwrap(), b"private modified contents");
    }

    #[test]
    fn prepare_install_params_are_strict_absolute_and_fingerprint_bound() {
        let absolute = std::env::current_dir()
            .unwrap()
            .join("prepare")
            .to_string_lossy()
            .into_owned();
        let params: PrepareInstallParams = serde_json::from_value(json!({
            "packagePath": absolute,
            "installBase": absolute,
            "stateRoot": absolute,
            "expectedFingerprint": "a".repeat(64),
        }))
        .unwrap();
        let validated = validate_prepare_install_params(params).unwrap();
        assert!(validated.package_path.is_absolute());
        assert!(validated.install_base.is_absolute());
        assert!(validated.state_root.is_absolute());
        assert_eq!(validated.expected_fingerprint, "a".repeat(64));

        assert!(
            serde_json::from_value::<PrepareInstallParams>(json!({
                "packagePath": absolute,
                "installBase": absolute,
                "stateRoot": absolute,
                "expectedFingerprint": "a".repeat(64),
                "allowUnsigned": true,
            }))
            .is_err()
        );
        let relative: PrepareInstallParams = serde_json::from_value(json!({
            "packagePath": "relative.luxpkg",
            "installBase": absolute,
            "stateRoot": absolute,
            "expectedFingerprint": "a".repeat(64),
        }))
        .unwrap();
        assert_eq!(
            validate_prepare_install_params(relative).unwrap_err().code,
            "invalid_params"
        );
        let bad_fingerprint: PrepareInstallParams = serde_json::from_value(json!({
            "packagePath": absolute,
            "installBase": absolute,
            "stateRoot": absolute,
            "expectedFingerprint": "A".repeat(64),
        }))
        .unwrap();
        assert_eq!(
            validate_prepare_install_params(bad_fingerprint)
                .unwrap_err()
                .code,
            "invalid_params"
        );
    }

    #[test]
    fn prepare_install_wire_covers_actions_migration_and_recovery() {
        let version = Version::new(1, 2, 3);
        let cases = [
            (
                InstallPrepareOutcome::Ready {
                    action: InstallAction::Install,
                    installed_version: None,
                    publisher_migration_required: false,
                },
                json!({
                    "status": "ready",
                    "action": "install",
                    "installedVersion": null,
                    "publisherMigrationRequired": false,
                }),
            ),
            (
                InstallPrepareOutcome::Ready {
                    action: InstallAction::Update,
                    installed_version: Some(version.clone()),
                    publisher_migration_required: true,
                },
                json!({
                    "status": "ready",
                    "action": "update",
                    "installedVersion": "1.2.3",
                    "publisherMigrationRequired": true,
                }),
            ),
            (
                InstallPrepareOutcome::Ready {
                    action: InstallAction::Repair,
                    installed_version: Some(version.clone()),
                    publisher_migration_required: false,
                },
                json!({
                    "status": "ready",
                    "action": "repair",
                    "installedVersion": "1.2.3",
                    "publisherMigrationRequired": false,
                }),
            ),
            (
                InstallPrepareOutcome::InsufficientSpace {
                    action: InstallAction::Update,
                    installed_version: Some(version),
                    publisher_migration_required: true,
                },
                json!({
                    "status": "insufficientSpace",
                    "action": "update",
                    "installedVersion": "1.2.3",
                    "publisherMigrationRequired": true,
                }),
            ),
            (
                InstallPrepareOutcome::RecoveryRequired,
                json!({"status": "recoveryRequired"}),
            ),
        ];
        for (outcome, expected) in cases {
            assert_eq!(
                serde_json::to_value(PrepareInstallResult::from_outcome(outcome).unwrap()).unwrap(),
                expected
            );
        }
        for outcome in [
            InstallPrepareOutcome::Ready {
                action: InstallAction::Downgrade,
                installed_version: Some(Version::new(2, 0, 0)),
                publisher_migration_required: false,
            },
            InstallPrepareOutcome::InsufficientSpace {
                action: InstallAction::Downgrade,
                installed_version: Some(Version::new(2, 0, 0)),
                publisher_migration_required: false,
            },
        ] {
            assert_eq!(
                PrepareInstallResult::from_outcome(outcome)
                    .unwrap_err()
                    .code,
                "internal_error"
            );
        }
    }

    #[test]
    fn install_result_serializes_every_actual_action() {
        let package_id = luxury_spec::PackageId::parse("dev.luxury.demo").unwrap();
        for (action, expected) in [
            (InstallAction::Install, "install"),
            (InstallAction::Update, "update"),
            (InstallAction::Repair, "repair"),
            (InstallAction::Downgrade, "downgrade"),
        ] {
            let value = serde_json::to_value(InstallResult::new(
                InstallOutcome {
                    package_id: package_id.clone(),
                    action,
                    installed_files: 1,
                    installed_bytes: 2,
                },
                "LuxuryDemo".into(),
            ))
            .unwrap();
            assert_eq!(value["action"], expected);
        }
    }

    #[test]
    fn install_action_event_serializes_every_factual_action() {
        for (action, expected) in [
            (InstallAction::Install, "install"),
            (InstallAction::Update, "update"),
            (InstallAction::Repair, "repair"),
            (InstallAction::Downgrade, "downgrade"),
        ] {
            let mut output = Vec::new();
            assert!(write_install_event(
                &mut output,
                "install-action",
                InstallEvent::Action(action),
            ));
            assert_eq!(
                serde_json::from_slice::<Value>(&output).unwrap(),
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "type": "event",
                    "id": "install-action",
                    "event": "action",
                    "data": { "action": expected },
                })
            );
        }
    }

    #[test]
    fn mutation_events_coalesce_latest_progress_and_flush_before_phase() {
        use luxury_engine::install::InstallProgress;

        let (sender, receiver) = mpsc::sync_channel(8);
        let progress = |completed_files| {
            MutationEvent::Install(InstallEvent::Progress(InstallProgress {
                completed_files,
                total_files: 3,
                completed_bytes: completed_files as u64,
                total_bytes: 3,
            }))
        };
        let mut events =
            MutationEvents::with_interval("install-progress", &sender, Duration::from_secs(60));

        events.emit(progress(0));
        events.flush();
        events.emit(progress(1));
        events.emit(progress(2));
        events.emit(MutationEvent::Install(InstallEvent::Phase(
            InstallPhase::Committing,
        )));
        drop(events);

        assert!(matches!(
            receiver.recv().unwrap(),
            ServerMessage::MutationEvent {
                event: MutationEvent::Install(InstallEvent::Progress(InstallProgress {
                    completed_files: 0,
                    ..
                })),
                ..
            }
        ));
        assert!(matches!(
            receiver.recv().unwrap(),
            ServerMessage::MutationEvent {
                event: MutationEvent::Install(InstallEvent::Progress(InstallProgress {
                    completed_files: 2,
                    ..
                })),
                ..
            }
        ));
        assert!(matches!(
            receiver.recv().unwrap(),
            ServerMessage::MutationEvent {
                event: MutationEvent::Install(InstallEvent::Phase(InstallPhase::Committing)),
                ..
            }
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        let (sender, receiver) = mpsc::sync_channel(4);
        let mut events =
            MutationEvents::with_interval("timed-progress", &sender, Duration::from_secs(60));
        events.emit(progress(1));
        events.emit(progress(2));
        events.ticker.as_ref().unwrap().thread().unpark();
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            ServerMessage::MutationEvent {
                event: MutationEvent::Install(InstallEvent::Progress(InstallProgress {
                    completed_files: 2,
                    ..
                })),
                ..
            }
        ));
    }

    #[test]
    fn mutation_events_keep_a_large_progress_burst_bounded() {
        use luxury_engine::install::InstallProgress;

        const TOTAL: usize = 100_000;
        let (sender, receiver) = mpsc::sync_channel(4);
        let mut events =
            MutationEvents::with_interval("bounded-progress", &sender, Duration::from_secs(60));
        for completed_files in 0..=TOTAL {
            events.emit(MutationEvent::Install(InstallEvent::Progress(
                InstallProgress {
                    completed_files,
                    total_files: TOTAL,
                    completed_bytes: completed_files as u64,
                    total_bytes: TOTAL as u64,
                },
            )));
        }
        events.emit(MutationEvent::Install(InstallEvent::Phase(
            InstallPhase::Committing,
        )));
        drop(events);

        assert!(matches!(
            receiver.recv().unwrap(),
            ServerMessage::MutationEvent {
                event: MutationEvent::Install(InstallEvent::Progress(InstallProgress {
                    completed_files: TOTAL,
                    ..
                })),
                ..
            }
        ));
        assert!(matches!(
            receiver.recv().unwrap(),
            ServerMessage::MutationEvent {
                event: MutationEvent::Install(InstallEvent::Phase(InstallPhase::Committing)),
                ..
            }
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn uninstall_phase_events_are_stable_and_modified_paths_are_suppressed() {
        for (phase, expected) in [
            (UninstallPhase::Recovering, "recovering"),
            (UninstallPhase::LoadingReceipt, "loadingReceipt"),
            (UninstallPhase::Removing, "removing"),
            (UninstallPhase::Committing, "committing"),
            (UninstallPhase::RollingBack, "rollingBack"),
            (UninstallPhase::Completed, "completed"),
            (UninstallPhase::Cancelled, "cancelled"),
            (UninstallPhase::Failed, "failed"),
        ] {
            let mut output = Vec::new();
            assert!(write_uninstall_event(
                &mut output,
                "uninstall-phase",
                UninstallEvent::Phase(phase),
            ));
            assert_eq!(
                serde_json::from_slice::<Value>(&output).unwrap(),
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "type": "event",
                    "id": "uninstall-phase",
                    "event": "phase",
                    "data": { "phase": expected },
                })
            );
        }

        let mut output = Vec::new();
        assert!(write_uninstall_event(
            &mut output,
            "uninstall-path",
            UninstallEvent::PreservedModified(PackagePath::parse("private/secret.txt").unwrap(),),
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn unsigned_prepare_install_needs_no_install_consent() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let package = temp.path().join("package.luxpkg");
        init_project(&project).unwrap();
        compile_project(&project, &package).unwrap();
        let inspected = inspect_package(package.clone(), None, &AtomicBool::new(false)).unwrap();
        let error = prepare_install_package(
            ValidPrepareInstallParams {
                package_path: package.clone(),
                install_base: temp.path().join("install"),
                state_root: temp.path().join("state"),
                expected_fingerprint: "0".repeat(64),
            },
            None,
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert_eq!(error.code, "package_changed");
        let response = stdio_request(
            "prepareInstall",
            json!({
                "packagePath": package,
                "installBase": temp.path().join("install"),
                "stateRoot": temp.path().join("state"),
                "expectedFingerprint": inspected.package_fingerprint,
            }),
        );
        assert_eq!(response["type"], "result");
        assert_eq!(
            response["result"],
            json!({
                "status": "ready",
                "action": "install",
                "installedVersion": null,
                "publisherMigrationRequired": false,
            })
        );
        assert!(!temp.path().join("install").exists());
        assert!(!temp.path().join("state").exists());
    }

    #[test]
    fn upgrade_policy_errors_have_stable_wire_codes() {
        let project = tempdir().unwrap();
        init_project(project.path()).unwrap();
        let version = luxury_compiler::validate_project(project.path())
            .unwrap()
            .package
            .version;
        let path = PackagePath::parse("bin/demo").unwrap();
        let publisher = PackageIdentity::TrustedPublisher {
            key_id: PublisherKeyId::parse("0".repeat(64)).unwrap(),
        };
        let cases = [
            (InstallError::LicenseNotAccepted, "license_not_accepted"),
            (
                InstallError::InvalidReceipt(ReceiptError::EmptyFiles),
                "invalid_state",
            ),
            (
                InstallError::ReceiptMismatch { field: "directory" },
                "state_conflict",
            ),
            (
                InstallError::PathAliasChanged {
                    installed: path.clone(),
                    requested: path,
                },
                "state_conflict",
            ),
            (
                InstallError::PublisherMigrationDenied {
                    installed: None,
                    requested: publisher,
                },
                "publisher_migration_required",
            ),
            (
                InstallError::PublisherMismatch {
                    installed: publisher,
                    requested: PackageIdentity::Unsigned,
                },
                "publisher_mismatch",
            ),
            (
                InstallError::PublisherRotationDenied {
                    installed: None,
                    signer_key_id: PublisherKeyId::parse("1".repeat(64)).unwrap(),
                    rotation_to: PublisherKeyId::parse("2".repeat(64)).unwrap(),
                },
                "publisher_rotation_denied",
            ),
            (
                InstallError::DowngradeDenied {
                    installed: version.clone(),
                    requested: version.clone(),
                },
                "downgrade_denied",
            ),
            (
                InstallError::ReinstallMismatch { version },
                "reinstall_mismatch",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(install_error(error).code, expected);
        }
    }

    #[test]
    fn uninstall_errors_have_stable_codes_and_redacted_messages() {
        let package_id = PackageId::parse("dev.luxury.demo").unwrap();
        let other_id = PackageId::parse("dev.luxury.other").unwrap();
        let cases = [
            (
                UninstallError::InvalidReceipt(ReceiptError::EmptyFiles),
                "invalid_state",
            ),
            (
                UninstallError::ReceiptPackageMismatch {
                    requested: package_id,
                    receipt: other_id,
                },
                "state_conflict",
            ),
            (UninstallError::Cancelled, "cancelled"),
            (
                UninstallError::Rollback {
                    cause: Box::new(UninstallError::Cancelled),
                    rollback: luxury_engine::PortError::new("PRIVATE ROLLBACK PATH"),
                },
                "rollback_failed",
            ),
            (
                UninstallError::Port {
                    step: "remove owned file",
                    source: luxury_engine::PortError::with_kind(
                        PortErrorKind::Permission,
                        "PRIVATE FILESYSTEM PATH",
                    ),
                },
                "permission_denied",
            ),
            (
                UninstallError::Port {
                    step: "commit",
                    source: luxury_engine::PortError::new("PRIVATE OTHER ERROR"),
                },
                "uninstall_failed",
            ),
        ];

        for (error, expected) in cases {
            let error = uninstall_error(error);
            assert_eq!(error.code, expected);
            assert!(!error.message.contains("PRIVATE"));
        }
    }

    #[test]
    fn launch_errors_have_stable_codes_and_redacted_messages() {
        let package_id = PackageId::parse("dev.luxury.demo").unwrap();
        let other_id = PackageId::parse("dev.luxury.other").unwrap();
        let entrypoint = PackagePath::parse("bin/private.exe").unwrap();
        let cases = [
            (
                LaunchError::RecoveryPending {
                    package_id: package_id.clone(),
                },
                "recovery_required",
            ),
            (
                LaunchError::NotInstalled {
                    package_id: package_id.clone(),
                },
                "launch_not_available",
            ),
            (
                LaunchError::MissingEntrypoint {
                    package_id: package_id.clone(),
                },
                "launch_not_available",
            ),
            (
                LaunchError::InvalidReceipt(ReceiptError::EmptyFiles),
                "invalid_state",
            ),
            (
                LaunchError::ReceiptPackageMismatch {
                    requested: package_id,
                    receipt: other_id,
                },
                "invalid_state",
            ),
            (
                LaunchError::EntrypointNotOwned { entrypoint },
                "invalid_state",
            ),
            (
                LaunchError::Port {
                    step: "launch owned entrypoint",
                    source: luxury_engine::PortError::with_kind(
                        PortErrorKind::Recovery,
                        "PRIVATE PENDING TRANSACTION",
                    ),
                },
                "recovery_required",
            ),
            (
                LaunchError::Port {
                    step: "launch owned entrypoint",
                    source: luxury_engine::PortError::with_kind(
                        PortErrorKind::Integrity,
                        "PRIVATE ENTRYPOINT PATH",
                    ),
                },
                "invalid_state",
            ),
            (
                LaunchError::Port {
                    step: "launch owned entrypoint",
                    source: luxury_engine::PortError::with_kind(
                        PortErrorKind::Permission,
                        "PRIVATE ENTRYPOINT PATH",
                    ),
                },
                "launch_failed",
            ),
        ];

        for (error, expected) in cases {
            let error = launch_error(error);
            assert_eq!(error.code, expected);
            assert!(!error.message.contains("PRIVATE"));
        }
    }

    #[test]
    fn unsigned_consent_and_trust_shape_are_enforced_after_verification() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let package = temp.path().join("package.luxpkg");
        init_project(&project).unwrap();
        compile_project(&project, &package).unwrap();
        let inspected = inspect_package(package.clone(), None, &AtomicBool::new(false)).unwrap();
        let inspected_json = serde_json::to_value(&inspected).unwrap();
        assert_eq!(inspected_json["trust"], json!({"kind": "unsigned"}));
        assert!(inspected_json["publisherRotation"].is_null());

        let install_base = temp.path().join("install");
        let state_root = temp.path().join("state");
        let (sender, _receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let fingerprint = inspected.package_fingerprint;
        let error = install_package(
            "install-1",
            ValidInstallParams {
                package_path: package.clone(),
                install_base: install_base.clone(),
                state_root: state_root.clone(),
                allow_unsigned: false,
                accept_license: false,
                allow_downgrade: false,
                allow_publisher_migration: false,
                expected_fingerprint: fingerprint.clone(),
            },
            None,
            &AtomicBool::new(false),
            &sender,
        )
        .unwrap_err();
        assert_eq!(error.code, "unsigned_not_allowed");
        assert!(!install_base.exists());
        assert!(!state_root.exists());

        let installed = install_package(
            "install-2",
            ValidInstallParams {
                package_path: package,
                install_base,
                state_root,
                allow_unsigned: true,
                accept_license: false,
                allow_downgrade: false,
                allow_publisher_migration: false,
                expected_fingerprint: fingerprint,
            },
            None,
            &AtomicBool::new(false),
            &sender,
        )
        .unwrap();
        assert_eq!(installed.installed_files, 1);
    }

    #[test]
    fn package_license_is_inspected_and_required_before_mutation() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let package = temp.path().join("licensed.luxpkg");
        init_project(&project).unwrap();
        let config = project.join("luxury.toml");
        let source = fs::read_to_string(&config)
            .unwrap()
            .replacen(
                "format_version = 1",
                "format_version = 1\nschema_version = 3",
                1,
            )
            .replacen(
                "publisher = \"Luxury Software\"",
                "publisher = \"Luxury Software\"\nlicense = \"Demo license terms.\"",
                1,
            );
        fs::write(config, source).unwrap();
        compile_project(&project, &package).unwrap();

        let inspected = inspect_package(package.clone(), None, &AtomicBool::new(false)).unwrap();
        assert_eq!(
            inspected.package.license.as_deref(),
            Some("Demo license terms.")
        );
        let fingerprint = inspected.package_fingerprint;
        let install_base = temp.path().join("install");
        let state_root = temp.path().join("state");
        let (sender, _receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);

        let error = install_package(
            "licensed-denied",
            ValidInstallParams {
                package_path: package.clone(),
                install_base: install_base.clone(),
                state_root: state_root.clone(),
                allow_unsigned: true,
                accept_license: false,
                allow_downgrade: false,
                allow_publisher_migration: false,
                expected_fingerprint: fingerprint.clone(),
            },
            None,
            &AtomicBool::new(false),
            &sender,
        )
        .unwrap_err();
        assert_eq!(error.code, "license_not_accepted");
        assert!(!install_base.exists());
        assert!(!state_root.exists());

        let installed = install_package(
            "licensed-approved",
            ValidInstallParams {
                package_path: package,
                install_base,
                state_root,
                allow_unsigned: true,
                accept_license: true,
                allow_downgrade: false,
                allow_publisher_migration: false,
                expected_fingerprint: fingerprint,
            },
            None,
            &AtomicBool::new(false),
            &sender,
        )
        .unwrap();
        assert_eq!(installed.installed_files, 1);
    }

    #[test]
    fn trusted_package_serializes_identity_and_binds_the_reviewed_fingerprint() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let unsigned = temp.path().join("unsigned.luxpkg");
        let mut manifest = compile_project(&project, &unsigned).unwrap();
        manifest.format_version = SIGNED_FORMAT_VERSION;

        let signing_key = PackageSigningKey::from_pkcs8_pem(SIGNING_KEY_PEM).unwrap();
        let trusted_key = TrustedPublisherKey::from_public_key_pem(TRUSTED_KEY_PEM).unwrap();
        let package = temp.path().join("signed.luxpkg");
        create_signed_bundle(
            File::create(&package).unwrap(),
            project.join("payload"),
            &manifest,
            &signing_key,
        )
        .unwrap();

        let other_signing_key = PackageSigningKey::from_pkcs8_pem(OTHER_SIGNING_KEY_PEM).unwrap();
        let other_trusted_key =
            TrustedPublisherKey::from_public_key_pem(OTHER_TRUSTED_KEY_PEM).unwrap();
        let other_package = temp.path().join("other-signed.luxpkg");
        create_signed_bundle(
            File::create(&other_package).unwrap(),
            project.join("payload"),
            &manifest,
            &other_signing_key,
        )
        .unwrap();

        assert_eq!(
            inspect_package(package.clone(), None, &AtomicBool::new(false))
                .err()
                .unwrap()
                .code,
            "publisher_untrusted"
        );
        assert_eq!(
            inspect_package(
                package.clone(),
                Some(&other_trusted_key),
                &AtomicBool::new(false),
            )
            .err()
            .unwrap()
            .code,
            "publisher_untrusted"
        );
        let inspected =
            inspect_package(package.clone(), Some(&trusted_key), &AtomicBool::new(false)).unwrap();
        let other_inspected = inspect_package(
            other_package,
            Some(&other_trusted_key),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&inspected).unwrap()["trust"],
            json!({
                "kind": "trustedPublisher",
                "keyId": trusted_key.key_id().to_string()
            })
        );
        assert_ne!(
            inspected.package_fingerprint,
            other_inspected.package_fingerprint
        );

        let install_base = temp.path().join("install");
        let state_root = temp.path().join("state");
        let (sender, _receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let error = install_package(
            "install-1",
            ValidInstallParams {
                package_path: package.clone(),
                install_base: install_base.clone(),
                state_root: state_root.clone(),
                allow_unsigned: false,
                accept_license: false,
                allow_downgrade: false,
                allow_publisher_migration: false,
                expected_fingerprint: other_inspected.package_fingerprint,
            },
            Some(&trusted_key),
            &AtomicBool::new(false),
            &sender,
        )
        .unwrap_err();
        assert_eq!(error.code, "package_changed");
        assert!(!install_base.exists());
        assert!(!state_root.exists());

        let installed = install_package(
            "install-2",
            ValidInstallParams {
                package_path: package,
                install_base: temp.path().join("trusted-install"),
                state_root: temp.path().join("trusted-state"),
                allow_unsigned: false,
                accept_license: false,
                allow_downgrade: false,
                allow_publisher_migration: false,
                expected_fingerprint: inspected.package_fingerprint,
            },
            Some(&trusted_key),
            &AtomicBool::new(false),
            &sender,
        )
        .unwrap();
        assert_eq!(installed.installed_files, 1);
    }

    #[test]
    fn v3_inspect_reports_verified_rotation_separately_from_the_current_signer() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        init_project(&project).unwrap();
        let unsigned = temp.path().join("unsigned.luxpkg");
        let mut manifest = compile_project(&project, &unsigned).unwrap();
        manifest.format_version = luxury_spec::PUBLISHER_ROTATION_FORMAT_VERSION;
        let current = PackageSigningKey::from_pkcs8_pem(SIGNING_KEY_PEM).unwrap();
        let next = PackageSigningKey::from_pkcs8_pem(OTHER_SIGNING_KEY_PEM).unwrap();
        manifest.publisher_rotation = Some(
            next.create_publisher_rotation(
                &manifest.package.id,
                &manifest.package.version,
                current.key_id(),
            )
            .unwrap(),
        );
        let package = temp.path().join("rotation.luxpkg");
        create_signed_bundle(
            File::create(&package).unwrap(),
            project.join("payload"),
            &manifest,
            &current,
        )
        .unwrap();
        let trusted = TrustedPublisherKey::from_public_key_pem(TRUSTED_KEY_PEM).unwrap();

        let inspected = inspect_package(package, Some(&trusted), &AtomicBool::new(false)).unwrap();
        let json = serde_json::to_value(inspected).unwrap();
        assert_eq!(
            json["trust"],
            json!({"kind": "trustedPublisher", "keyId": current.key_id().to_string()})
        );
        assert_eq!(
            json["publisherRotation"],
            json!({
                "signerKeyId": current.key_id().to_string(),
                "nextKeyId": next.key_id().to_string(),
            })
        );
        let encoded = serde_json::to_string(&json).unwrap();
        assert!(!encoded.contains("PRIVATE KEY"));
        assert!(!encoded.contains(SIGNING_KEY_PEM));
        assert!(!encoded.contains(OTHER_SIGNING_KEY_PEM));
    }

    #[test]
    fn trusted_key_arguments_and_signature_errors_are_stable() {
        assert!(load_trusted_publisher_key(&[]).unwrap().is_none());
        assert_eq!(
            load_trusted_publisher_key(&[
                OsString::from("--trusted-publisher-key"),
                OsString::from("relative.pem"),
            ])
            .err()
            .unwrap()
            .code,
            "invalid_request"
        );

        let temp = tempdir().unwrap();
        let key_path = temp.path().join("publisher.pem");
        fs::write(&key_path, TRUSTED_KEY_PEM).unwrap();
        let key = load_trusted_publisher_key(&[
            OsString::from("--trusted-publisher-key"),
            key_path.into_os_string(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            key.key_id().to_string(),
            TrustedPublisherKey::from_public_key_pem(TRUSTED_KEY_PEM)
                .unwrap()
                .key_id()
                .to_string()
        );

        let invalid_path = temp.path().join("invalid.pem");
        fs::write(&invalid_path, b"not a public key").unwrap();
        assert_eq!(
            load_trusted_publisher_key(&[
                OsString::from("--trusted-publisher-key"),
                invalid_path.into_os_string(),
            ])
            .err()
            .unwrap()
            .code,
            "trusted_publisher_key_invalid"
        );

        let oversized_path = temp.path().join("oversized.pem");
        fs::write(
            &oversized_path,
            vec![b'x'; MAX_TRUSTED_KEY_BYTES as usize + 1],
        )
        .unwrap();
        assert_eq!(
            load_trusted_publisher_key(&[
                OsString::from("--trusted-publisher-key"),
                oversized_path.into_os_string(),
            ])
            .err()
            .unwrap()
            .code,
            "trusted_publisher_key_invalid"
        );

        assert_eq!(
            bundle_error(BundleError::MissingSignature, "inspect_failed").code,
            "signature_missing"
        );
        assert_eq!(
            bundle_error(BundleError::InvalidSignature, "inspect_failed").code,
            "signature_invalid"
        );
        assert_eq!(
            bundle_error(
                BundleError::MalformedSignature {
                    expected: 96,
                    found: 1,
                },
                "inspect_failed",
            )
            .code,
            "signature_invalid"
        );
        assert_eq!(
            bundle_error(
                BundleError::UntrustedPublisher {
                    key_id: "0".repeat(64),
                },
                "inspect_failed",
            )
            .code,
            "publisher_untrusted"
        );
        assert_eq!(
            bundle_error(BundleError::SignatureForbidden, "inspect_failed").code,
            "signature_invalid"
        );
        assert_eq!(
            bundle_error(BundleError::InvalidPublisherRotationProof, "inspect_failed").code,
            "publisher_rotation_invalid"
        );
        assert_eq!(
            bundle_error(
                BundleError::DuplicateEntry(SIGNATURE_ENTRY.to_owned()),
                "inspect_failed",
            )
            .code,
            "signature_invalid"
        );
    }

    #[test]
    fn cancellation_is_scoped_to_the_active_request() {
        let active = ActiveMutation {
            id: "install-1".into(),
            cancel: Arc::new(AtomicBool::new(false)),
            cancellable: true,
            finished: Arc::new(AtomicBool::new(false)),
            worker: thread::spawn(|| {}),
        };
        assert!(!request_cancellation(Some(&active), None, "install-2"));
        assert!(request_cancellation(Some(&active), None, "install-1"));
        assert!(active.cancel.load(Ordering::Acquire));
        active.worker.join().unwrap();

        let launch = ActiveMutation {
            id: "launch-1".into(),
            cancel: Arc::new(AtomicBool::new(false)),
            cancellable: false,
            finished: Arc::new(AtomicBool::new(false)),
            worker: thread::spawn(|| {}),
        };
        assert!(!request_cancellation(Some(&launch), None, "launch-1"));
        assert!(!launch.cancel.load(Ordering::Acquire));
        launch.worker.join().unwrap();
    }

    #[test]
    fn late_operation_cancellation_is_rejected_before_done_is_dequeued() {
        let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let operation = start_operation("operation-1".into(), sender, |_| Ok(json!(null))).unwrap();
        while !operation.finished.load(Ordering::Acquire) {
            thread::yield_now();
        }

        assert!(!request_cancellation(None, Some(&operation), "operation-1"));
        assert!(!operation.cancel.load(Ordering::Acquire));

        let ServerMessage::OperationDone { id, result } = receiver.recv().unwrap() else {
            panic!("operation worker returned an unexpected message");
        };
        assert_eq!(id, operation.id);
        assert_eq!(result.unwrap(), Value::Null);
        operation.worker.join().unwrap();
    }

    #[test]
    fn mutations_and_read_only_operations_are_mutually_exclusive() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        let package = temp.path().join("package.luxpkg");
        init_project(&project).unwrap();
        compile_project(&project, &package).unwrap();

        let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let mutation = ActiveMutation {
            id: "install-1".into(),
            cancel: Arc::new(AtomicBool::new(false)),
            cancellable: true,
            finished: Arc::new(AtomicBool::new(false)),
            worker: thread::spawn(|| {}),
        };
        let mut active_mutation = Some(mutation);
        let mut active_operation = None;
        let mut output = Vec::new();
        assert!(handle_request(
            Ok(Request {
                protocol_version: PROTOCOL_VERSION,
                id: "inspect-1".into(),
                method: "inspect".into(),
                params: json!({"packagePath": package.to_str().unwrap()}),
            }),
            &sender,
            &mut active_mutation,
            &mut active_operation,
            &mut output,
            None,
        ));
        assert_eq!(
            serde_json::from_slice::<Value>(output.strip_suffix(b"\n").unwrap()).unwrap()["error"]
                ["code"],
            "busy"
        );
        output.clear();
        assert!(handle_request(
            Ok(Request {
                protocol_version: PROTOCOL_VERSION,
                id: "uninstall-while-installing".into(),
                method: "uninstall".into(),
                params: json!({}),
            }),
            &sender,
            &mut active_mutation,
            &mut active_operation,
            &mut output,
            None,
        ));
        assert_eq!(
            serde_json::from_slice::<Value>(output.strip_suffix(b"\n").unwrap()).unwrap()["error"]
                ["code"],
            "busy"
        );
        active_mutation.take().unwrap().worker.join().unwrap();

        output.clear();
        assert!(handle_request(
            Ok(Request {
                protocol_version: PROTOCOL_VERSION,
                id: "inspect-2".into(),
                method: "inspect".into(),
                params: json!({"packagePath": package.to_str().unwrap()}),
            }),
            &sender,
            &mut active_mutation,
            &mut active_operation,
            &mut output,
            None,
        ));
        assert!(output.is_empty());
        assert!(active_operation.is_some());

        assert!(handle_request(
            Ok(Request {
                protocol_version: PROTOCOL_VERSION,
                id: "install-2".into(),
                method: "install".into(),
                params: json!({}),
            }),
            &sender,
            &mut active_mutation,
            &mut active_operation,
            &mut output,
            None,
        ));
        assert_eq!(
            serde_json::from_slice::<Value>(output.strip_suffix(b"\n").unwrap()).unwrap()["error"]
                ["code"],
            "busy"
        );
        output.clear();
        assert!(handle_request(
            Ok(Request {
                protocol_version: PROTOCOL_VERSION,
                id: "uninstall-while-inspecting".into(),
                method: "uninstall".into(),
                params: json!({}),
            }),
            &sender,
            &mut active_mutation,
            &mut active_operation,
            &mut output,
            None,
        ));
        assert_eq!(
            serde_json::from_slice::<Value>(output.strip_suffix(b"\n").unwrap()).unwrap()["error"]
                ["code"],
            "busy"
        );

        let ServerMessage::OperationDone { id, result } = receiver.recv().unwrap() else {
            panic!("inspect worker returned an unexpected message");
        };
        let operation = active_operation.take().unwrap();
        assert_eq!(id, operation.id);
        operation.worker.join().unwrap();
        assert_eq!(result.unwrap()["package"]["id"], "dev.luxury.demo");
    }

    #[test]
    fn shutdown_cancels_install_and_operation_workers() {
        let mutation = ActiveMutation {
            id: "install-1".into(),
            cancel: Arc::new(AtomicBool::new(false)),
            cancellable: true,
            finished: Arc::new(AtomicBool::new(false)),
            worker: thread::spawn(|| {}),
        };
        let operation = ActiveOperation {
            id: "operation-1".into(),
            cancel: Arc::new(AtomicBool::new(false)),
            finished: Arc::new(AtomicBool::new(false)),
            worker: thread::spawn(|| {}),
        };

        request_shutdown(Some(&mutation), Some(&operation));

        assert!(mutation.cancel.load(Ordering::Acquire));
        assert!(operation.cancel.load(Ordering::Acquire));
        mutation.worker.join().unwrap();
        operation.worker.join().unwrap();
    }
}
