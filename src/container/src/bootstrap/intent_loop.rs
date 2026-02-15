/// Intent command loop for app runtime.
///
/// Handles RuntimeIntent commands and routes them to AppRuntime.
#[cfg(target_os = "linux")]
use crate::app_spec::AppState;
use crate::intent::RuntimeIntent;
use std::path::PathBuf;
use tokio::sync::mpsc;

/// Check system requirements before starting the intent loop.
/// Returns Ok(()) if all requirements are met, Err with message otherwise.
/// When running as root (UID 0), skips rootless checks so the daemon can run
/// as a system service (e.g. User=vapp) with privileged containers.
pub fn check_system_requirements() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if nix::unistd::Uid::current().as_raw() == 0 {
            return Ok(());
        }
        let system_check = crate::rootless::system_check::check_system_requirements();
        if !system_check.passed {
            if let Some(error_msg) = system_check.error_message() {
                eprintln!("{}", error_msg);
                return Err(
                    "System requirements not met for rootless containers. Run: sudo ./scripts/linux-container-setup.sh".to_string()
                );
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("Container runtime only available on Linux".to_string())
    }
}

/// Run intent command loop with AppRuntime.
pub async fn run_intent_command_loop(
    mut receiver: mpsc::Receiver<RuntimeIntent>,
    app_dir: PathBuf,
) {
    tracing::info!("[AppRuntime] Starting intent command loop");
    tracing::info!("[AppRuntime] App directory: {}", app_dir.display());

    #[cfg(not(target_os = "linux"))]
    {
        let _ = app_dir;
        tracing::error!("[AppRuntime] Only available on Linux");
        while let Ok(intent) = receiver.try_recv() {
            if let RuntimeIntent::StartApp { callback, .. } = intent {
                let _ = callback.send(Err("App runtime only available on Linux".to_string()));
            }
        }
        return;
    }

    #[cfg(target_os = "linux")]
    {
        use crate::app_runtime::AppRuntime;
        use crate::provisioner::{ChannelProgressReporter, ProvisionError};
        use std::sync::Arc;

        let mut runtime = match AppRuntime::new(app_dir) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("[AppRuntime] Failed to initialize: {}", e);
                while let Ok(intent) = receiver.try_recv() {
                    if let RuntimeIntent::StartApp { callback, .. } = intent {
                        let _ = callback.send(Err(format!("App runtime not available: {}", e)));
                    }
                }
                return;
            }
        };

        while let Some(intent) = receiver.recv().await {
            match intent {
                RuntimeIntent::StartApp {
                    spec,
                    progress,
                    callback,
                } => {
                    tracing::info!(
                        "[AppRuntime] StartApp: {} (image: {})",
                        spec.app_id,
                        spec.image,
                    );

                    let progress_reporter = Arc::new(ChannelProgressReporter::with_instance_name(
                        progress,
                        spec.app_id.clone(),
                    ));
                    // start() moves progress_reporter, dropping it (and closing the
                    // progress channel) when it returns. The daemon relies on the channel
                    // closing BEFORE callback.send() below so it can drain all progress in
                    // order, then read the callback result.
                    let result = runtime
                        .start(&spec, progress_reporter)
                        .await
                        .map_err(|e| match e {
                            ProvisionError::Config(msg) => msg,
                            ProvisionError::Runtime(msg) => msg,
                            ProvisionError::Image(msg) => msg,
                            ProvisionError::Volume(msg) => msg,
                            ProvisionError::Bundle(msg) => msg,
                            ProvisionError::Network(msg) => msg,
                            ProvisionError::Bootstrap(msg) => msg,
                            ProvisionError::Io(e) => format!("IO error: {}", e),
                        });

                    let _ = callback.send(result);
                }

                RuntimeIntent::StopApp { app_id } => {
                    tracing::info!("[AppRuntime] StopApp: {}", app_id);
                    if let Err(e) = runtime.stop(&app_id).await {
                        tracing::error!(
                            "[AppRuntime] Failed to stop app {}: {}",
                            app_id,
                            e,
                        );
                    }
                }

                RuntimeIntent::AppState { app_id, reply } => {
                    let state = match runtime.state(&app_id).await {
                        Ok(s) => s,
                        Err(_) => AppState::Stopped,
                    };
                    let _ = reply.send(state);
                }

                RuntimeIntent::ListApps { reply } => {
                    let apps = runtime.list();
                    let _ = reply.send(apps);
                }
            }
        }
    }
}
