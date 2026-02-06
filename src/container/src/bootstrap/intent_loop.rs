/// Intent command loop for container provisioner
///
/// This handles RuntimeIntent commands and routes them to ContainerProvisioner
use crate::intent::{InstanceState, RuntimeIntent};
use crate::provisioner::{ChannelProgressReporter, ProvisionError, RuntimeProvisioner};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::bootstrap::provisioner::ContainerProvisioner;

/// Check system requirements before starting the intent loop
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
                // Print to stderr so it's visible even without logging
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

/// Run intent command loop with ContainerProvisioner
pub async fn run_intent_command_loop(
    mut receiver: mpsc::Receiver<RuntimeIntent>,
    app_dir: PathBuf,
) {
    tracing::info!("[container_bootstrap] Starting intent command loop");
    tracing::info!("[container_bootstrap] App directory: {}", app_dir.display());

    // Create provisioner instance
    let mut provisioner = match ContainerProvisioner::new(app_dir) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("[ContainerProvisioner] Failed to create provisioner: {}", e);
            // Send error response to any waiting callers before exiting
            while let Ok(intent) = receiver.try_recv() {
                match intent {
                    RuntimeIntent::Start { callback, .. } => {
                        let _ = callback.send(Err(format!("Container runtime not available: {}", e)));
                    }
                    RuntimeIntent::RunContainer { callback, .. } => {
                        let _ = callback.send(Err(format!("Container runtime not available: {}", e)));
                    }
                    _ => {}
                }
            }
            return;
        }
    };
    while let Some(intent) = receiver.recv().await {
        match intent {
            RuntimeIntent::Start {
                spec,
                progress,
                callback,
            } => {
                let spec = *spec;
                let role_str = match spec.role {
                    crate::intent::InstanceRole::Device => "device",
                    crate::intent::InstanceRole::App => "app",
                };
                tracing::info!(
                    "[ContainerProvisioner] Starting {}: {}",
                    role_str,
                    spec.instance_id
                );

                let progress_reporter = Arc::new(ChannelProgressReporter::with_instance_name(
                    progress,
                    spec.instance_id.clone(),
                ));
                let result = provisioner
                    .provision(&spec, progress_reporter)
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

            RuntimeIntent::RunContainer {
                spec,
                progress,
                callback,
            } => {
                let instance_id = spec
                    .instance_id
                    .as_deref()
                    .unwrap_or("run-container");
                tracing::info!(
                    "[ContainerProvisioner] RunContainer: {} (image: {})",
                    instance_id,
                    spec.image
                );
                let progress_reporter = Arc::new(ChannelProgressReporter::with_instance_name(
                    progress,
                    instance_id.to_string(),
                ));
                let result = provisioner
                    .run_container(&spec, progress_reporter)
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

            RuntimeIntent::Stop { instance_id } => {
                tracing::info!("[ContainerProvisioner] Stopping instance: {}", instance_id);
                let result = provisioner.stop(&instance_id).await;
                if let Err(e) = result {
                    tracing::error!(
                        "[ContainerProvisioner] Failed to stop instance {}: {}",
                        instance_id,
                        e
                    );
                }
            }

            RuntimeIntent::GetState { instance_id, reply } => {
                let result = provisioner.state(&instance_id).await;
                let state = match result {
                    Ok(s) => s,
                    Err(_) => InstanceState::Stopped, // Default to Stopped on error
                };
                let _ = reply.send(state).await;
            }

            RuntimeIntent::GetEndpoint {
                instance_id,
                callback,
            } => {
                let result = provisioner.endpoint(&instance_id).await;
                let _ = callback.send(result);
            }
        }
    }
}
