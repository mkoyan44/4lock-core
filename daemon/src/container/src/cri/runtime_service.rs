//! CRI RuntimeService implementation
//!
//! This module implements the Kubernetes CRI RuntimeService gRPC interface.

use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::bootstrap::config::ImageConfig;
use crate::bootstrap::image_manager::ImageManager;
use crate::rootless::lifecycle;

use super::container_registry::ContainerRegistry;
use super::sandbox::{system_time_to_nanos, SandboxRegistry};
use super::server::runtime::v1::runtime_service_server::RuntimeService;
use super::server::runtime::v1::*;

/// RuntimeService implementation
pub struct RuntimeServiceImpl {
    app_dir: PathBuf,
    sandbox_registry: Arc<Mutex<SandboxRegistry>>,
    container_registry: Arc<Mutex<ContainerRegistry>>,
    image_manager: Arc<ImageManager>,
}

impl RuntimeServiceImpl {
    pub fn new(
        app_dir: PathBuf,
        _image_cache_dir: PathBuf,
        sandbox_registry: Arc<Mutex<SandboxRegistry>>,
    ) -> Self {
        let container_registry = Arc::new(Mutex::new(ContainerRegistry::new(app_dir.clone())));

        // Initialize ImageManager for pulling container images
        let image_config = ImageConfig::default();
        let image_manager = ImageManager::new(&image_config, app_dir.clone())
            .expect("Failed to initialize ImageManager");

        Self {
            app_dir,
            sandbox_registry,
            container_registry,
            image_manager: Arc::new(image_manager),
        }
    }
}

type GetContainerEventsStream = Pin<
    Box<dyn futures::Stream<Item = Result<ContainerEventResponse, Status>> + Send + 'static>,
>;

#[tonic::async_trait]
impl RuntimeService for RuntimeServiceImpl {
    type GetContainerEventsStream = GetContainerEventsStream;
    async fn version(
        &self,
        _request: Request<VersionRequest>,
    ) -> Result<Response<VersionResponse>, Status> {
        tracing::info!("[CRI RuntimeService] Version request received");
        let response = VersionResponse {
            version: "0.1.0".to_string(),
            runtime_name: "vapp".to_string(),
            runtime_version: "0.1.0".to_string(),
            runtime_api_version: "v1".to_string(),
        };
        tracing::info!("[CRI RuntimeService] Sending version response: {:?}", response);
        Ok(Response::new(response))
    }

    async fn run_pod_sandbox(
        &self,
        request: Request<RunPodSandboxRequest>,
    ) -> Result<Response<RunPodSandboxResponse>, Status> {
        let req = request.into_inner();
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("Missing sandbox config"))?;

        let metadata = config
            .metadata
            .ok_or_else(|| Status::invalid_argument("Missing sandbox metadata"))?;

        let sandbox_id = format!(
            "{}-{}-{}",
            metadata.namespace, metadata.name, metadata.uid
        );

        tracing::info!("[CRI RuntimeService] Creating sandbox: {}", sandbox_id);

        let mut registry = self.sandbox_registry.lock().await;
        registry
            .create_sandbox(
                &sandbox_id,
                &metadata.name,
                &metadata.namespace,
                &metadata.uid,
                metadata.attempt,
                config.labels,
                config.annotations,
            )
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(RunPodSandboxResponse {
            pod_sandbox_id: sandbox_id,
        }))
    }

    async fn stop_pod_sandbox(
        &self,
        request: Request<StopPodSandboxRequest>,
    ) -> Result<Response<StopPodSandboxResponse>, Status> {
        let sandbox_id = request.into_inner().pod_sandbox_id;
        tracing::info!("[CRI RuntimeService] Stopping sandbox: {}", sandbox_id);
        Ok(Response::new(StopPodSandboxResponse {}))
    }

    async fn remove_pod_sandbox(
        &self,
        request: Request<RemovePodSandboxRequest>,
    ) -> Result<Response<RemovePodSandboxResponse>, Status> {
        let sandbox_id = request.into_inner().pod_sandbox_id;
        tracing::info!("[CRI RuntimeService] Removing sandbox: {}", sandbox_id);

        let mut registry = self.sandbox_registry.lock().await;
        registry.remove_sandbox(&sandbox_id);

        Ok(Response::new(RemovePodSandboxResponse {}))
    }

    async fn pod_sandbox_status(
        &self,
        request: Request<PodSandboxStatusRequest>,
    ) -> Result<Response<PodSandboxStatusResponse>, Status> {
        let sandbox_id = request.into_inner().pod_sandbox_id;

        let registry = self.sandbox_registry.lock().await;
        let sandbox = registry.get_sandbox(&sandbox_id);

        let status = if let Some(s) = sandbox {
            PodSandboxStatus {
                id: s.id.clone(),
                metadata: Some(PodSandboxMetadata {
                    name: s.name.clone(),
                    uid: s.uid.clone(),
                    namespace: s.namespace.clone(),
                    attempt: s.attempt,
                }),
                state: PodSandboxState::SandboxReady as i32,
                created_at: system_time_to_nanos(s.created_at),
                network: None,
                linux: None,
                labels: s.labels.clone(),
                annotations: s.annotations.clone(),
                runtime_handler: String::new(),
            }
        } else {
            PodSandboxStatus {
                id: sandbox_id.clone(),
                metadata: None,
                state: PodSandboxState::SandboxNotready as i32,
                created_at: 0,
                network: None,
                linux: None,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                runtime_handler: String::new(),
            }
        };

        Ok(Response::new(PodSandboxStatusResponse {
            status: Some(status),
            info: HashMap::new(),
            containers_statuses: vec![],
            timestamp: 0,
        }))
    }

    async fn list_pod_sandbox(
        &self,
        _request: Request<ListPodSandboxRequest>,
    ) -> Result<Response<ListPodSandboxResponse>, Status> {
        let registry = self.sandbox_registry.lock().await;
        let sandboxes = registry.list_sandboxes();

        let items: Vec<PodSandbox> = sandboxes
            .iter()
            .map(|s| PodSandbox {
                id: s.id.clone(),
                metadata: Some(PodSandboxMetadata {
                    name: s.name.clone(),
                    uid: s.uid.clone(),
                    namespace: s.namespace.clone(),
                    attempt: s.attempt,
                }),
                state: PodSandboxState::SandboxReady as i32,
                created_at: system_time_to_nanos(s.created_at),
                labels: s.labels.clone(),
                annotations: s.annotations.clone(),
                runtime_handler: String::new(),
            })
            .collect();

        Ok(Response::new(ListPodSandboxResponse { items }))
    }

    async fn create_container(
        &self,
        request: Request<CreateContainerRequest>,
    ) -> Result<Response<CreateContainerResponse>, Status> {
        let req = request.into_inner();
        let sandbox_id = req.pod_sandbox_id;
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("Missing container config"))?;

        let metadata = config
            .metadata
            .clone()
            .ok_or_else(|| Status::invalid_argument("Missing container metadata"))?;

        let container_id = format!("{}-{}", sandbox_id, metadata.name);
        tracing::info!("[CRI RuntimeService] Creating container: {}", container_id);

        // Extract image reference
        let image_spec = config
            .image
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("Missing image spec"))?;
        let image_ref = &image_spec.image;

        tracing::info!(
            "[CRI RuntimeService] Pulling image for container {}: {}",
            container_id,
            image_ref
        );

        // Pull/cache image using ImageManager
        let image_dir = self
            .image_manager
            .ensure_image(image_ref)
            .await
            .map_err(|e| Status::internal(format!("Failed to pull image: {}", e)))?;

        let image_rootfs = image_dir.join("rootfs");
        if !image_rootfs.exists() {
            return Err(Status::internal(format!(
                "Image rootfs not found: {:?}",
                image_rootfs
            )));
        }

        // Create bundle directory
        let bundles_dir = self.app_dir.join("containers/bundles");
        std::fs::create_dir_all(&bundles_dir)
            .map_err(|e| Status::internal(format!("Failed to create bundles dir: {}", e)))?;

        let bundle_dir = bundles_dir.join(&container_id);
        std::fs::create_dir_all(&bundle_dir)
            .map_err(|e| Status::internal(format!("Failed to create bundle dir: {}", e)))?;

        let bundle_rootfs = bundle_dir.join("rootfs");

        // Copy image rootfs to bundle
        tracing::info!(
            "[CRI RuntimeService] Copying rootfs from {:?} to {:?}",
            image_rootfs,
            bundle_rootfs
        );

        Self::copy_dir_all(&image_rootfs, &bundle_rootfs)
            .map_err(|e| Status::internal(format!("Failed to copy rootfs: {}", e)))?;

        // Generate OCI spec
        let spec_path = bundle_dir.join("config.json");
        let container_args = if config.command.is_empty() {
            config.args
        } else {
            let mut args = config.command;
            args.extend(config.args);
            args
        };

        // Clone labels and annotations for OCI spec generation
        let labels_clone = config.labels.clone();
        let annotations_clone = config.annotations.clone();

        Self::generate_oci_spec_for_container(
            &spec_path,
            &container_args,
            &config.envs,
            &config.mounts,
            labels_clone,
            annotations_clone,
            &config.working_dir,
        )
        .map_err(|e| Status::internal(format!("Failed to generate OCI spec: {}", e)))?;

        // Create the container using lifecycle
        tracing::info!(
            "[CRI RuntimeService] Creating container via lifecycle: {}",
            container_id
        );

        lifecycle::create_container(&container_id, &bundle_dir, &self.app_dir)
            .map_err(|e| Status::internal(format!("Failed to create container: {}", e)))?;

        // Register in container registry
        let mut registry = self.container_registry.lock().await;
        registry
            .register_container(
                &container_id,
                &sandbox_id,
                &metadata.name,
                image_ref,
                image_ref, // image_ref same as image for now
                bundle_dir.clone(),
                config.labels,
                config.annotations,
                Some(metadata.clone()),
            )
            .map_err(|e| Status::internal(format!("Failed to register container: {}", e)))?;

        tracing::info!(
            "[CRI RuntimeService] Container created successfully: {}",
            container_id
        );

        Ok(Response::new(CreateContainerResponse { container_id }))
    }

    async fn start_container(
        &self,
        request: Request<StartContainerRequest>,
    ) -> Result<Response<StartContainerResponse>, Status> {
        let container_id = request.into_inner().container_id;
        tracing::info!("[CRI RuntimeService] Starting container: {}", container_id);

        // Start container using lifecycle
        lifecycle::start_container(&self.app_dir, &container_id)
            .map_err(|e| Status::internal(format!("Failed to start container: {}", e)))?;

        // Update container state in registry
        let mut registry = self.container_registry.lock().await;
        registry
            .mark_running(&container_id)
            .map_err(|e| Status::internal(format!("Failed to update container state: {}", e)))?;

        tracing::info!(
            "[CRI RuntimeService] Container started successfully: {}",
            container_id
        );

        Ok(Response::new(StartContainerResponse {}))
    }

    async fn stop_container(
        &self,
        request: Request<StopContainerRequest>,
    ) -> Result<Response<StopContainerResponse>, Status> {
        let container_id = request.into_inner().container_id;
        tracing::info!("[CRI RuntimeService] Stopping container: {}", container_id);

        // Stop container using lifecycle
        lifecycle::stop_container(&self.app_dir, &container_id)
            .map_err(|e| Status::internal(format!("Failed to stop container: {}", e)))?;

        // Update container state in registry
        let mut registry = self.container_registry.lock().await;
        registry
            .mark_exited(&container_id, 0)
            .map_err(|e| Status::internal(format!("Failed to update container state: {}", e)))?;

        tracing::info!(
            "[CRI RuntimeService] Container stopped successfully: {}",
            container_id
        );

        Ok(Response::new(StopContainerResponse {}))
    }

    async fn remove_container(
        &self,
        request: Request<RemoveContainerRequest>,
    ) -> Result<Response<RemoveContainerResponse>, Status> {
        let container_id = request.into_inner().container_id;
        tracing::info!("[CRI RuntimeService] Removing container: {}", container_id);

        // Delete container using lifecycle
        lifecycle::delete_container(&self.app_dir, &container_id, true)
            .map_err(|e| Status::internal(format!("Failed to delete container: {}", e)))?;

        // Remove from registry
        let mut registry = self.container_registry.lock().await;
        registry.remove_container(&container_id);

        // Clean up bundle directory
        let bundle_dir = self
            .app_dir
            .join("containers/bundles")
            .join(&container_id);
        if bundle_dir.exists() {
            let _ = std::fs::remove_dir_all(&bundle_dir);
        }

        tracing::info!(
            "[CRI RuntimeService] Container removed successfully: {}",
            container_id
        );

        Ok(Response::new(RemoveContainerResponse {}))
    }

    async fn list_containers(
        &self,
        _request: Request<ListContainersRequest>,
    ) -> Result<Response<ListContainersResponse>, Status> {
        let registry = self.container_registry.lock().await;
        let containers = registry.list_containers();

        let items: Vec<Container> = containers
            .iter()
            .map(|c| Container {
                id: c.id.clone(),
                pod_sandbox_id: c.sandbox_id.clone(),
                metadata: c.metadata.clone(),
                image: Some(ImageSpec {
                    image: c.image.clone(),
                    annotations: HashMap::new(),
                    user_specified_image: String::new(),
                    runtime_handler: String::new(),
                }),
                image_ref: c.image_ref.clone(),
                image_id: String::new(),
                state: c.state.to_cri_state(),
                created_at: system_time_to_nanos(c.created_at),
                labels: c.labels.clone(),
                annotations: c.annotations.clone(),
            })
            .collect();

        Ok(Response::new(ListContainersResponse { containers: items }))
    }

    async fn container_status(
        &self,
        request: Request<ContainerStatusRequest>,
    ) -> Result<Response<ContainerStatusResponse>, Status> {
        let container_id = request.into_inner().container_id;

        let registry = self.container_registry.lock().await;
        let container = registry
            .get_container(&container_id)
            .ok_or_else(|| Status::not_found(format!("Container {} not found", container_id)))?;

        Ok(Response::new(ContainerStatusResponse {
            status: Some(ContainerStatus {
                id: container.id.clone(),
                metadata: container.metadata.clone(),
                state: container.state.to_cri_state(),
                created_at: system_time_to_nanos(container.created_at),
                started_at: container
                    .started_at
                    .map(system_time_to_nanos)
                    .unwrap_or(0),
                finished_at: container
                    .finished_at
                    .map(system_time_to_nanos)
                    .unwrap_or(0),
                exit_code: container.exit_code,
                image: Some(ImageSpec {
                    image: container.image.clone(),
                    annotations: HashMap::new(),
                    user_specified_image: String::new(),
                    runtime_handler: String::new(),
                }),
                image_ref: container.image_ref.clone(),
                image_id: String::new(),
                reason: String::new(),
                message: String::new(),
                labels: container.labels.clone(),
                annotations: container.annotations.clone(),
                mounts: vec![],
                log_path: String::new(),
                resources: None,
            }),
            info: HashMap::new(),
        }))
    }

    async fn update_container_resources(
        &self,
        _request: Request<UpdateContainerResourcesRequest>,
    ) -> Result<Response<UpdateContainerResourcesResponse>, Status> {
        Ok(Response::new(UpdateContainerResourcesResponse {}))
    }

    async fn reopen_container_log(
        &self,
        _request: Request<ReopenContainerLogRequest>,
    ) -> Result<Response<ReopenContainerLogResponse>, Status> {
        Ok(Response::new(ReopenContainerLogResponse {}))
    }

    async fn exec_sync(
        &self,
        request: Request<ExecSyncRequest>,
    ) -> Result<Response<ExecSyncResponse>, Status> {
        let req = request.into_inner();
        let container_id = req.container_id;
        let cmd = req.cmd;
        let timeout_secs = req.timeout;

        tracing::info!(
            "[CRI RuntimeService] ExecSync in {}: {:?}",
            container_id,
            cmd
        );

        // Get container PID from state
        let state_file = self
            .app_dir
            .join("containers")
            .join(&container_id)
            .join("state.json");

        if !state_file.exists() {
            return Err(Status::not_found(format!(
                "Container {} not found",
                container_id
            )));
        }

        let content = std::fs::read_to_string(&state_file)
            .map_err(|e| Status::internal(format!("Failed to read state: {}", e)))?;

        let state: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| Status::internal(format!("Failed to parse state: {}", e)))?;

        let pid = state["pid"]
            .as_u64()
            .ok_or_else(|| Status::internal("Container has no PID"))?;

        // Execute using nsenter
        let mut nsenter_cmd = std::process::Command::new("nsenter");
        nsenter_cmd
            .arg("-t")
            .arg(pid.to_string())
            .arg("-m")
            .arg("-u")
            .arg("-i")
            .arg("-p")
            .arg("--")
            .args(&cmd);

        let timeout = std::time::Duration::from_secs(if timeout_secs > 0 {
            timeout_secs as u64
        } else {
            30
        });

        let output = tokio::time::timeout(timeout, async {
            tokio::task::spawn_blocking(move || nsenter_cmd.output()).await
        })
        .await
        .map_err(|_| Status::deadline_exceeded("Exec timeout"))?
        .map_err(|e| Status::internal(format!("Exec failed: {}", e)))?
        .map_err(|e| Status::internal(format!("Exec failed: {}", e)))?;

        Ok(Response::new(ExecSyncResponse {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code().unwrap_or(-1),
        }))
    }

    async fn exec(
        &self,
        _request: Request<ExecRequest>,
    ) -> Result<Response<ExecResponse>, Status> {
        Err(Status::unimplemented("Exec streaming not implemented"))
    }

    async fn attach(
        &self,
        _request: Request<AttachRequest>,
    ) -> Result<Response<AttachResponse>, Status> {
        Err(Status::unimplemented("Attach not implemented"))
    }

    async fn port_forward(
        &self,
        _request: Request<PortForwardRequest>,
    ) -> Result<Response<PortForwardResponse>, Status> {
        Err(Status::unimplemented("PortForward not implemented"))
    }

    async fn container_stats(
        &self,
        request: Request<ContainerStatsRequest>,
    ) -> Result<Response<ContainerStatsResponse>, Status> {
        let container_id = request.into_inner().container_id;

        // Basic stats response
        Ok(Response::new(ContainerStatsResponse {
            stats: Some(ContainerStats {
                attributes: Some(ContainerAttributes {
                    id: container_id,
                    metadata: None,
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                }),
                cpu: Some(CpuUsage {
                    timestamp: 0,
                    usage_core_nano_seconds: None,
                    usage_nano_cores: None,
                }),
                memory: Some(MemoryUsage {
                    timestamp: 0,
                    working_set_bytes: None,
                    available_bytes: None,
                    usage_bytes: None,
                    rss_bytes: None,
                    page_faults: None,
                    major_page_faults: None,
                }),
                writable_layer: None,
                swap: None,
            }),
        }))
    }

    async fn list_container_stats(
        &self,
        _request: Request<ListContainerStatsRequest>,
    ) -> Result<Response<ListContainerStatsResponse>, Status> {
        Ok(Response::new(ListContainerStatsResponse { stats: vec![] }))
    }

    async fn pod_sandbox_stats(
        &self,
        _request: Request<PodSandboxStatsRequest>,
    ) -> Result<Response<PodSandboxStatsResponse>, Status> {
        Err(Status::unimplemented("PodSandboxStats not implemented"))
    }

    async fn list_pod_sandbox_stats(
        &self,
        _request: Request<ListPodSandboxStatsRequest>,
    ) -> Result<Response<ListPodSandboxStatsResponse>, Status> {
        Ok(Response::new(ListPodSandboxStatsResponse { stats: vec![] }))
    }

    async fn update_runtime_config(
        &self,
        _request: Request<UpdateRuntimeConfigRequest>,
    ) -> Result<Response<UpdateRuntimeConfigResponse>, Status> {
        Ok(Response::new(UpdateRuntimeConfigResponse {}))
    }

    async fn status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        tracing::debug!("[CRI RuntimeService] Status check requested");

        Ok(Response::new(StatusResponse {
            status: Some(RuntimeStatus {
                conditions: vec![
                    RuntimeCondition {
                        r#type: "RuntimeReady".to_string(),
                        status: true,
                        reason: "RuntimeReady".to_string(),
                        message: "vapp container runtime is ready".to_string(),
                    },
                    RuntimeCondition {
                        r#type: "NetworkReady".to_string(),
                        status: true,
                        reason: "NetworkReady".to_string(),
                        message: "vapp network is ready (host networking mode)".to_string(),
                    },
                ],
            }),
            info: {
                let mut info = HashMap::new();
                info.insert("handlers".to_string(), "[\"vapp\"]".to_string());
                info
            },
            runtime_handlers: vec![RuntimeHandler {
                name: "vapp".to_string(),
                features: None,
            }],
        }))
    }

    async fn checkpoint_container(
        &self,
        _request: Request<CheckpointContainerRequest>,
    ) -> Result<Response<CheckpointContainerResponse>, Status> {
        Err(Status::unimplemented("Checkpoint not implemented"))
    }

    async fn get_container_events(
        &self,
        _request: Request<GetEventsRequest>,
    ) -> Result<Response<Self::GetContainerEventsStream>, Status> {
        // Return an empty stream
        let stream = futures::stream::empty();
        Ok(Response::new(Box::pin(stream)))
    }

    async fn list_metric_descriptors(
        &self,
        _request: Request<ListMetricDescriptorsRequest>,
    ) -> Result<Response<ListMetricDescriptorsResponse>, Status> {
        Ok(Response::new(ListMetricDescriptorsResponse {
            descriptors: vec![],
        }))
    }

    async fn list_pod_sandbox_metrics(
        &self,
        _request: Request<ListPodSandboxMetricsRequest>,
    ) -> Result<Response<ListPodSandboxMetricsResponse>, Status> {
        Ok(Response::new(ListPodSandboxMetricsResponse {
            pod_metrics: vec![],
        }))
    }

    async fn runtime_config(
        &self,
        _request: Request<RuntimeConfigRequest>,
    ) -> Result<Response<RuntimeConfigResponse>, Status> {
        Ok(Response::new(RuntimeConfigResponse { linux: None }))
    }
}

// Helper methods for RuntimeServiceImpl
impl RuntimeServiceImpl {
    /// Recursively copy a directory
    fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if ty.is_dir() {
                Self::copy_dir_all(&src_path, &dst_path)?;
            } else if ty.is_file() {
                std::fs::copy(&src_path, &dst_path)?;
            } else if ty.is_symlink() {
                // Copy symlinks as-is
                let target = std::fs::read_link(&src_path)?;
                #[cfg(unix)]
                std::os::unix::fs::symlink(&target, &dst_path)?;
                #[cfg(not(unix))]
                {
                    // On non-Unix, just copy the file the symlink points to
                    let _ = target;
                    std::fs::copy(&src_path, &dst_path)?;
                }
            }
        }
        Ok(())
    }

    /// Generate OCI spec for a CRI container
    fn generate_oci_spec_for_container(
        spec_path: &std::path::Path,
        args: &[String],
        envs: &[KeyValue],
        mounts: &[Mount],
        labels: HashMap<String, String>,
        annotations: HashMap<String, String>,
        working_dir: &str,
    ) -> Result<(), String> {
        use serde_json::json;

        // Build environment variables
        let mut env_vars = vec![
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            "TERM=xterm".to_string(),
        ];
        for kv in envs {
            env_vars.push(format!("{}={}", kv.key, kv.value));
        }

        // Build mounts from CRI mount specs
        let mut oci_mounts = Vec::new();
        for mount in mounts {
            let mut options = vec![];
            if mount.readonly {
                options.push("ro");
            } else {
                options.push("rw");
            }
            options.push("rbind");

            oci_mounts.push(json!({
                "destination": mount.container_path,
                "type": "bind",
                "source": mount.host_path,
                "options": options
            }));
        }

        // Add standard tmpfs mount
        oci_mounts.push(json!({
            "destination": "/tmp",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "nodev", "size=1048576k"]
        }));

        // Build namespaces for rootless containers
        let namespaces = vec![
            json!({"type": "user"}),
            json!({"type": "ipc"}),
            json!({"type": "uts"}),
            json!({"type": "mount"}),
        ];

        // UID/GID mappings for rootless
        #[cfg(target_os = "linux")]
        use nix::unistd::{Gid, Uid};
        #[cfg(target_os = "linux")]
        let host_uid = Uid::current().as_raw();
        #[cfg(target_os = "linux")]
        let host_gid = Gid::current().as_raw();

        #[cfg(target_os = "linux")]
        let uid_mappings = vec![json!({
            "containerID": 0,
            "hostID": host_uid,
            "size": 1
        })];

        #[cfg(target_os = "linux")]
        let gid_mappings = vec![json!({
            "containerID": 0,
            "hostID": host_gid,
            "size": 1
        })];

        #[cfg(not(target_os = "linux"))]
        let uid_mappings: Vec<serde_json::Value> = vec![];
        #[cfg(not(target_os = "linux"))]
        let gid_mappings: Vec<serde_json::Value> = vec![];

        // Set working directory, default to /
        let cwd = if working_dir.is_empty() {
            "/"
        } else {
            working_dir
        };

        // Build OCI spec
        let spec = json!({
            "ociVersion": "1.0.2",
            "process": {
                "terminal": false,
                "user": {
                    "uid": 0,
                    "gid": 0
                },
                "env": env_vars,
                "cwd": cwd,
                "args": args,
                "apparmorProfile": null,
                "capabilities": {
                    "bounding": [
                        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                        "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                        "CAP_AUDIT_WRITE"
                    ],
                    "effective": [
                        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                        "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                        "CAP_AUDIT_WRITE"
                    ],
                    "inheritable": [
                        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                        "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                        "CAP_AUDIT_WRITE"
                    ],
                    "permitted": [
                        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                        "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                        "CAP_AUDIT_WRITE"
                    ]
                }
            },
            "root": {
                "path": "rootfs",
                "readonly": false
            },
            "mounts": oci_mounts,
            "linux": {
                "namespaces": namespaces,
                "uidMappings": uid_mappings,
                "gidMappings": gid_mappings,
                "resources": {},
                "seccomp": null
            },
            "annotations": annotations,
            "labels": labels,
        });

        // Write spec to file
        let spec_json = serde_json::to_string_pretty(&spec)
            .map_err(|e| format!("Failed to serialize OCI spec: {}", e))?;

        std::fs::write(spec_path, spec_json)
            .map_err(|e| format!("Failed to write OCI spec: {}", e))?;

        Ok(())
    }
}
