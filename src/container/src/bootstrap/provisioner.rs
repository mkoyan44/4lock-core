use crate::common::ContainerRuntime;
/// Container provisioner - implements RuntimeProvisioner for containers
use async_trait::async_trait;
use crate::intent::{ContainerRunSpec, Endpoint, InstanceHandle, InstanceState, StorageSpec, VappSpec};
use crate::provisioner::{ProgressReporter, ProvisionError, RuntimeProvisioner};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::bootstrap::config::ContainerProvisionerConfig;
use crate::bootstrap::image_manager::ImageManager;
#[cfg(target_os = "linux")]
use crate::bootstrap::template_renderer::TemplateRenderer;
#[cfg(target_os = "linux")]
use crate::bootstrap::utility_runner::{UtilityContainerConfig, UtilityRunner};
use crate::bootstrap::volume_manager::VolumeManager;
use crate::bootstrap::workflow;
#[cfg(target_os = "linux")]
use std::collections::HashMap;

/// Certificate paths for mounted volumes
pub struct CertificatePaths {
    pub ca_dir: PathBuf,
    pub k8s_certs_dir: PathBuf,
    pub etcd_certs_dir: PathBuf,
}

/// Container provisioner - implements RuntimeProvisioner
pub struct ContainerProvisioner {
    config: ContainerProvisionerConfig,
    runtime: Arc<dyn ContainerRuntime>,
    image_manager: ImageManager,
    volume_manager: VolumeManager,
    #[allow(dead_code)]
    app_dir: PathBuf,
    #[cfg(target_os = "linux")]
    container_manager: crate::rootless::orchestration::ContainerManager,
    #[cfg(target_os = "linux")]
    utility_runner: UtilityRunner,
    #[cfg(target_os = "linux")]
    template_renderer: TemplateRenderer,
}

impl ContainerProvisioner {
    /// Create a new container provisioner
    pub fn new(app_dir: PathBuf) -> Result<Self, String> {
        tracing::info!("[ContainerProvisioner] Initializing...");
        tracing::info!(
            "[ContainerProvisioner] App directory: {}",
            app_dir.display()
        );

        #[cfg(not(target_os = "linux"))]
        {
            Err("Container provisioner only available on Linux".to_string())
        }

        #[cfg(target_os = "linux")]
        {
            // Check system requirements for rootless containers
            let system_check = crate::rootless::system_check::check_system_requirements();
            if !system_check.passed {
                if let Some(error_msg) = system_check.error_message() {
                    tracing::error!("{}", error_msg);
                    return Err(
                        "System requirements not met for rootless containers. Run: sudo ./scripts/linux-container-setup.sh"
                            .to_string(),
                    );
                }
            } else {
                tracing::info!("[ContainerProvisioner] System requirements check passed");
            }

            // Clean up orphaned pasta processes from previous runs
            // This prevents port binding conflicts when containers restart
            crate::rootless::cleanup_orphaned_pasta();

            // Initialize shared network namespace for all containers
            // This creates a single namespace with pasta providing internet connectivity
            // All containers will join this namespace for localhost communication
            let ns_path = crate::rootless::initialize_shared_namespace().map_err(|e| {
                format!(
                    "Failed to initialize shared network namespace: {}. \
                    Check if user namespaces are enabled and pasta (passt) is installed.",
                    e
                )
            })?;
            tracing::info!(
                "[ContainerProvisioner] Shared network namespace initialized: {}",
                ns_path
            );

            // Load config
            let config = ContainerProvisionerConfig::load(&app_dir)?;

            // Initialize OCI runtime
            use crate::rootless::RootlessContainerRuntime;
            let runtime: Arc<dyn ContainerRuntime> = Arc::new(
                RootlessContainerRuntime::new(app_dir.clone())
                    .map_err(|e| format!("Failed to initialize container runtime: {}", e))?,
            );

            // Initialize managers
            let image_manager = ImageManager::new(&config.image, app_dir.clone())
                .map_err(|e| format!("Failed to initialize image manager: {}", e))?;
            let volume_manager = VolumeManager::new(app_dir.clone())
                .map_err(|e| format!("Failed to initialize volume manager: {}", e))?;

            // Initialize ContainerManager for container group management
            let container_manager =
                crate::rootless::orchestration::ContainerManager::new(app_dir.clone())
                    .map_err(|e| format!("Failed to initialize container manager: {}", e))?;

            // Initialize platform-specific container_dir with app_dir
            crate::rootless::config::container_dir::init_app_dir(app_dir.clone());

            // Initialize utility runner
            let utility_runner = UtilityRunner::new(app_dir.clone(), container_manager.clone());
            tracing::debug!("[ContainerProvisioner] UtilityRunner initialized");

            // Initialize template renderer from embedded templates (self-contained binary).
            // Use VAPPC_TEMPLATES_DIR for local development to load from filesystem instead.
            let template_renderer = if let Ok(dir) = std::env::var("VAPPC_TEMPLATES_DIR") {
                let templates_dir = std::path::PathBuf::from(dir);
                tracing::debug!(
                    "[ContainerProvisioner] Initializing TemplateRenderer from VAPPC_TEMPLATES_DIR: {}",
                    templates_dir.display()
                );
                TemplateRenderer::new(templates_dir)
            } else {
                TemplateRenderer::from_embedded()
            }
            .map_err(|e| format!("Failed to initialize template renderer: {}", e))?;

            tracing::info!("[ContainerProvisioner] Initialized successfully");

            Ok(Self {
                config,
                runtime,
                image_manager,
                volume_manager,
                app_dir,
                container_manager,
                utility_runner,
                template_renderer,
            })
        }
    }

    /// Convert StorageSpec to volume mounts
    /// Note: Container storage implementation will be discussed later per plan
    /// For now, creates volumes directly from StorageSpec
    async fn storage_to_volumes(
        &mut self,
        instance_id: &str,
        storage: &[StorageSpec],
    ) -> Result<Vec<crate::common::VolumeMount>, ProvisionError> {
        // TODO: Full container storage implementation to be discussed later
        // For now, create basic volume mounts from StorageSpec
        let instance_volumes_dir = self.volume_manager.volumes_dir().join(instance_id);
        std::fs::create_dir_all(&instance_volumes_dir).map_err(ProvisionError::Io)?;

        let mut volumes = Vec::new();
        for spec in storage {
            let volume_path = instance_volumes_dir.join(&spec.disk_type);
            std::fs::create_dir_all(&volume_path).map_err(ProvisionError::Io)?;

            volumes.push(crate::common::VolumeMount {
                source: volume_path.clone(),
                destination: PathBuf::from(&spec.mount_path),
                options: vec!["rw".to_string(), "bind".to_string()],
            });
        }
        Ok(volumes)
    }

    /// Prepare OCI bundle for container
    ///
    /// Uses linux crate's OCI spec generation instead of duplicating logic
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    fn prepare_bundle(
        &self,
        instance_id: &str,
        vapp: &VappSpec,
        container_type: &str,
        volumes: &[crate::common::VolumeMount],
    ) -> Result<PathBuf, ProvisionError> {
        #[cfg(target_os = "linux")]
        {
            use crate::rootless::bundle;
            use crate::rootless::config::ContainerConfig;
            use std::collections::HashMap;

            // Create bundle directory
            let bundle_dir = self.app_dir.join("containers/bundles").join(instance_id);

            // Clean up existing bundle directory if it exists (from previous failed attempts)
            if bundle_dir.exists() {
                tracing::debug!(
                    "[ContainerProvisioner] Removing existing bundle directory: {:?}",
                    bundle_dir
                );
                let _ = std::fs::remove_dir_all(&bundle_dir);
            }

            std::fs::create_dir_all(&bundle_dir).map_err(ProvisionError::Io)?;

            let rootfs = bundle_dir.join("rootfs");
            std::fs::create_dir_all(&rootfs).map_err(ProvisionError::Io)?;

            // Convert VappSpec to ContainerConfig
            let mut container_config =
                ContainerConfig::new(instance_id.to_string(), container_type.to_string())
                    .with_cpu_limit(vapp.resources.cpu_cores as u64)
                    .with_memory_limit(vapp.resources.memory_mb);

            // Add volumes (bind mounts)
            let mut volume_map = HashMap::new();
            for volume in volumes {
                volume_map.insert(
                    volume.source.to_string_lossy().to_string(),
                    volume.destination.to_string_lossy().to_string(),
                );
            }
            container_config.volumes = volume_map;

            // Add environment variables
            container_config = container_config
                .add_env("CONTAINER_NAME".to_string(), instance_id.to_string())
                .add_env("CONTAINER_ROLE".to_string(), container_type.to_string())
                .add_env("CLUSTER_NAME".to_string(), vapp.cluster.name.clone())
                .add_env(
                    "K8S_SERVICE_CIDR".to_string(),
                    vapp.cluster.service_cidr.clone(),
                )
                .add_env("K8S_POD_CIDR".to_string(), vapp.cluster.pod_cidr.clone())
                .add_env(
                    "K8S_DNS_ADDRESS".to_string(),
                    vapp.cluster.dns_address.clone(),
                )
                .add_env(
                    "ZT_NETWORK_ID".to_string(),
                    vapp.network.zt_network_id.clone(),
                )
                .add_env("ZT_TOKEN".to_string(), vapp.network.zt_token.clone());

            if let Some(upstream_api) = &vapp.cluster.upstream_api {
                container_config =
                    container_config.add_env("K8S_UPSTREAM_API".to_string(), upstream_api.clone());
            }

            // Use host network mode for internet connectivity and DNS resolution
            // All containers need internet access for DNS resolution and ZeroTier connectivity
            container_config.network_mode = "host".to_string();
            tracing::info!("[ContainerProvisioner] Using host network mode for container {} to enable DNS and internet connectivity", instance_id);

            // Create bundle structure
            bundle::create_bundle_structure(&bundle_dir, &rootfs).map_err(|e| {
                ProvisionError::Bundle(format!("Failed to create bundle structure: {}", e))
            })?;

            // CRITICAL: Create /etc/resolv.conf in rootfs with DNS servers BEFORE generating OCI spec
            // This ensures containers have working DNS from the start
            let resolv_conf_path = rootfs.join("etc").join("resolv.conf");
            if let Some(parent) = resolv_conf_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create /etc directory in rootfs: {}",
                        e
                    )))
                })?;
            }

            // Get DNS servers from config (defaults to 8.8.8.8, 8.8.4.4 if not set)
            let dns_servers = if !container_config.dns_servers.is_empty() {
                container_config.dns_servers.clone()
            } else {
                vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]
            };

            // Create resolv.conf with DNS servers
            let mut resolv_conf_content = String::new();
            for dns_server in &dns_servers {
                resolv_conf_content.push_str(&format!("nameserver {}\n", dns_server));
            }
            resolv_conf_content.push_str("options ndots:0\n");
            resolv_conf_content.push_str("options timeout:2\n");
            resolv_conf_content.push_str("options attempts:3\n");

            std::fs::write(&resolv_conf_path, resolv_conf_content).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create /etc/resolv.conf in rootfs: {}",
                    e
                )))
            })?;

            tracing::info!(
                    "[ContainerProvisioner] Created /etc/resolv.conf for container {} with DNS servers: {:?}",
                    instance_id,
                    dns_servers
                );

            // CRITICAL: Create /etc/resolv.conf in rootfs with DNS servers BEFORE generating OCI spec
            // This ensures utility containers have working DNS from the start
            let resolv_conf_path = rootfs.join("etc").join("resolv.conf");
            if let Some(parent) = resolv_conf_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create /etc directory in rootfs: {}",
                        e
                    )))
                })?;
            }

            // Get DNS servers from config (defaults to 8.8.8.8, 8.8.4.4 if not set)
            let dns_servers = if !container_config.dns_servers.is_empty() {
                container_config.dns_servers.clone()
            } else {
                vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]
            };

            // Create resolv.conf with DNS servers
            let mut resolv_conf_content = String::new();
            for dns_server in &dns_servers {
                resolv_conf_content.push_str(&format!("nameserver {}\n", dns_server));
            }
            resolv_conf_content.push_str("options ndots:0\n");
            resolv_conf_content.push_str("options timeout:2\n");
            resolv_conf_content.push_str("options attempts:3\n");

            std::fs::write(&resolv_conf_path, resolv_conf_content).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create /etc/resolv.conf in rootfs: {}",
                    e
                )))
            })?;

            tracing::debug!(
                "[ContainerProvisioner] Created /etc/resolv.conf for utility container {} with DNS servers: {:?}",
                container_config.container_name,
                dns_servers
            );

            // Generate OCI spec using linux crate
            bundle::generate_oci_spec(&container_config, &rootfs, &bundle_dir, None).map_err(
                |e| ProvisionError::Bundle(format!("Failed to generate OCI spec: {}", e)),
            )?;

            tracing::info!("[ContainerProvisioner] Prepared bundle at {:?}", bundle_dir);

            Ok(bundle_dir)
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Suppress unused variable warnings - these are used in the Linux cfg block
            let _ = (instance_id, vapp, container_type, volumes);
            Err(ProvisionError::Config(
                "Container provisioner only available on Linux".to_string(),
            ))
        }
    }

    /// Get endpoint for an instance
    async fn get_endpoint(&self, instance_id: &str) -> Result<Endpoint, ProvisionError> {
        // Container uses Unix socket in its rootfs
        let socket_path = self.volume_manager.socket_path(instance_id);
        Ok(Endpoint::Socket(socket_path))
    }

    /// Create container group for an instance
    #[cfg(target_os = "linux")]
    fn create_container_group(
        &self,
        instance_id: &str,
    ) -> Result<crate::rootless::orchestration::group::ContainerGroup, ProvisionError> {
        use crate::rootless::error::ContainerError as LinuxError;
        self.container_manager
            .create_container_group(instance_id)
            .map_err(|e: LinuxError| {
                ProvisionError::Runtime(format!("Failed to create container group: {}", e))
            })
    }

    /// Wait for etcd to be ready
    #[cfg(target_os = "linux")]
    async fn wait_for_etcd_ready(
        &self,
        instance_id: &str,
        timeout: Duration,
    ) -> Result<(), ProvisionError> {
        use crate::rootless::commands::{load_container, ContainerStatus};
        use std::time::Instant;
        use tokio::time::sleep;

        tracing::info!("[ContainerProvisioner] Waiting for etcd to be ready...");

        let start = Instant::now();
        let etcd_container_name = format!("{}-etcd", instance_id);
        let root_path = self.container_manager.root_path();

        // CRITICAL: In rootless containers, we cannot use nsenter to enter the container's network namespace
        // (Operation not permitted - user namespace restriction). Instead, we wait for the container to be Running
        // and add a delay for etcd to initialize.
        // NOTE: With shared network namespace, all containers are accessible via localhost.
        loop {
            // Load container to check status
            match load_container(root_path, &etcd_container_name) {
                Ok(container) => {
                    if container.status() == ContainerStatus::Running {
                        // Container is running - wait a bit for etcd to initialize
                        // etcd typically starts quickly, but we give it a few seconds
                        let elapsed = start.elapsed();
                        let init_delay = Duration::from_secs(3);

                        if elapsed >= init_delay {
                            tracing::info!(
                                "[ContainerProvisioner] etcd container is running (waited {:?} for initialization)",
                                elapsed
                            );
                            return Ok(());
                        } else {
                            let remaining = init_delay - elapsed;
                            tracing::debug!(
                                "[ContainerProvisioner] etcd container is running, waiting {:?} for initialization...",
                                remaining
                            );
                            sleep(remaining).await;
                            tracing::info!(
                                "[ContainerProvisioner] etcd is ready (container running)"
                            );
                            return Ok(());
                        }
                    } else {
                        // Container exists but not running - check if it stopped
                        if container.status() == crate::rootless::commands::ContainerStatus::Stopped {
                            // Container stopped - read logs to see why
                            let container_logs = self.read_container_logs(&etcd_container_name, 100);
                            let error_msg = if container_logs != "(container logs not available)" {
                                format!(
                                    "etcd container stopped unexpectedly (status: Stopped).\n\nContainer stderr/logs (last 100 lines):\n{}\n\nCheck bundle directory for full logs: {}",
                                    container_logs,
                                    self.app_dir.join("containers/bundles").join(&etcd_container_name).display()
                                )
                            } else {
                                format!(
                                    "etcd container stopped unexpectedly (status: Stopped). Container logs not available.\n\nCheck bundle directory: {}",
                                    self.app_dir.join("containers/bundles").join(&etcd_container_name).display()
                                )
                            };
                            tracing::error!("[ContainerProvisioner] {}", error_msg);
                            return Err(ProvisionError::Runtime(error_msg));
                        }
                        
                        // Container exists but not running yet
                        if start.elapsed() > timeout {
                            // Read logs even if timeout - might give us a clue
                            let container_logs = self.read_container_logs(&etcd_container_name, 50);
                            let error_msg = if container_logs != "(container logs not available)" {
                                format!(
                                    "Timeout waiting for etcd container to be running (status: {:?}).\n\nContainer stderr/logs (last 50 lines):\n{}",
                                    container.status(),
                                    container_logs
                                )
                            } else {
                                format!(
                                    "Timeout waiting for etcd container to be running (status: {:?})",
                                    container.status()
                                )
                            };
                            return Err(ProvisionError::Runtime(error_msg));
                        }
                        tracing::debug!(
                            "[ContainerProvisioner] etcd container status: {:?}, retrying... ({:?} elapsed)",
                            container.status(),
                            start.elapsed()
                        );
                    }
                }
                Err(e) => {
                    if start.elapsed() > timeout {
                        return Err(ProvisionError::Runtime(format!(
                            "Timeout waiting for etcd container to be created: {}",
                            e
                        )));
                    }
                    tracing::debug!(
                        "[ContainerProvisioner] etcd container not created yet, retrying... ({:?} elapsed)",
                        start.elapsed()
                    );
                }
            }

            if start.elapsed() > timeout {
                return Err(ProvisionError::Runtime(format!(
                    "Timeout waiting for etcd to be ready after {:?}",
                    timeout
                )));
            }

            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Read container logs/stderr from bundle directory
    /// Tries multiple locations where logs might be stored
    #[cfg(target_os = "linux")]
    fn read_container_logs(&self, container_name: &str, max_lines: usize) -> String {
        use std::io::{BufRead, BufReader};

        // Try multiple log locations
        let log_locations = vec![
            // CRITICAL: New log location - bundle_dir/logs/stderr.log (from lifecycle.rs)
            self.app_dir
                .join("containers/bundles")
                .join(container_name)
                .join("logs/stderr.log"),
            // Host output directory (for utility containers)
            self.app_dir
                .join("containers/utility-output")
                .join(container_name)
                .join("stderr.log"),
            // Bundle rootfs output directory (for utility containers)
            self.app_dir
                .join("containers/bundles")
                .join(container_name)
                .join("rootfs/tmp/utility-output/stderr.log"),
            // Bundle rootfs (direct)
            self.app_dir
                .join("containers/bundles")
                .join(container_name)
                .join("rootfs/tmp/stderr.log"),
            // K8s component logs (if redirected)
            self.app_dir
                .join("containers/bundles")
                .join(container_name)
                .join("rootfs/var/log/stderr.log"),
        ];

        for log_path in log_locations {
            if let Ok(file) = std::fs::File::open(&log_path) {
                let reader = BufReader::new(file);
                let lines: Vec<String> = reader
                    .lines()
                    .filter_map(|l| l.ok())
                    .collect();

                if !lines.is_empty() {
                    // Return last N lines
                    let start = if lines.len() > max_lines {
                        lines.len() - max_lines
                    } else {
                        0
                    };
                    let relevant_lines = &lines[start..];
                    let log_content = relevant_lines.join("\n");
                    tracing::debug!(
                        "[ContainerProvisioner] Found container logs at {:?} ({} lines)",
                        log_path,
                        relevant_lines.len()
                    );
                    return log_content;
                }
            }
        }

        // No logs found
        String::from("(container logs not available)")
    }

    /// Wait for dependent containers to be ready
    #[cfg(target_os = "linux")]
    async fn wait_for_dependencies(
        &self,
        instance_id: &str,
        component: &crate::bootstrap::k8s_components::K8sComponent,
        group: &crate::rootless::orchestration::group::ContainerGroup,
    ) -> Result<(), ProvisionError> {
        use crate::rootless::orchestration::group::ContainerState;
        use std::time::{Duration, Instant};

        for dep_suffix in &component.depends_on {
            let dep_container_name = format!("{}-{}", instance_id, dep_suffix);

            // Find the dependency container in the group
            let dep_container = group
                .containers
                .iter()
                .find(|c| c.name == dep_container_name);

            if let Some(container_info) = dep_container {
                tracing::info!(
                    "[ContainerProvisioner] Waiting for dependency {} to be ready...",
                    dep_container_name
                );

                // Use health endpoint checks for etcd and apiserver, fallback to state check for others
                let timeout = Duration::from_secs(30);

                if *dep_suffix == "etcd" {
                    // Use etcd health endpoint with client certificates
                    self.wait_for_etcd_ready(instance_id, timeout).await?;
                } else if *dep_suffix == "apiserver" {
                    // CRITICAL: In rootless containers, we cannot check health from the host
                    // (same limitation as etcd - network namespace isolation). Instead, wait
                    // for the container to be Running and verify it stays running for a delay period.
                    let start = Instant::now();
                    let init_delay = Duration::from_secs(3);
                    let mut running_start: Option<Instant> = None;

                    loop {
                        match self
                            .container_manager
                            .get_container_state(&container_info.container_id)
                        {
                            Ok(ContainerState::Running) => {
                                // Container is running - track when it started running
                                if running_start.is_none() {
                                    running_start = Some(Instant::now());
                                    tracing::debug!(
                                        "[ContainerProvisioner] Dependency {} is now running, waiting {:?} to ensure it stays running...",
                                        dep_container_name,
                                        init_delay
                                    );
                                }

                                // Check if it has been running continuously for the required delay
                                if let Some(running_since) = running_start {
                                    if running_since.elapsed() >= init_delay {
                                        tracing::info!(
                                            "[ContainerProvisioner] Dependency {} is ready (running continuously for {:?})",
                                            dep_container_name,
                                            running_since.elapsed()
                                        );
                                        break;
                                    }
                                }
                            }
                            Ok(state) => {
                                // Container is not running - reset running_start and check if we should fail
                                running_start = None;

                                if start.elapsed() > timeout {
                                    // Read logs before timeout to help debug
                                    let container_logs = self.read_container_logs(&dep_container_name, 100);
                                    
                                    tracing::error!(
                                        "[ContainerProvisioner] ========================================"
                                    );
                                    tracing::error!(
                                        "[ContainerProvisioner] Timeout waiting for dependency {} to be ready (status: {:?})",
                                        dep_container_name,
                                        state
                                    );
                                    
                                    if container_logs != "(container logs not available)" {
                                        tracing::error!(
                                            "[ContainerProvisioner] Container stderr/logs (last 100 lines):\n{}",
                                            container_logs
                                        );
                                    } else {
                                        tracing::error!(
                                            "[ContainerProvisioner] Container logs not available"
                                        );
                                    }
                                    tracing::error!(
                                        "[ContainerProvisioner] Check bundle directory: {}",
                                        self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                                    );
                                    tracing::error!(
                                        "[ContainerProvisioner] ========================================"
                                    );
                                    
                                    let error_msg = if container_logs != "(container logs not available)" {
                                        format!(
                                            "Timeout waiting for dependency {} to be ready (status: {:?}).\n\nContainer stderr/logs (last 100 lines):\n{}\n\nCheck bundle directory for full logs: {}",
                                            dep_container_name,
                                            state,
                                            container_logs,
                                            self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                                        )
                                    } else {
                                        format!(
                                            "Timeout waiting for dependency {} to be ready (status: {:?}). (Container logs not available - check bundle directory: {})",
                                            dep_container_name,
                                            state,
                                            self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                                        )
                                    };
                                    return Err(ProvisionError::Runtime(error_msg));
                                }

                                // If container was running but now stopped, it crashed
                                if state == ContainerState::Stopped {
                                    // Try to read container logs for debugging
                                    let container_logs = self.read_container_logs(&dep_container_name, 100);
                                    
                                    // CRITICAL: Print logs to terminal for debugging
                                    tracing::error!(
                                        "[ContainerProvisioner] ========================================"
                                    );
                                    tracing::error!(
                                        "[ContainerProvisioner] Dependency {} CRASHED (status: Stopped)",
                                        dep_container_name
                                    );
                                    tracing::error!(
                                        "[ContainerProvisioner] ========================================"
                                    );
                                    
                                    if container_logs != "(container logs not available)" {
                                        tracing::error!(
                                            "[ContainerProvisioner] Container stderr/logs (last 100 lines):\n{}",
                                            container_logs
                                        );
                                        tracing::error!(
                                            "[ContainerProvisioner] ========================================"
                                        );
                                        
                                        let error_msg = format!(
                                            "Dependency {} crashed (status: Stopped). Container may have failed to start or encountered an error.\n\nContainer stderr/logs (last 100 lines):\n{}\n\nCheck bundle directory for full logs: {}",
                                            dep_container_name,
                                            container_logs,
                                            self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                                        );
                                        return Err(ProvisionError::Runtime(error_msg));
                                    } else {
                                        tracing::error!(
                                            "[ContainerProvisioner] Container logs not available"
                                        );
                                        tracing::error!(
                                            "[ContainerProvisioner] Check bundle directory: {}",
                                            self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                                        );
                                        tracing::error!(
                                            "[ContainerProvisioner] ========================================"
                                        );
                                        
                                        let error_msg = format!(
                                            "Dependency {} crashed (status: Stopped). Container may have failed to start or encountered an error. (Container logs not available - check bundle directory: {})",
                                            dep_container_name,
                                            self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                                        );
                                        return Err(ProvisionError::Runtime(error_msg));
                                    }
                                }

                                tracing::debug!(
                                    "[ContainerProvisioner] Dependency {} status: {:?}, retrying...",
                                    dep_container_name,
                                    state
                                );
                            }
                            Err(e) => {
                                running_start = None;
                                if start.elapsed() > timeout {
                                    return Err(ProvisionError::Runtime(format!(
                                        "Timeout waiting for dependency {} to be created: {}",
                                        dep_container_name, e
                                    )));
                                }
                                tracing::debug!(
                                    "[ContainerProvisioner] Dependency {} not created yet, retrying...",
                                    dep_container_name
                                );
                            }
                        }

                        if start.elapsed() > timeout {
                            // Read logs before timeout to help debug
                            let container_logs = self.read_container_logs(&dep_container_name, 100);
                            
                            tracing::error!(
                                "[ContainerProvisioner] ========================================"
                            );
                            tracing::error!(
                                "[ContainerProvisioner] Timeout waiting for dependency {} to be ready after {:?}",
                                dep_container_name,
                                timeout
                            );
                            
                            if container_logs != "(container logs not available)" {
                                tracing::error!(
                                    "[ContainerProvisioner] Container stderr/logs (last 100 lines):\n{}",
                                    container_logs
                                );
                            } else {
                                tracing::error!(
                                    "[ContainerProvisioner] Container logs not available"
                                );
                            }
                            tracing::error!(
                                "[ContainerProvisioner] Check bundle directory: {}",
                                self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                            );
                            tracing::error!(
                                "[ContainerProvisioner] ========================================"
                            );
                            
                            let error_msg = if container_logs != "(container logs not available)" {
                                format!(
                                    "Timeout waiting for dependency {} to be ready after {:?}.\n\nContainer stderr/logs (last 100 lines):\n{}\n\nCheck bundle directory for full logs: {}",
                                    dep_container_name,
                                    timeout,
                                    container_logs,
                                    self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                                )
                            } else {
                                format!(
                                    "Timeout waiting for dependency {} to be ready after {:?}. (Container logs not available - check bundle directory: {})",
                                    dep_container_name,
                                    timeout,
                                    self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                                )
                            };
                            return Err(ProvisionError::Runtime(error_msg));
                        }

                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                } else {
                    // Fallback to container state check for other dependencies
                    let start = Instant::now();
                    let mut last_state = None;
                    loop {
                        match self
                            .container_manager
                            .get_container_state(&container_info.container_id)
                        {
                            Ok(ContainerState::Running) => {
                                tracing::info!(
                                    "[ContainerProvisioner] Dependency {} is running",
                                    dep_container_name
                                );
                                break;
                            }
                            Ok(state) => {
                                if last_state != Some(state) {
                                    tracing::debug!(
                                        "[ContainerProvisioner] Dependency {} state: {:?}",
                                        dep_container_name,
                                        state
                                    );
                                    last_state = Some(state);
                                }

                                // If container stopped, it crashed
                                if state == ContainerState::Stopped {
                                    // Try to read container logs for debugging
                                    let container_logs = self.read_container_logs(&dep_container_name, 100);
                                    
                                    // CRITICAL: Print logs to terminal for debugging
                                    tracing::error!(
                                        "[ContainerProvisioner] ========================================"
                                    );
                                    tracing::error!(
                                        "[ContainerProvisioner] Dependency {} CRASHED (status: Stopped)",
                                        dep_container_name
                                    );
                                    tracing::error!(
                                        "[ContainerProvisioner] ========================================"
                                    );
                                    
                                    if container_logs != "(container logs not available)" {
                                        tracing::error!(
                                            "[ContainerProvisioner] Container stderr/logs (last 100 lines):\n{}",
                                            container_logs
                                        );
                                        tracing::error!(
                                            "[ContainerProvisioner] ========================================"
                                        );
                                        
                                        let error_msg = format!(
                                            "Dependency {} crashed (status: Stopped). Container may have failed to start or encountered an error.\n\nContainer stderr/logs (last 100 lines):\n{}\n\nCheck bundle directory for full logs: {}",
                                            dep_container_name,
                                            container_logs,
                                            self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                                        );
                                        return Err(ProvisionError::Runtime(error_msg));
                                    } else {
                                        tracing::error!(
                                            "[ContainerProvisioner] Container logs not available"
                                        );
                                        tracing::error!(
                                            "[ContainerProvisioner] Check bundle directory: {}",
                                            self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                                        );
                                        tracing::error!(
                                            "[ContainerProvisioner] ========================================"
                                        );
                                        
                                        let error_msg = format!(
                                            "Dependency {} crashed (status: Stopped). Container may have failed to start or encountered an error. (Container logs not available - check bundle directory: {})",
                                            dep_container_name,
                                            self.app_dir.join("containers/bundles").join(&dep_container_name).display()
                                        );
                                        return Err(ProvisionError::Runtime(error_msg));
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "[ContainerProvisioner] Failed to get state for {}: {}",
                                    dep_container_name,
                                    e
                                );
                            }
                        }

                        if start.elapsed() > timeout {
                            return Err(ProvisionError::Runtime(format!(
                                "Timeout waiting for dependency {} to be ready",
                                dep_container_name
                            )));
                        }

                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            } else {
                tracing::warn!(
                    "[ContainerProvisioner] Dependency {} not found in group, skipping wait",
                    dep_container_name
                );
            }
        }

        Ok(())
    }

    /// Create and start a K8s component container
    #[cfg(target_os = "linux")]
    async fn create_and_start_k8s_container(
        &self,
        instance_id: &str,
        component: &crate::bootstrap::k8s_components::K8sComponent,
        container_name: &str,
        network_spec: Option<&crate::intent::NetworkSpec>,
        zt_ip: Option<&str>,
    ) -> Result<crate::rootless::orchestration::group::ContainerInfo, ProvisionError> {
        use crate::rootless::config::ContainerConfig;
        use crate::rootless::lifecycle;
        use crate::rootless::orchestration::group::ContainerInfo;

        // 1. Get image rootfs path
        let image_dir = self
            .image_manager
            .ensure_image(component.image)
            .await
            .map_err(|e| {
                ProvisionError::Image(format!(
                    "Failed to ensure image {} for {}: {}",
                    component.image, component.suffix, e
                ))
            })?;

        let image_rootfs = image_dir.join("rootfs");

        // 2. Clean up existing container if it exists (MUST happen before bundle removal)
        // This ensures the bundle directory can be safely removed
        let container_id = container_name.to_string(); // Use container_name as container_id
        let root_path = self.container_manager.root_path().to_path_buf();
        let bundle_dir = self.app_dir.join("containers/bundles").join(container_name);

        use crate::rootless::commands::{load_container, ContainerStatus};
        match load_container(&root_path, &container_id) {
            Ok(container) => {
                match container.status() {
                    ContainerStatus::Stopped => {
                        tracing::info!(
                            "[ContainerProvisioner] Found existing container {} with status: Stopped - deleting and recreating (libcontainer cannot start from Stopped)",
                            container_id
                        );
                        if let Err(e) = lifecycle::delete_container(&root_path, &container_id, true) {
                            tracing::warn!(
                                "[ContainerProvisioner] Failed to delete stopped container {}: {}",
                                container_id,
                                e
                            );
                        }
                        // Fall through to step 3 (create bundle and container)
                    }
                    ContainerStatus::Running => {
                        // Libcontainer cannot start from Stopped, so "stop then start" would fail.
                        // Delete and recreate (same as Stopped) to get a fresh container.
                        tracing::info!(
                            "[ContainerProvisioner] Found existing container {} with status: Running - stopping, deleting and recreating (libcontainer cannot start from Stopped)",
                            container_id
                        );
                        if let Err(e) = lifecycle::stop_container(&root_path, &container_id) {
                            tracing::warn!(
                                "[ContainerProvisioner] Failed to stop container {}: {}",
                                container_id,
                                e
                            );
                        } else {
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        }
                        if let Err(e) = lifecycle::delete_container(&root_path, &container_id, true) {
                            tracing::warn!(
                                "[ContainerProvisioner] Failed to delete container {}: {}",
                                container_id,
                                e
                            );
                        }
                        // Fall through to step 3 (create bundle and container)
                    }
                    ContainerStatus::Created => {
                        tracing::info!(
                            "[ContainerProvisioner] Found existing container {} with status: Created - starting",
                            container_id
                        );
                        lifecycle::start_container(&root_path, &container_id).map_err(|e| {
                            ProvisionError::Runtime(format!(
                                "Failed to start existing container {}: {}",
                                container_name, e
                            ))
                        })?;
                        let container_info = ContainerInfo {
                            id: container_id.clone(),
                            name: container_name.to_string(),
                            container_id: container_id.clone(),
                            order_index: component.order as usize,
                            state_path: self.container_manager.root_path().join("state").join(&container_id),
                            bundle_path: bundle_dir.clone(),
                        };
                        tracing::info!(
                            "[ContainerProvisioner] Successfully started existing container: {}",
                            container_name
                        );
                        return Ok(container_info);
                    }
                }
            }
            Err(_) => {
                tracing::debug!(
                    "[ContainerProvisioner] No existing container {} found, proceeding with creation",
                    container_id
                );
            }
        }

        // 3. Create bundle directory (container does not exist)

        // Clean up existing bundle directory if it exists (from previous failed attempts)
        // This ensures we start with a clean slate
        // CRITICAL: Unmount any bind mounts before removing directory
        // Bind mounts can prevent directory removal (EBUSY error)
        if bundle_dir.exists() {
            tracing::info!(
                "[ContainerProvisioner] Removing existing bundle directory: {:?}",
                bundle_dir
            );

            // Try to unmount any bind mounts in the bundle rootfs
            // This is necessary because libcontainer may not clean up mounts on container deletion
            // Use findmnt to detect active mounts, then unmount them
            #[cfg(target_os = "linux")]
            {
                use std::process::Command;
                let bundle_dir_str = bundle_dir.to_string_lossy();

                // Use findmnt to find all mounts under the bundle directory
                if let Ok(output) = Command::new("findmnt")
                    .arg("-n") // No header
                    .arg("-o") // Output format
                    .arg("TARGET")
                    .arg("-r") // Raw format
                    .arg(bundle_dir_str.as_ref())
                    .output()
                {
                    if let Ok(mounts_str) = String::from_utf8(output.stdout) {
                        for mount_line in mounts_str.lines() {
                            let mount_point = mount_line.trim();
                            if !mount_point.is_empty() {
                                tracing::debug!(
                                    "[ContainerProvisioner] Attempting to unmount: {}",
                                    mount_point
                                );
                                // Use lazy unmount (-l) which doesn't require the mount to be idle
                                let _ = Command::new("umount")
                                    .arg("-l") // Lazy unmount - detach immediately
                                    .arg(mount_point)
                                    .output();
                            }
                        }
                    }
                }

                // Also try direct unmount of common mount points as fallback
                let bundle_rootfs = bundle_dir.join("rootfs");
                if bundle_rootfs.exists() {
                    let potential_mounts = vec![
                        bundle_rootfs.join("certs/ca"),
                        bundle_rootfs.join("certs/etcd"),
                        bundle_rootfs.join("certs/kubernetes"),
                        bundle_rootfs.join("var/lib/etcd"),
                        bundle_rootfs.join("var/lib/zerotier-one"),
                    ];

                    for mount_point in &potential_mounts {
                        if mount_point.exists() {
                            let _ = Command::new("umount").arg("-l").arg(mount_point).output();
                        }
                    }
                }

                // Give mounts time to detach after lazy unmount
                std::thread::sleep(std::time::Duration::from_millis(200));
            }

            // Retry up to 3 times with small delays to handle race conditions
            for attempt in 0..3 {
                match std::fs::remove_dir_all(&bundle_dir) {
                    Ok(_) => break,
                    Err(e) if attempt < 2 => {
                        tracing::debug!(
                            "[ContainerProvisioner] Retry {}/3 removing bundle dir: {}",
                            attempt + 1,
                            e
                        );
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(e) => {
                        return Err(ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to remove existing bundle directory {:?}: {}",
                            bundle_dir, e
                        ))));
                    }
                }
            }
        }

        std::fs::create_dir_all(&bundle_dir).map_err(ProvisionError::Io)?;

        let bundle_rootfs = bundle_dir.join("rootfs");

        // 4. Copy image rootfs to bundle rootfs
        tracing::info!(
            "[ContainerProvisioner] Copying rootfs from image to bundle for {}",
            container_name
        );
        if image_rootfs.exists() {
            // Use a simple copy approach (for now)
            // In production, this might use hard links or symlinks for efficiency
            if bundle_rootfs.exists() {
                std::fs::remove_dir_all(&bundle_rootfs).map_err(ProvisionError::Io)?;
            }

            // Copy directory tree using recursive copy
            self.copy_dir_recursive(&image_rootfs, &bundle_rootfs)?;

            // Chown all rootfs files to UID 0/GID 0 to simplify UID/GID mappings
            // This allows using only the root mapping (host UID -> container 0)
            self.chown_rootfs_to_uid0(&bundle_rootfs)?;

            // CRITICAL: Ensure rootfs directory itself has correct permissions for user namespace
            // The rootfs must be traversable (execute permission) for user namespace execution
            use std::os::unix::fs::PermissionsExt;
            let rootfs_meta = std::fs::metadata(&bundle_rootfs)?;
            let mut rootfs_perms = rootfs_meta.permissions();
            rootfs_perms.set_mode(0o755);
            std::fs::set_permissions(&bundle_rootfs, rootfs_perms)?;

            // CRITICAL: Ensure all parent directories leading to rootfs are traversable
            // This is required for user namespace path resolution after chroot/pivot_root
            let mut current_path = bundle_rootfs.as_path();
            while let Some(parent) = current_path.parent() {
                if let Ok(meta) = std::fs::metadata(parent) {
                    let mut perms = meta.permissions();
                    let mode = perms.mode();
                    // Ensure execute permission for traversal
                    if mode & 0o111 == 0 {
                        perms.set_mode(mode | 0o111);
                        let _ = std::fs::set_permissions(parent, perms);
                    }
                }
                current_path = parent;
                // Stop at reasonable depth to avoid going too far up
                if current_path == std::path::Path::new("/") || 
                   current_path.components().count() < 3 {
                    break;
                }
            }

            // Fix permissions to ensure binaries have execute permissions
            // This is critical because copying from cache may preserve incorrect permissions
            self.fix_rootfs_permissions(&bundle_rootfs)?;

            // Validate rootfs has essential directories
            self.validate_rootfs_structure(&bundle_rootfs)?;

            // For kubelet containers, ensure /bin/sh exists (required for startup script)
            if component.suffix == "kubelet" {
                let sh_path = bundle_rootfs.join("bin/sh");
                // Check if sh exists as a file or symlink (symlink_metadata doesn't follow links)
                if !sh_path.symlink_metadata().is_ok() {
                    return Err(ProvisionError::Image(format!(
                        "Kubelet image missing /bin/sh at {:?}. Required for startup script execution.",
                        sh_path
                    )));
                }
                tracing::debug!(
                    "[ContainerProvisioner] Verified /bin/sh exists for kubelet container: {:?}",
                    sh_path
                );
            }

            // Validate rootfs has required binaries for this component
            self.validate_rootfs_binaries(&bundle_rootfs, component)?;

            // For Alpine-based components, copy busybox shell for wrapper scripts
            // Alpine images have /bin/sh as a symlink to /bin/busybox (absolute path)
            // which breaks .exists() checks outside the container context
            // Copy busybox directly to avoid symlink resolution issues
            if component.image.contains("alpine") || component.suffix == "etcd" {
                let alpine_rootfs = self.app_dir.join("containers/images/alpine_latest/rootfs");
                let host_uid = nix::unistd::Uid::current();
                let host_gid = nix::unistd::Gid::current();

                // Copy busybox for shell support
                // CRITICAL: Copy busybox as both 'busybox' and 'sh' instead of using symlink
                // Symlinks can cause permission issues in user namespaces when libcontainer
                // tries to resolve and execute the interpreter. By copying the binary directly,
                // we avoid symlink resolution issues.
                let busybox_src = alpine_rootfs.join("bin/busybox");
                if busybox_src.exists() {
                    let bin_dir = bundle_rootfs.join("bin");
                    std::fs::create_dir_all(&bin_dir).ok();
                    let busybox_dst = bin_dir.join("busybox");
                    let sh_dst = bin_dir.join("sh");

                    // Remove existing sh if it's a symlink (std::fs::copy can't overwrite symlinks)
                    if sh_dst.symlink_metadata().is_ok() {
                        std::fs::remove_file(&sh_dst).ok();
                    }

                    // Copy busybox binary
                    std::fs::copy(&busybox_src, &busybox_dst).ok();
                    // Copy again as 'sh' to avoid symlink resolution issues in user namespaces
                    std::fs::copy(&busybox_src, &sh_dst).ok();
                    
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        // Set execute permissions on both copies
                        std::fs::set_permissions(
                            &busybox_dst,
                            std::fs::Permissions::from_mode(0o755),
                        )
                        .ok();
                        std::fs::set_permissions(
                            &sh_dst,
                            std::fs::Permissions::from_mode(0o755),
                        )
                        .ok();
                    }
                    // Set ownership on both copies
                    nix::unistd::chown(&busybox_dst, Some(host_uid), Some(host_gid)).ok();
                    nix::unistd::chown(&sh_dst, Some(host_uid), Some(host_gid)).ok();
                    tracing::info!(
                        "[ContainerProvisioner] Injected busybox shell into {} rootfs (copied as both busybox and sh)",
                        component.suffix
                    );
                }

                // CRITICAL: Re-run fix_rootfs_permissions after injecting busybox
                // This ensures busybox and any other injected files have correct permissions
                // for user namespace execution. The initial fix_rootfs_permissions call happens
                // before busybox injection, so we need to fix permissions again.
                self.fix_rootfs_permissions(&bundle_rootfs)?;

                // Copy musl dynamic linker and libc for busybox execution
                // busybox from Alpine is dynamically linked to musl, so we need both libraries
                let lib_dir = bundle_rootfs.join("lib");
                std::fs::create_dir_all(&lib_dir).ok();

                // Copy musl libc
                let musl_libc_src = alpine_rootfs.join("lib/libc.musl-x86_64.so.1");
                if musl_libc_src.exists() {
                    let musl_libc_dst = lib_dir.join("libc.musl-x86_64.so.1");
                    std::fs::copy(&musl_libc_src, &musl_libc_dst).ok();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&musl_libc_dst, std::fs::Permissions::from_mode(0o755))
                            .ok();
                    }
                    nix::unistd::chown(&musl_libc_dst, Some(host_uid), Some(host_gid)).ok();
                }

                // Copy musl dynamic linker
                let musl_ld_src = alpine_rootfs.join("lib/ld-musl-x86_64.so.1");
                if musl_ld_src.exists() {
                    let musl_ld_dst = lib_dir.join("ld-musl-x86_64.so.1");
                    std::fs::copy(&musl_ld_src, &musl_ld_dst).ok();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&musl_ld_dst, std::fs::Permissions::from_mode(0o755))
                            .ok();
                    }
                    nix::unistd::chown(&musl_ld_dst, Some(host_uid), Some(host_gid)).ok();
                    tracing::info!(
                        "[ContainerProvisioner] Injected musl libraries (x86_64) into {} rootfs",
                        component.suffix
                    );
                }
            }
        } else {
            return Err(ProvisionError::Image(format!(
                "Image rootfs not found at {:?}",
                image_rootfs
            )));
        }

        // 5. Create bundle structure
        crate::rootless::bundle::create_bundle_structure(&bundle_dir, &bundle_rootfs).map_err(
            |e| ProvisionError::Bundle(format!("Failed to create bundle structure: {}", e)),
        )?;

        // 6. Create ContainerConfig for this K8s component
        let mut container_config =
            ContainerConfig::new(container_name.to_string(), component.suffix.to_string())
                .with_base_image(component.image.to_string())
                .with_cpu_limit(2) // Default CPU limit
                .with_memory_limit(2048); // Default memory limit

        // Set network mode: join existing namespace if specified, otherwise use host network
        if let Some(ns_name) = component.network_namespace {
            // Join existing network namespace (e.g., ZeroTier's namespace)
            // Format: container:<container_id>
            let zt_container_id = format!("{}-{}", instance_id, ns_name);
            container_config.network_mode = format!("container:{}", zt_container_id);
        } else {
            // Use host network mode for internet connectivity and DNS resolution
            // All containers need internet access for DNS resolution and ZeroTier connectivity
            container_config.network_mode = "host".to_string();
            tracing::info!("[ContainerProvisioner] Using host network mode for component {} to enable DNS and internet connectivity", component.suffix);
        }

        // Add volume mounts for etcd data directory if this is etcd
        if component.suffix == "etcd" {
            let etcd_data_dir = self
                .app_dir
                .join("containers/volumes")
                .join(instance_id)
                .join("etcd-data");
            std::fs::create_dir_all(&etcd_data_dir).map_err(ProvisionError::Io)?;

            // Create destination directory in rootfs before mounting
            // libcontainer's bind mount requires the destination to exist
            let etcd_mount_dest = bundle_rootfs.join("var/lib/etcd");
            std::fs::create_dir_all(&etcd_mount_dest).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create mount destination {:?}: {}",
                    etcd_mount_dest, e
                )))
            })?;

            container_config.volumes.insert(
                etcd_data_dir.to_string_lossy().to_string(),
                "/var/lib/etcd".to_string(),
            );

            tracing::info!(
                "[ContainerProvisioner] Added etcd data volume mount: {:?} -> /var/lib/etcd",
                etcd_data_dir
            );
        }

        // Add certificate volume mounts for secure components
        let volumes_base = self.app_dir.join("containers/volumes").join(instance_id);
        let ca_dir = volumes_base.join("ca");
        let k8s_certs_dir = volumes_base.join("kubernetes");
        let etcd_certs_dir = volumes_base.join("etcd");

        if component.suffix == "apiserver"
            || component.suffix == "controller-manager"
            || component.suffix == "scheduler"
            || component.suffix == "kubelet"
        {
            // Create destination directories in rootfs before mounting
            // CRITICAL: Remove existing directories first to ensure bind mounts work correctly
            // Bind mounts require empty or non-existent destination directories
            let k8s_certs_dest = bundle_rootfs.join("certs/kubernetes");
            let ca_dest = bundle_rootfs.join("certs/ca");

            // Remove existing directories if they exist (from image or previous run)
            if k8s_certs_dest.exists() {
                std::fs::remove_dir_all(&k8s_certs_dest).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to remove existing mount destination {:?}: {}",
                        k8s_certs_dest, e
                    )))
                })?;
            }
            if ca_dest.exists() {
                std::fs::remove_dir_all(&ca_dest).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to remove existing mount destination {:?}: {}",
                        ca_dest, e
                    )))
                })?;
            }

            // CRITICAL: Copy certificates into rootfs instead of bind mounting
            // Bind mounts don't work reliably in rootless containers with user namespaces
            // Copying ensures certificates are always available to the container
            std::fs::create_dir_all(&k8s_certs_dest).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create certs destination {:?}: {}",
                    k8s_certs_dest, e
                )))
            })?;
            std::fs::create_dir_all(&ca_dest).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create CA destination {:?}: {}",
                    ca_dest, e
                )))
            })?;

            // Copy all files from host cert directories to container rootfs
            // This ensures certificates are available even if bind mounts fail
            if k8s_certs_dir.exists() {
                tracing::info!(
                    "[ContainerProvisioner] Copying Kubernetes certificates from {:?} to {:?}",
                    k8s_certs_dir,
                    k8s_certs_dest
                );
                for entry in std::fs::read_dir(&k8s_certs_dir).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to read certs directory {:?}: {}",
                        k8s_certs_dir, e
                    )))
                })? {
                    let entry = entry.map_err(ProvisionError::Io)?;
                    let src_path = entry.path();
                    if src_path.is_file() {
                        let dst_path = k8s_certs_dest.join(entry.file_name());
                        std::fs::copy(&src_path, &dst_path).map_err(|e| {
                            ProvisionError::Io(std::io::Error::other(format!(
                                "Failed to copy cert file {:?} to {:?}: {}",
                                src_path, dst_path, e
                            )))
                        })?;
                        // Preserve permissions (certificates need specific permissions)
                        #[cfg(unix)]
                        {
                            let metadata = std::fs::metadata(&src_path).map_err(ProvisionError::Io)?;
                            std::fs::set_permissions(&dst_path, metadata.permissions())
                                .map_err(ProvisionError::Io)?;
                        }
                    }
                }
            }

            if ca_dir.exists() {
                tracing::info!(
                    "[ContainerProvisioner] Copying CA certificates from {:?} to {:?}",
                    ca_dir,
                    ca_dest
                );
                for entry in std::fs::read_dir(&ca_dir).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to read CA directory {:?}: {}",
                        ca_dir, e
                    )))
                })? {
                    let entry = entry.map_err(ProvisionError::Io)?;
                    let src_path = entry.path();
                    if src_path.is_file() {
                        let dst_path = ca_dest.join(entry.file_name());
                        std::fs::copy(&src_path, &dst_path).map_err(|e| {
                            ProvisionError::Io(std::io::Error::other(format!(
                                "Failed to copy CA file {:?} to {:?}: {}",
                                src_path, dst_path, e
                            )))
                        })?;
                        // Preserve permissions
                        #[cfg(unix)]
                        {
                            let metadata = std::fs::metadata(&src_path).map_err(ProvisionError::Io)?;
                            std::fs::set_permissions(&dst_path, metadata.permissions())
                                .map_err(ProvisionError::Io)?;
                        }
                    }
                }
            }

            // CRITICAL: apiserver needs etcd client certificates to connect to etcd
            // These certificates are stored in the etcd directory, not kubernetes directory
            if component.suffix == "apiserver" {
                let etcd_certs_dest = bundle_rootfs.join("certs/etcd");

                // Remove existing directory if it exists
                if etcd_certs_dest.exists() {
                    std::fs::remove_dir_all(&etcd_certs_dest).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to remove existing mount destination {:?}: {}",
                            etcd_certs_dest, e
                        )))
                    })?;
                }

                // CRITICAL: Copy etcd certificates into rootfs instead of bind mounting
                std::fs::create_dir_all(&etcd_certs_dest).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create etcd certs destination {:?}: {}",
                        etcd_certs_dest, e
                    )))
                })?;

                // Copy etcd certificates
                if etcd_certs_dir.exists() {
                    tracing::info!(
                        "[ContainerProvisioner] Copying etcd certificates from {:?} to {:?}",
                        etcd_certs_dir,
                        etcd_certs_dest
                    );
                    for entry in std::fs::read_dir(&etcd_certs_dir).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to read etcd certs directory {:?}: {}",
                            etcd_certs_dir, e
                        )))
                    })? {
                        let entry = entry.map_err(ProvisionError::Io)?;
                        let src_path = entry.path();
                        if src_path.is_file() {
                            let dst_path = etcd_certs_dest.join(entry.file_name());
                            std::fs::copy(&src_path, &dst_path).map_err(|e| {
                                ProvisionError::Io(std::io::Error::other(format!(
                                    "Failed to copy etcd cert file {:?} to {:?}: {}",
                                    src_path, dst_path, e
                                )))
                            })?;
                            // Preserve permissions
                            #[cfg(unix)]
                            {
                                let metadata = std::fs::metadata(&src_path).map_err(ProvisionError::Io)?;
                                std::fs::set_permissions(&dst_path, metadata.permissions())
                                    .map_err(ProvisionError::Io)?;
                            }
                        }
                    }
                }
                tracing::info!(
                    "[ContainerProvisioner] Added etcd certificate mounts for apiserver"
                );
            }
            
            // For Kubernetes components using Alpine base image, inject binaries
            // This handles apiserver, controller-manager, scheduler, and kubelet
            if (component.suffix == "apiserver"
                || component.suffix == "controller-manager"
                || component.suffix == "scheduler"
                || component.suffix == "kubelet")
                && component.image.starts_with("alpine:")
            {
                // Map component suffix to binary name
                let binary_name = match component.suffix {
                    "apiserver" => "kube-apiserver",
                    "controller-manager" => "kube-controller-manager",
                    "scheduler" => "kube-scheduler",
                    "kubelet" => "kubelet",
                    _ => return Err(ProvisionError::Runtime(format!(
                        "Unknown component suffix for binary injection: {}",
                        component.suffix
                    ))),
                };
                // Download kube-apiserver binary from Kubernetes release
                // Architecture: detect from host (aarch64 or x86_64)
                let arch = if cfg!(target_arch = "aarch64") {
                    "arm64"
                } else {
                    "amd64"
                };
                
                let k8s_version = "v1.29.0";
                let binary_url = format!(
                    "https://dl.k8s.io/release/{}/bin/linux/{}/{}",
                    k8s_version, arch, binary_name
                );
                
                let bin_dir = bundle_rootfs.join("usr/local/bin");
                std::fs::create_dir_all(&bin_dir).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create bin directory {:?}: {}",
                        bin_dir, e
                    )))
                })?;
                
                let binary_path = bin_dir.join(binary_name);
                
                // Download binary if it doesn't exist
                if !binary_path.exists() {
                    tracing::info!(
                        "[ContainerProvisioner] Downloading {} binary from {}",
                        binary_name, binary_url
                    );
                    
                    // Use spawn_blocking to download binary in a blocking thread
                    // This avoids "Cannot start a runtime from within a runtime" error
                    let binary_url_clone = binary_url.clone();
                    let binary_data = tokio::task::spawn_blocking(move || {
                        // Use blocking reqwest client in blocking thread
                        // Enable redirect following (default is up to 10 redirects)
                        let client = reqwest::blocking::Client::builder()
                            .timeout(std::time::Duration::from_secs(120))
                            .build()
                            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
                        
                        tracing::debug!("[ContainerProvisioner] Starting download from {}", binary_url_clone);
                        let response = client.get(&binary_url_clone)
                            .send()
                            .map_err(|e| format!("HTTP request failed: {}", e))?;
                        
                        tracing::debug!("[ContainerProvisioner] Download response status: {}", response.status());
                        let response = response.error_for_status()
                            .map_err(|e| format!("HTTP error: {}", e))?;
                        
                        tracing::debug!("[ContainerProvisioner] Reading response bytes...");
                        // Read raw bytes - use bytes() which returns Bytes (implements AsRef<[u8]>)
                        // This handles binary data correctly without trying to decode as text
                        let bytes = response.bytes()
                            .map_err(|e| format!("Failed to read response bytes: {}", e))?;
                        
                        tracing::debug!("[ContainerProvisioner] Downloaded {} bytes", bytes.len());
                        Ok::<_, String>(bytes)
                    })
                    .await
                    .map_err(|e| {
                        ProvisionError::Runtime(format!(
                            "Download task panicked: {}",
                            e
                        ))
                    })?
                    .map_err(|e| {
                        ProvisionError::Runtime(format!(
                            "Failed to download {} binary: {}",
                            binary_name, e
                        ))
                    })?;
                    
                    let mut file = std::fs::File::create(&binary_path).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to create binary file {:?}: {}",
                            binary_path, e
                        )))
                    })?;
                    
                    std::io::copy(&mut binary_data.as_ref(), &mut file).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to write binary file {:?}: {}",
                            binary_path, e
                        )))
                    })?;
                    
                    // Set executable permissions
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(
                            &binary_path,
                            std::fs::Permissions::from_mode(0o755),
                        )
                        .map_err(|e| {
                            ProvisionError::Io(std::io::Error::other(format!(
                                "Failed to set executable permissions on {:?}: {}",
                                binary_path, e
                            )))
                        })?;
                    }
                    
                    // Set ownership to current user
                    let host_uid = nix::unistd::Uid::current();
                    let host_gid = nix::unistd::Gid::current();
                    nix::unistd::chown(&binary_path, Some(host_uid), Some(host_gid))
                        .map_err(|e| {
                            ProvisionError::Runtime(format!(
                                "Failed to chown binary {:?}: {}",
                                binary_path, e
                            ))
                        })?;
                    
                    tracing::info!(
                        "[ContainerProvisioner] Successfully downloaded and installed {} binary to {:?}",
                        binary_name, binary_path
                    );
                } else {
                    tracing::debug!(
                        "[ContainerProvisioner] {} binary already exists at {:?}",
                        binary_name, binary_path
                    );
                }
                
                // CRITICAL: Create /var/run/kubernetes directory for apiserver
                // The apiserver tries to create self-signed certificates here if the directory doesn't exist
                // Even though we provide certificates via flags, it still needs this directory to exist
                if component.suffix == "apiserver" {
                    let kubernetes_run_dir = bundle_rootfs.join("var/run/kubernetes");
                    std::fs::create_dir_all(&kubernetes_run_dir).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to create /var/run/kubernetes directory {:?}: {}",
                            kubernetes_run_dir, e
                        )))
                    })?;
                    
                    // Set ownership to current user (maps to root inside container)
                    let host_uid = nix::unistd::Uid::current();
                    let host_gid = nix::unistd::Gid::current();
                    nix::unistd::chown(&kubernetes_run_dir, Some(host_uid), Some(host_gid))
                        .map_err(|e| {
                            ProvisionError::Runtime(format!(
                                "Failed to chown /var/run/kubernetes directory {:?}: {}",
                                kubernetes_run_dir, e
                            ))
                        })?;
                    
                    tracing::debug!(
                        "[ContainerProvisioner] Created /var/run/kubernetes directory for apiserver"
                    );
                }
            }

            tracing::info!(
                "[ContainerProvisioner] Added certificate mounts for {}",
                component.suffix
            );
        }

        if component.suffix == "etcd" {
            // Create destination directories in rootfs before mounting
            let etcd_certs_dest = bundle_rootfs.join("certs/etcd");
            let ca_dest = bundle_rootfs.join("certs/ca");
            std::fs::create_dir_all(&etcd_certs_dest).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create mount destination {:?}: {}",
                    etcd_certs_dest, e
                )))
            })?;
            std::fs::create_dir_all(&ca_dest).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create mount destination {:?}: {}",
                    ca_dest, e
                )))
            })?;

            container_config.volumes.insert(
                etcd_certs_dir.to_string_lossy().to_string(),
                "/certs/etcd".to_string(),
            );
            container_config.volumes.insert(
                ca_dir.to_string_lossy().to_string(),
                "/certs/ca".to_string(),
            );
            tracing::info!("[ContainerProvisioner] Added etcd certificate mounts");
        }

        // Add kubelet-specific volume mounts
        if component.suffix == "kubelet" {
            // Mount kubelet config directory
            let kubelet_config_dir = volumes_base.join("kubelet");
            // Ensure kubelet config directory exists (should have been created by generate_kubelet_config)
            if !kubelet_config_dir.exists() {
                std::fs::create_dir_all(&kubelet_config_dir).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create kubelet config directory {:?}: {}",
                        kubelet_config_dir, e
                    )))
                })?;
                tracing::warn!(
                    "[ContainerProvisioner] Kubelet config directory did not exist, created it. This may indicate generate_kubelet_config was not called."
                );
            }
            let kubelet_config_dest = bundle_rootfs.join("var/lib/kubelet");
            std::fs::create_dir_all(&kubelet_config_dest).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create mount destination {:?}: {}",
                    kubelet_config_dest, e
                )))
            })?;

            container_config.volumes.insert(
                kubelet_config_dir.to_string_lossy().to_string(),
                "/var/lib/kubelet".to_string(),
            );

            // Mount certificates
            let k8s_certs_dest = bundle_rootfs.join("certs/kubernetes");
            let ca_dest = bundle_rootfs.join("certs/ca");
            std::fs::create_dir_all(&k8s_certs_dest).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create mount destination {:?}: {}",
                    k8s_certs_dest, e
                )))
            })?;
            std::fs::create_dir_all(&ca_dest).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create mount destination {:?}: {}",
                    ca_dest, e
                )))
            })?;

            container_config.volumes.insert(
                k8s_certs_dir.to_string_lossy().to_string(),
                "/certs/kubernetes".to_string(),
            );
            container_config.volumes.insert(
                ca_dir.to_string_lossy().to_string(),
                "/certs/ca".to_string(),
            );

            // Mount vapp CRI socket directory for kubelet instead of host containerd
            // IMPORTANT: We cannot bind-mount a socket file directly (EINVAL error)
            // Instead, mount the directory containing the socket, then kubelet accesses the socket inside
            // The vapp CRI server runs on the host and provides CRI protocol for kubelet
            // This avoids permission issues with host containerd socket in rootless containers

            // Mount the app directory (containing cri.sock) to /var/4lock-agent in the container
            let cri_dir_mount_dest = "/var/4lock-agent";
            let cri_dir_mount_dest_path = bundle_rootfs.join("var/4lock-agent");

            // Create the mount destination directory
            if !cri_dir_mount_dest_path.exists() {
                std::fs::create_dir_all(&cri_dir_mount_dest_path).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create CRI directory mount destination {:?}: {}",
                        cri_dir_mount_dest_path, e
                    )))
                })?;
            }

            // Mount the app directory so kubelet can access cri.sock at /var/4lock-agent/cri.sock
            container_config.volumes.insert(
                self.app_dir.to_string_lossy().to_string(),
                cri_dir_mount_dest.to_string(),
            );
            tracing::info!(
                "[ContainerProvisioner] Added vapp CRI directory mount for kubelet: {:?} -> {} (socket will be at {}/cri.sock)",
                self.app_dir,
                cri_dir_mount_dest,
                cri_dir_mount_dest
            );

            // Mount /sys read-only for kubelet's cadvisor to access cgroup information
            // Cadvisor needs /sys/fs/cgroup to detect cgroup version and gather metrics
            // Use read-only mount to prevent kubelet from modifying host system
            container_config.volumes.insert(
                "/sys".to_string(),
                "/sys".to_string(),
            );

            // Mount /proc read-only for kubelet to access process information
            container_config.volumes.insert(
                "/proc".to_string(),
                "/proc".to_string(),
            );

            tracing::info!("[ContainerProvisioner] Added /sys and /proc mounts for kubelet (read-only for cadvisor)");

            // Create kubelet startup script
            let kubelet_startup_script_path = bundle_rootfs.join("start-kubelet.sh");
            // Use NODE_IP environment variable if set (will be updated with ZeroTier IP), otherwise default to 127.0.0.1
            // psdn/kubelet image has kubelet binary pre-installed at /usr/local/bin/kubelet
            // Uses vapp CRI socket instead of host containerd for rootless compatibility
            let kubelet_startup_script = format!(
                r#"#!/bin/sh
set -e

INSTANCE_ID="{}"
KUBELET_BIN="/usr/local/bin/kubelet"
NODE_IP="${{NODE_IP:-127.0.0.1}}"
LOG_FILE="/var/lib/kubelet/kubelet-startup.log"
# Use vapp CRI socket from mounted directory (app_dir mounted at /var/4lock-agent)
# The CRI socket is at /var/4lock-agent/cri.sock
CRI_SOCKET="/var/4lock-agent/cri.sock"

# Ensure log directory exists
mkdir -p /var/lib/kubelet 2>/dev/null || true

# Function to log with timestamp
log() {{
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}}

log "[Kubelet] Starting kubelet for $INSTANCE_ID"
log "[Kubelet] Node IP: $NODE_IP"
log "[Kubelet] Binary: $KUBELET_BIN"
log "[Kubelet] CRI Socket: $CRI_SOCKET (vapp CRI server)"

# Verify kubelet binary exists (should be pre-installed in psdn/kubelet image)
if [ ! -f "$KUBELET_BIN" ]; then
    log "[Kubelet] ERROR: Kubelet binary not found at $KUBELET_BIN"
    exit 1
fi

# Verify kubelet is executable
if [ ! -x "$KUBELET_BIN" ]; then
    chmod +x "$KUBELET_BIN"
fi

# Verify vapp CRI socket exists (mounted from host vappd)
if [ ! -S "$CRI_SOCKET" ]; then
    log "[Kubelet] ERROR: vapp CRI socket not found at $CRI_SOCKET"
    log "[Kubelet] The CRI socket should be mounted from the host vappd process"
    log "[Kubelet] Check that vappd is running and the socket mount is configured"
    exit 1
fi
log "[Kubelet] vapp CRI socket available"

log "[Kubelet] Starting kubelet with configuration..."
log "[Kubelet] Config: /var/lib/kubelet/kubelet-config.yaml"
log "[Kubelet] Kubeconfig: /var/lib/kubelet/kubelet.kubeconfig"

# Execute kubelet with all arguments, redirecting stderr to log file for debugging
# Uses vapp CRI socket for rootless container runtime integration
# Additional flags for rootless mode to avoid cgroup/privileged access
exec "$KUBELET_BIN" \
  --config=/var/lib/kubelet/kubelet-config.yaml \
  --kubeconfig=/var/lib/kubelet/kubelet.kubeconfig \
  --hostname-override="$INSTANCE_ID" \
  --container-runtime-endpoint=unix://$CRI_SOCKET \
  --root-dir=/var/lib/kubelet \
  --runtime-cgroups=/kubelet.slice \
  --kubelet-cgroups=/kubelet.slice \
  --cgroup-root=/ \
  --pod-infra-container-image=k8s.gcr.io/pause:3.9 \
  --v=2 \
  2>> "$LOG_FILE"
"#,
                instance_id
            );

            // Write startup script to rootfs
            std::fs::write(&kubelet_startup_script_path, kubelet_startup_script).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to write kubelet startup script: {}",
                    e
                )))
            })?;

            // Make script executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &kubelet_startup_script_path,
                    std::fs::Permissions::from_mode(0o755),
                )
                .map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to set kubelet startup script permissions: {}",
                        e
                    )))
                })?;
            }

            tracing::info!(
                "[ContainerProvisioner] Created kubelet startup script at {:?}",
                kubelet_startup_script_path
            );

            // Add NODE_IP environment variable for kubelet startup script
            // Use ZeroTier IP if available, otherwise default to 127.0.0.1
            let node_ip = zt_ip.unwrap_or("127.0.0.1");
            container_config = container_config.add_env("NODE_IP".to_string(), node_ip.to_string());
            tracing::info!(
                "[ContainerProvisioner] Set NODE_IP={} for kubelet container",
                node_ip
            );

            tracing::info!("[ContainerProvisioner] Added kubelet volume mounts");
        }

        // 7. Check rootless container prerequisites before creating container
        self.check_rootless_prerequisites()?;

        // Add ZeroTier-specific volume mounts and configuration
        if component.suffix == "zerotier" {
            // Mount ZeroTier data directory
            let zt_data_dir = self
                .app_dir
                .join("containers/volumes")
                .join(instance_id)
                .join("zerotier-data");
            std::fs::create_dir_all(&zt_data_dir).map_err(ProvisionError::Io)?;

            let zt_mount_dest = bundle_rootfs.join("var/lib/zerotier-one");
            // Ensure parent directories exist
            if let Some(parent) = zt_mount_dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create parent directory {:?}: {}",
                        parent, e
                    )))
                })?;
            }
            // Create mount destination directory (must exist for bind mount to work)
            std::fs::create_dir_all(&zt_mount_dest).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create mount destination {:?}: {}",
                    zt_mount_dest, e
                )))
            })?;
            tracing::debug!(
                "[ContainerProvisioner] Created mount destination directory: {:?}",
                zt_mount_dest
            );
            // Verify directory was created
            if !zt_mount_dest.exists() {
                return Err(ProvisionError::Io(std::io::Error::other(format!(
                    "Mount destination directory was not created: {:?}",
                    zt_mount_dest
                ))));
            }

            container_config.volumes.insert(
                zt_data_dir.to_string_lossy().to_string(),
                "/var/lib/zerotier-one".to_string(),
            );

            // ZeroTier TUN device will be created via OCI linux.devices field
            // No need to bind mount /dev/net/tun - device node is created directly
            // /dev/net directory is created in rootfs and mounted as tmpfs in OCI spec
            tracing::debug!(
                "[ContainerProvisioner] ZeroTier TUN device will be created via OCI linux.devices field"
            );

            tracing::info!("[ContainerProvisioner] Added ZeroTier volume mounts");

            // ZeroTier container needs internet access to contact controllers
            // Use host network mode for ZeroTier container to enable internet connectivity
            container_config.network_mode = "host".to_string();
            tracing::info!("[ContainerProvisioner] ZeroTier container using host network mode for internet access");

            // Create ZeroTier configuration files in the data directory
            if let Some(network_spec) = network_spec {
                let devicemap_path = zt_data_dir.join("devicemap");
                std::fs::write(
                    &devicemap_path,
                    format!("{}=zt0\n", network_spec.zt_network_id),
                )
                .map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create devicemap: {}",
                        e
                    )))
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        &devicemap_path,
                        std::fs::Permissions::from_mode(0o644),
                    )
                    .map_err(ProvisionError::Io)?;
                }

                let local_conf_path = zt_data_dir.join("local.conf");
                // ZeroTier local configuration
                // IMPORTANT: For rootless containers, we need to enable TCP fallback relay
                // because UDP port 9993 might not be bindable in the container namespace
                // Also need to bind to 0.0.0.0 to allow ZeroTier to listen on all interfaces
                let local_conf = r#"{
  "settings": {
    "primaryPort": 9993,
    "allowSecondaryPort": false,
    "allowTcpFallbackRelay": true,
    "portMappingEnabled": false,
    "interfacePrefixPattern": "zt",
    "bind": ["0.0.0.0"],
    "controller": {
      "enabled": false
    }
  }
}"#;
                std::fs::write(&local_conf_path, local_conf).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create local.conf: {}",
                        e
                    )))
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        &local_conf_path,
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .map_err(ProvisionError::Io)?;
                }

                tracing::info!(
                    "[ContainerProvisioner] Created ZeroTier configuration files in {}",
                    zt_data_dir.display()
                );

                // Create startup script that joins network and authorizes node
                let startup_script_path = zt_data_dir.join("start-zerotier.sh");
                let startup_script = r#"#!/bin/sh
set +e  # Don't exit on errors - keep container running even if some commands fail

ZT_DATA_DIR="/var/lib/zerotier-one"
ZT_NETWORK_ID="${ZT_NETWORK_ID:-}"
ZT_TOKEN="${ZT_TOKEN:-}"

# Log environment variables for debugging (mask token for security)
# Write to status file so host can read it (stderr might not be captured)
if [ -n "$ZT_NETWORK_ID" ]; then
    NETWORK_ID_PREFIX=$(echo -n "$ZT_NETWORK_ID" | head -c 8)
    NETWORK_ID_LEN=$(echo -n "$ZT_NETWORK_ID" | wc -c)
    echo "[ZeroTier] ZT_NETWORK_ID is set: $NETWORK_ID_PREFIX... (length: $NETWORK_ID_LEN)" >&2
    echo "ZT_NETWORK_ID is set (length: $NETWORK_ID_LEN)" > "$STATUS_FILE" 2>&1 || true
else
    echo "[ZeroTier] WARNING: ZT_NETWORK_ID is NOT set or empty" >&2
    echo "WARNING: ZT_NETWORK_ID is NOT set or empty" > "$STATUS_FILE" 2>&1 || true
fi
if [ -n "$ZT_TOKEN" ]; then
    TOKEN_LEN=$(echo -n "$ZT_TOKEN" | wc -c)
    echo "[ZeroTier] ZT_TOKEN is set (length: $TOKEN_LEN)" >&2
    echo "ZT_TOKEN is set (length: $TOKEN_LEN)" >> "$STATUS_FILE" 2>&1 || true
else
    echo "[ZeroTier] WARNING: ZT_TOKEN is NOT set or empty" >&2
    echo "WARNING: ZT_TOKEN is NOT set or empty" >> "$STATUS_FILE" 2>&1 || true
fi

# Ensure data directory exists and is writable
mkdir -p "$ZT_DATA_DIR" 2>&1 || true
STATUS_FILE="$ZT_DATA_DIR/status.txt"
echo "Starting" > "$STATUS_FILE" 2>&1 || true

# CRITICAL: Ensure resolv.conf exists with DNS servers
# This is required for ZeroTier daemon to resolve api.zerotier.com
if [ ! -f /etc/resolv.conf ] || [ ! -s /etc/resolv.conf ]; then
    echo "[ZeroTier] Creating /etc/resolv.conf with DNS servers..." >&2
    mkdir -p /etc 2>&1 || true
    echo "nameserver 8.8.8.8" > /etc/resolv.conf 2>&1 || true
    echo "nameserver 8.8.4.4" >> /etc/resolv.conf 2>&1 || true
    echo "options ndots:0" >> /etc/resolv.conf 2>&1 || true
    echo "options timeout:2" >> /etc/resolv.conf 2>&1 || true
    echo "options attempts:3" >> /etc/resolv.conf 2>&1 || true
    echo "[ZeroTier] Created /etc/resolv.conf" >&2
fi

echo "[ZeroTier] Starting ZeroTier daemon..." >&2

# Verify devicemap file exists before starting daemon (required for zt0 interface name)
if [ -f "$ZT_DATA_DIR/devicemap" ]; then
    echo "[ZeroTier] devicemap file found: $(cat "$ZT_DATA_DIR/devicemap")" >&2
else
    echo "[ZeroTier] WARNING: devicemap file not found at $ZT_DATA_DIR/devicemap" >&2
    echo "[ZeroTier] ZeroTier will use fallback interface name instead of zt0" >&2
fi

# Find zerotier-one - check common locations
ZT_ONE_CMD=""
for cmd in zerotier-one /usr/sbin/zerotier-one /usr/bin/zerotier-one; do
    if command -v "$cmd" 2>&1 || [ -x "$cmd" ] 2>&1; then
        ZT_ONE_CMD="$cmd"
        break
    fi
done

if [ -z "$ZT_ONE_CMD" ]; then
    echo "[ZeroTier] ERROR: zerotier-one not found" >&2
    echo "Error: zerotier-one not found" > "$STATUS_FILE"
    exit 1
fi

echo "[ZeroTier] Using zerotier-one: $ZT_ONE_CMD" >&2
echo "Starting daemon: $ZT_ONE_CMD" > "$STATUS_FILE" 2>&1 || true

# Start daemon in background and capture any errors
# CRITICAL: ZeroTier daemon must be started with proper data directory
# The daemon will create control socket/port file in the data directory
# IMPORTANT: Use nohup to ensure daemon continues running even if parent shell exits
# Redirect both stdout and stderr to log file for debugging
echo "[ZeroTier] Starting daemon with data dir: $ZT_DATA_DIR" >&2
echo "[ZeroTier] Verifying local.conf exists before starting..." >&2
if [ -f "$ZT_DATA_DIR/local.conf" ]; then
    echo "[ZeroTier] local.conf found, content:" >&2
    cat "$ZT_DATA_DIR/local.conf" >&2
else
    echo "[ZeroTier] WARNING: local.conf not found at $ZT_DATA_DIR/local.conf" >&2
fi
# Start daemon in background with nohup to ensure it keeps running
# CRITICAL: ZeroTier daemon must be started with data directory as argument
# The daemon will daemonize itself, so we use nohup to ensure it continues
# IMPORTANT: Do NOT use -d flag (daemonize) - zerotier-one does this automatically
echo "[ZeroTier] Starting daemon: $ZT_ONE_CMD $ZT_DATA_DIR" >&2
nohup $ZT_ONE_CMD "$ZT_DATA_DIR" > "$ZT_DATA_DIR/daemon.log" 2>&1 &
ZT_PID=$!
echo "[ZeroTier] Daemon started with PID: $ZT_PID" >&2
# Give daemon a moment to fork and daemonize
sleep_helper 2
# Re-check PID - daemon may have forked
if ! kill -0 $ZT_PID 2>&1; then
    # Daemon may have forked, try to find new PID
    sleep_helper 1
    NEW_PID=$(pgrep -f "zerotier-one.*$ZT_DATA_DIR" | head -1 || echo "")
    if [ -n "$NEW_PID" ]; then
        echo "[ZeroTier] Daemon forked, new PID: $NEW_PID" >&2
        ZT_PID=$NEW_PID
    fi
fi

# Wait a moment for daemon to start
sleep_helper 3

# Check if daemon process is still running
if ! kill -0 $ZT_PID 2>&1; then
    echo "[ZeroTier] ERROR: Daemon process died immediately after start" >&2
    echo "Error: Daemon died" > "$STATUS_FILE" 2>&1 || true
    if [ -f "$ZT_DATA_DIR/daemon.log" ]; then
        echo "[ZeroTier] Daemon log:" >&2
        cat "$ZT_DATA_DIR/daemon.log" >&2
        echo "[ZeroTier] Daemon log (full):" > "$STATUS_FILE" 2>&1 || true
        cat "$ZT_DATA_DIR/daemon.log" >> "$STATUS_FILE" 2>&1 || true
    fi
    exit 1
fi

echo "[ZeroTier] Daemon process started (PID: $ZT_PID)" >&2
echo "Daemon started (PID: $ZT_PID)" > "$STATUS_FILE" 2>&1 || true
echo "[ZeroTier] Checking daemon log for initialization..." >&2
if [ -f "$ZT_DATA_DIR/daemon.log" ]; then
    DAEMON_LOG_LINES=$(wc -l < "$ZT_DATA_DIR/daemon.log" 2>&1 || echo "0")
    echo "[ZeroTier] Daemon log has $DAEMON_LOG_LINES lines" >&2
    echo "Daemon log has $DAEMON_LOG_LINES lines" >> "$STATUS_FILE" 2>&1 || true
    if [ "$DAEMON_LOG_LINES" -gt 0 ]; then
        echo "[ZeroTier] Last 5 lines of daemon log:" >&2
        tail -5 "$ZT_DATA_DIR/daemon.log" >&2
        echo "Daemon log (last 5):" >> "$STATUS_FILE" 2>&1 || true
        tail -5 "$ZT_DATA_DIR/daemon.log" >> "$STATUS_FILE" 2>&1 || true
    fi
else
    echo "[ZeroTier] WARNING: Daemon log file not found at $ZT_DATA_DIR/daemon.log" >&2
    echo "WARNING: Daemon log file not found" >> "$STATUS_FILE" 2>&1 || true
fi

# Run network connectivity tests (inside container with proper permissions)
CONNECTIVITY_FILE="$ZT_DATA_DIR/connectivity.txt"
echo "[ZeroTier] Running network connectivity tests..." >&2
echo "Running connectivity tests" > "$STATUS_FILE" 2>&1 || true

# Initialize connectivity results file
echo "=== Network Connectivity Test Results ===" > "$CONNECTIVITY_FILE" 2>&1 || true
echo "Timestamp: $(date)" >> "$CONNECTIVITY_FILE" 2>&1 || true

# Test 1: Network interfaces
echo "" >> "$CONNECTIVITY_FILE" 2>&1 || true
echo "=== Network Interfaces ===" >> "$CONNECTIVITY_FILE" 2>&1 || true
if command -v ip >/dev/null 2>&1; then
    ip link show >> "$CONNECTIVITY_FILE" 2>&1 || echo "Failed: ip link show" >> "$CONNECTIVITY_FILE" 2>&1
else
    echo "ip command not found" >> "$CONNECTIVITY_FILE" 2>&1
fi

# Test 2: Routing table
echo "" >> "$CONNECTIVITY_FILE" 2>&1 || true
echo "=== Routing Table ===" >> "$CONNECTIVITY_FILE" 2>&1 || true
if command -v ip >/dev/null 2>&1; then
    ip route show >> "$CONNECTIVITY_FILE" 2>&1 || echo "Failed: ip route show" >> "$CONNECTIVITY_FILE" 2>&1
else
    echo "ip command not found" >> "$CONNECTIVITY_FILE" 2>&1
fi

# Test 3: DNS resolution
echo "" >> "$CONNECTIVITY_FILE" 2>&1 || true
echo "=== DNS Resolution Test ===" >> "$CONNECTIVITY_FILE" 2>&1 || true
if command -v getent >/dev/null 2>&1; then
    getent hosts google.com >> "$CONNECTIVITY_FILE" 2>&1 || echo "Failed: getent hosts google.com" >> "$CONNECTIVITY_FILE" 2>&1
elif command -v nslookup >/dev/null 2>&1; then
    nslookup google.com >> "$CONNECTIVITY_FILE" 2>&1 || echo "Failed: nslookup google.com" >> "$CONNECTIVITY_FILE" 2>&1
else
    echo "DNS tools (getent/nslookup) not found" >> "$CONNECTIVITY_FILE" 2>&1
fi

# Test 4: Ping test
echo "" >> "$CONNECTIVITY_FILE" 2>&1 || true
echo "=== Ping Test (8.8.8.8) ===" >> "$CONNECTIVITY_FILE" 2>&1 || true
if command -v ping >/dev/null 2>&1; then
    ping -c 1 -W 2 8.8.8.8 >> "$CONNECTIVITY_FILE" 2>&1 || echo "Failed: ping 8.8.8.8" >> "$CONNECTIVITY_FILE" 2>&1
else
    echo "ping command not found" >> "$CONNECTIVITY_FILE" 2>&1
fi

# Test 5: HTTP connectivity
echo "" >> "$CONNECTIVITY_FILE" 2>&1 || true
echo "=== HTTP Connectivity Test ===" >> "$CONNECTIVITY_FILE" 2>&1 || true
if command -v curl >/dev/null 2>&1; then
    curl -s --max-time 5 http://8.8.8.8 >> "$CONNECTIVITY_FILE" 2>&1 || curl -s --max-time 5 https://www.google.com >> "$CONNECTIVITY_FILE" 2>&1 || echo "Failed: curl connectivity test" >> "$CONNECTIVITY_FILE" 2>&1
else
    echo "curl command not found" >> "$CONNECTIVITY_FILE" 2>&1
fi

# Test 6: IP address information
echo "" >> "$CONNECTIVITY_FILE" 2>&1 || true
echo "=== IP Address Information ===" >> "$CONNECTIVITY_FILE" 2>&1 || true
if command -v ip >/dev/null 2>&1; then
    ip addr show >> "$CONNECTIVITY_FILE" 2>&1 || echo "Failed: ip addr show" >> "$CONNECTIVITY_FILE" 2>&1
else
    echo "ip command not found" >> "$CONNECTIVITY_FILE" 2>&1
fi

echo "[ZeroTier] Connectivity tests completed. Results written to $CONNECTIVITY_FILE" >&2
echo "Connectivity tests completed" > "$STATUS_FILE" 2>&1 || true

# Find zerotier-cli - check common locations
ZT_CLI_CMD=""
for cmd in zerotier-cli /usr/bin/zerotier-cli /usr/sbin/zerotier-cli; do
    if command -v "$cmd" 2>&1 || [ -x "$cmd" ] 2>&1; then
        ZT_CLI_CMD="$cmd"
        break
    fi
done

# Helper function to sleep (use built-in if sleep not available)
sleep_helper() {{
    # Try sleep command first
    if command -v sleep >/dev/null 2>&1; then
        sleep "$1"
    else
        # Fallback: busy wait (not ideal but works)
        end=$(($(date +%s) + $1))
        while [ $(date +%s) -lt $end ]; do
            : # busy wait
        done
    fi
}}

# Wait for ZeroTier daemon to be ready (wait longer - daemon can take time to initialize)
if [ -n "$ZT_CLI_CMD" ]; then
    echo "[ZeroTier] Waiting for daemon to be ready..." >&2
    echo "Waiting for daemon" > "$STATUS_FILE" 2>&1 || true
    DAEMON_READY=false
    
    # First, wait for control socket/port file to be created and contain valid port
    # CRITICAL: Wait longer and check both port file AND actual socket/listening state
    SOCKET_FILE="$ZT_DATA_DIR/zerotier-one.port"
    UNIX_SOCKET_FILE="$ZT_DATA_DIR/zerotier-one.sock"
    PORT_FILE_READY=false
    for i in $(seq 1 120); do # Increased to 120 attempts (2 minutes) for port file
        # Check for Unix socket first (most reliable)
        if [ -S "$UNIX_SOCKET_FILE" ] 2>&1; then
            echo "[ZeroTier] Control Unix socket found (attempt $i)" >&2
            PORT_FILE_READY=true
            break
        fi
        # Check for port file
        if [ -f "$SOCKET_FILE" ]; then
            PORT=$(cat "$SOCKET_FILE" 2>&1 | tr -d '\n\r ' || echo "")
            if [ -n "$PORT" ] && [ "$PORT" -gt 0 ] 2>&1; then
                echo "[ZeroTier] Control port file found with port: $PORT (attempt $i)" >&2
                # Verify daemon is actually listening on this port (if netstat/ss available)
                if command -v netstat >/dev/null 2>&1 || command -v ss >/dev/null 2>&1; then
                    if netstat -tln 2>/dev/null | grep -q ":$PORT " || ss -tln 2>/dev/null | grep -q ":$PORT "; then
                        echo "[ZeroTier] Verified: Daemon is listening on port $PORT" >&2
                        PORT_FILE_READY=true
                        break
                    else
                        echo "[ZeroTier] Port file exists but daemon not listening yet (attempt $i)" >&2
                    fi
                else
                    # If netstat/ss not available, just check port file exists
                    PORT_FILE_READY=true
                    break
                fi
            fi
        fi
        if [ $((i % 10)) -eq 0 ]; then
            echo "[ZeroTier] Waiting for control socket/port... (attempt $i/120)" >&2
            # Check if daemon is still running
            if ! kill -0 $ZT_PID 2>&1; then
                echo "[ZeroTier] ERROR: Daemon process died" >&2
                echo "Error: Daemon died" > "$STATUS_FILE" 2>&1 || true
                if [ -f "$ZT_DATA_DIR/daemon.log" ]; then
                    echo "[ZeroTier] Daemon log:" >&2
                    cat "$ZT_DATA_DIR/daemon.log" >&2
                fi
                exit 1
            fi
            # Check daemon log for any fatal errors
            if [ -f "$ZT_DATA_DIR/daemon.log" ]; then
                FATAL_ERRORS=$(tail -20 "$ZT_DATA_DIR/daemon.log" 2>&1 | grep -i "fatal\|cannot bind\|error.*port\|failed.*start" || echo "")
                if [ -n "$FATAL_ERRORS" ]; then
                    echo "[ZeroTier] FATAL ERROR in daemon log:" >&2
                    echo "$FATAL_ERRORS" >&2
                    echo "FATAL: $FATAL_ERRORS" > "$STATUS_FILE" 2>&1 || true
                fi
            fi
        fi
        sleep_helper 1
    done
    if [ "$PORT_FILE_READY" != "true" ]; then
        echo "[ZeroTier] WARNING: Control socket/port file not ready after 120 attempts" >&2
        echo "[ZeroTier] Port file exists: $([ -f "$SOCKET_FILE" ] && echo "yes ($(cat "$SOCKET_FILE" 2>&1))" || echo "no")" >&2
        echo "[ZeroTier] Socket exists: $([ -S "$UNIX_SOCKET_FILE" ] && echo "yes" || echo "no")" >&2
        if [ -f "$ZT_DATA_DIR/daemon.log" ]; then
            echo "[ZeroTier] Last 30 lines of daemon log:" >&2
            tail -30 "$ZT_DATA_DIR/daemon.log" >&2
        fi
    fi
    
    # Read port from port file if it exists (after port file is ready)
    ZT_PORT=""
    if [ "$PORT_FILE_READY" = "true" ] && [ -f "$SOCKET_FILE" ]; then
        ZT_PORT=$(cat "$SOCKET_FILE" 2>&1 | tr -d '\n\r ' || echo "")
        if [ -n "$ZT_PORT" ] && [ "$ZT_PORT" -gt 0 ] 2>&1; then
            echo "[ZeroTier] Using port from port file: $ZT_PORT" >&2
        else
            ZT_PORT=""
        fi
    fi
    
    # Build zerotier-cli command - prefer Unix socket, then TCP port
    # Note: zerotier-cli -p flag syntax: -p<port> (no space, no quotes)
    # Note: zerotier-cli -D flag syntax: -D<path> (no space, no quotes)
    # CRITICAL: Always use -D flag to specify data directory (ensures correct control socket path)
    UNIX_SOCKET_FILE="$ZT_DATA_DIR/zerotier-one.sock"
    if [ -S "$UNIX_SOCKET_FILE" ] 2>&1; then
        # Use Unix socket if available (more reliable than TCP)
        ZT_CLI_BASE="$ZT_CLI_CMD -D$ZT_DATA_DIR"
        echo "[ZeroTier] Using Unix socket for zerotier-cli" >&2
    elif [ -n "$ZT_PORT" ] && [ "$ZT_PORT" != "9993" ]; then
        ZT_CLI_BASE="$ZT_CLI_CMD -p$ZT_PORT -D$ZT_DATA_DIR"
        echo "[ZeroTier] Using explicit port $ZT_PORT for zerotier-cli" >&2
    else
        # Default to port 9993 (standard ZeroTier control port)
        ZT_CLI_BASE="$ZT_CLI_CMD -p9993 -D$ZT_DATA_DIR"
        echo "[ZeroTier] Using default port 9993 for zerotier-cli" >&2
    fi
    
    # Now wait for daemon to respond to commands - test actual connection
    # CRITICAL: Must wait for daemon to be fully ready before proceeding
    # Try multiple connection methods: Unix socket first, then TCP port
    # IMPORTANT: ZeroTier daemon can take significant time to initialize control interface
    # Some versions may take 2-5 minutes to fully start, especially in container environments
    for i in $(seq 1 600); do # Increased to 600 attempts (10 minutes) - daemon can take very long time
        # Method 1: Try with Unix socket if available (most reliable, no port needed)
        INFO_OUTPUT=""
        INFO_EXIT=1
        if [ -S "$UNIX_SOCKET_FILE" ] 2>&1; then
            # Try with Unix socket (no port needed, most reliable method)
            INFO_OUTPUT=$(eval "$ZT_CLI_CMD -D$ZT_DATA_DIR info" 2>&1 || echo "")
            INFO_EXIT=$?
            if [ $INFO_EXIT -eq 0 ] && echo "$INFO_OUTPUT" | grep -q "200 info"; then
                echo "[ZeroTier] Daemon is ready via Unix socket (attempt $i)" >&2
                echo "[ZeroTier] Info output: $INFO_OUTPUT" >&2
                echo "Daemon ready (Unix socket)" > "$STATUS_FILE" 2>&1 || true
                DAEMON_READY=true
                break
            fi
        fi
        
        # Method 2: Try TCP port connection (if Unix socket not available or failed)
        if [ "$DAEMON_READY" != "true" ]; then
            # Try with explicit port from port file
            if [ -n "$ZT_PORT" ] && [ "$ZT_PORT" -gt 0 ] 2>&1; then
                INFO_OUTPUT=$(eval "$ZT_CLI_CMD -p$ZT_PORT -D$ZT_DATA_DIR info" 2>&1 || echo "")
                INFO_EXIT=$?
            else
                # Try default port 9993
                INFO_OUTPUT=$(eval "$ZT_CLI_CMD -p9993 -D$ZT_DATA_DIR info" 2>&1 || echo "")
                INFO_EXIT=$?
            fi
            
            # Check if TCP connection succeeded
            if [ $INFO_EXIT -eq 0 ] && echo "$INFO_OUTPUT" | grep -q "200 info"; then
                echo "[ZeroTier] Daemon is ready via TCP port (attempt $i)" >&2
                echo "[ZeroTier] Info output: $INFO_OUTPUT" >&2
                echo "Daemon ready (TCP port)" > "$STATUS_FILE" 2>&1 || true
                DAEMON_READY=true
                break
            fi
        fi
        
        # Method 3: Try without explicit port (let zerotier-cli auto-detect from data dir)
        if [ "$DAEMON_READY" != "true" ]; then
            INFO_OUTPUT=$(eval "$ZT_CLI_CMD -D$ZT_DATA_DIR info" 2>&1 || echo "")
            INFO_EXIT=$?
            if [ $INFO_EXIT -eq 0 ] && echo "$INFO_OUTPUT" | grep -q "200 info"; then
                echo "[ZeroTier] Daemon is ready via auto-detect (attempt $i)" >&2
                echo "[ZeroTier] Info output: $INFO_OUTPUT" >&2
                echo "Daemon ready (auto-detect)" > "$STATUS_FILE" 2>&1 || true
                DAEMON_READY=true
                break
            fi
        fi
        
        # Check if daemon is still running
        if ! kill -0 $ZT_PID 2>&1; then
            echo "[ZeroTier] ERROR: Daemon process died during initialization" >&2
            echo "Error: Daemon died" > "$STATUS_FILE" 2>&1 || true
            if [ -f "$ZT_DATA_DIR/daemon.log" ]; then
                echo "[ZeroTier] Daemon log:" >&2
                cat "$ZT_DATA_DIR/daemon.log" >&2
            fi
            exit 1
        fi
        
        # Log error details periodically
        if [ $((i % 20)) -eq 0 ]; then
            echo "[ZeroTier] Still waiting for daemon... (attempt $i/600)" >&2
            echo "[ZeroTier] Info command exit code: $INFO_EXIT" >&2
            echo "[ZeroTier] Info command output: $INFO_OUTPUT" >&2
            PORT_FILE_STATUS=$([ -f "$SOCKET_FILE" ] && echo "yes ($(cat "$SOCKET_FILE" 2>&1))" || echo "no")
            SOCKET_STATUS=$([ -S "$UNIX_SOCKET_FILE" ] && echo "yes" || echo "no")
            echo "[ZeroTier] Port file exists: $PORT_FILE_STATUS" >&2
            echo "[ZeroTier] Socket exists: $SOCKET_STATUS" >&2
            echo "Waiting for daemon (attempt $i/600) | Port file: $PORT_FILE_STATUS | Socket: $SOCKET_STATUS | Exit: $INFO_EXIT" > "$STATUS_FILE" 2>&1 || true
            # Check daemon log for errors
            if [ -f "$ZT_DATA_DIR/daemon.log" ]; then
                DAEMON_ERRORS=$(tail -30 "$ZT_DATA_DIR/daemon.log" 2>&1 | grep -i "error\|fail\|warn\|fatal\|cannot bind" || echo "")
                if [ -n "$DAEMON_ERRORS" ]; then
                    echo "[ZeroTier] Daemon log errors: $DAEMON_ERRORS" >&2
                    echo "Daemon log errors: $DAEMON_ERRORS" >> "$STATUS_FILE" 2>&1 || true
                fi
                # Show last few lines of daemon log periodically for context
                if [ $((i % 60)) -eq 0 ]; then
                    echo "[ZeroTier] Last 20 lines of daemon log:" >&2
                    tail -20 "$ZT_DATA_DIR/daemon.log" >&2
                fi
            fi
        fi
        sleep_helper 1
    done
    if [ "$DAEMON_READY" != "true" ]; then
        echo "[ZeroTier] ERROR: Daemon not ready after 600 attempts (10 minutes) - cannot proceed" >&2
        echo "ERROR: Daemon not ready after 600 attempts" > "$STATUS_FILE" 2>&1 || true
        # Show daemon log if available
        if [ -f "$ZT_DATA_DIR/daemon.log" ]; then
            echo "[ZeroTier] Last 30 lines of daemon log:" >&2
            tail -30 "$ZT_DATA_DIR/daemon.log" >&2
        fi
        # Show port/socket status
        echo "[ZeroTier] Port file: $([ -f "$SOCKET_FILE" ] && echo "exists: $(cat "$SOCKET_FILE" 2>&1)" || echo "missing")" >&2
        echo "[ZeroTier] Socket: $([ -S "$ZT_DATA_DIR/zerotier-one.sock" ] && echo "exists" || echo "missing")" >&2
        echo "[ZeroTier] Daemon PID: $ZT_PID (running: $(kill -0 $ZT_PID 2>&1 && echo "yes" || echo "no"))" >&2
        # Don't proceed if daemon isn't ready - network join will fail
        echo "[ZeroTier] Skipping network join - daemon not ready" >&2
        echo "Skipping network join - daemon not ready" > "$STATUS_FILE" 2>&1 || true
    fi
fi

# Join network if network ID is provided AND daemon is ready
if [ -n "$ZT_NETWORK_ID" ] && [ -n "$ZT_CLI_CMD" ] && [ "$DAEMON_READY" = "true" ]; then
    # Verify daemon is still responding before joining (double-check)
    INFO_CHECK=$(eval "$ZT_CLI_BASE info" 2>&1 || echo "")
    if ! echo "$INFO_CHECK" | grep -q "200 info"; then
        echo "[ZeroTier] WARNING: Daemon not responding before network join" >&2
        echo "[ZeroTier] Info output: $INFO_CHECK" >&2
        echo "Daemon not responding before join" > "$STATUS_FILE" 2>&1 || true
        # Wait a bit more and retry (up to 3 times)
        for retry in 1 2 3; do
            sleep_helper 3
            INFO_CHECK=$(eval "$ZT_CLI_BASE info" 2>&1 || echo "")
            if echo "$INFO_CHECK" | grep -q "200 info"; then
                echo "[ZeroTier] Daemon responded after retry $retry" >&2
                break
            fi
        done
        if ! echo "$INFO_CHECK" | grep -q "200 info"; then
            echo "[ZeroTier] ERROR: Daemon still not responding after retries - skipping network join" >&2
            echo "ERROR: Daemon not responding - join skipped" > "$STATUS_FILE" 2>&1 || true
            # Skip network join if daemon isn't responding
            ZT_NETWORK_ID=""  # Clear to skip join section
        fi
    fi
    echo "[ZeroTier] Joining network $ZT_NETWORK_ID..." >&2
    echo "Joining network $ZT_NETWORK_ID" > "$STATUS_FILE" 2>&1 || true
    JOIN_OUTPUT=$(eval "$ZT_CLI_BASE join \"$ZT_NETWORK_ID\"" 2>&1)
    JOIN_EXIT=$?
    echo "[ZeroTier] Join output: $JOIN_OUTPUT" >&2
    echo "[ZeroTier] Join exit code: $JOIN_EXIT" >&2
    if [ $JOIN_EXIT -ne 0 ]; then
        echo "[ZeroTier] Join command exited with code $JOIN_EXIT" >&2
        echo "Join failed (exit code $JOIN_EXIT): $JOIN_OUTPUT" > "$STATUS_FILE" 2>&1 || true
    else
        echo "[ZeroTier] Join command succeeded" >&2
        echo "Join succeeded" > "$STATUS_FILE" 2>&1 || true
    fi
    
    # Wait a bit for join to process
    sleep_helper 2
    
    # Get node ID - wait for daemon to be ready first
    echo "[ZeroTier] Getting node ID..." >&2
    NODE_ID=""
    for i in $(seq 1 30); do
        INFO_OUTPUT=$(eval "$ZT_CLI_BASE info" 2>&1 || echo "")
        if [ -n "$INFO_OUTPUT" ] && echo "$INFO_OUTPUT" | grep -q "200 info"; then
            # Parse node ID from "200 info <node_id> <version> <port>" format
            NODE_ID=$(echo "$INFO_OUTPUT" | grep "^200 info" | awk '{{print $3}}' | head -1)
            if [ -n "$NODE_ID" ] && [ $(echo -n "$NODE_ID" | wc -c) -eq 10 ]; then
                echo "[ZeroTier] Node ID: $NODE_ID" >&2
                break
            fi
        fi
        if [ $i -lt 30 ]; then
            sleep_helper 1
        fi
    done
    if [ -z "$NODE_ID" ]; then
        echo "[ZeroTier] Failed to get node ID after 30 attempts" >&2
        echo "[ZeroTier] Info output was: $INFO_OUTPUT" >&2
    fi
    
    if [ -n "$NODE_ID" ] && [ -n "$ZT_TOKEN" ]; then
        echo "[ZeroTier] Authorizing node $NODE_ID..." >&2
        if command -v curl >/dev/null 2>&1; then
            AUTH_OUTPUT=$(curl -s -X POST \
                -H "Authorization: token $ZT_TOKEN" \
                -H "Content-Type: application/json" \
                -d '{{"config":{{"authorized":true}}}}' \
                "https://api.zerotier.com/api/v1/network/$ZT_NETWORK_ID/member/$NODE_ID" 2>&1)
            AUTH_EXIT=$?
            if [ $AUTH_EXIT -eq 0 ]; then
                echo "[ZeroTier] Authorization successful" >&2
            else
                echo "[ZeroTier] Authorization failed: $AUTH_OUTPUT" >&2
            fi
        else
            echo "[ZeroTier] curl not found, skipping authorization" >&2
        fi
    else
        if [ -z "$NODE_ID" ]; then
            echo "[ZeroTier] Cannot authorize: node ID not available" >&2
            echo "Authorization skipped: node ID not available" > "$STATUS_FILE" 2>&1 || true
        fi
        if [ -z "$ZT_TOKEN" ]; then
            echo "[ZeroTier] Cannot authorize: token not provided" >&2
            echo "Authorization skipped: token not provided" > "$STATUS_FILE" 2>&1 || true
        fi
    fi
else
    if [ "$DAEMON_READY" != "true" ]; then
        echo "[ZeroTier] WARNING: Daemon not ready - skipping network join" >&2
        echo "Network join skipped: daemon not ready" > "$STATUS_FILE" 2>&1 || true
    elif [ -z "$ZT_NETWORK_ID" ]; then
        echo "[ZeroTier] WARNING: ZT_NETWORK_ID not set - skipping network join" >&2
        echo "Network join skipped: ZT_NETWORK_ID not set" > "$STATUS_FILE" 2>&1 || true
    elif [ -z "$ZT_CLI_CMD" ]; then
        echo "[ZeroTier] WARNING: zerotier-cli not found - skipping network join" >&2
        echo "Network join skipped: zerotier-cli not found" > "$STATUS_FILE" 2>&1 || true
    fi
fi

# Wait for ZeroTier IP and write it to a file for the host to read
echo "[ZeroTier] Waiting for IP assignment..."
IP_FILE="$ZT_DATA_DIR/ip.txt"
rm -f "$IP_FILE"

# Wait for IP to be assigned (check zt0 first, then any zt* interface)
echo "[ZeroTier] Starting IP detection loop..." >&2
echo "Starting IP detection" > "$STATUS_FILE"

# Read port from port file if it exists (needed for ZT_CLI_BASE)
ZT_PORT=""
if [ -f "$ZT_DATA_DIR/zerotier-one.port" ]; then
    ZT_PORT=$(cat "$ZT_DATA_DIR/zerotier-one.port" 2>&1 | tr -d '\n\r ' || echo "")
    if [ -n "$ZT_PORT" ] && [ "$ZT_PORT" -gt 0 ] 2>&1; then
        echo "[ZeroTier] Using port from port file: $ZT_PORT" >&2
    else
        ZT_PORT=""
    fi
fi

# Build zerotier-cli command with port if available
# Note: zerotier-cli -p flag syntax: -p<port> (no space, no quotes)
# Note: zerotier-cli -D flag syntax: -D<path> (no space, no quotes)
# CRITICAL: Use the port from the port file, or default to 9993
# The -D flag should make zerotier-cli use the correct control socket automatically
# But we also specify -p explicitly to ensure correct port
if [ -n "$ZT_PORT" ]; then
    ZT_CLI_BASE="$ZT_CLI_CMD -p$ZT_PORT -D$ZT_DATA_DIR"
    echo "[ZeroTier] Using port $ZT_PORT from port file for zerotier-cli" >&2
else
    # Default to 9993 (standard ZeroTier control port)
    ZT_CLI_BASE="$ZT_CLI_CMD -p9993 -D$ZT_DATA_DIR"
    echo "[ZeroTier] Using default port 9993 for zerotier-cli" >&2
fi

# First, verify network join status
if [ -n "$ZT_CLI_CMD" ]; then
    NETWORK_LIST=$(eval "$ZT_CLI_BASE listnetworks" 2>&1 || echo "")
    echo "[ZeroTier] Current networks: $NETWORK_LIST" >&2
    echo "Networks: $NETWORK_LIST" >> "$STATUS_FILE" 2>&1 || true
fi


# Wait indefinitely for IP (provisioner will timeout if needed)
# But log progress every 30 seconds
i=0
while true; do
    i=$((i + 1))
    IP=""
    
    # Method 1: Try to get IP from listnetworks output
    if [ -n "$ZT_CLI_CMD" ]; then
        # Use the same port-aware command we built earlier
        NETWORK_INFO=$(eval "$ZT_CLI_BASE listnetworks" 2>&1 || echo "")
        if [ -n "$NETWORK_INFO" ]; then
            if echo "$NETWORK_INFO" | grep -q "$ZT_NETWORK_ID"; then
                # Check network status - extract status field (3rd field after network ID)
                NETWORK_LINE=$(echo "$NETWORK_INFO" | grep "$ZT_NETWORK_ID" | head -1)
                NETWORK_STATUS=$(echo "$NETWORK_LINE" | awk '{{print $3}}' | head -1)
                
                if [ $((i % 30)) -eq 0 ]; then
                    echo "[ZeroTier] Network $ZT_NETWORK_ID found in listnetworks (status: $NETWORK_STATUS)" >&2
                    echo "[ZeroTier] Full network line: $NETWORK_LINE" >&2
                fi
                
                # Check if network is in a state that prevents IP assignment
                if echo "$NETWORK_STATUS" | grep -qE "REQUESTING_CONFIGURATION|ACCESS_DENIED|NOT_FOUND"; then
                    if [ $((i % 30)) -eq 0 ]; then
                        echo "[ZeroTier] WARNING: Network status is $NETWORK_STATUS - IP may not be assigned yet" >&2
                        echo "[ZeroTier] This may indicate authorization is pending or failed" >&2
                    fi
                fi
                
                # Network is joined - extract IP from listnetworks output
                # Format: <nwid> <name> <mac> <status> <type> <dev> <ZT assigned addresses>
                # Example: 3efa5cb78ac0734e 4lock-agent 4e:4a:e7:bd:8d:20 OK PUBLIC zt0 10.35.176.34/16
                # Try to extract IP from the last field (which may contain CIDR notation)
                IP_RAW=$(echo "$NETWORK_INFO" | grep "$ZT_NETWORK_ID" | awk '{print $NF}' | head -1)
                if [ -n "$IP_RAW" ]; then
                    # Extract IP address (remove CIDR notation if present)
                    # Use cut to remove everything after /, or sed to extract just the IP
                    if echo "$IP_RAW" | grep -qE "^[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*"; then
                        # IP is at the start - extract it (handles both with and without CIDR)
                        IP=$(echo "$IP_RAW" | cut -d'/' -f1 | head -1)
                        # Validate it's a valid IP format (simpler regex that works in shell)
                        if echo "$IP" | grep -qE "^[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*$"; then
                            echo "[ZeroTier] IP found via listnetworks: $IP (raw: $IP_RAW)" >&2
                        else
                            IP=""
                            if [ $((i % 30)) -eq 0 ]; then
                                echo "[ZeroTier] Invalid IP format from listnetworks: $IP_RAW" >&2
                            fi
                        fi
                    else
                        # Try to find IP anywhere in the string (simpler regex)
                        IP=$(echo "$IP_RAW" | grep -oE "[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*" | head -1)
                        if [ -n "$IP" ]; then
                            echo "[ZeroTier] IP found via listnetworks: $IP (raw: $IP_RAW)" >&2
                        else
                            if [ $((i % 30)) -eq 0 ]; then
                                echo "[ZeroTier] Could not parse IP from listnetworks output: $IP_RAW" >&2
                            fi
                        fi
                    fi
                else
                    if [ $((i % 30)) -eq 0 ]; then
                        echo "[ZeroTier] Network found but no IP field in listnetworks output" >&2
                        echo "[ZeroTier] Full listnetworks line: $(echo "$NETWORK_INFO" | grep "$ZT_NETWORK_ID")" >&2
                    fi
                fi
            else
                if [ $((i % 30)) -eq 0 ]; then
                    echo "[ZeroTier] Network $ZT_NETWORK_ID not found in listnetworks yet (iteration $i)" >&2
                    echo "[ZeroTier] listnetworks output: $NETWORK_INFO" >&2
                    echo "Network not found in listnetworks (iteration $i)" > "$STATUS_FILE"
                fi
            fi
        else
            if [ $((i % 30)) -eq 0 ]; then
                echo "[ZeroTier] listnetworks returned empty output (iteration $i)" >&2
                echo "[ZeroTier] Command used: $ZT_CLI_BASE listnetworks" >&2
                echo "listnetworks empty (iteration $i)" > "$STATUS_FILE"
            fi
        fi
    fi
    
    # Method 2: Fallback to checking zt0 interface directly
    if [ -z "$IP" ] && [ -x /bin/ip ]; then
        # Check zt0 interface (as configured in devicemap)
        if /bin/ip link show zt0 >/dev/null 2>&1; then
            IP=$(/bin/ip addr show zt0 2>/dev/null | grep -oE "inet [0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*" | awk '{print $2}' | head -1)
            if [ -n "$IP" ]; then
                echo "[ZeroTier] IP found via zt0 interface: $IP" >&2
            else
                if [ $((i % 30)) -eq 0 ]; then
                    echo "[ZeroTier] zt0 interface exists but has no IP address" >&2
                    /bin/ip addr show zt0 2>&1 | head -5 >&2
                fi
            fi
        else
            if [ $((i % 30)) -eq 0 ]; then
                echo "[ZeroTier] zt0 interface not found" >&2
            fi
        fi
    fi
    
    # Method 3: Fallback to checking any zt* interface
    if [ -z "$IP" ] && [ -x /bin/ip ]; then
        ZT_INTERFACES=$(/bin/ip link show 2>/dev/null | grep -oE "^[0-9]+: zt[^:]+" | awk '{print $2}' || echo "")
        if [ -n "$ZT_INTERFACES" ]; then
            if [ $((i % 30)) -eq 0 ]; then
                echo "[ZeroTier] Found ZeroTier interfaces: $ZT_INTERFACES" >&2
            fi
            for iface in $ZT_INTERFACES; do
                IP=$(/bin/ip addr show "$iface" 2>/dev/null | grep -oE "inet [0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*" | awk '{print $2}' | head -1)
                if [ -n "$IP" ]; then
                    echo "[ZeroTier] IP found via $iface interface: $IP" >&2
                    break
                else
                    if [ $((i % 30)) -eq 0 ]; then
                        echo "[ZeroTier] Interface $iface exists but has no IP" >&2
                    fi
                fi
            done
        else
            if [ $((i % 30)) -eq 0 ]; then
                echo "[ZeroTier] No zt* interfaces found" >&2
            fi
        fi
    fi
    
    # If IP found, write it to file and exit loop
    if [ -n "$IP" ] && [ "$IP" != "null" ]; then
        echo "$IP" > "$IP_FILE"
        echo "[ZeroTier] IP detected: $IP" >&2
        echo "[ZeroTier] IP file written to $IP_FILE" >&2
        echo "IP detected: $IP" > "$STATUS_FILE"
        break
    fi
    
    # Update status file every 10 iterations with diagnostic info
    if [ $((i % 10)) -eq 0 ]; then
        echo "[ZeroTier] Still waiting for IP assignment... (iteration $i)" >&2
        STATUS_MSG="Waiting for IP (iteration $i)"
        if [ -n "$ZT_CLI_CMD" ]; then
            NETWORK_STATUS=$(eval "$ZT_CLI_BASE listnetworks" 2>&1 | grep "$ZT_NETWORK_ID" || echo "not found")
            STATUS_MSG="$STATUS_MSG | Network: $NETWORK_STATUS"
        fi
        if [ -x /bin/ip ]; then
            INTERFACE_STATUS=$(/bin/ip link show 2>/dev/null | grep -E "^[0-9]+: zt" | awk '{{print $2}}' | tr '\n' ' ' || echo "none")
            STATUS_MSG="$STATUS_MSG | Interfaces: $INTERFACE_STATUS"
        fi
        echo "$STATUS_MSG" > "$STATUS_FILE" 2>&1 || true
    fi
    
    sleep_helper 1
done

# Keep zerotier-one running - if it exits, the container exits
echo "[ZeroTier] Waiting for zerotier-one to exit..." >&2
echo "Running (waiting for zerotier-one)" > "$STATUS_FILE"
wait $ZT_PID
EXIT_CODE=$?
echo "[ZeroTier] zerotier-one exited with code $EXIT_CODE" >&2
echo "Exited with code $EXIT_CODE" > "$STATUS_FILE"
exit $EXIT_CODE
"#;
                std::fs::write(&startup_script_path, startup_script).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create startup script: {}",
                        e
                    )))
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        &startup_script_path,
                        std::fs::Permissions::from_mode(0o755),
                    )
                    .map_err(ProvisionError::Io)?;
                }

                // Copy startup script to container rootfs
                let script_dest = bundle_rootfs.join("start-zerotier.sh");
                std::fs::copy(&startup_script_path, &script_dest).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to copy startup script to rootfs: {}",
                        e
                    )))
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&script_dest, std::fs::Permissions::from_mode(0o755))
                        .map_err(ProvisionError::Io)?;
                }

                tracing::info!("[ContainerProvisioner] Created ZeroTier startup script");

                // Override args to use startup script for ZeroTier
                let mut zerotier_args = component.args.clone();
                if component.suffix == "zerotier" {
                    zerotier_args = vec!["/bin/sh".to_string(), "/start-zerotier.sh".to_string()];
                }

                // Add environment variables for ZeroTier (network_spec is already unwrapped in this block)
                container_config = container_config
                    .add_env(
                        "ZT_NETWORK_ID".to_string(),
                        network_spec.zt_network_id.clone(),
                    )
                    .add_env("ZT_TOKEN".to_string(), network_spec.zt_token.clone());

                // 7. Generate OCI spec with custom args (use startup script for ZeroTier)
                self.generate_k8s_oci_spec(
                    &container_config,
                    &bundle_rootfs,
                    &bundle_dir,
                    &zerotier_args,
                    component.privileged,
                )?;
            } else {
                // 7. Generate OCI spec with custom args
                // Use startup script for kubelet (has shell), but not for apiserver (Kubernetes images don't have /bin/sh)
                let args_to_use = if component.suffix == "kubelet" {
                    vec!["/bin/sh".to_string(), "/start-kubelet.sh".to_string()]
                } else {
                    component.args.clone()
                };
                
                self.generate_k8s_oci_spec(
                    &container_config,
                    &bundle_rootfs,
                    &bundle_dir,
                    &args_to_use,
                    component.privileged,
                )?;
            }
        } else {
            // 7. Generate OCI spec with custom args
            // Use startup script for kubelet (has shell), but not for apiserver (Kubernetes images don't have /bin/sh)
            let args_to_use = if component.suffix == "kubelet" {
                vec!["/bin/sh".to_string(), "/start-kubelet.sh".to_string()]
            } else {
                component.args.clone()
            };
            
            self.generate_k8s_oci_spec(
                &container_config,
                &bundle_rootfs,
                &bundle_dir,
                &args_to_use,
                component.privileged,
            )?;
        }

        // 8. Create container using lifecycle
        // (container_id and root_path already defined in step 2)
        if component.suffix == "zerotier" {
            // Verify rootfs exists before creating mount destination
            if !bundle_rootfs.exists() {
                return Err(ProvisionError::Bundle(format!(
                    "Bundle rootfs does not exist when creating mount destination: {:?}",
                    bundle_rootfs
                )));
            }

            let zt_mount_dest = bundle_rootfs.join("var/lib/zerotier-one");
            tracing::debug!(
                "[ContainerProvisioner] Creating ZeroTier mount destination: {:?}",
                zt_mount_dest
            );

            // Ensure parent directories exist
            if let Some(parent) = zt_mount_dest.parent() {
                tracing::debug!(
                    "[ContainerProvisioner] Creating parent directory: {:?}",
                    parent
                );
                std::fs::create_dir_all(parent).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create parent directory {:?}: {}",
                        parent, e
                    )))
                })?;
            }

            // Remove mount destination if it exists (from image or previous run)
            // This ensures bind mount works correctly - destination must be empty or non-existent
            if zt_mount_dest.exists() {
                tracing::debug!(
                    "[ContainerProvisioner] Removing existing mount destination before bind mount: {:?}",
                    zt_mount_dest
                );
                if zt_mount_dest.is_dir() {
                    std::fs::remove_dir_all(&zt_mount_dest).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to remove existing mount destination directory {:?}: {}",
                            zt_mount_dest, e
                        )))
                    })?;
                } else {
                    std::fs::remove_file(&zt_mount_dest).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to remove existing mount destination file {:?}: {}",
                            zt_mount_dest, e
                        )))
                    })?;
                }
            }

            // Create mount destination directory (empty, for bind mount)
            std::fs::create_dir_all(&zt_mount_dest).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create mount destination {:?}: {}",
                    zt_mount_dest, e
                )))
            })?;

            // Ensure mount destination directory has correct permissions (readable/writable)
            // This is critical for rootless containers with user namespace mapping
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&zt_mount_dest, std::fs::Permissions::from_mode(0o755))
                    .map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to set permissions on mount destination {:?}: {}",
                            zt_mount_dest, e
                        )))
                    })?;
            }

            // Final verification - directory must exist for libcontainer
            if !zt_mount_dest.exists() {
                return Err(ProvisionError::Bundle(format!(
                    "Failed to create mount destination directory: {:?}",
                    zt_mount_dest
                )));
            }

            tracing::info!(
                "[ContainerProvisioner] Successfully created ZeroTier mount destination: {:?}",
                zt_mount_dest
            );

            // Additional verification: check that the path libcontainer will check actually exists
            // libcontainer uses: bundle_rootfs.join(dest.strip_prefix("/").unwrap_or(dest))
            let dest = "/var/lib/zerotier-one";
            let libcontainer_path = bundle_rootfs.join(dest.strip_prefix("/").unwrap_or(dest));
            if !libcontainer_path.exists() {
                tracing::warn!(
                    "[ContainerProvisioner] WARNING: libcontainer path check will fail: {:?}",
                    libcontainer_path
                );
                // Try to create it again using the exact path libcontainer will check
                std::fs::create_dir_all(&libcontainer_path).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create libcontainer path {:?}: {}",
                        libcontainer_path, e
                    )))
                })?;
            }
        }

        lifecycle::create_container(&container_id, &bundle_dir, &root_path).map_err(|e| {
            ProvisionError::Runtime(format!(
                "Failed to create container {}: {}",
                container_name, e
            ))
        })?;

        // 9. Start container
        // (root_path already defined in step 2)
        lifecycle::start_container(&root_path, &container_id).map_err(|e| {
            ProvisionError::Runtime(format!(
                "Failed to start container {}: {}",
                container_name, e
            ))
        })?;

        // 10. Create ContainerInfo
        let container_info = ContainerInfo {
            id: container_id.clone(),
            name: container_name.to_string(),
            container_id: container_id.clone(),
            order_index: component.order as usize, // Cast isize to usize
            state_path: self
                .container_manager
                .root_path()
                .join("state")
                .join(&container_id),
            bundle_path: bundle_dir.clone(),
        };

        tracing::info!(
            "[ContainerProvisioner] Successfully created and started container: {}",
            container_name
        );

        Ok(container_info)
    }

    /// Generate startContainer hook for loopback setup
    /// Returns hook JSON if shell/ip is available in rootfs, None otherwise
    ///
    /// This hook runs INSIDE the container's network namespace, so it can
    /// properly bring up the loopback interface without needing nsenter.
    #[cfg(target_os = "linux")]
    fn generate_loopback_hook(rootfs_path: &std::path::Path) -> Option<serde_json::Value> {
        use serde_json::json;

        let has_shell =
            rootfs_path.join("bin/sh").exists() || rootfs_path.join("bin/busybox").exists();
        let has_ip =
            rootfs_path.join("sbin/ip").exists() || rootfs_path.join("usr/sbin/ip").exists();

        if has_shell {
            // Use shell with fallback paths for ip command
            Some(json!([{
                "path": "/bin/sh",
                "args": ["sh", "-c", "/sbin/ip link set lo up 2>/dev/null || ip link set lo up 2>/dev/null || true"]
            }]))
        } else if has_ip {
            // Direct ip command if no shell available
            let ip_path = if rootfs_path.join("sbin/ip").exists() {
                "/sbin/ip"
            } else {
                "/usr/sbin/ip"
            };
            Some(json!([{
                "path": ip_path,
                "args": ["ip", "link", "set", "lo", "up"]
            }]))
        } else {
            None
        }
    }

    /// Generate OCI spec for K8s component with custom command arguments
    #[cfg(target_os = "linux")]
    fn generate_k8s_oci_spec(
        &self,
        config: &crate::rootless::config::ContainerConfig,
        _rootfs: &std::path::Path,
        bundle_path: &std::path::Path,
        custom_args: &[String],
        privileged: bool,
    ) -> Result<std::path::PathBuf, ProvisionError> {
        use serde_json::json;

        let spec_path = bundle_path.join("config.json");
        let bundle_rootfs = bundle_path.join("rootfs");

        // CRITICAL: Create log directories for K8s containers to capture stdout/stderr
        // This allows us to debug container crashes
        let log_dir = bundle_rootfs.join("var/log");
        std::fs::create_dir_all(&log_dir).map_err(|e| {
            ProvisionError::Io(std::io::Error::other(format!(
                "Failed to create log directory {:?}: {}",
                log_dir, e
            )))
        })?;
        
        // Set ownership to current user (maps to root inside container)
        #[cfg(target_os = "linux")]
        {
            use nix::unistd::{Gid, Uid};
            let host_uid = Uid::current();
            let host_gid = Gid::current();
            nix::unistd::chown(&log_dir, Some(host_uid), Some(host_gid)).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to set ownership on log directory {:?}: {}",
                    log_dir, e
                )))
            })?;
        }

        // Build environment variables
        let mut env = vec![
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            "TERM=xterm".to_string(),
            format!("CONTAINER_NAME={}", config.container_name),
            format!("CONTAINER_TYPE={}", config.container_type),
        ];

        for (key, value) in &config.environment {
            env.push(format!("{}={}", key, value));
        }

        // Build mounts
        // For privileged containers needing /dev/net/tun:
        // - Mount /dev as tmpfs (creates device nodes like /dev/null)
        // - Mount /dev/net as tmpfs (creates directory for TUN device)
        // - TUN device node is created via OCI linux.devices field (not bind mount)

        let mut mounts = Vec::new();

        // Add all volume bind mounts
        // For privileged containers, ensure bind mounts work correctly with user namespace
        // Use rprivate propagation (default) which works best with user namespaces
        for (host_path, container_path) in &config.volumes {
            // Verify source path exists before mounting (critical for bind mounts)
            if !std::path::Path::new(host_path).exists() {
                tracing::warn!(
                    "[ContainerProvisioner] WARNING: Bind mount source path does not exist: {}",
                    host_path
                );
            }

            // Check if source is a socket file (not a directory)
            // Also check if path ends with .sock as a fallback for socket detection
            #[cfg(unix)]
            let is_socket = {
                use std::os::unix::fs::FileTypeExt;
                let metadata_is_socket = std::path::Path::new(host_path)
                    .metadata()
                    .ok()
                    .map(|m| m.file_type().is_socket())
                    .unwrap_or(false);
                let path_looks_like_socket = host_path.ends_with(".sock") || container_path.ends_with(".sock");
                let result = metadata_is_socket || path_looks_like_socket;

                tracing::info!(
                    "[ContainerProvisioner] Socket detection for mount: host_path={}, container_path={}, metadata_is_socket={}, path_looks_like_socket={}, is_socket={}",
                    host_path, container_path, metadata_is_socket, path_looks_like_socket, result
                );

                result
            };
            #[cfg(not(unix))]
            let is_socket = false;

            let mount_options = if is_socket {
                // For socket files, use regular "bind" (not "rbind") - rbind is for directories
                // Socket files don't need propagation options like "rprivate" - they're just files
                vec!["bind", "rw"]
            } else {
                // For rootless containers (even if marked as privileged for capabilities),
                // use rbind without rprivate to avoid mount propagation issues in user namespaces
                // rprivate can cause "failed to prepare rootfs" errors in rootless mode
                vec!["rbind", "rw"]
            };

            // CRITICAL: Ensure mount destination directory exists in rootfs
            // libcontainer's prepare_rootfs() requires mount destinations to exist
            // For directories, create the parent directory; for files, ensure parent exists
            let mount_dest_path = bundle_rootfs.join(container_path.strip_prefix("/").unwrap_or(container_path));

            tracing::info!(
                "[ContainerProvisioner] Mount dest handling: container_path={}, mount_dest_path={:?}, is_socket={}, dest_exists={}",
                container_path, mount_dest_path, is_socket, mount_dest_path.exists()
            );

            if !is_socket {
                // For directory mounts, ensure the destination directory exists
                if !mount_dest_path.exists() {
                    tracing::info!(
                        "[ContainerProvisioner] Creating directory for NON-SOCKET mount: {:?}",
                        mount_dest_path
                    );
                    std::fs::create_dir_all(&mount_dest_path).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to create mount destination directory {:?}: {}",
                            mount_dest_path, e
                        )))
                    })?;
                    tracing::debug!(
                        "[ContainerProvisioner] Created mount destination directory: {:?}",
                        mount_dest_path
                    );
                }
            } else {
                // For socket/file mounts, only create the parent directory
                // DO NOT create the socket file itself - libcontainer will handle the bind mount
                tracing::info!(
                    "[ContainerProvisioner] Handling SOCKET mount - ensuring parent directory exists"
                );
                if let Some(parent) = mount_dest_path.parent() {
                    if !parent.exists() {
                        tracing::info!(
                            "[ContainerProvisioner] Creating parent directory for socket mount: {:?}",
                            parent
                        );
                        std::fs::create_dir_all(parent).map_err(|e| {
                            ProvisionError::Io(std::io::Error::other(format!(
                                "Failed to create mount destination parent directory {:?}: {}",
                                parent, e
                            )))
                        })?;
                    }
                }

                // DO NOT create the socket file - let libcontainer handle the bind mount
                tracing::info!(
                    "[ContainerProvisioner] Socket mount parent directory ready, libcontainer will create the bind mount at: {:?}",
                    mount_dest_path
                );
            }

            tracing::debug!(
                "[ContainerProvisioner] Adding bind mount: {} -> {} (options: {:?})",
                host_path,
                container_path,
                mount_options
            );

            mounts.push(json!({
                "destination": container_path,
                "type": "bind",
                "source": host_path,
                "options": mount_options
            }));
        }

        // NOTE: Standard mounts (proc, dev, sysfs, devpts) are NOT added for rootless containers
        // These can cause "failed to prepare rootfs" errors in user namespaces
        // The container rootfs from the image already has these directories
        // and libcontainer handles basic device nodes automatically
        tracing::debug!(
            "[ContainerProvisioner] Skipping proc/dev/sys mounts for rootless container compatibility"
        );
        mounts.push(json!({
            "destination": "/tmp",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "nodev", "size=1048576k"]
        }));

        // Build namespaces for rootless containers
        // User namespace is required by libcontainer for rootless containers
        // CRITICAL: PID namespace is NOT used for rootless containers (EPERM in rootless)
        // We use the host PID namespace instead, which is the standard approach for rootless containers

        // Omit network namespace for host networking (per 00-os-specific-rules: containers share host network).
        // Adding network ns (even with path to join host) causes EPERM in rootless; utility containers omit it and work.
        tracing::info!(
            "[ContainerProvisioner] Omitting network namespace for {} (host network - inherit host stack)",
            config.container_name
        );

        // CRITICAL: Privileged containers running as root must NOT use user namespace
        // User namespace isolation prevents TUN/TAP ioctl operations (TUNSETIFF fails with EPERM)
        // even with CAP_NET_ADMIN. ZeroTier requires initial user namespace for TUN device creation.
        let namespaces = if privileged && nix::unistd::Uid::current().as_raw() == 0 {
            vec![
                json!({"type": "ipc"}),
                json!({"type": "uts"}),
                json!({"type": "mount"}),
                // NO user namespace for privileged containers running as root
            ]
        } else {
            vec![
                json!({"type": "user"}), // Required for rootless containers
                json!({"type": "ipc"}),
                json!({"type": "uts"}),
                json!({"type": "mount"}),
                // Network namespace omitted for host networking - avoids EPERM in rootless
            ]
        };

        // Build UID/GID mappings for rootless containers
        // For rootless containers, we need two mappings:
        // 1. Map host UID/GID to container 0 (for root user in container)
        // 2. Map subuid/subgid range starting at 1 (for other users in container)
        // CRITICAL: Privileged containers running as root have NO user namespace,
        // so NO UID/GID mappings are needed (empty vectors)
        #[cfg(target_os = "linux")]
        use nix::unistd::{Gid, Uid};
        #[cfg(target_os = "linux")]
        let host_uid = Uid::current().as_raw();
        #[cfg(target_os = "linux")]
        let host_gid = Gid::current().as_raw();

        #[cfg(target_os = "linux")]
        let (uid_mappings, gid_mappings) = if privileged && host_uid == 0 {
            // Privileged containers running as root: NO user namespace, NO UID/GID mappings
            (vec![], vec![])
        } else {
            // Parse subuid/subgid ranges for the current user
            let (subuid_start, subuid_size) = Self::parse_subuid_range().unwrap_or((host_uid, 1));
            let (subgid_start, subgid_size) = Self::parse_subgid_range().unwrap_or((host_gid, 1));

            // Build UID mappings: host UID -> container 0
            let uid_maps = vec![json!({
                "containerID": 0,
                "hostID": host_uid,
                "size": 1
            })];

            // Build GID mappings: host GID -> container 0
            let gid_maps = vec![json!({
                "containerID": 0,
                "hostID": host_gid,
                "size": 1
            })];

            // Silence unused variable warnings
            let _ = (subuid_start, subuid_size, subgid_start, subgid_size);

            (uid_maps, gid_maps)
        };

        #[cfg(not(target_os = "linux"))]
        let uid_mappings: Vec<serde_json::Value> = vec![];
        #[cfg(not(target_os = "linux"))]
        let gid_mappings: Vec<serde_json::Value> = vec![];

        // Build resources
        let mut resources = json!({});
        if let Some(cpu_limit) = config.cpu_limit {
            resources["cpu"] = json!({
                "shares": cpu_limit * 1024,
                "quota": cpu_limit * 100000,
                "period": 100000
            });
        }
        if let Some(memory_mb) = config.memory_limit_mb {
            resources["memory"] = json!({
                "limit": memory_mb * 1024 * 1024,
                "swap": memory_mb * 1024 * 1024
            });
        }

        // Detect if systemd is available for cgroup management
        // When systemd is available, omit cgroupsPath to let systemd automatically
        // create cgroups under the user's delegated slice (allows rootless containers).
        // When systemd is not available, specify cgroupsPath explicitly.
        let use_systemd = std::path::Path::new("/run/systemd/system").exists()
            || std::path::Path::new("/sys/fs/cgroup/systemd").exists()
            || std::process::Command::new("systemctl")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

        tracing::debug!(
            "[ContainerProvisioner] Systemd detection for {}: use_systemd={}, will {} cgroupsPath",
            config.container_name,
            use_systemd,
            if use_systemd { "omit" } else { "include" }
        );

        // Resolve binary path to absolute path if first arg is not already absolute
        // This ensures libcontainer can execute the binary even if PATH resolution fails
        //
        // CRITICAL: Kubernetes official images (registry.k8s.io/*) use go-runner as entrypoint.
        // The go-runner binary expects the first argument to be the component name (e.g., "kube-apiserver").
        // We need to check for go-runner first and use it if present.
        let mut resolved_args = custom_args.to_vec();
        if !resolved_args.is_empty() && !resolved_args[0].starts_with('/') {
            let binary_name = resolved_args[0].clone();

            // Check for go-runner first (used by Kubernetes official images)
            let go_runner_path = bundle_path.join("rootfs").join("go-runner");
            if go_runner_path.exists() && go_runner_path.is_file() {
                // Use go-runner as executable, keep original args (first arg is component name)
                resolved_args.insert(0, "/go-runner".to_string());
                tracing::info!(
                    "[ContainerProvisioner] Using go-runner entrypoint for {}: args={:?}",
                    binary_name,
                    resolved_args
                );
            } else {
                // Standard binary resolution: look for binary in common locations
                let binary_paths = vec![
                    bundle_path
                        .join("rootfs")
                        .join("usr/local/bin")
                        .join(&binary_name),
                    bundle_path
                        .join("rootfs")
                        .join("usr/bin")
                        .join(&binary_name),
                    bundle_path.join("rootfs").join("bin").join(&binary_name),
                    bundle_path.join("rootfs").join("sbin").join(&binary_name),
                    bundle_path
                        .join("rootfs")
                        .join("usr/sbin")
                        .join(&binary_name),
                ];

                let mut found_binary = false;
                for binary_path in &binary_paths {
                    if binary_path.exists() && binary_path.is_file() {
                        // Convert to absolute path within container rootfs
                        if let Ok(relative_path) =
                            binary_path.strip_prefix(&bundle_path.join("rootfs"))
                        {
                            resolved_args[0] = format!("/{}", relative_path.to_string_lossy());
                            tracing::debug!(
                                "[ContainerProvisioner] Resolved binary path for {}: {}",
                                binary_name,
                                resolved_args[0]
                            );
                            found_binary = true;
                            break;
                        }
                    }
                }

                if !found_binary {
                    tracing::warn!(
                        "[ContainerProvisioner] Binary '{}' not found in standard locations and go-runner not present. \
                        Container may fail to start. Checked paths: {:?}",
                        binary_name,
                        binary_paths
                    );
                }
            }
        }
        
        // CRITICAL FIX FOR EACCES: Execute command directly without wrapper script
        // The wrapper script approach causes EACCES because libcontainer's execve fails
        // when trying to execute /bin/busybox or /bin/sh. By executing the command directly,
        // we avoid the wrapper script complexity and potential path resolution issues.
        // 
        // For logging, we'll rely on libcontainer's stdio redirection or handle it differently.
        // The key is to use the resolved_args directly as the process args.
        
        // CRITICAL: Ensure the main executable is accessible and has correct permissions
        // This must happen AFTER all rootfs modifications (busybox injection, etc.)
        // CRITICAL FIX: Copy executable to /bin/ for better path resolution in user namespace
        if !resolved_args.is_empty() {
            let original_binary = bundle_rootfs.join(resolved_args[0].trim_start_matches('/'));
            let bin_dir = bundle_rootfs.join("bin");
            let bin_binary = bin_dir.join(
                original_binary
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("executable")
            );
            
            // Ensure /bin directory exists
            if !bin_dir.exists() {
                std::fs::create_dir_all(&bin_dir).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create /bin directory: {}",
                        e
                    )))
                })?;
            }
            
            if original_binary.exists() {
                // Copy executable to /bin/ for better path resolution
                // This avoids potential path resolution issues in user namespace with chroot
                if bin_binary != original_binary {
                    std::fs::copy(&original_binary, &bin_binary).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to copy executable from {} to {}: {}",
                            original_binary.display(),
                            bin_binary.display(),
                            e
                        )))
                    })?;
                    tracing::info!(
                        "[ContainerProvisioner] Copied executable from {} to {} for better path resolution",
                        original_binary.display(),
                        bin_binary.display()
                    );
                }
                
                // Set executable permissions on both original and copied binary
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o755);
                
                if let Err(e) = std::fs::set_permissions(&original_binary, perms.clone()) {
                    tracing::warn!(
                        "[ContainerProvisioner] Failed to set permissions on {}: {}",
                        original_binary.display(),
                        e
                    );
                }
                
                if bin_binary != original_binary {
                    if let Err(e) = std::fs::set_permissions(&bin_binary, perms) {
                        tracing::warn!(
                            "[ContainerProvisioner] Failed to set permissions on {}: {}",
                            bin_binary.display(),
                            e
                        );
                    }
                }
                
                tracing::info!(
                    "[ContainerProvisioner] Ensured executable permissions on: {}",
                    original_binary.display()
                );
                
                // CRITICAL: Also ensure all parent directories are traversable
                // This is required for path resolution in user namespaces after chroot/pivot_root
                let mut current_path = bin_binary.parent();
                while let Some(parent) = current_path {
                    if parent == bundle_rootfs || parent.parent().is_none() {
                        break;
                    }
                    if let Ok(meta) = std::fs::metadata(parent) {
                        use std::os::unix::fs::PermissionsExt;
                        let mut perms = meta.permissions();
                        let mode = perms.mode();
                        if mode & 0o111 == 0 {
                            perms.set_mode(mode | 0o111);
                            let _ = std::fs::set_permissions(parent, perms);
                        }
                    }
                    current_path = parent.parent();
                }
            } else {
                tracing::error!(
                    "[ContainerProvisioner] CRITICAL: Main executable not found: {} (resolved from {})",
                    original_binary.display(),
                    resolved_args[0]
                );
            }
        }
        
        // Final permission fix pass - ensures everything is correct
        self.fix_rootfs_permissions(&bundle_rootfs)?;
        
        // CRITICAL FIX: Use /bin/ path for executable if we copied it there
        // This improves path resolution in user namespace with chroot
        let mut final_args = resolved_args;
        if !final_args.is_empty() {
            let original_path = final_args[0].clone(); // Clone to avoid borrow checker issue
            tracing::debug!(
                "[ContainerProvisioner] Checking if we should use /bin/ path for: {}",
                original_path
            );
            
            // Check if we copied the executable to /bin/ earlier
            let bin_name = std::path::Path::new(&original_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            
            if !bin_name.is_empty() {
                let bin_path = format!("/bin/{}", bin_name);
                let bin_binary = bundle_rootfs.join(bin_path.trim_start_matches('/'));
                
                tracing::debug!(
                    "[ContainerProvisioner] Checking if /bin/ copy exists: {}",
                    bin_binary.display()
                );
                
                if bin_binary.exists() {
                    final_args[0] = bin_path.clone();
                    tracing::info!(
                        "[ContainerProvisioner] Using /bin/ path for executable: {} (was {})",
                        bin_path,
                        original_path
                    );
                } else {
                    tracing::warn!(
                        "[ContainerProvisioner] /bin/ copy not found at {}, using original path: {}",
                        bin_binary.display(),
                        original_path
                    );
                }
            }
        }
        
        // CRITICAL FIX: Use shell wrapper to work around EACCES in libcontainer's init process
        // The issue is that libcontainer's init process can't directly execve the Go binary
        // in user namespace. Using busybox sh to exec the command works around this.
        // busybox is already injected for etcd containers, so this should work.
        let mut process_args = final_args.clone();
        let busybox_path = bundle_rootfs.join("bin/busybox");
        let busybox_exists = busybox_path.exists();
        
        tracing::debug!(
            "[ContainerProvisioner] Checking busybox for {}: path={}, exists={}",
            config.container_name,
            busybox_path.display(),
            busybox_exists
        );
        
        if !final_args.is_empty() && busybox_exists {
            // CRITICAL FIX: Use /bin/sh directly (which is busybox copied as sh)
            // This avoids the need for busybox to exec sh, which may cause EACCES
            // The /bin/sh binary is a direct copy of busybox, so it should work
            let sh_path = bundle_rootfs.join("bin/sh");
            let use_sh_directly = sh_path.exists();
            
            let exec_cmd = format!("exec {}", final_args.iter().map(|a| {
                // Escape arguments for shell - use single quotes for safety
                if a.contains(' ') || a.contains('"') || a.contains("'") || a.contains('$') {
                    // Use single quotes and escape single quotes within
                    format!("'{}'", a.replace("'", "'\"'\"'"))
                } else {
                    a.clone()
                }
            }).collect::<Vec<_>>().join(" "));
            
            if use_sh_directly {
                // Use /bin/sh directly (busybox copy)
                process_args = vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    exec_cmd,
                ];
                tracing::info!(
                    "[ContainerProvisioner] Using /bin/sh wrapper (busybox) for {} to work around EACCES: {:?}",
                    config.container_name,
                    process_args
                );
            } else {
                // Fallback to busybox sh
                process_args = vec![
                    "/bin/busybox".to_string(),
                    "sh".to_string(),
                    "-c".to_string(),
                    exec_cmd,
                ];
                tracing::info!(
                    "[ContainerProvisioner] Using busybox sh wrapper for {} to work around EACCES: {:?}",
                    config.container_name,
                    process_args
                );
            }
        } else {
            if !busybox_exists {
                tracing::warn!(
                    "[ContainerProvisioner] busybox not found at {}, using direct execution (may fail with EACCES)",
                    busybox_path.display()
                );
            }
            tracing::info!(
                "[ContainerProvisioner] Using direct command execution for {}: {:?}",
                config.container_name,
                final_args
            );
        }

        // Build OCI spec
        let mut spec = json!({
            "ociVersion": "1.0.2",
            "process": {
                "terminal": false,
                "user": {
                    "uid": 0,
                    "gid": 0
                },
                "env": env,
                "cwd": "/",
                "args": process_args, // Use shell wrapper to work around EACCES
                // Disable AppArmor for rootless containers (like utility containers)
                // This may be necessary for user namespace execution to work correctly
                "apparmorProfile": null,
                "capabilities": {
                    "bounding": if privileged {
                        // Privileged containers (ZeroTier) get full capabilities including NET_ADMIN
                        vec![
                            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                            "CAP_NET_RAW", "CAP_NET_ADMIN", "CAP_SYS_CHROOT", "CAP_MKNOD",
                            "CAP_AUDIT_WRITE", "CAP_SETFCAP", "CAP_SYS_ADMIN", "CAP_SYS_TIME"
                        ]
                    } else {
                        // Non-privileged (rootless) containers get minimal capabilities
                        // Many capabilities are not available in rootless user namespaces
                        // Using only capabilities that are safe and available for rootless containers
                        vec![
                            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                            "CAP_AUDIT_WRITE"
                        ]
                    },
                    "effective": if privileged {
                        // Privileged containers (ZeroTier) get full capabilities including NET_ADMIN
                        vec![
                            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                            "CAP_NET_RAW", "CAP_NET_ADMIN", "CAP_SYS_CHROOT", "CAP_MKNOD",
                            "CAP_AUDIT_WRITE", "CAP_SETFCAP", "CAP_SYS_ADMIN", "CAP_SYS_TIME"
                        ]
                    } else {
                        // Non-privileged (rootless) containers get minimal capabilities
                        vec![
                            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                            "CAP_AUDIT_WRITE"
                        ]
                    },
                    "inheritable": if privileged {
                        // Privileged containers (ZeroTier) get full capabilities including NET_ADMIN
                        vec![
                            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                            "CAP_NET_RAW", "CAP_NET_ADMIN", "CAP_SYS_CHROOT", "CAP_MKNOD",
                            "CAP_AUDIT_WRITE", "CAP_SETFCAP", "CAP_SYS_ADMIN", "CAP_SYS_TIME"
                        ]
                    } else {
                        // Non-privileged (rootless) containers get minimal capabilities
                        vec![
                            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                            "CAP_AUDIT_WRITE"
                        ]
                    },
                    "permitted": if privileged {
                        // Privileged containers (ZeroTier) get full capabilities including NET_ADMIN
                        vec![
                            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                            "CAP_NET_RAW", "CAP_NET_ADMIN", "CAP_SYS_CHROOT", "CAP_MKNOD",
                            "CAP_AUDIT_WRITE", "CAP_SETFCAP", "CAP_SYS_ADMIN", "CAP_SYS_TIME"
                        ]
                    } else {
                        // Non-privileged (rootless) containers get minimal capabilities
                        vec![
                            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
                            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE",
                            "CAP_AUDIT_WRITE"
                        ]
                    }
                }
            },
            "root": {
                "path": "rootfs",
                "readonly": false
            },
            "mounts": mounts,
            "linux": {
                "namespaces": namespaces,
                "uidMappings": uid_mappings,
                "gidMappings": gid_mappings,
                "resources": resources,
                // Disable seccomp for rootless containers (like utility containers)
                // This may be necessary for user namespace execution to work correctly
                "seccomp": null,
                // Add TUN device node via linux.devices for privileged containers
                // This creates /dev/net/tun device node directly (major 10, minor 200)
                // This avoids mount ordering issues with bind mounts
                "devices": if privileged {
                    vec![json!({
                        "path": "/dev/net/tun",
                        "type": "c",
                        "major": 10,
                        "minor": 200,
                        "fileMode": 420,  // 0644 in decimal
                        "uid": 0,
                        "gid": 0
                    })]
                } else {
                    vec![]
                }
            }
        });

        // CRITICAL: Add startContainer hook to bring up loopback interface
        // This ensures lo is UP when container starts, required for zerotier-cli
        // to connect to daemon on 127.0.0.1:9993
        //
        // IMPORTANT: Use startContainer hook (not prestart) because:
        // - startContainer runs INSIDE the container's network namespace
        // - prestart runs in the runtime namespace and cannot access container's network
        // - This avoids the "Operation not permitted" error from nsenter in rootless containers
        //
        // IMPORTANT: Add hooks AFTER building the spec, but BEFORE writing to file
        // This ensures hooks are not overwritten by cgroupsPath modifications
        let rootfs_path = bundle_path.join("rootfs");

        if let Some(loopback_hook) = Self::generate_loopback_hook(&rootfs_path) {
            if let Some(linux) = spec.get_mut("linux") {
                if let Some(linux_obj) = linux.as_object_mut() {
                    // Add hooks object if it doesn't exist
                    if !linux_obj.contains_key("hooks") {
                        linux_obj.insert("hooks".to_string(), json!({}));
                    }

                    // Get or create hooks object
                    if let Some(hooks) = linux_obj.get_mut("hooks") {
                        if let Some(hooks_obj) = hooks.as_object_mut() {
                            // Add startContainer hook (runs inside container namespace)
                            hooks_obj.insert("startContainer".to_string(), loopback_hook);
                            tracing::debug!(
                                "[ContainerProvisioner] Added startContainer hook for loopback setup on {}",
                                config.container_name
                            );
                        }
                    }
                }
            }
        } else {
            tracing::debug!(
                "[ContainerProvisioner] Skipping loopback hook for {} - no shell or ip command in rootfs",
                config.container_name
            );
        }

        // Conditionally add cgroupsPath only when systemd is not available
        // When systemd is available, omit cgroupsPath to let systemd automatically
        // create cgroups under the user's delegated slice (allows rootless containers).
        if !use_systemd {
            if let Some(linux) = spec.get_mut("linux") {
                if let Some(linux_obj) = linux.as_object_mut() {
                    linux_obj.insert(
                        "cgroupsPath".to_string(),
                        json!(format!("/{}/{}", "4lock-agent", config.container_name)),
                    );
                }
            }
        }

        // Write spec to file
        let spec_json = serde_json::to_string_pretty(&spec)
            .map_err(|e| ProvisionError::Bundle(format!("Failed to serialize OCI spec: {}", e)))?;

        std::fs::write(&spec_path, spec_json).map_err(ProvisionError::Io)?;

        tracing::info!(
            "[ContainerProvisioner] Generated OCI spec for {} at {:?}",
            config.container_name,
            spec_path
        );

        Ok(spec_path)
    }

    /// Recursively copy directory from source to destination
    ///
    /// Preserves symlinks, special files, and directory structure.
    /// This is critical for OCI container rootfs which may contain
    /// symlinks that libcontainer expects to be valid.
    #[cfg(target_os = "linux")]
    fn copy_dir_recursive(
        &self,
        src: &std::path::Path,
        dst: &std::path::Path,
    ) -> Result<(), ProvisionError> {
        use std::fs;
        use std::os::unix::fs::symlink;

        if !src.is_dir() {
            return Err(ProvisionError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Source path is not a directory: {:?}", src),
            )));
        }

        // Create destination directory
        fs::create_dir_all(dst).map_err(ProvisionError::Io)?;

        // Read source directory entries
        let entries = fs::read_dir(src).map_err(|e| {
            ProvisionError::Io(std::io::Error::other(format!(
                "Failed to read directory {:?}: {}",
                src, e
            )))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to read directory entry in {:?}: {}",
                    src, e
                )))
            })?;
            let path = entry.path();
            let file_name = entry.file_name();
            let dst_path = dst.join(&file_name);

            // Use symlink_metadata to avoid following symlinks
            // This allows us to distinguish between directories, files, and symlinks
            let metadata = fs::symlink_metadata(&path).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to get metadata for {:?}: {}",
                    path, e
                )))
            })?;

            if metadata.is_dir() {
                // Before recursively copying subdirectory, check if destination exists
                // as something other than a directory (from previous failed copy)
                if dst_path.exists() {
                    let dst_meta = fs::symlink_metadata(&dst_path).ok();
                    if let Some(m) = dst_meta {
                        if !m.is_dir() {
                            // Destination exists but is not a directory - remove it
                            if m.file_type().is_symlink() || m.is_file() {
                                fs::remove_file(&dst_path).map_err(|e| {
                                    ProvisionError::Io(std::io::Error::other(format!(
                                        "Failed to remove existing file/symlink {:?} before directory copy: {}",
                                        dst_path, e
                                    )))
                                })?;
                            }
                        }
                    }
                }
                // Recursively copy subdirectory
                self.copy_dir_recursive(&path, &dst_path)?;
            } else if metadata.file_type().is_symlink() {
                // Preserve symlinks instead of copying their targets
                // This is critical for OCI containers which often use symlinks
                let link_target = fs::read_link(&path).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to read symlink {:?}: {}",
                        path, e
                    )))
                })?;

                // Remove destination if it exists (might be from previous failed copy)
                // Handle both files AND directories that might exist at the destination
                if dst_path.exists() || dst_path.symlink_metadata().is_ok() {
                    let dst_meta = fs::symlink_metadata(&dst_path).ok();
                    if let Some(m) = dst_meta {
                        if m.is_dir() {
                            // Destination is a directory - remove it recursively
                            fs::remove_dir_all(&dst_path).map_err(|e| {
                                ProvisionError::Io(std::io::Error::other(format!(
                                    "Failed to remove existing directory {:?} for symlink: {}",
                                    dst_path, e
                                )))
                            })?;
                        } else {
                            // Destination is a file or symlink - remove it
                            fs::remove_file(&dst_path).map_err(|e| {
                                ProvisionError::Io(std::io::Error::other(format!(
                                    "Failed to remove existing file {:?} for symlink: {}",
                                    dst_path, e
                                )))
                            })?;
                        }
                    }
                }

                symlink(&link_target, &dst_path).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create symlink {:?} -> {:?}: {}",
                        dst_path, link_target, e
                    )))
                })?;
            } else {
                // Regular file, device node, FIFO, or socket - copy it
                // Note: Device nodes and special files will be copied as regular files
                // which is acceptable for most container images (they get recreated at runtime)

                // Remove destination if it exists as something other than a regular file
                if dst_path.exists() {
                    let dst_meta = fs::symlink_metadata(&dst_path).ok();
                    if let Some(m) = dst_meta {
                        if m.is_dir() {
                            // Destination is a directory - remove it recursively
                            fs::remove_dir_all(&dst_path).map_err(|e| {
                                ProvisionError::Io(std::io::Error::other(format!(
                                    "Failed to remove existing directory {:?} for file copy: {}",
                                    dst_path, e
                                )))
                            })?;
                        }
                        // For files and symlinks, fs::copy will overwrite them
                    }
                }

                fs::copy(&path, &dst_path).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to copy file {:?} to {:?}: {}",
                        path, dst_path, e
                    )))
                })?;

                // Preserve file permissions (important for executables and special files)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(src_meta) = fs::metadata(&path) {
                        if let Ok(dst_meta) = fs::metadata(&dst_path) {
                            let mut perms = dst_meta.permissions();
                            perms.set_mode(src_meta.permissions().mode());
                            let _ = fs::set_permissions(&dst_path, perms);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Write OCI config.json for a generic container run (ContainerRunSpec).
    #[cfg(target_os = "linux")]
    fn write_oci_spec_for_run(
        &self,
        spec_path: &std::path::Path,
        spec: &crate::intent::ContainerRunSpec,
    ) -> Result<(), ProvisionError> {
        use serde_json::json;

        let args: Vec<String> = spec
            .command
            .clone()
            .unwrap_or_default()
            .into_iter()
            .chain(spec.args.clone().unwrap_or_default())
            .collect();
        let args: Vec<String> = if args.is_empty() {
            vec!["/bin/sh".to_string()]
        } else {
            args
        };

        let mut env_vars = vec![
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            "TERM=xterm".to_string(),
        ];
        if let Some(env) = &spec.env {
            env_vars.extend(env.clone());
        }

        let mut oci_mounts = Vec::new();
        if let Some(mounts) = &spec.mounts {
            for m in mounts {
                let options: Vec<String> = if m.read_only {
                    vec!["ro".to_string(), "rbind".to_string()]
                } else {
                    vec!["rw".to_string(), "rbind".to_string()]
                };
                oci_mounts.push(json!({
                    "destination": m.container_path,
                    "type": "bind",
                    "source": m.host_path,
                    "options": options
                }));
            }
        }
        oci_mounts.push(json!({
            "destination": "/tmp",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "nodev", "size=1048576k"]
        }));

        let (namespaces, uid_mappings, gid_mappings, capabilities): (
            Vec<serde_json::Value>,
            Vec<serde_json::Value>,
            Vec<serde_json::Value>,
            serde_json::Value,
        ) = if spec.privileged && nix::unistd::Uid::current().as_raw() == 0 {
            (
                vec![
                    json!({"type": "ipc"}),
                    json!({"type": "uts"}),
                    json!({"type": "mount"}),
                ],
                vec![],
                vec![],
                json!({
                    "bounding": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "effective": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "inheritable": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "permitted": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"]
                }),
            )
        } else {
            let uid_mappings = vec![json!({
                "containerID": 0,
                "hostID": nix::unistd::Uid::current().as_raw(),
                "size": 1
            })];
            let gid_mappings = vec![json!({
                "containerID": 0,
                "hostID": nix::unistd::Gid::current().as_raw(),
                "size": 1
            })];
            (
                vec![
                    json!({"type": "user"}),
                    json!({"type": "ipc"}),
                    json!({"type": "uts"}),
                    json!({"type": "mount"}),
                ],
                uid_mappings,
                gid_mappings,
                json!({
                    "bounding": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "effective": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "inheritable": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "permitted": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"]
                }),
            )
        };

        let oci = json!({
            "ociVersion": "1.0.2",
            "process": {
                "terminal": false,
                "user": { "uid": 0, "gid": 0 },
                "env": env_vars,
                "cwd": "/",
                "args": args,
                "apparmorProfile": null,
                "capabilities": capabilities
            },
            "root": { "path": "rootfs", "readonly": false },
            "mounts": oci_mounts,
            "linux": {
                "namespaces": namespaces,
                "uidMappings": uid_mappings,
                "gidMappings": gid_mappings,
                "resources": {},
                "seccomp": null
            },
            "annotations": {},
            "labels": {}
        });

        let json = serde_json::to_string_pretty(&oci)
            .map_err(|e| ProvisionError::Config(format!("OCI spec serialize: {}", e)))?;
        std::fs::write(spec_path, json).map_err(ProvisionError::Io)?;
        Ok(())
    }

    /// Recursively chown all files and directories in rootfs to current user's UID/GID
    ///
    /// Chown all files in rootfs to the current user's UID/GID (maps to container 0:0).
    /// This simplifies UID/GID mappings by requiring only the root mapping.
    /// Note: This is a workaround for a libcontainer issue where multiple
    /// UID/GID mappings cause "failed to prepare rootfs" errors during container
    /// initialization. By chowning all files to the current user's UID/GID (which
    /// maps to container UID 0 via the user namespace), we can use only the root
    /// mapping (host UID -> container 0) instead of multiple mappings, which works
    /// reliably (as proven by utility containers).
    ///
    /// This function recursively walks the rootfs and changes ownership of all
    /// files and directories to the current user's UID/GID, which will map to
    /// container UID 0/GID 0 in the user namespace.
    #[cfg(target_os = "linux")]
    fn chown_rootfs_to_uid0(&self, rootfs_path: &std::path::Path) -> Result<(), ProvisionError> {
        use nix::libc::{c_char, chown};
        use nix::unistd::{Gid, Uid};

        // Get current user's UID/GID (which maps to container UID 0/GID 0)
        let uid = Uid::current();
        let gid = Gid::current();

        tracing::info!(
            "[ContainerProvisioner] Chowning all files in rootfs to UID {}/GID {} (maps to container 0/0): {:?}",
            uid.as_raw(),
            gid.as_raw(),
            rootfs_path
        );

        // Recursively walk the directory tree
        fn chown_recursive(
            path: &std::path::Path,
            uid: Uid,
            gid: Gid,
        ) -> Result<(), std::io::Error> {
            use std::fs;

            // Chown the current path
            // Note: chown may fail for some special files, but we continue anyway
            // Chown the current path
            // Note: chown may fail for some special files, but we continue anyway
            let path_cstr = std::ffi::CString::new(path.to_string_lossy().as_ref())
                .map_err(|e| std::io::Error::other(format!("Invalid path: {}", e)))?;
            unsafe {
                let _ = chown(
                    path_cstr.as_ptr() as *const c_char,
                    uid.as_raw(),
                    gid.as_raw(),
                );
            }

            // Get metadata to check if it's a directory
            let metadata = fs::symlink_metadata(path)?;

            if metadata.is_dir() {
                // Recursively process directory entries
                let entries = fs::read_dir(path)?;
                for entry in entries {
                    let entry = entry?;
                    let entry_path = entry.path();
                    chown_recursive(&entry_path, uid, gid)?;
                }
            }

            Ok(())
        }

        chown_recursive(rootfs_path, uid, gid).map_err(|e| {
            ProvisionError::Io(std::io::Error::other(format!(
                "Failed to chown rootfs at {:?}: {}",
                rootfs_path, e
            )))
        })?;

        tracing::info!("[ContainerProvisioner] Successfully chowned rootfs to UID 0/GID 0");

        Ok(())
    }

    /// Fix permissions on rootfs to ensure binaries have execute permissions
    ///
    /// After copying rootfs from cached images, permissions may be incorrect.
    /// This function ensures that binary files have execute permissions.
    #[cfg(target_os = "linux")]
    fn fix_rootfs_permissions(&self, rootfs_path: &std::path::Path) -> Result<(), ProvisionError> {
        use std::os::unix::fs::PermissionsExt;

        /// Check if a file should be executable based on its content and location
        fn should_be_executable(path: &std::path::Path) -> bool {
            // Check if file is in standard binary directories
            let path_str = path.to_string_lossy();
            let binary_dir_patterns = [
                "/bin/",
                "/sbin/",
                "/usr/bin/",
                "/usr/sbin/",
                "/usr/local/bin/",
                "/usr/local/sbin/",
            ];
            if binary_dir_patterns
                .iter()
                .any(|pattern| path_str.contains(pattern))
            {
                return true;
            }

            // Check file content for ELF magic bytes or shebang
            if let Ok(mut file) = std::fs::File::open(path) {
                use std::io::Read;
                let mut buffer = [0u8; 4];
                if file.read_exact(&mut buffer).is_ok() {
                    // Check for ELF magic bytes: \x7fELF
                    if buffer == [0x7f, 0x45, 0x4c, 0x46] {
                        return true;
                    }
                    // Check for shebang: #!
                    if buffer[0..2] == [0x23, 0x21] {
                        return true;
                    }
                }
            }

            false
        }

        fn fix_permissions_recursive(path: &std::path::Path) -> std::io::Result<()> {
            let metadata = std::fs::symlink_metadata(path)?;

            // Don't modify symlinks
            if metadata.file_type().is_symlink() {
                return Ok(());
            }

            let mut perms = metadata.permissions();
            let mode = perms.mode();

            if metadata.is_dir() {
                // CRITICAL: In user namespaces, directories must be fully traversable
                // Set to 0o755 (rwxr-xr-x) to ensure execute permission for all
                // This is necessary for user namespace permission checks
                if mode != 0o755 {
                    perms.set_mode(0o755);
                    std::fs::set_permissions(path, perms)?;
                }

                // Recurse into directory
                for entry in std::fs::read_dir(path)? {
                    let entry = entry?;
                    fix_permissions_recursive(&entry.path())?;
                }
            } else {
                // For files: check if it should be executable
                if should_be_executable(path) {
                    // CRITICAL: In user namespaces, permission checks use mapped host UID/GID
                    // The kernel checks if the mapped host UID can execute the file
                    // Since container UID 0 maps to host UID 1000, and file is owned by UID 1000,
                    // we need to ensure the file is executable by owner (UID 1000)
                    // However, user namespace permission checks can be stricter, so we ensure
                    // execute permission for owner, group, and others (0o755)
                    // This ensures the file is executable regardless of how the permission check is performed
                    perms.set_mode(0o755);
                    std::fs::set_permissions(path, perms)?;

                    // Double-check: verify the file is actually executable after setting permissions
                    // This helps catch any filesystem-level issues
                    let verify_meta = std::fs::metadata(path)?;
                    let verify_perms = verify_meta.permissions();
                    let verify_mode = verify_perms.mode();
                    if verify_mode & 0o111 == 0 {
                        tracing::warn!(
                            "[ContainerProvisioner] WARNING: Failed to set execute permission on {:?} (mode: {:o})",
                            path,
                            verify_mode
                        );
                    }
                } else {
                    // Regular files just need read permission
                    // Ensure at least 0o644 (rw-r--r--) for user namespace compatibility
                    if mode & 0o444 != 0o444 {
                        perms.set_mode(0o644);
                        std::fs::set_permissions(path, perms)?;
                    }
                }
            }

            Ok(())
        }

        tracing::info!(
            "[ContainerProvisioner] Fixing permissions on rootfs: {:?}",
            rootfs_path
        );

        fix_permissions_recursive(rootfs_path).map_err(|e| {
            ProvisionError::Io(std::io::Error::other(format!(
                "Failed to fix permissions on rootfs at {:?}: {}",
                rootfs_path, e
            )))
        })?;

        tracing::debug!("[ContainerProvisioner] Successfully fixed rootfs permissions");

        Ok(())
    }

    /// Validate and ensure rootfs has essential directory structure
    ///
    /// libcontainer requires certain directories to exist in the rootfs
    /// even if they're later mounted. This ensures the rootfs is in a valid state.
    #[cfg(target_os = "linux")]
    fn validate_rootfs_structure(
        &self,
        rootfs_path: &std::path::Path,
    ) -> Result<(), ProvisionError> {
        use std::fs;

        tracing::debug!(
            "[ContainerProvisioner] Validating rootfs structure at {:?}",
            rootfs_path
        );

        // Essential directories that libcontainer expects to exist
        // These are required even if they're later mounted as tmpfs or proc
        // /dev/pts must exist for setup_ptmx() to create /dev/ptmx symlink
        // /dev/net must exist for privileged containers that need /dev/net/tun bind mount
        let essential_dirs = vec![
            "bin",
            "sbin",
            "usr/bin",
            "usr/sbin",
            "usr/local/bin",
            "etc",
            "proc",
            "sys",
            "dev",
            "dev/pts",
            "dev/net", // Required for /dev/net/tun bind mount in privileged containers
            "tmp",
            "var",
            "root",
            "lib",
            "lib64",
            "usr/lib",
            "usr/lib64",
        ];

        let mut created_dirs = Vec::new();
        for dir in essential_dirs {
            let dir_path = rootfs_path.join(dir);
            if !dir_path.exists() {
                fs::create_dir_all(&dir_path).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create essential directory {:?}: {}",
                        dir_path, e
                    )))
                })?;
                created_dirs.push(dir);
            }
        }

        if !created_dirs.is_empty() {
            tracing::info!(
                "[ContainerProvisioner] Created missing essential directories: {:?}",
                created_dirs
            );
        }

        // Ensure /etc/passwd exists (required for user namespace)
        let etc_passwd = rootfs_path.join("etc/passwd");
        if !etc_passwd.exists() {
            fs::write(&etc_passwd, "root:x:0:0:root:/root:/bin/sh\n").map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create /etc/passwd: {}",
                    e
                )))
            })?;
            tracing::debug!("[ContainerProvisioner] Created /etc/passwd");
        }

        // Ensure /etc/group exists
        let etc_group = rootfs_path.join("etc/group");
        if !etc_group.exists() {
            fs::write(&etc_group, "root:x:0:\n").map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create /etc/group: {}",
                    e
                )))
            })?;
            tracing::debug!("[ContainerProvisioner] Created /etc/group");
        }

        // Ensure /etc/hosts exists
        let etc_hosts = rootfs_path.join("etc/hosts");
        if !etc_hosts.exists() {
            fs::write(&etc_hosts, "127.0.0.1\tlocalhost\n::1\tlocalhost\n").map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create /etc/hosts: {}",
                    e
                )))
            })?;
            tracing::debug!("[ContainerProvisioner] Created /etc/hosts");
        }

        // Ensure /dev directory has basic structure
        // libcontainer may need /dev to exist and be accessible during rootfs preparation
        // Even though devices are mounted at runtime, the directory must be valid
        let dev_dir = rootfs_path.join("dev");
        if dev_dir.exists() && dev_dir.is_dir() {
            // Check if /dev is empty - libcontainer may fail if it's completely empty
            let dev_entries: Vec<_> = fs::read_dir(&dev_dir)
                .map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to read /dev directory: {}",
                        e
                    )))
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to read /dev entries: {}",
                        e
                    )))
                })?;

            if dev_entries.is_empty() {
                tracing::debug!("[ContainerProvisioner] /dev directory is empty - this is normal, devices will be created at runtime");
            }
        }

        tracing::debug!("[ContainerProvisioner] Rootfs structure validated successfully");
        Ok(())
    }

    /// Validate rootfs has required binaries for the component
    ///
    /// Checks that the rootfs contains the binary that will be executed.
    /// This helps catch image pull failures early before container creation.
    #[cfg(target_os = "linux")]
    fn validate_rootfs_binaries(
        &self,
        rootfs_path: &std::path::Path,
        component: &crate::bootstrap::k8s_components::K8sComponent,
    ) -> Result<(), ProvisionError> {
        use std::fs;

        tracing::debug!(
            "[ContainerProvisioner] Validating rootfs binaries for {} at {:?}",
            component.suffix,
            rootfs_path
        );

        // Get the binary name from component args (first arg is usually the binary)
        let binary_name = component.args.first().map(|arg| arg.as_str()).unwrap_or("");

        if binary_name.is_empty() {
            tracing::warn!(
                "[ContainerProvisioner] No binary name found in component args, skipping binary validation"
            );
            return Ok(());
        }

        // Common binary locations in container images
        let binary_paths = vec![
            rootfs_path.join("usr/local/bin").join(binary_name),
            rootfs_path.join("usr/bin").join(binary_name),
            rootfs_path.join("bin").join(binary_name),
            rootfs_path.join("sbin").join(binary_name),
            rootfs_path.join("usr/sbin").join(binary_name),
        ];

        let mut found_binary = false;
        let mut checked_paths = Vec::new();

        for binary_path in &binary_paths {
            checked_paths.push(binary_path.clone());
            if binary_path.exists() {
                // Check if it's a file and executable
                if let Ok(metadata) = fs::metadata(binary_path) {
                    if metadata.is_file() {
                        found_binary = true;
                        tracing::info!(
                            "[ContainerProvisioner] Found required binary {} at {:?}",
                            binary_name,
                            binary_path
                        );
                        break;
                    }
                }
            }
        }

        if !found_binary {
            // Check if rootfs is empty or very minimal (indicates image pull failure)
            let rootfs_entries: Vec<_> = fs::read_dir(rootfs_path)
                .map(|entries| entries.collect::<Result<Vec<_>, _>>().unwrap_or_default())
                .unwrap_or_default();

            if rootfs_entries.is_empty() {
                return Err(ProvisionError::Image(format!(
                    "Rootfs is empty at {:?}. Image pull likely failed.\n\
                    \n\
                    DIAGNOSTIC STEPS:\n\
                    1. Check if podman is installed: which podman\n\
                    2. Check if skopeo is installed: which skopeo\n\
                    3. Check if docker-proxy is running: curl -s http://localhost:5051/v2/\n\
                    4. Check image cache: ls -la ~/.local/share/4lock-agent/4lock-agent/containers/images/\n\
                    \n\
                    RECOMMENDED FIX:\n\
                    Install podman for reliable image pulling:\n\
                      sudo apt-get install podman  # or dnf install podman",
                    rootfs_path
                )));
            }

            // Rootfs exists but binary is missing - this could be a valid image structure issue
            tracing::warn!(
                "[ContainerProvisioner] Required binary '{}' not found in rootfs at {:?}\n\
                Checked paths: {:?}\n\
                Rootfs has {} entries. This may indicate:\n\
                1. Image pull was incomplete\n\
                2. Binary is in a non-standard location\n\
                3. Image structure is different than expected\n\
                \n\
                Container creation will proceed, but may fail if binary is truly missing.",
                binary_name,
                rootfs_path,
                checked_paths,
                rootfs_entries.len()
            );
        }

        Ok(())
    }

    /// Check rootless container prerequisites
    ///
    /// Validates that the system has the necessary support for rootless containers:
    /// - User namespace support enabled
    /// - UID/GID mapping tools available (newuidmap/newgidmap)
    /// - Subuid/subgid configured for the user
    #[cfg(target_os = "linux")]
    fn check_rootless_prerequisites(&self) -> Result<(), ProvisionError> {
        tracing::debug!("[ContainerProvisioner] Checking rootless container prerequisites");

        // Check user namespace support
        let user_ns_enabled = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
            .map(|s| s.trim() == "1")
            .unwrap_or(false);

        if !user_ns_enabled {
            tracing::warn!(
                "[ContainerProvisioner] User namespace support may not be enabled (/proc/sys/kernel/unprivileged_userns_clone != 1)"
            );
        }

        // Check for UID mapping tools (check common locations directly)
        let uidmap_available = ["/usr/bin/newuidmap", "/usr/sbin/newuidmap"]
            .iter()
            .any(|path| std::path::Path::new(path).exists())
            || std::process::Command::new("which")
                .arg("newuidmap")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

        let gidmap_available = ["/usr/bin/newgidmap", "/usr/sbin/newgidmap"]
            .iter()
            .any(|path| std::path::Path::new(path).exists())
            || std::process::Command::new("which")
                .arg("newgidmap")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

        // Check subuid/subgid configuration
        let current_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        let subuid_configured = std::fs::read_to_string("/etc/subuid")
            .map(|content| content.lines().any(|line| line.starts_with(&current_user)))
            .unwrap_or(false);

        let subgid_configured = std::fs::read_to_string("/etc/subgid")
            .map(|content| content.lines().any(|line| line.starts_with(&current_user)))
            .unwrap_or(false);

        // Log diagnostic information
        tracing::debug!(
            "[ContainerProvisioner] Rootless prerequisites check:\n\
            - User namespace enabled: {}\n\
            - newuidmap available: {}\n\
            - newgidmap available: {}\n\
            - subuid configured for {}: {}\n\
            - subgid configured for {}: {}",
            user_ns_enabled,
            uidmap_available,
            gidmap_available,
            current_user,
            subuid_configured,
            current_user,
            subgid_configured
        );

        // Warn if prerequisites are missing, but don't fail (container might still work)
        if !uidmap_available || !gidmap_available {
            tracing::warn!(
                "[ContainerProvisioner] UID/GID mapping tools not found. Rootless containers may fail.\n\
                Install with: sudo apt-get install uidmap"
            );
        }

        if !subuid_configured || !subgid_configured {
            tracing::warn!(
                "[ContainerProvisioner] subuid/subgid not configured for user '{}'. Rootless containers may fail.\n\
                Configure with: sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 {}",
                current_user,
                current_user
            );
        }

        // Only fail if user namespace is explicitly disabled
        if !user_ns_enabled {
            return Err(ProvisionError::Runtime(format!(
                "User namespace support is not enabled. Rootless containers require:\n\
                1. /proc/sys/kernel/unprivileged_userns_clone = 1\n\
                2. UID mapping tools: sudo apt-get install uidmap\n\
                3. Subuid/subgid configuration: sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 {}\n\
                \n\
                After configuration, you may need to log out and log back in.",
                current_user
            )));
        }

        // Check and configure systemd cgroup delegation (required for rootless containers)
        self.ensure_systemd_cgroup_delegation()?;

        Ok(())
    }

    /// Parse subuid range for the current user from /etc/subuid
    /// Returns (start_uid, size) or None if parsing fails
    #[cfg(target_os = "linux")]
    fn parse_subuid_range() -> Option<(u32, u32)> {
        let current_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .ok()?;

        let content = std::fs::read_to_string("/etc/subuid").ok()?;
        for line in content.lines() {
            if let Some(colon_pos) = line.find(':') {
                let user = &line[..colon_pos];
                if user == current_user {
                    let rest = &line[colon_pos + 1..];
                    let parts: Vec<&str> = rest.split(':').collect();
                    if parts.len() >= 2 {
                        if let (Ok(start), Ok(size)) =
                            (parts[0].parse::<u32>(), parts[1].parse::<u32>())
                        {
                            return Some((start, size));
                        }
                    }
                }
            }
        }
        None
    }

    /// Parse subgid range for the current user from /etc/subgid
    /// Returns (start_gid, size) or None if parsing fails
    #[cfg(target_os = "linux")]
    fn parse_subgid_range() -> Option<(u32, u32)> {
        let current_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .ok()?;

        let content = std::fs::read_to_string("/etc/subgid").ok()?;
        for line in content.lines() {
            if let Some(colon_pos) = line.find(':') {
                let user = &line[..colon_pos];
                if user == current_user {
                    let rest = &line[colon_pos + 1..];
                    let parts: Vec<&str> = rest.split(':').collect();
                    if parts.len() >= 2 {
                        if let (Ok(start), Ok(size)) =
                            (parts[0].parse::<u32>(), parts[1].parse::<u32>())
                        {
                            return Some((start, size));
                        }
                    }
                }
            }
        }
        None
    }

    /// Ensure systemd cgroup delegation is configured for rootless containers
    ///
    /// This function checks if systemd is configured to delegate cgroup controllers to user sessions.
    /// If the config file exists but delegation is not active, it restarts the user systemd session
    /// to apply the changes without requiring a re-login.
    #[cfg(target_os = "linux")]
    fn ensure_systemd_cgroup_delegation(&self) -> Result<(), ProvisionError> {
        use std::process::Command;

        tracing::debug!("[ContainerProvisioner] Checking systemd cgroup delegation");

        // Check if systemd is available
        let systemd_available = std::path::Path::new("/run/systemd/system").exists()
            || std::path::Path::new("/sys/fs/cgroup/systemd").exists()
            || Command::new("systemctl")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

        if !systemd_available {
            tracing::debug!(
                "[ContainerProvisioner] Systemd not available, skipping cgroup delegation check"
            );
            return Ok(());
        }

        // Check if delegation is actually active by checking for cgroup controllers
        // The Delegate property may be empty even when delegation is working,
        // so we check the actual cgroup controllers file instead
        let uid = std::env::var("UID")
            .or_else(|_| {
                Command::new("id")
                    .arg("-u")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .ok_or(std::env::VarError::NotPresent)
            })
            .unwrap_or_else(|_| "1000".to_string());

        let cgroup_controllers_path = format!(
            "/sys/fs/cgroup/user.slice/user-{}.slice/user@{}.service/cgroup.controllers",
            uid, uid
        );

        let delegation_active = std::fs::read_to_string(&cgroup_controllers_path)
            .ok()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if delegation_active {
            tracing::debug!("[ContainerProvisioner] Systemd cgroup delegation is already active");
            return Ok(());
        }

        // Check if config file exists (may have been created manually or by previous run)
        let delegate_config_path = "/etc/systemd/system/user@.service.d/delegate.conf";
        let delegate_config_exists = std::path::Path::new(delegate_config_path).exists();

        if !delegate_config_exists {
            tracing::warn!(
                "[ContainerProvisioner] Systemd cgroup delegation not configured. \
                Rootless containers may fail with EPERM errors. \
                To fix, run: sudo mkdir -p /etc/systemd/system/user@.service.d && \
                echo -e '[Service]\\nDelegate=yes' | sudo tee /etc/systemd/system/user@.service.d/delegate.conf && \
                sudo systemctl daemon-reload"
            );
            // Don't fail - containers might still work, but will likely fail with EPERM
            return Ok(());
        }

        // Config file exists but delegation not active
        // Note: systemd cgroup delegation requires a new user session to take effect.
        // We cannot restart the user service (systemctl restart user@...) as it logs out the user.
        // The delegation will be active after the user logs out and logs back in.
        tracing::warn!(
            "[ContainerProvisioner] Systemd cgroup delegation config found but not active. \
            Delegation requires a new user session to take effect. \
            Please log out and log back in, or the delegation will be active on your next login. \
            Rootless containers may fail with EPERM errors until then."
        );

        // Don't fail - the config is in place, it will work after re-login
        // We cannot automatically activate it without logging out the user
        Ok(())
    }

    /// Verify Kubernetes API is accessible
    ///
    /// Uses client certificates for authentication since the API server
    /// is configured with RBAC authorization mode.
    #[cfg(target_os = "linux")]
    async fn verify_k8s_api_accessible(&self, _zt_ip: Option<&str>) -> Result<(), ProvisionError> {
        use std::time::Duration;
        use tokio::time::sleep;

        tracing::info!("[ContainerProvisioner] Verifying Kubernetes API accessibility...");

        // NOTE: With shared network namespace, all containers (including API server) share
        // the same network namespace with pasta providing internet connectivity.
        // The API server is accessible via localhost:6443 from all containers in the namespace.
        let api_url = "https://127.0.0.1:6443/healthz".to_string();

        // Get certificate paths from the volume manager
        // The instance ID follows the pattern vapp-{uuid}
        let volumes_dir = self.app_dir.join("containers/volumes");

        // Find the first vapp-* directory (there should be only one active instance)
        let instance_volume = std::fs::read_dir(&volumes_dir).ok().and_then(|entries| {
            entries
                .filter_map(|e| e.ok())
                .find(|e| e.file_name().to_string_lossy().starts_with("vapp-"))
                .map(|e| e.path())
        });

        let (cert_path, key_path, ca_path) = if let Some(volume_path) = instance_volume {
            let k8s_certs = volume_path.join("kubernetes");
            let ca_dir = volume_path.join("ca");
            (
                Some(k8s_certs.join("admin.crt")),
                Some(k8s_certs.join("admin.key")),
                Some(ca_dir.join("ca.pem")),
            )
        } else {
            tracing::warn!(
                "[ContainerProvisioner] No instance volume found, checking API without client certs"
            );
            (None, None, None)
        };

        tracing::info!(
            "[ContainerProvisioner] Checking API server at: {} (with client certificates: {})",
            api_url,
            cert_path.is_some()
        );

        // Poll up to 60 seconds (2 second intervals = 30 attempts)
        let max_attempts = 30;
        let delay = Duration::from_secs(2);

        for attempt in 1..=max_attempts {
            let result = if let (Some(ref cert), Some(ref key)) = (&cert_path, &key_path) {
                self.check_health_endpoint_with_certs(
                    &api_url,
                    Some(cert.as_path()),
                    Some(key.as_path()),
                    ca_path.as_deref(),
                )
                .await
            } else {
                self.check_health_endpoint(&api_url).await
            };

            match result {
                Ok(_) => {
                    tracing::info!(
                        "[ContainerProvisioner] Kubernetes API is accessible (attempt {})",
                        attempt
                    );
                    return Ok(());
                }
                Err(e) => {
                    if attempt < max_attempts {
                        tracing::debug!(
                            "[ContainerProvisioner] API check failed (attempt {}/{}): {}, retrying...",
                            attempt,
                            max_attempts,
                            e
                        );
                        sleep(delay).await;
                    } else {
                        return Err(ProvisionError::Runtime(format!(
                            "Kubernetes API not accessible after {} attempts: {}",
                            max_attempts, e
                        )));
                    }
                }
            }
        }

        Err(ProvisionError::Runtime(
            "Kubernetes API verification timeout".to_string(),
        ))
    }

    /// Check health endpoint using reqwest HTTP client (curl not available in containers)
    #[cfg(target_os = "linux")]
    async fn check_health_endpoint(&self, url: &str) -> Result<(), ProvisionError> {
        self.check_health_endpoint_with_certs(url, None, None, None)
            .await
    }

    /// Check health endpoint with optional client certificates
    #[cfg(target_os = "linux")]
    async fn check_health_endpoint_with_certs(
        &self,
        url: &str,
        client_cert_path: Option<&std::path::Path>,
        client_key_path: Option<&std::path::Path>,
        _ca_cert_path: Option<&std::path::Path>,
    ) -> Result<(), ProvisionError> {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::crypto::{ring::default_provider, CryptoProvider};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
        use rustls::{Error, SignatureScheme};
        use rustls_pemfile::{certs, pkcs8_private_keys};
        use std::fs::File;
        use std::io::BufReader;
        use std::sync::Arc;

        // Ensure crypto provider is installed (rustls 0.23+ requirement)
        let _ = CryptoProvider::install_default(default_provider());

        // Build rustls client config with optional client certificates
        let client_config = if let (Some(cert_path), Some(key_path)) =
            (client_cert_path, client_key_path)
        {
            if cert_path.exists() && key_path.exists() {
                // Read and parse certificate
                let cert_file = File::open(cert_path).map_err(|e| {
                    ProvisionError::Runtime(format!("Failed to read client certificate: {}", e))
                })?;
                let mut cert_reader = BufReader::new(cert_file);
                let cert_chain: Vec<CertificateDer> = certs(&mut cert_reader)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| {
                        ProvisionError::Runtime(format!(
                            "Failed to parse client certificate: {}",
                            e
                        ))
                    })?;

                if cert_chain.is_empty() {
                    return Err(ProvisionError::Runtime(
                        "No certificates found in client cert file".to_string(),
                    ));
                }

                // Read and parse private key
                let key_file = File::open(key_path).map_err(|e| {
                    ProvisionError::Runtime(format!("Failed to read client key: {}", e))
                })?;
                let mut key_reader = BufReader::new(key_file);
                let mut keys: Vec<_> = pkcs8_private_keys(&mut key_reader)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| {
                        ProvisionError::Runtime(format!("Failed to parse client key: {}", e))
                    })?;

                if keys.is_empty() {
                    return Err(ProvisionError::Runtime(
                        "No private keys found in client key file".to_string(),
                    ));
                }

                let key = PrivateKeyDer::Pkcs8(keys.remove(0));

                // Build root store with CA certificate if provided
                let mut root_store = rustls::RootCertStore::empty();
                if let Some(ca_path) = _ca_cert_path {
                    if ca_path.exists() {
                        let ca_file = File::open(ca_path).map_err(|e| {
                            ProvisionError::Runtime(format!("Failed to read CA certificate: {}", e))
                        })?;
                        let mut ca_reader = BufReader::new(ca_file);
                        let ca_certs: Vec<CertificateDer> = certs(&mut ca_reader)
                            .collect::<std::result::Result<Vec<_>, _>>()
                            .map_err(|e| {
                                ProvisionError::Runtime(format!(
                                    "Failed to parse CA certificate: {}",
                                    e
                                ))
                            })?;

                        for cert in &ca_certs {
                            root_store.add(cert.clone()).map_err(|e| {
                                ProvisionError::Runtime(format!(
                                    "Failed to add CA certificate to root store: {}",
                                    e
                                ))
                            })?;
                        }
                    }
                }

                // Build client config with client certificate and custom verifier that accepts any server cert
                // (since we're using self-signed certificates and danger_accept_invalid_certs)
                #[derive(Debug)]
                struct AcceptAnyServerCertVerifier;
                impl ServerCertVerifier for AcceptAnyServerCertVerifier {
                    fn verify_server_cert(
                        &self,
                        _end_entity: &CertificateDer<'_>,
                        _intermediates: &[CertificateDer<'_>],
                        _server_name: &ServerName<'_>,
                        _ocsp_response: &[u8],
                        _now: UnixTime,
                    ) -> Result<ServerCertVerified, Error> {
                        Ok(ServerCertVerified::assertion())
                    }

                    fn verify_tls12_signature(
                        &self,
                        _message: &[u8],
                        _cert: &CertificateDer<'_>,
                        _dss: &rustls::DigitallySignedStruct,
                    ) -> Result<HandshakeSignatureValid, Error> {
                        Ok(HandshakeSignatureValid::assertion())
                    }

                    fn verify_tls13_signature(
                        &self,
                        _message: &[u8],
                        _cert: &CertificateDer<'_>,
                        _dss: &rustls::DigitallySignedStruct,
                    ) -> Result<HandshakeSignatureValid, Error> {
                        Ok(HandshakeSignatureValid::assertion())
                    }

                    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                        vec![
                            SignatureScheme::ECDSA_NISTP256_SHA256,
                            SignatureScheme::ECDSA_NISTP384_SHA384,
                            SignatureScheme::ECDSA_NISTP521_SHA512,
                            SignatureScheme::ED25519,
                            SignatureScheme::ED448,
                            SignatureScheme::RSA_PSS_SHA256,
                            SignatureScheme::RSA_PSS_SHA384,
                            SignatureScheme::RSA_PSS_SHA512,
                            SignatureScheme::RSA_PKCS1_SHA256,
                            SignatureScheme::RSA_PKCS1_SHA384,
                            SignatureScheme::RSA_PKCS1_SHA512,
                        ]
                    }
                }

                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCertVerifier))
                    .with_client_auth_cert(cert_chain, key)
                    .map_err(|e| {
                        ProvisionError::Runtime(format!(
                            "Failed to build client config with certificates: {}",
                            e
                        ))
                    })?
            } else {
                // No client certs - use default config
                rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth()
            }
        } else {
            // No client certs - use default config
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth()
        };

        // Build HTTP client using hyper with custom rustls config
        use http_body_util::Full;
        use hyper::Request;
        use hyper_rustls::HttpsConnectorBuilder;
        use hyper_util::client::legacy::Client;
        use hyper_util::rt::TokioExecutor;

        // Create HTTPS connector with custom rustls config
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_or_http()
            .enable_http2()
            .build();

        // Create HTTP client
        let client: Client<_, Full<hyper::body::Bytes>> = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .build(https);

        // Parse URL
        let uri: hyper::Uri = url
            .parse()
            .map_err(|e| ProvisionError::Runtime(format!("Failed to parse URL: {}", e)))?;

        // Create request
        let req = Request::builder()
            .uri(uri)
            .method("GET")
            .body(Full::<hyper::body::Bytes>::default())
            .map_err(|e| ProvisionError::Runtime(format!("Failed to create request: {}", e)))?;

        // Make request with timeout
        let response = tokio::time::timeout(Duration::from_secs(5), client.request(req))
            .await
            .map_err(|_| ProvisionError::Runtime("Request timeout".to_string()))?
            .map_err(|e| ProvisionError::Runtime(format!("HTTP request failed: {}", e)))?;

        // HTTP 200 means healthy
        if response.status().as_u16() == 200 {
            Ok(())
        } else {
            Err(ProvisionError::Runtime(format!(
                "Health endpoint returned status code: {}",
                response.status().as_u16()
            )))
        }
    }

    /// Generate K8s certificates using alpine utility container
    #[cfg(target_os = "linux")]
    async fn generate_certificates(
        &self,
        instance_id: &str,
        service_cidr: &str,
    ) -> Result<CertificatePaths, ProvisionError> {
        // 0. Check rootless container prerequisites before creating utility containers
        self.check_rootless_prerequisites()?;

        // 1. Prepare volume directories
        let volumes_base = self.app_dir.join("containers/volumes").join(instance_id);
        let ca_dir = volumes_base.join("ca");
        let k8s_certs_dir = volumes_base.join("kubernetes");
        let etcd_certs_dir = volumes_base.join("etcd");

        std::fs::create_dir_all(&ca_dir).map_err(ProvisionError::Io)?;
        std::fs::create_dir_all(&k8s_certs_dir).map_err(ProvisionError::Io)?;
        std::fs::create_dir_all(&etcd_certs_dir).map_err(ProvisionError::Io)?;

        // 2. First, generate CA if it doesn't exist
        let ca_script = self
            .template_renderer
            .render("certs/10-ca-certificate.sh", &HashMap::new())?;
        let scripts_dir = self.app_dir.join("containers/utility-scripts");
        std::fs::create_dir_all(&scripts_dir).map_err(ProvisionError::Io)?;
        let ca_script_path = scripts_dir.join("ca-gen.sh");
        std::fs::write(&ca_script_path, ca_script).map_err(ProvisionError::Io)?;
        // Make script executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&ca_script_path)
                .map_err(ProvisionError::Io)?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&ca_script_path, perms).map_err(ProvisionError::Io)?;
        }

        // Run CA generation utility container
        // The script writes directly to mounted output files and CA directory since container stdout/stderr go to /dev/null
        let ca_output = self
            .utility_runner
            .run(
                &self.image_manager,
                UtilityContainerConfig {
                    name: format!("utility-{}-ca-gen", instance_id),
                    image: "alpine:latest".to_string(),
                    command: vec!["/bin/sh".to_string(), "/scripts/ca-gen.sh".to_string()],
                    volumes: HashMap::from([
                        (
                            ca_script_path.to_string_lossy().to_string(),
                            "/scripts/ca-gen.sh".to_string(),
                        ),
                        (
                            ca_dir.to_string_lossy().to_string(),
                            "/output/ca".to_string(),
                        ),
                    ]),
                    env: HashMap::new(),
                    network_mode: "none".to_string(),
                },
            )
            .await?;

        if ca_output.exit_code != 0 {
            tracing::error!(
                "[ContainerProvisioner] CA generation failed with exit code {}: stdout={}, stderr={}",
                ca_output.exit_code,
                ca_output.stdout,
                ca_output.stderr
            );
            return Err(ProvisionError::Runtime(format!(
                "CA generation failed: {}",
                ca_output.stderr
            )));
        }

        if !ca_output.stdout.is_empty() && !ca_output.stderr.is_empty() {
            tracing::debug!(
                "[ContainerProvisioner] CA generation stdout: {}, stderr: {}",
                ca_output.stdout,
                ca_output.stderr
            );
        }

        // Verify CA certificate was created before proceeding
        let ca_pem_path = ca_dir.join("ca.pem");
        let ca_key_path = ca_dir.join("ca.key");
        if !ca_pem_path.exists() || !ca_key_path.exists() {
            tracing::error!(
                "[ContainerProvisioner] CA certificate files not found after generation. ca.pem exists: {}, ca.key exists: {}, ca_dir: {:?}",
                ca_pem_path.exists(),
                ca_key_path.exists(),
                ca_dir
            );
            if let Ok(entries) = std::fs::read_dir(&ca_dir) {
                let files: Vec<String> = entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect();
                tracing::error!("[ContainerProvisioner] Directory contents: {:?}", files);
            }
            return Err(ProvisionError::Runtime(format!(
                "CA certificate not generated. Exit code was 0 but files not found. stdout: {}, stderr: {}",
                ca_output.stdout,
                ca_output.stderr
            )));
        }

        tracing::info!(
            "[ContainerProvisioner] CA certificate generated successfully: {:?}",
            ca_pem_path
        );

        // 3. Render certificate generation script
        let vars = HashMap::from([
            ("instance_id".to_string(), instance_id.to_string()),
            ("service_cidr".to_string(), service_cidr.to_string()),
        ]);
        let script = self
            .template_renderer
            .render("certs/20-api-certificates.sh", &vars)?;

        // 4. Write script to temp location
        let script_path = scripts_dir.join("cert-gen.sh");
        std::fs::write(&script_path, script).map_err(ProvisionError::Io)?;

        // 5. Run alpine utility container with openssl
        let output = self
            .utility_runner
            .run(
                &self.image_manager,
                UtilityContainerConfig {
                    name: format!("utility-{}-cert-gen", instance_id),
                    image: "alpine:latest".to_string(),
                    command: vec!["/bin/sh".to_string(), "/scripts/cert-gen.sh".to_string()],
                    volumes: HashMap::from([
                        (
                            script_path.to_string_lossy().to_string(),
                            "/scripts/cert-gen.sh".to_string(),
                        ),
                        (
                            ca_dir.to_string_lossy().to_string(),
                            "/input/ca".to_string(),
                        ),
                        (
                            k8s_certs_dir.to_string_lossy().to_string(),
                            "/output/kubernetes".to_string(),
                        ),
                        (
                            etcd_certs_dir.to_string_lossy().to_string(),
                            "/output/etcd".to_string(),
                        ),
                    ]),
                    env: HashMap::new(),
                    network_mode: "host".to_string(), // Use host network to allow apk to download openssl if needed
                },
            )
            .await?;

        if output.exit_code != 0 {
            return Err(ProvisionError::Runtime(format!(
                "Certificate generation failed: {}",
                output.stderr
            )));
        }

        // 6. Verify certificates were created (re-check after cert generation)
        let ca_pem_path = ca_dir.join("ca.pem");
        if !ca_pem_path.exists() {
            tracing::error!(
                "[ContainerProvisioner] CA certificate not found after certificate generation. ca_dir: {:?}",
                ca_dir
            );
            if let Ok(entries) = std::fs::read_dir(&ca_dir) {
                let files: Vec<String> = entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect();
                tracing::error!("[ContainerProvisioner] CA directory contents: {:?}", files);
            }
            return Err(ProvisionError::Runtime(format!(
                "CA certificate not generated. Files not found in {:?}",
                ca_dir
            )));
        }

        // Verify etcd certificates were created
        let etcd_server_cert = etcd_certs_dir.join("etcd-server.crt");
        let etcd_server_key = etcd_certs_dir.join("etcd-server.key");
        let etcd_healthcheck_cert = etcd_certs_dir.join("etcd-healthcheck-client.crt");
        let etcd_healthcheck_key = etcd_certs_dir.join("etcd-healthcheck-client.key");

        if !etcd_server_cert.exists() || !etcd_server_key.exists() {
            tracing::error!(
                "[ContainerProvisioner] etcd server certificates not found after generation. etcd_certs_dir: {:?}",
                etcd_certs_dir
            );
            if let Ok(entries) = std::fs::read_dir(&etcd_certs_dir) {
                let files: Vec<String> = entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect();
                tracing::error!(
                    "[ContainerProvisioner] etcd directory contents: {:?}",
                    files
                );
            }
            return Err(ProvisionError::Runtime(format!(
                "etcd server certificates not generated. Expected files not found in {:?}. Script stdout: {}, stderr: {}",
                etcd_certs_dir,
                output.stdout,
                output.stderr
            )));
        }

        if !etcd_healthcheck_cert.exists() || !etcd_healthcheck_key.exists() {
            tracing::error!(
                "[ContainerProvisioner] etcd healthcheck client certificates not found after generation. etcd_certs_dir: {:?}",
                etcd_certs_dir
            );
            return Err(ProvisionError::Runtime(format!(
                "etcd healthcheck client certificates not generated. Expected files not found in {:?}. Script stdout: {}, stderr: {}",
                etcd_certs_dir,
                output.stdout,
                output.stderr
            )));
        }

        tracing::info!(
            "[ContainerProvisioner] Certificates generated successfully for {} (etcd certificates verified)",
            instance_id
        );

        // Generate kubeconfig files for controller-manager and scheduler
        // These use localhost:6443 to reach the API server (shared network namespace)
        tracing::info!(
            "[ContainerProvisioner] Generating kubeconfig files for controller-manager and scheduler"
        );

        let controller_kubeconfig = self
            .template_renderer
            .render("kubeconfig/controller.kubeconfig.j2", &HashMap::new())?;
        let controller_kubeconfig_path = k8s_certs_dir.join("controller.kubeconfig");
        std::fs::write(&controller_kubeconfig_path, controller_kubeconfig)
            .map_err(ProvisionError::Io)?;
        tracing::info!(
            "[ContainerProvisioner] Generated controller.kubeconfig at {:?}",
            controller_kubeconfig_path
        );

        let scheduler_kubeconfig = self
            .template_renderer
            .render("kubeconfig/scheduler.kubeconfig.j2", &HashMap::new())?;
        let scheduler_kubeconfig_path = k8s_certs_dir.join("scheduler.kubeconfig");
        std::fs::write(&scheduler_kubeconfig_path, scheduler_kubeconfig)
            .map_err(ProvisionError::Io)?;
        tracing::info!(
            "[ContainerProvisioner] Generated scheduler.kubeconfig at {:?}",
            scheduler_kubeconfig_path
        );

        // Generate admin.kubeconfig for local access (uses absolute paths for host access)
        let admin_kubeconfig = format!(
            r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: {}
    server: https://127.0.0.1:6443
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: admin
  name: admin@kubernetes
current-context: admin@kubernetes
users:
- name: admin
  user:
    client-certificate: {}
    client-key: {}
"#,
            ca_dir.join("ca.pem").display(),
            k8s_certs_dir.join("admin.crt").display(),
            k8s_certs_dir.join("admin.key").display()
        );
        let admin_kubeconfig_path = k8s_certs_dir.join("admin.kubeconfig");
        std::fs::write(&admin_kubeconfig_path, admin_kubeconfig).map_err(ProvisionError::Io)?;
        tracing::info!(
            "[ContainerProvisioner] Generated admin.kubeconfig at {:?}",
            admin_kubeconfig_path
        );

        Ok(CertificatePaths {
            ca_dir,
            k8s_certs_dir,
            etcd_certs_dir,
        })
    }

    /// Generate kubelet configuration files
    ///
    /// Creates kubelet-config.yaml and kubelet.kubeconfig files that will be mounted
    /// into the kubelet container.
    #[cfg(target_os = "linux")]
    fn generate_kubelet_config(
        &self,
        instance_id: &str,
        cert_paths: &CertificatePaths,
        cluster: &crate::intent::ClusterSpec,
    ) -> Result<PathBuf, ProvisionError> {
        use std::collections::HashMap;

        tracing::info!(
            "[ContainerProvisioner] Generating kubelet configuration for {}",
            instance_id
        );

        // Create kubelet config directory
        let kubelet_config_dir = cert_paths
            .k8s_certs_dir
            .parent()
            .ok_or_else(|| {
                ProvisionError::Io(std::io::Error::other(
                    "Failed to get parent directory for kubelet config",
                ))
            })?
            .join("kubelet");
        std::fs::create_dir_all(&kubelet_config_dir).map_err(ProvisionError::Io)?;

        // Render kubelet-config.yaml
        let mut kubelet_config_vars = HashMap::new();
        kubelet_config_vars.insert("instance_id".to_string(), instance_id.to_string());
        kubelet_config_vars.insert("cluster_name".to_string(), cluster.name.clone());
        kubelet_config_vars.insert("dns_address".to_string(), cluster.dns_address.clone());

        let kubelet_config_yaml = self
            .template_renderer
            .render("kubelet/kubelet-config.yaml.j2", &kubelet_config_vars)?;
        let kubelet_config_path = kubelet_config_dir.join("kubelet-config.yaml");
        std::fs::write(&kubelet_config_path, kubelet_config_yaml).map_err(ProvisionError::Io)?;
        tracing::info!(
            "[ContainerProvisioner] Generated kubelet-config.yaml at {:?}",
            kubelet_config_path
        );

        // Render kubelet.kubeconfig
        let kubelet_kubeconfig = self
            .template_renderer
            .render("kubelet/kubelet.kubeconfig.j2", &kubelet_config_vars)?;
        let kubelet_kubeconfig_path = kubelet_config_dir.join("kubelet.kubeconfig");
        std::fs::write(&kubelet_kubeconfig_path, kubelet_kubeconfig).map_err(ProvisionError::Io)?;
        tracing::info!(
            "[ContainerProvisioner] Generated kubelet.kubeconfig at {:?}",
            kubelet_kubeconfig_path
        );

        Ok(kubelet_config_dir)
    }

    /// Wait for ZeroTier IP to be assigned by polling the IP file written by start-zerotier.sh
    #[cfg(target_os = "linux")]
    async fn wait_for_zerotier_ip(
        &self,
        instance_id: &str,
        timeout: Duration,
    ) -> Result<String, ProvisionError> {
        let ip_file = self
            .app_dir
            .join("containers/volumes")
            .join(instance_id)
            .join("zerotier-data/ip.txt");

        tracing::info!(
            "[ContainerProvisioner] Waiting for ZeroTier IP file: {}",
            ip_file.display()
        );

        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Ok(contents) = std::fs::read_to_string(&ip_file) {
                let ip = contents.trim();
                if !ip.is_empty() {
                    return Ok(ip.to_string());
                }
            }
            if std::time::Instant::now() > deadline {
                return Err(ProvisionError::Runtime(format!(
                    "ZeroTier IP not assigned within {}s. Check container logs.",
                    timeout.as_secs()
                )));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

#[async_trait]
impl RuntimeProvisioner for ContainerProvisioner {
    async fn provision_device(
        &mut self,
        spec: &VappSpec,
        progress: Arc<dyn ProgressReporter>,
    ) -> Result<InstanceHandle, ProvisionError> {
        let instance_id = &spec.instance_id;

        tracing::info!(
            "[ContainerProvisioner] Provisioning device (ZeroTier VPN): {}",
            instance_id
        );

        #[cfg(not(target_os = "linux"))]
        {
            let _ = &progress;
            return Err(ProvisionError::Config(
                "Container provisioner only available on Linux".to_string(),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            // 1. Create container group
            progress.emit(5, "Creating container group...".to_string());
            let _group = self.create_container_group(instance_id)?;
            tracing::info!(
                "[ContainerProvisioner] Created container group: {}",
                instance_id
            );

            // 2. Pull ZeroTier image
            progress.emit(10, "Pulling ZeroTier image...".to_string());
            use crate::bootstrap::k8s_components::get_zerotier_component;
            let mut zt_component = get_zerotier_component();
            tracing::info!(
                "[ContainerProvisioner] Pulling image: {}",
                zt_component.image
            );
            self.image_manager
                .ensure_image(zt_component.image)
                .await
                .map_err(|e| {
                    ProvisionError::Image(format!(
                        "Failed to pull ZeroTier image {}: {}",
                        zt_component.image, e
                    ))
                })?;

            // 3. Create and start ZeroTier container
            progress.emit(30, "Starting ZeroTier container...".to_string());
            let container_name = format!("{}-zerotier", instance_id);
            tracing::info!(
                "[ContainerProvisioner] Creating ZeroTier container: {}",
                container_name
            );

            let mut group = self
                .container_manager
                .get_container_group(instance_id)
                .map_err(|e| {
                    ProvisionError::Runtime(format!("Failed to get container group: {}", e))
                })?;

            let container_info = self
                .create_and_start_k8s_container(
                    instance_id,
                    &mut zt_component,
                    &container_name,
                    Some(&spec.network),
                    None,
                )
                .await?;

            // Save container to group
            group.containers.push(container_info.clone());
            let content = serde_json::to_string_pretty(&group).map_err(|e| {
                ProvisionError::Runtime(format!("Failed to serialize container group: {}", e))
            })?;
            std::fs::write(&group.state_file, content).map_err(ProvisionError::Io)?;

            progress.emit(50, "ZeroTier container started".to_string());
            tracing::info!(
                "[ContainerProvisioner] ZeroTier container started: {}",
                container_name
            );

            // 4. Wait for ZeroTier IP assignment
            progress.emit(60, "Waiting for ZeroTier IP assignment...".to_string());
            let zt_ip = self
                .wait_for_zerotier_ip(instance_id, Duration::from_secs(120))
                .await?;

            tracing::info!(
                "[ContainerProvisioner] ZeroTier VPN connected - IP: {}",
                zt_ip
            );
            progress.emit(90, format!("ZeroTier VPN connected ({})", zt_ip));

            progress.emit(100, "VPN ready".to_string());

            let endpoint = self.get_endpoint(instance_id).await?;

            let handle = InstanceHandle {
                instance_id: instance_id.clone(),
                endpoint,
            };

            Ok(handle)
        }
    }

    async fn provision_app(
        &mut self,
        spec: &VappSpec,
        progress: Arc<dyn ProgressReporter>,
    ) -> Result<InstanceHandle, ProvisionError> {
        let instance_id = &spec.instance_id;
        let app_name = spec.app_name.as_deref().unwrap_or("unknown");

        tracing::info!(
            "[ContainerProvisioner] Provisioning app container: {} (app: {})",
            instance_id,
            app_name
        );

        // 1. Pull/prepare image (container-specific!)
        progress.emit(10, "Pulling container image...".to_string());
        let _image_path = self
            .image_manager
            .ensure_image(&self.config.image.base_image)
            .await
            .map_err(|e| ProvisionError::Image(e.to_string()))?;

        // 2. Create volumes from StorageSpec (container-specific!)
        progress.emit(20, "Creating volumes...".to_string());
        let volumes = self.storage_to_volumes(instance_id, &spec.storage).await?;

        // 3. Prepare OCI bundle
        progress.emit(30, "Preparing container bundle...".to_string());
        let bundle = self
            .prepare_bundle(instance_id, spec, "worker", &volumes)
            .map_err(|e| ProvisionError::Bundle(e.to_string()))?;

        // 4. Create container
        progress.emit(50, "Creating container...".to_string());
        self.runtime
            .create(instance_id, &bundle)
            .await
            .map_err(|e| ProvisionError::Runtime(e.to_string()))?;

        // 5. Start container
        progress.emit(60, "Starting container...".to_string());
        self.runtime
            .start(instance_id)
            .await
            .map_err(|e| ProvisionError::Runtime(e.to_string()))?;

        // 6. Bootstrap workflow (container-specific scripts)
        progress.emit(70, "Running bootstrap...".to_string());
        workflow::run_bootstrap(instance_id, spec, &bundle, self.runtime.clone())
            .await
            .map_err(|e| ProvisionError::Bootstrap(e.to_string()))?;

        // 7. Setup Kubernetes
        progress.emit(85, "Setting up Kubernetes...".to_string());
        workflow::setup_kubernetes(instance_id, spec, "worker", self.runtime.clone())
            .await
            .map_err(|e| ProvisionError::Bootstrap(e.to_string()))?;

        progress.emit(100, "App container provisioned successfully".to_string());

        let endpoint = self.get_endpoint(instance_id).await?;

        let handle = InstanceHandle {
            instance_id: instance_id.clone(),
            endpoint,
        };

        Ok(handle)
    }

    async fn run_container(
        &mut self,
        spec: &ContainerRunSpec,
        progress: Arc<dyn ProgressReporter>,
    ) -> Result<InstanceHandle, ProvisionError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (spec, progress);
            return Err(ProvisionError::Config(
                "run_container only available on Linux".to_string(),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            use crate::rootless::lifecycle;

            let instance_id = spec.instance_id.clone().unwrap_or_else(|| {
                format!(
                    "run-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                )
            });

            progress.emit(5, "Pulling image...".to_string());
            let image_dir = self
                .image_manager
                .ensure_image(&spec.image)
                .await
                .map_err(|e| ProvisionError::Image(e.to_string()))?;
            let image_rootfs = image_dir.join("rootfs");
            if !image_rootfs.exists() {
                return Err(ProvisionError::Image(format!(
                    "Image rootfs not found at {:?}",
                    image_rootfs
                )));
            }

            let bundles_dir = self.app_dir.join("containers/bundles");
            let bundle_dir = bundles_dir.join(&instance_id);
            std::fs::create_dir_all(&bundle_dir).map_err(ProvisionError::Io)?;
            let bundle_rootfs = bundle_dir.join("rootfs");

            progress.emit(20, "Copying rootfs...".to_string());
            if bundle_rootfs.exists() {
                std::fs::remove_dir_all(&bundle_rootfs).map_err(ProvisionError::Io)?;
            }
            self.copy_dir_recursive(&image_rootfs, &bundle_rootfs)?;

            progress.emit(40, "Creating container...".to_string());
            self.write_oci_spec_for_run(&bundle_dir.join("config.json"), spec)?;

            lifecycle::create_container(&instance_id, &bundle_dir, &self.app_dir)
                .map_err(|e| ProvisionError::Runtime(e.to_string()))?;
            lifecycle::start_container(&self.app_dir, &instance_id)
                .map_err(|e| ProvisionError::Runtime(e.to_string()))?;

            progress.emit(100, "Running".to_string());

            let endpoint = Endpoint::Socket(bundle_dir.clone());
            Ok(InstanceHandle {
                instance_id,
                endpoint,
            })
        }
    }

    async fn stop(&mut self, instance_id: &str) -> Result<(), String> {
        tracing::info!("[ContainerProvisioner] Stopping container: {}", instance_id);

        self.runtime
            .stop(instance_id, Duration::from_secs(30))
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    async fn state(&self, instance_id: &str) -> Result<InstanceState, String> {
        let state = self
            .runtime
            .state(instance_id)
            .await
            .map_err(|e| e.to_string())?;

        Ok(match state {
            crate::common::ContainerState::Creating => InstanceState::Provisioning { progress: 50 },
            crate::common::ContainerState::Running => InstanceState::Running,
            crate::common::ContainerState::Stopped => InstanceState::Stopped,
            crate::common::ContainerState::Failed => InstanceState::Failed {
                reason: "Container failed".to_string(),
            },
            crate::common::ContainerState::Paused => InstanceState::Stopped,
        })
    }

    async fn endpoint(&self, instance_id: &str) -> Result<Endpoint, String> {
        self.get_endpoint(instance_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn cleanup_all(&mut self) -> Result<usize, String> {
        tracing::info!("[ContainerProvisioner] Cleaning up all containers");

        let containers = self.runtime.list().await.map_err(|e| e.to_string())?;

        let count = containers.len();

        for container in containers {
            let _ = self
                .runtime
                .stop(&container.id, Duration::from_secs(5))
                .await;
            let _ = self.runtime.delete(&container.id).await;
        }

        Ok(count)
    }
}
