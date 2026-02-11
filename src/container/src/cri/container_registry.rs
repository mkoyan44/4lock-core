//! Container registry for CRI
//!
//! This module tracks containers created via the CRI interface.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

use super::server::runtime::v1::ContainerMetadata;

/// Container state tracking for CRI
#[derive(Debug, Clone)]
pub struct CriContainerState {
    pub id: String,
    pub sandbox_id: String,
    pub name: String,
    pub image: String,
    pub image_ref: String,
    pub created_at: SystemTime,
    pub started_at: Option<SystemTime>,
    pub finished_at: Option<SystemTime>,
    pub state: ContainerRuntimeState,
    pub exit_code: i32,
    pub bundle_path: PathBuf,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub metadata: Option<ContainerMetadata>,
}

/// Runtime state of a container
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerRuntimeState {
    Created,
    Running,
    Exited,
    Unknown,
}

impl ContainerRuntimeState {
    /// Convert to CRI ContainerState enum value
    pub fn to_cri_state(&self) -> i32 {
        use super::server::runtime::v1::ContainerState;
        match self {
            Self::Created => ContainerState::ContainerCreated as i32,
            Self::Running => ContainerState::ContainerRunning as i32,
            Self::Exited => ContainerState::ContainerExited as i32,
            Self::Unknown => ContainerState::ContainerUnknown as i32,
        }
    }
}

/// Registry for tracking CRI containers
pub struct ContainerRegistry {
    pub containers: HashMap<String, CriContainerState>,
    pub app_dir: PathBuf,
}

impl ContainerRegistry {
    pub fn new(app_dir: PathBuf) -> Self {
        Self {
            containers: HashMap::new(),
            app_dir,
        }
    }

    /// Register a new container
    pub fn register_container(
        &mut self,
        container_id: &str,
        sandbox_id: &str,
        name: &str,
        image: &str,
        image_ref: &str,
        bundle_path: PathBuf,
        labels: HashMap<String, String>,
        annotations: HashMap<String, String>,
        metadata: Option<ContainerMetadata>,
    ) -> Result<(), String> {
        if self.containers.contains_key(container_id) {
            return Err(format!("Container {} already exists", container_id));
        }

        let state = CriContainerState {
            id: container_id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            name: name.to_string(),
            image: image.to_string(),
            image_ref: image_ref.to_string(),
            created_at: SystemTime::now(),
            started_at: None,
            finished_at: None,
            state: ContainerRuntimeState::Created,
            exit_code: 0,
            bundle_path,
            labels,
            annotations,
            metadata,
        };

        self.containers.insert(container_id.to_string(), state);
        Ok(())
    }

    /// Get a container by ID
    pub fn get_container(&self, container_id: &str) -> Option<&CriContainerState> {
        self.containers.get(container_id)
    }

    /// Get a mutable reference to a container
    pub fn get_container_mut(&mut self, container_id: &str) -> Option<&mut CriContainerState> {
        self.containers.get_mut(container_id)
    }

    /// Update container state to Running
    pub fn mark_running(&mut self, container_id: &str) -> Result<(), String> {
        let container = self
            .containers
            .get_mut(container_id)
            .ok_or_else(|| format!("Container {} not found", container_id))?;

        container.state = ContainerRuntimeState::Running;
        container.started_at = Some(SystemTime::now());
        Ok(())
    }

    /// Update container state to Exited
    pub fn mark_exited(&mut self, container_id: &str, exit_code: i32) -> Result<(), String> {
        let container = self
            .containers
            .get_mut(container_id)
            .ok_or_else(|| format!("Container {} not found", container_id))?;

        container.state = ContainerRuntimeState::Exited;
        container.finished_at = Some(SystemTime::now());
        container.exit_code = exit_code;
        Ok(())
    }

    /// Remove a container
    pub fn remove_container(&mut self, container_id: &str) -> Option<CriContainerState> {
        self.containers.remove(container_id)
    }

    /// List all containers
    pub fn list_containers(&self) -> Vec<&CriContainerState> {
        self.containers.values().collect()
    }

    /// List containers in a specific sandbox
    pub fn list_containers_in_sandbox(&self, sandbox_id: &str) -> Vec<&CriContainerState> {
        self.containers
            .values()
            .filter(|c| c.sandbox_id == sandbox_id)
            .collect()
    }

    /// Discover containers from youki state files on disk that aren't in the in-memory registry.
    /// This bridges the gap between containers created by the provisioner (via lifecycle directly)
    /// and the CRI's in-memory tracking.
    pub fn discover_containers_from_disk(&mut self) {
        let containers_dir = self.app_dir.join("containers");
        tracing::info!(
            "[ContainerRegistry] discover_containers_from_disk: scanning {:?} (in-memory count: {})",
            containers_dir,
            self.containers.len()
        );
        let entries = match std::fs::read_dir(&containers_dir) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(
                    "[ContainerRegistry] discover_containers_from_disk: failed to read {:?}: {}",
                    containers_dir,
                    e
                );
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
            let state_file = path.join("state.json");
            if !state_file.exists() {
                tracing::debug!(
                    "[ContainerRegistry] Skipping {:?}: no state.json",
                    dir_name
                );
                continue;
            }

            let container_id = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name.to_string(),
                None => continue,
            };

            // Skip if already tracked in-memory
            if self.containers.contains_key(&container_id) {
                tracing::debug!(
                    "[ContainerRegistry] Skipping {}: already tracked in-memory",
                    container_id
                );
                continue;
            }

            tracing::info!(
                "[ContainerRegistry] Found untracked container on disk: {} (state file: {:?})",
                container_id,
                state_file
            );

            // Parse youki state.json
            let content = match std::fs::read_to_string(&state_file) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        "[ContainerRegistry] Failed to read state.json for {}: {}",
                        container_id,
                        e
                    );
                    continue;
                }
            };

            let state: serde_json::Value = match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        "[ContainerRegistry] Failed to parse state.json for {}: {}",
                        container_id,
                        e
                    );
                    continue;
                }
            };

            let status = state["status"].as_str().unwrap_or("unknown");
            let pid = state["pid"].as_u64().unwrap_or(0);
            let bundle = state["bundle"]
                .as_str()
                .map(PathBuf::from)
                .unwrap_or_default();
            let created_str = state["created"].as_str().unwrap_or("");

            // Determine runtime state
            let runtime_state = match status {
                "running" => {
                    // Verify the process is actually alive
                    if pid > 0 && std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                        ContainerRuntimeState::Running
                    } else {
                        ContainerRuntimeState::Exited
                    }
                }
                "created" => ContainerRuntimeState::Created,
                "stopped" => ContainerRuntimeState::Exited,
                _ => ContainerRuntimeState::Unknown,
            };

            // Try to extract image info from the bundle's config.json
            let config_path = bundle.join("config.json");
            let (image, labels, annotations) = if config_path.exists() {
                let config_content = std::fs::read_to_string(&config_path).unwrap_or_default();
                let config: serde_json::Value =
                    serde_json::from_str(&config_content).unwrap_or_default();

                // Try annotations for image name, fall back to container name
                let image = config["annotations"]["io.kubernetes.cri.image-name"]
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| container_id
                        .rsplit('-')
                        .next()
                        .unwrap_or(&container_id)
                        .to_string());

                let labels = config["labels"]
                    .as_object()
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();

                let annotations = config["annotations"]
                    .as_object()
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();

                (image, labels, annotations)
            } else {
                ("unknown".to_string(), HashMap::new(), HashMap::new())
            };

            // Parse created timestamp
            let created_at = chrono::DateTime::parse_from_rfc3339(created_str)
                .map(|dt| {
                    SystemTime::UNIX_EPOCH
                        + std::time::Duration::from_secs(dt.timestamp() as u64)
                })
                .unwrap_or(SystemTime::now());

            let started_at = if runtime_state == ContainerRuntimeState::Running {
                Some(created_at)
            } else {
                None
            };

            // Derive a human-readable name from the container ID
            // Container IDs are typically like "vapp-<hash>-<name>"
            let name = container_id
                .rsplit('-')
                .next()
                .unwrap_or(&container_id)
                .to_string();

            let metadata = Some(ContainerMetadata {
                name: name.clone(),
                attempt: 0,
            });

            let cri_state = CriContainerState {
                id: container_id.clone(),
                sandbox_id: String::new(), // provisioner containers don't have a CRI sandbox
                name,
                image: image.clone(),
                image_ref: image,
                created_at,
                started_at,
                finished_at: None,
                state: runtime_state,
                exit_code: 0,
                bundle_path: bundle,
                labels,
                annotations,
                metadata,
            };

            tracing::info!(
                "[ContainerRegistry] Discovered container from disk: {} (status: {})",
                container_id,
                status
            );

            self.containers.insert(container_id, cri_state);
        }
    }
}
