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
}
