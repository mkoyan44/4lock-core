//! Container orchestration and group management
use super::error::ContainerError;
use std::path::PathBuf;

#[derive(Clone)]
pub struct ContainerManager {
    app_dir: PathBuf,
}

impl ContainerManager {
    pub fn new(app_dir: PathBuf) -> Result<Self, String> {
        Ok(Self { app_dir })
    }

    pub fn root_path(&self) -> &PathBuf {
        &self.app_dir
    }

    pub fn create_container_group(
        &self,
        name: &str,
    ) -> Result<group::ContainerGroup, ContainerError> {
        Ok(group::ContainerGroup {
            name: name.to_string(),
            containers: Vec::new(),
            state_file: self.app_dir.join("state.json"),
        })
    }

    pub fn get_container_group(&self, name: &str) -> Result<group::ContainerGroup, String> {
        Ok(group::ContainerGroup {
            name: name.to_string(),
            containers: Vec::new(),
            state_file: self.app_dir.join("state.json"),
        })
    }

    pub fn get_container_state(&self, container_id: &str) -> Result<group::ContainerState, String> {
        use crate::rootless::commands::load_container;

        // Load container to check its actual state
        match load_container(&self.app_dir, container_id) {
            Ok(container) => {
                // Convert ContainerStatus to ContainerState
                match container.status() {
                    crate::rootless::commands::ContainerStatus::Running => {
                        Ok(group::ContainerState::Running)
                    }
                    crate::rootless::commands::ContainerStatus::Created => {
                        Ok(group::ContainerState::Created)
                    }
                    crate::rootless::commands::ContainerStatus::Stopped => {
                        Ok(group::ContainerState::Stopped)
                    }
                }
            }
            Err(e) => {
                // Container not found or error loading - treat as stopped
                tracing::debug!(
                    "[ContainerManager] Failed to load container {}: {}",
                    container_id,
                    e
                );
                Err(format!("Failed to load container {}: {}", container_id, e))
            }
        }
    }
}

pub mod group {
    use serde::{Deserialize, Serialize};
    use std::path::PathBuf;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ContainerGroup {
        pub name: String,
        pub containers: Vec<ContainerInfo>,
        pub state_file: std::path::PathBuf,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ContainerInfo {
        pub id: String,
        pub name: String,
        pub container_id: String,
        pub order_index: usize,
        pub state_path: PathBuf,
        pub bundle_path: PathBuf,
    }

    impl ContainerInfo {
        pub fn new(
            id: String,
            name: String,
            container_id: String,
            order_index: usize,
            state_path: PathBuf,
            bundle_path: PathBuf,
        ) -> Self {
            Self {
                id,
                name,
                container_id,
                order_index,
                state_path,
                bundle_path,
            }
        }
    }

    impl Default for ContainerInfo {
        fn default() -> Self {
            Self {
                id: String::new(),
                name: String::new(),
                container_id: String::new(),
                order_index: 0,
                state_path: PathBuf::new(),
                bundle_path: PathBuf::new(),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ContainerState {
        Created,
        Running,
        Stopped,
    }
}
