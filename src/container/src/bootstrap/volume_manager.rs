/// Volume manager for creating and managing container volumes
use crate::common::{ContainerError, VolumeMount};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing;

/// Volume manager for container volumes
pub struct VolumeManager {
    volumes_dir: PathBuf,
    volumes: HashMap<String, Vec<VolumeMount>>,
}

impl VolumeManager {
    /// Create a new volume manager
    pub fn new(app_dir: PathBuf) -> Result<Self, String> {
        let volumes_dir = app_dir.join("containers/volumes");

        std::fs::create_dir_all(&volumes_dir)
            .map_err(|e| format!("Failed to create volumes directory: {}", e))?;

        tracing::info!(
            "[VolumeManager] Initialized with volumes dir: {:?}",
            volumes_dir
        );

        Ok(Self {
            volumes_dir,
            volumes: HashMap::new(),
        })
    }

    /// Create volumes for an instance
    pub async fn create_volumes(
        &mut self,
        instance_id: &str,
        profile: &crate::bootstrap::config::VolumeProfile,
    ) -> Result<Vec<VolumeMount>, ContainerError> {
        tracing::info!(
            "[VolumeManager] Creating volumes for instance: {}",
            instance_id
        );

        let instance_volumes_dir = self.volumes_dir.join(instance_id);
        std::fs::create_dir_all(&instance_volumes_dir).map_err(ContainerError::Io)?;

        let mut mounts = Vec::new();

        for volume_spec in &profile.volumes {
            let volume_path = instance_volumes_dir.join(&volume_spec.name);

            std::fs::create_dir_all(&volume_path).map_err(ContainerError::Io)?;

            let mount = VolumeMount {
                source: volume_path.clone(),
                destination: volume_spec.mount_path.clone(),
                options: vec!["rw".to_string()],
            };

            mounts.push(mount);

            tracing::info!(
                "[VolumeManager] Created volume '{}' at {:?}",
                volume_spec.name,
                volume_path
            );
        }

        self.volumes.insert(instance_id.to_string(), mounts.clone());

        Ok(mounts)
    }

    /// Get socket path for an instance
    pub fn socket_path(&self, instance_id: &str) -> PathBuf {
        self.volumes_dir.join(instance_id).join("socket")
    }

    /// Get volumes directory
    pub fn volumes_dir(&self) -> &PathBuf {
        &self.volumes_dir
    }
}
