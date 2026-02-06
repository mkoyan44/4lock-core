/// Container bootstrap configuration
/// Loaded from container-bootstrap.toml
use crate::common::{RegistryAuth, VolumeSpec};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Container bootstrap configuration
/// Loaded from container-bootstrap.toml
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContainerProvisionerConfig {
    /// Image configuration
    #[serde(default)]
    pub image: ImageConfig,

    // resources REMOVED - now comes from VappSpec.resources
    /// Volume profiles per role
    #[serde(default)]
    pub volume_profiles: HashMap<String, VolumeProfile>,

    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,
}

impl ContainerProvisionerConfig {
    /// Load configuration from file
    pub fn load(app_dir: &std::path::Path) -> Result<Self, String> {
        // Try to find config file in multiple locations
        let config_paths = vec![
            PathBuf::from("container-bootstrap.toml"),
            PathBuf::from("crates/technology/container/container-bootstrap.toml"),
            app_dir.join("container-bootstrap.toml"),
        ];

        for path in config_paths {
            if path.exists() {
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| format!("Failed to read config file {:?}: {}", path, e))?;

                let config: ContainerProvisionerConfig = toml::from_str(&content)
                    .map_err(|e| format!("Failed to parse config file {:?}: {}", path, e))?;

                tracing::info!("Loaded container provisioner config from {:?}", path);
                return Ok(config);
            }
        }

        // Return default config if no file found
        tracing::warn!("No container-bootstrap.toml found, using defaults");
        Ok(Self::default())
    }

    /// Get volume profile for a role
    pub fn get_volume_profile(&self, role: &str) -> Option<&VolumeProfile> {
        self.volume_profiles.get(role)
    }
}

/// Image configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageConfig {
    /// Base OCI image reference
    pub base_image: String,

    /// Registry URL (optional, defaults from image ref)
    pub registry: Option<String>,

    /// Authentication (optional)
    pub auth: Option<RegistryAuth>,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            base_image: "ghcr.io/4lock/agent-base:latest".to_string(),
            registry: None,
            auth: None,
        }
    }
}

/// Volume profile for a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeProfile {
    /// Volumes in this profile
    pub volumes: Vec<VolumeSpec>,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network namespace mode
    #[serde(default)]
    pub namespace_mode: NamespaceMode,

    /// DNS servers
    #[serde(default = "default_dns_servers")]
    pub dns_servers: Vec<String>,
}

fn default_dns_servers() -> Vec<String> {
    vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            namespace_mode: NamespaceMode::New,
            dns_servers: default_dns_servers(),
        }
    }
}

/// Network namespace mode
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum NamespaceMode {
    /// Create new network namespace
    #[serde(rename = "new")]
    #[default]
    New,
    /// Use host network
    #[serde(rename = "host")]
    Host,
    /// Join existing container's network
    #[serde(rename = "container")]
    Container(String),
}
