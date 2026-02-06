/// Container volume types
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Volume specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeSpec {
    /// Volume name
    pub name: String,

    /// Size (e.g., "10Gi")
    pub size: String,

    /// Mount path in container
    pub mount_path: PathBuf,

    /// Additional bind mounts
    #[serde(default)]
    pub bind_mounts: Vec<PathBuf>,
}

/// Volume mount information
#[derive(Debug, Clone)]
pub struct VolumeMount {
    /// Source path on host
    pub source: PathBuf,

    /// Destination path in container
    pub destination: PathBuf,

    /// Mount options
    pub options: Vec<String>,
}
