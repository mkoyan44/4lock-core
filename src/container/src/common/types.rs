/// Container-specific types
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Container instance state for lifecycle management
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContainerState {
    /// Container is being created
    Creating,
    /// Container is running
    Running,
    /// Container is stopped
    Stopped,
    /// Container is paused
    Paused,
    /// Container failed
    Failed,
}

/// Parameters for starting a new container.
///
/// This is container-specific: containers use OCI images and volumes, not ISO files.
pub struct StartContainerParams<'a> {
    pub name: &'a str,
    pub container_type: &'a str, // e.g., "master", "worker"
    pub cpu: usize,
    pub memory: u64,
    pub volumes: HashMap<String, PathBuf>, // volume_name -> mount_path
    pub image: &'a str,                    // OCI image reference
}

/// Container instance state for lifecycle management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerInstanceState {
    Stopped = 0,
    Running = 1,
    Paused = 2,
    Error = 3,
    Starting = 4,
    Pausing = 5,
    Resuming = 6,
    Stopping = 7,
    Unknown = -1,
}

impl From<ContainerState> for ContainerInstanceState {
    fn from(state: ContainerState) -> Self {
        match state {
            ContainerState::Creating => ContainerInstanceState::Starting,
            ContainerState::Running => ContainerInstanceState::Running,
            ContainerState::Stopped => ContainerInstanceState::Stopped,
            ContainerState::Paused => ContainerInstanceState::Paused,
            ContainerState::Failed => ContainerInstanceState::Error,
        }
    }
}

impl From<ContainerInstanceState> for ContainerState {
    fn from(state: ContainerInstanceState) -> Self {
        match state {
            ContainerInstanceState::Running => ContainerState::Running,
            ContainerInstanceState::Stopped => ContainerState::Stopped,
            ContainerInstanceState::Paused => ContainerState::Paused,
            ContainerInstanceState::Error => ContainerState::Failed,
            ContainerInstanceState::Starting => ContainerState::Creating,
            ContainerInstanceState::Pausing
            | ContainerInstanceState::Resuming
            | ContainerInstanceState::Stopping => ContainerState::Paused,
            ContainerInstanceState::Unknown => ContainerState::Failed,
        }
    }
}

/// Container lifecycle operations trait
#[async_trait]
pub trait ContainerRuntime: Send + Sync {
    /// Create container from OCI bundle
    async fn create(&self, id: &str, bundle: &Path) -> Result<(), ContainerError>;

    /// Start a created container
    async fn start(&self, id: &str) -> Result<(), ContainerError>;

    /// Stop a running container
    async fn stop(&self, id: &str, timeout: Duration) -> Result<(), ContainerError>;

    /// Delete container
    async fn delete(&self, id: &str) -> Result<(), ContainerError>;

    /// Get container state
    async fn state(&self, id: &str) -> Result<ContainerState, ContainerError>;

    /// List all containers
    async fn list(&self) -> Result<Vec<ContainerInfo>, ContainerError>;

    /// Execute command in container
    async fn exec(&self, id: &str, cmd: &[String]) -> Result<ExecResult, ContainerError>;
}

/// Container info
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    /// Container ID
    pub id: String,

    /// Current state
    pub state: ContainerState,

    /// Creation timestamp
    pub created_at: SystemTime,

    /// Path to OCI bundle
    pub bundle_path: PathBuf,
}

/// Execution result from container command
#[derive(Debug, Clone)]
pub struct ExecResult {
    /// Exit code
    pub exit_code: i32,

    /// Standard output
    pub stdout: String,

    /// Standard error
    pub stderr: String,
}

/// Container-specific error type
#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    #[error("Container not found: {0}")]
    ContainerNotFound(String),

    #[error("Container already exists: {0}")]
    ContainerExists(String),

    #[error("Invalid container state: {0}")]
    InvalidState(String),

    #[error("OCI bundle error: {0}")]
    Bundle(String),

    #[error("Runtime error: {0}")]
    Runtime(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(String),
}
