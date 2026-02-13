//! AppSpec — standardized application specification for 4lock-core.
//!
//! Defines what to run (image, command, env, resources) and lifecycle hooks
//! (config templates to render, setup tasks to execute after start).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level application specification.
///
/// One AppSpec = one container launched directly by the core runtime.
/// Scaling is handled by the platform (spinning up more core instances).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSpec {
    /// Unique application instance ID
    pub app_id: String,
    /// Human-readable application name
    pub name: String,
    /// OCI image reference (e.g., "nginx:alpine", "zerotier/zerotier:latest")
    pub image: String,

    /// Command to run (overrides image entrypoint)
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Arguments to command (overrides image cmd)
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// Environment variables (KEY=VALUE format)
    #[serde(default)]
    pub env: Vec<String>,
    /// Volume mounts
    #[serde(default)]
    pub mounts: Vec<MountSpec>,
    /// CPU and memory resource limits
    #[serde(default)]
    pub resources: Option<ResourceSpec>,
    /// Run as privileged (no user namespace, full capabilities — for ZeroTier TUN device)
    #[serde(default)]
    pub privileged: bool,
    /// Working directory inside the container
    #[serde(default)]
    pub working_dir: Option<String>,

    // --- Lifecycle hooks ---

    /// Template variables for rendering config files.
    /// Available in templates as `{{ var_name }}` alongside `{{ app_id }}` and `{{ app_name }}`.
    #[serde(default)]
    pub template_vars: HashMap<String, String>,

    /// Config files to render into the container after start.
    /// Templates are rendered with template_vars + app metadata, then written to destination paths.
    #[serde(default)]
    pub config_templates: Vec<ConfigTemplate>,

    /// Setup tasks to run inside the container after start (sequential, ordered).
    /// Each task is an exec into the running container. All must succeed for the app to be "ready".
    #[serde(default)]
    pub setup_tasks: Vec<TaskSpec>,
}

/// A config file to render from a template and write into the container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigTemplate {
    /// Template name (e.g., "app/nginx.conf.j2") — resolved from embedded or filesystem templates
    pub template: String,
    /// Destination path inside the container (e.g., "/etc/nginx/nginx.conf")
    pub destination: String,
}

/// A setup task to execute inside the container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSpec {
    /// Display name for progress reporting
    pub name: String,
    /// Command to exec inside the container
    pub command: Vec<String>,
    /// Timeout in seconds (default: 120)
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    120
}

/// Volume mount specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountSpec {
    /// Host path (source)
    pub host_path: String,
    /// Container path (destination)
    pub container_path: String,
    /// Read-only mount
    #[serde(default)]
    pub read_only: bool,
}

/// CPU and memory resource limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSpec {
    /// Memory limit in megabytes
    #[serde(default)]
    pub memory_mb: Option<u64>,
    /// CPU core limit (e.g., 2 = two cores)
    #[serde(default)]
    pub cpu_cores: Option<u32>,
}

// --- Response / state types ---

/// Handle returned after successfully starting an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppHandle {
    pub app_id: String,
    pub name: String,
}

/// Runtime state of an application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppState {
    Starting,
    Running,
    Stopped,
    Failed { reason: String },
}

/// Summary of a running app (for list responses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSummary {
    pub app_id: String,
    pub name: String,
    pub state: AppState,
}
