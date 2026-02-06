//! Pod sandbox management for CRI
//!
//! This module provides pod sandbox lifecycle management.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

/// Sandbox state tracking
#[derive(Debug, Clone)]
pub struct SandboxState {
    pub id: String,
    pub pause_container_id: String,
    pub network_namespace: PathBuf,
    pub created_at: SystemTime,
    // CRI Metadata fields
    pub name: String,
    pub namespace: String,
    pub uid: String,
    pub attempt: u32,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}

/// Registry for tracking pod sandboxes
pub struct SandboxRegistry {
    pub sandboxes: HashMap<String, SandboxState>,
    pub app_dir: PathBuf,
}

impl SandboxRegistry {
    pub fn new(app_dir: PathBuf) -> Self {
        Self {
            sandboxes: HashMap::new(),
            app_dir,
        }
    }

    /// Create a new pod sandbox
    pub fn create_sandbox(
        &mut self,
        sandbox_id: &str,
        name: &str,
        namespace: &str,
        uid: &str,
        attempt: u32,
        labels: HashMap<String, String>,
        annotations: HashMap<String, String>,
    ) -> Result<SandboxState, String> {
        if self.sandboxes.contains_key(sandbox_id) {
            return Err(format!("Sandbox {} already exists", sandbox_id));
        }

        let pause_container_id = format!("{}-pause", sandbox_id);
        let network_namespace = self
            .app_dir
            .join("containers")
            .join(&pause_container_id)
            .join("ns")
            .join("net");

        let state = SandboxState {
            id: sandbox_id.to_string(),
            pause_container_id,
            network_namespace,
            created_at: SystemTime::now(),
            name: name.to_string(),
            namespace: namespace.to_string(),
            uid: uid.to_string(),
            attempt,
            labels,
            annotations,
        };

        self.sandboxes.insert(sandbox_id.to_string(), state.clone());
        Ok(state)
    }

    /// Get a sandbox by ID
    pub fn get_sandbox(&self, sandbox_id: &str) -> Option<&SandboxState> {
        self.sandboxes.get(sandbox_id)
    }

    /// Remove a sandbox
    pub fn remove_sandbox(&mut self, sandbox_id: &str) -> Option<SandboxState> {
        self.sandboxes.remove(sandbox_id)
    }

    /// List all sandboxes
    pub fn list_sandboxes(&self) -> Vec<&SandboxState> {
        self.sandboxes.values().collect()
    }
}

/// Convert SystemTime to nanoseconds since Unix epoch
pub fn system_time_to_nanos(time: SystemTime) -> i64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Convert RFC3339 timestamp string to nanoseconds
pub fn rfc3339_to_nanos(s: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.timestamp_nanos_opt().unwrap_or(0))
        .unwrap_or(0)
}
