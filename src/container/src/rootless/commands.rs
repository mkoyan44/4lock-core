//! OCI CLI commands and container loading
use std::path::Path;

pub struct LoadedContainer {
    pub id: String,
    pub status: ContainerStatus,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerStatus {
    Created,
    Running,
    Stopped,
}

impl LoadedContainer {
    pub fn status(&self) -> ContainerStatus {
        self.status
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }
}

pub fn load_container(root_path: &Path, container_id: &str) -> Result<LoadedContainer, String> {
    use serde_json::Value;
    use std::fs;

    // State file is at: <root_path>/containers/<container_id>/state.json
    // root_path is app_dir, containers are stored in app_dir/containers/
    let state_file = root_path
        .join("containers")
        .join(container_id)
        .join("state.json");

    if !state_file.exists() {
        return Err(format!("Container state file not found: {:?}", state_file));
    }

    // Read and parse state.json
    let content = fs::read_to_string(&state_file)
        .map_err(|e| format!("Failed to read state file {:?}: {}", state_file, e))?;

    let state: Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse state file {:?}: {}", state_file, e))?;

    // Extract status and PID from state.json
    let status_str = state["status"]
        .as_str()
        .ok_or_else(|| "Missing or invalid 'status' field in state file".to_string())?;

    let status = match status_str {
        "running" => ContainerStatus::Running,
        "created" => ContainerStatus::Created,
        "stopped" => ContainerStatus::Stopped,
        _ => {
            // Default to Stopped for unknown status
            ContainerStatus::Stopped
        }
    };

    // Extract PID (may be null if container is stopped)
    let pid = state["pid"].as_u64().map(|p| p as u32);

    // Verify PID is actually running (if status says running)
    let verified_status = if status == ContainerStatus::Running {
        if let Some(pid_val) = pid {
            // Check if process is still running
            // On Linux, check if /proc/<pid> exists and if it's not a zombie
            let proc_path = format!("/proc/{}", pid_val);
            let proc_stat_path = format!("/proc/{}/stat", pid_val);

            if !std::path::Path::new(&proc_path).exists() {
                // Process doesn't exist, container is actually stopped
                tracing::debug!(
                    "[load_container] Process {} doesn't exist, container is stopped",
                    pid_val
                );
                ContainerStatus::Stopped
            } else if let Ok(stat_content) = std::fs::read_to_string(&proc_stat_path) {
                // Check process state from /proc/<pid>/stat
                // State is the 3rd field in stat file
                let state_char = stat_content.split_whitespace().nth(2);
                if let Some(state) = state_char {
                    if state == "Z" {
                        // Process is a zombie (exited but not reaped)
                        tracing::debug!(
                            "[load_container] Process {} is a zombie, container is stopped",
                            pid_val
                        );
                        ContainerStatus::Stopped
                    } else if state == "T" || state == "t" {
                        // Process is stopped (T) or traced/stopped (t)
                        tracing::debug!(
                            "[load_container] Process {} is stopped (state: {}), container is stopped",
                            pid_val,
                            state
                        );
                        ContainerStatus::Stopped
                    } else {
                        // Process is running or in other active states
                        ContainerStatus::Running
                    }
                } else {
                    // Can't parse stat, assume running if process exists
                    ContainerStatus::Running
                }
            } else {
                // Can't read stat file, assume running if process directory exists
                ContainerStatus::Running
            }
        } else {
            // No PID but status says running - treat as stopped
            tracing::debug!("[load_container] No PID in state, treating as stopped");
            ContainerStatus::Stopped
        }
    } else {
        status
    };

    Ok(LoadedContainer {
        id: container_id.to_string(),
        status: verified_status,
        pid,
    })
}
