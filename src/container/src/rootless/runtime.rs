//! Rootless OCI container runtime implementation
//!
//! This module provides the main RootlessContainerRuntime implementation.

use crate::common::{ContainerError, ContainerInfo, ContainerRuntime, ContainerState, ExecResult};
use crate::rootless::lifecycle;
use async_trait::async_trait;
use std::path::PathBuf;
use std::time::Duration;

/// Rootless container runtime implementation (user namespaces, OCI/youki).
pub struct RootlessContainerRuntime {
    app_dir: PathBuf,
}

impl RootlessContainerRuntime {
    pub fn new(app_dir: PathBuf) -> Result<Self, String> {
        Ok(Self { app_dir })
    }
}

#[async_trait]
impl ContainerRuntime for RootlessContainerRuntime {
    async fn create(&self, _id: &str, _bundle: &std::path::Path) -> Result<(), ContainerError> {
        // Container creation is handled by ContainerLifecycle
        Err(ContainerError::Other(
            "Use ContainerLifecycle for container creation".to_string(),
        ))
    }

    async fn start(&self, _id: &str) -> Result<(), ContainerError> {
        // Container start is handled by ContainerLifecycle
        Err(ContainerError::Other(
            "Use ContainerLifecycle for container start".to_string(),
        ))
    }

    async fn stop(&self, id: &str, _timeout: Duration) -> Result<(), ContainerError> {
        lifecycle::stop_container(&self.app_dir, id)
            .map_err(|e| ContainerError::Other(e.to_string()))
    }

    async fn delete(&self, id: &str) -> Result<(), ContainerError> {
        lifecycle::delete_container(&self.app_dir, id, true)
            .map_err(|e| ContainerError::Other(e.to_string()))
    }

    async fn state(&self, id: &str) -> Result<ContainerState, ContainerError> {
        let state_file = self.app_dir.join("containers").join(id).join("state.json");

        if !state_file.exists() {
            return Ok(ContainerState::Stopped);
        }

        let content = std::fs::read_to_string(&state_file)
            .map_err(|e| ContainerError::Other(format!("Failed to read state: {}", e)))?;

        let state: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| ContainerError::Other(format!("Failed to parse state: {}", e)))?;

        let status = state["status"].as_str().unwrap_or("stopped");
        Ok(match status {
            "running" => ContainerState::Running,
            "created" => ContainerState::Creating,
            "stopped" => ContainerState::Stopped,
            "paused" => ContainerState::Paused,
            _ => ContainerState::Stopped,
        })
    }

    async fn list(&self) -> Result<Vec<ContainerInfo>, ContainerError> {
        let containers_dir = self.app_dir.join("containers");
        if !containers_dir.exists() {
            return Ok(vec![]);
        }

        let mut containers = Vec::new();
        let entries = std::fs::read_dir(&containers_dir)
            .map_err(|e| ContainerError::Other(format!("Failed to read dir: {}", e)))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name == "bundles" || name == "images" {
                        continue;
                    }
                    let state = self.state(name).await.unwrap_or(ContainerState::Stopped);
                    let created_at = std::fs::metadata(&path)
                        .and_then(|m| m.created())
                        .unwrap_or_else(|_| std::time::SystemTime::now());
                    containers.push(ContainerInfo {
                        id: name.to_string(),
                        state,
                        created_at,
                        bundle_path: path.join("bundle"),
                    });
                }
            }
        }

        Ok(containers)
    }

    async fn exec(&self, id: &str, cmd: &[String]) -> Result<ExecResult, ContainerError> {
        use std::process::Command;

        let state_file = self.app_dir.join("containers").join(id).join("state.json");

        if !state_file.exists() {
            return Err(ContainerError::Other(format!("Container {} not found", id)));
        }

        let content = std::fs::read_to_string(&state_file)
            .map_err(|e| ContainerError::Other(format!("Failed to read state: {}", e)))?;

        let state: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| ContainerError::Other(format!("Failed to parse state: {}", e)))?;

        let pid = state["pid"]
            .as_u64()
            .ok_or_else(|| ContainerError::Other("No PID in state".to_string()))?;

        let proc_path = format!("/proc/{}", pid);
        if !std::path::Path::new(&proc_path).exists() {
            return Err(ContainerError::Other(format!(
                "Container {} not running",
                id
            )));
        }

        let output = Command::new("nsenter")
            .arg("-t")
            .arg(pid.to_string())
            .arg("-m")
            .arg("-u")
            .arg("-i")
            .arg("-p")
            .arg("--")
            .args(cmd)
            .output()
            .map_err(|e| ContainerError::Other(format!("Exec failed: {}", e)))?;

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}
