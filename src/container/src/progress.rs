//! Progress types for container provisioning (4lock-core; no dependency on 4lock-agent runtime).

use serde::{Deserialize, Serialize};

/// Start progress for runtime instances.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RuntimeStartProgress {
    pub percentage: u32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_name: Option<String>,
}

impl RuntimeStartProgress {
    pub fn new(instance_name: Option<String>, percentage: u32, message: String) -> Self {
        Self {
            percentage,
            message,
            phase: None,
            instance_name,
            task_name: None,
        }
    }
}
