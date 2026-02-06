/// KubectlTask - applies or deletes Kubernetes manifests via kubectl container
use std::time::Duration;

/// Action to perform with kubectl
#[derive(Debug, Clone)]
pub enum KubectlAction {
    Apply,
    Delete,
}

/// Task for applying/deleting Kubernetes manifests via kubectl container
#[derive(Debug, Clone)]
pub struct KubectlTask {
    /// Task name for logging
    pub name: String,
    /// YAML manifest content to apply
    pub manifest_content: String,
    /// Action: Apply or Delete
    pub action: KubectlAction,
    /// Timeout for the operation
    pub timeout: Duration,
}

impl KubectlTask {
    /// Create a new apply task
    pub fn apply(name: impl Into<String>, manifest: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            manifest_content: manifest.into(),
            action: KubectlAction::Apply,
            timeout: Duration::from_secs(120),
        }
    }

    /// Create a new delete task
    pub fn delete(name: impl Into<String>, manifest: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            manifest_content: manifest.into(),
            action: KubectlAction::Delete,
            timeout: Duration::from_secs(60),
        }
    }

    /// Set custom timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get display name for logging
    pub fn display_name(&self) -> String {
        format!("kubectl/{}", self.name)
    }

    /// Get timeout
    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }

    /// Get action string
    pub fn action_str(&self) -> &'static str {
        match self.action {
            KubectlAction::Apply => "apply",
            KubectlAction::Delete => "delete",
        }
    }
}
