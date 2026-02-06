/// ContainerTask - unified task type for container operations (similar to VmTask)
use super::kubectl_task::KubectlTask;
use std::borrow::Cow;
use std::time::Duration;

/// Unified task enum for container operations
#[derive(Debug, Clone)]
pub enum ContainerTask {
    Kubectl(KubectlTask),
}

impl ContainerTask {
    /// Get task display name
    pub fn display_name(&self) -> Cow<'_, str> {
        match self {
            ContainerTask::Kubectl(task) => Cow::Owned(format!("kubectl/{}", task.name)),
        }
    }

    /// Get normalized task ID for tracking
    pub fn task_id(&self) -> Cow<'static, str> {
        Cow::Owned(Self::normalize_task_name(self.display_name().as_ref()))
    }

    fn normalize_task_name(raw: &str) -> String {
        let trimmed = raw.trim();
        let mut normalized = if trimmed.contains('/') {
            trimmed.replace('/', ".")
        } else {
            trimmed.to_owned()
        };

        if normalized.contains('-') {
            normalized = normalized.replace('-', "_");
        }

        normalized
    }

    /// Get task timeout
    pub fn get_timeout(&self) -> Duration {
        match self {
            ContainerTask::Kubectl(task) => task.get_timeout(),
        }
    }

    /// Get task name
    pub fn get_name(&self) -> String {
        self.display_name().into_owned()
    }

    /// Create kubectl task
    pub fn kubectl(task: KubectlTask) -> Self {
        ContainerTask::Kubectl(task)
    }
}
