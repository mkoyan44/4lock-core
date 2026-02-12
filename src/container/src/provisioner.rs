//! Provisioner trait and error types (4lock-core; no dependency on 4lock-agent runtime).

use async_trait::async_trait;
use std::sync::Arc;

use crate::intent::{ContainerRunSpec, Endpoint, InstanceHandle, InstanceState, VappSpec};
use crate::progress::RuntimeStartProgress;

/// Channel-based progress reporter.
pub struct ChannelProgressReporter {
    sender: tokio::sync::mpsc::Sender<RuntimeStartProgress>,
    instance_name: Option<String>,
}

impl ChannelProgressReporter {
    pub fn new(sender: tokio::sync::mpsc::Sender<RuntimeStartProgress>) -> Self {
        Self {
            sender,
            instance_name: None,
        }
    }

    pub fn with_instance_name(
        sender: tokio::sync::mpsc::Sender<RuntimeStartProgress>,
        instance_name: String,
    ) -> Self {
        Self {
            sender,
            instance_name: Some(instance_name),
        }
    }
}

impl ProgressReporter for ChannelProgressReporter {
    fn emit(&self, percentage: u32, message: String) {
        self.emit_detailed(percentage, message, None, None);
    }

    fn emit_detailed(
        &self,
        percentage: u32,
        message: String,
        phase: Option<String>,
        task_name: Option<String>,
    ) {
        let mut progress =
            RuntimeStartProgress::new(self.instance_name.clone(), percentage, message);
        progress.phase = phase;
        progress.task_name = task_name;
        let _ = self.sender.try_send(progress);
    }
}

/// Progress reporter for provisioning operations.
pub trait ProgressReporter: Send + Sync + 'static {
    fn emit(&self, percentage: u32, message: String);

    /// Emit progress with phase and task_name metadata.
    fn emit_detailed(
        &self,
        percentage: u32,
        message: String,
        phase: Option<String>,
        task_name: Option<String>,
    ) {
        // Default: ignore phase/task_name, delegate to emit
        self.emit(percentage, message);
    }
}

/// Error type for provisioning operations.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Runtime error: {0}")]
    Runtime(String),

    #[error("Image error: {0}")]
    Image(String),

    #[error("Volume error: {0}")]
    Volume(String),

    #[error("Bundle error: {0}")]
    Bundle(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Bootstrap error: {0}")]
    Bootstrap(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Runtime provisioner trait - container implements this.
#[async_trait]
pub trait RuntimeProvisioner: Send + Sync {
    async fn provision(
        &mut self,
        spec: &VappSpec,
        progress: Arc<dyn ProgressReporter>,
    ) -> Result<InstanceHandle, ProvisionError> {
        match spec.role {
            crate::intent::InstanceRole::Device => self.provision_device(spec, progress).await,
            crate::intent::InstanceRole::App => self.provision_app(spec, progress).await,
        }
    }

    async fn provision_device(
        &mut self,
        spec: &VappSpec,
        progress: Arc<dyn ProgressReporter>,
    ) -> Result<InstanceHandle, ProvisionError>;

    async fn provision_app(
        &mut self,
        spec: &VappSpec,
        progress: Arc<dyn ProgressReporter>,
    ) -> Result<InstanceHandle, ProvisionError>;

    /// Run a single container from a generic spec (image, command, args, env, mounts). For debug/ad-hoc.
    async fn run_container(
        &mut self,
        spec: &ContainerRunSpec,
        progress: Arc<dyn ProgressReporter>,
    ) -> Result<InstanceHandle, ProvisionError> {
        let _ = (spec, progress);
        Err(ProvisionError::Config(
            "run_container not implemented".to_string(),
        ))
    }

    async fn stop(&mut self, instance_id: &str) -> Result<(), String>;
    async fn state(&self, instance_id: &str) -> Result<InstanceState, String>;
    async fn endpoint(&self, instance_id: &str) -> Result<Endpoint, String>;
    async fn cleanup_all(&mut self) -> Result<usize, String>;
}
