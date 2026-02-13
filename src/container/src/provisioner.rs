//! Progress reporting and error types for provisioning operations.
//! (4lock-core; no dependency on 4lock-agent runtime.)

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
        _phase: Option<String>,
        _task_name: Option<String>,
    ) {
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
