/// ExecTask — run a command inside a container
use crate::app_spec::TaskSpec;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ExecTask {
    pub name: String,
    pub command: Vec<String>,
    pub timeout: Duration,
}

impl ExecTask {
    pub fn from_spec(spec: &TaskSpec) -> Self {
        Self {
            name: spec.name.clone(),
            command: spec.command.clone(),
            timeout: Duration::from_secs(spec.timeout_secs),
        }
    }

    pub fn new(name: impl Into<String>, command: Vec<String>) -> Self {
        Self {
            name: name.into(),
            command,
            timeout: Duration::from_secs(120),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn display_name(&self) -> String {
        self.name.clone()
    }

    pub fn task_id(&self) -> String {
        self.name
            .trim()
            .replace('/', ".")
            .replace('-', "_")
    }

    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }
}
