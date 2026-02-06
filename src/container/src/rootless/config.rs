//! Container configuration types
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    pub root_path: PathBuf,
    pub container_name: String,
    pub container_type: String,
    pub image: String,
    pub command: Vec<String>,
    pub args: Vec<String>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
    pub environment: HashMap<String, String>,
    pub volumes: HashMap<String, String>,
    pub network_mode: String,
    pub cpu_limit: Option<u64>,
    pub memory_limit: Option<u64>,
    pub memory_limit_mb: Option<u64>,
    pub capabilities: Vec<String>,
    pub devices: Vec<String>,
    pub mounts: Vec<serde_json::Value>,
    pub dns_servers: Vec<String>,
}

impl ContainerConfig {
    pub fn new(container_name: String, container_type: String) -> Self {
        Self {
            root_path: PathBuf::new(),
            container_name,
            container_type,
            image: String::new(),
            command: Vec::new(),
            args: Vec::new(),
            working_dir: None,
            user: None,
            environment: HashMap::new(),
            volumes: HashMap::new(),
            network_mode: "new".to_string(),
            cpu_limit: None,
            memory_limit: None,
            memory_limit_mb: None,
            capabilities: Vec::new(),
            devices: Vec::new(),
            mounts: Vec::new(),
            dns_servers: Vec::new(),
        }
    }

    pub fn with_cpu_limit(mut self, cpu: u64) -> Self {
        self.cpu_limit = Some(cpu);
        self
    }

    pub fn with_memory_limit(mut self, memory: u64) -> Self {
        self.memory_limit = Some(memory);
        self.memory_limit_mb = Some(memory);
        self
    }

    pub fn add_env(mut self, key: String, value: String) -> Self {
        self.environment.insert(key, value);
        self
    }

    pub fn with_base_image(mut self, image: String) -> Self {
        self.image = image;
        self
    }
}

pub mod container_dir {
    use std::path::PathBuf;

    pub fn init_app_dir(_app_dir: PathBuf) {
        // Stub implementation
    }
}
