//! Intent and spec types for container provisioning (4lock-core; no dependency on 4lock-agent runtime).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

use crate::progress::RuntimeStartProgress;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InstanceRole {
    Device,
    App,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSpec {
    pub name: String,
    pub service_cidr: String,
    pub pod_cidr: String,
    pub dns_address: String,
    #[serde(default)]
    pub upstream_api: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSpec {
    pub zt_network_id: String,
    pub zt_token: String,
    #[serde(default)]
    pub docker_proxy_ca_cert: Option<String>,
    #[serde(default)]
    pub docker_proxy_host: Option<String>,
    #[serde(default)]
    pub docker_proxy_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSpec {
    pub disk_type: String,
    pub size_mb: u64,
    pub mount_path: String,
    #[serde(default)]
    pub bind_mounts: Vec<String>,
    #[serde(default = "default_managed_by")]
    pub managed_by: String,
}

fn default_managed_by() -> String {
    "vm".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSpec {
    pub memory_mb: u64,
    pub cpu_cores: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VappSpec {
    pub instance_id: String,
    pub role: InstanceRole,
    pub cluster: ClusterSpec,
    pub network: NetworkSpec,
    pub storage: Vec<StorageSpec>,
    pub resources: ResourceSpec,
    #[serde(default)]
    pub kubeconfig: Option<String>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub app_type: Option<String>,
    #[serde(default)]
    pub app_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceHandle {
    pub instance_id: String,
    pub endpoint: Endpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Endpoint {
    Socket(PathBuf),
    Tcp(String),
    Vsock { cid: u32, port: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountSpec {
    pub host_path: String,
    pub container_path: String,
    #[serde(default)]
    pub read_only: bool,
}

/// Generic container run spec for ad-hoc/debug runs (image + cmd + args + env + mounts).
/// Used with VappcCommand::RunContainer and RuntimeIntent::RunContainer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRunSpec {
    pub image: String,
    #[serde(default)]
    pub command: Option<Vec<String>>,
    #[serde(default)]
    pub args: Option<Vec<String>>,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub mounts: Option<Vec<MountSpec>>,
    #[serde(default)]
    pub instance_id: Option<String>,
    #[serde(default)]
    pub privileged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceState {
    Provisioning { progress: u32 },
    Running,
    Stopped,
    Failed { reason: String },
}

/// High-level intent - what the controller wants (used by intent loop).
#[derive(Debug)]
pub enum RuntimeIntent {
    Start {
        spec: Box<VappSpec>,
        progress: mpsc::Sender<RuntimeStartProgress>,
        callback: oneshot::Sender<Result<InstanceHandle, String>>,
    },
    /// Run a single container from a generic spec (image, command, args, env, mounts). Used for debug/ad-hoc.
    RunContainer {
        spec: ContainerRunSpec,
        progress: mpsc::Sender<RuntimeStartProgress>,
        callback: oneshot::Sender<Result<InstanceHandle, String>>,
    },
    Stop {
        instance_id: String,
    },
    GetState {
        instance_id: String,
        reply: mpsc::Sender<InstanceState>,
    },
    GetEndpoint {
        instance_id: String,
        callback: oneshot::Sender<Result<Endpoint, String>>,
    },
}
