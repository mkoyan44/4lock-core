//! Minimal wire protocol for vappc daemon (4lock-core). No dependency on 4lock-agent.

use serde::{Deserialize, Serialize};

use container::intent::{
    ContainerRunSpec, Endpoint, InstanceHandle, InstanceState, VappSpec,
};

/// Commands the minimal daemon accepts over the Unix socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "data")]
pub enum VappcCommand {
    /// Health check; daemon responds with OkUnit when ready to accept commands.
    Ping,
    Start {
        spec: VappSpec,
    },
    /// Run a single container from a generic spec (image, command, args, env, mounts). For debug/ad-hoc.
    RunContainer {
        spec: ContainerRunSpec,
    },
    Stop {
        instance_id: String,
    },
    GetState {
        instance_id: String,
    },
    GetEndpoint {
        instance_id: String,
    },
    /// Query network interface IP address (e.g., eth0, zt0)
    GetInterfaceIp {
        interface: String,
    },
}

/// Response sent back to the client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum VappcResponse {
    OkHandle(InstanceHandle),
    OkState(InstanceState),
    OkEndpoint(Endpoint),
    OkUnit,
    OkInterfaceIp { interface: String, ip: Option<String> },
    Err { message: String },
}

impl VappcResponse {
    pub fn ok_handle(h: InstanceHandle) -> Self {
        VappcResponse::OkHandle(h)
    }
    pub fn ok_state(s: InstanceState) -> Self {
        VappcResponse::OkState(s)
    }
    pub fn ok_endpoint(e: Endpoint) -> Self {
        VappcResponse::OkEndpoint(e)
    }
    pub fn ok_unit() -> Self {
        VappcResponse::OkUnit
    }
    pub fn ok_interface_ip(interface: String, ip: Option<String>) -> Self {
        VappcResponse::OkInterfaceIp { interface, ip }
    }
    pub fn err(message: String) -> Self {
        VappcResponse::Err { message }
    }

    pub fn is_err(&self) -> bool {
        matches!(self, VappcResponse::Err { .. })
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            VappcResponse::Err { message } => Some(message),
            _ => None,
        }
    }
}
