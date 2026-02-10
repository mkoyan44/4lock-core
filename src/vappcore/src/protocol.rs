//! Wire protocol for vapp-core daemon (4lock-core). No dependency on 4lock-agent.
//!
//! ## Wire Format: NDJSON (Newline-Delimited JSON)
//!
//! Each message is a single JSON object terminated by `\n` (0x0A).
//!
//! - **Request**: One `VappCoreCommand` NDJSON line.
//! - **Response**: One or more `WireMessage` NDJSON lines.
//!   - For non-streaming commands (Ping, GetState, etc.): exactly one `Ok` or `Error` line.
//!   - For streaming commands (Start, RunContainer): zero or more `Progress` lines,
//!     followed by exactly one `Ok` or `Error` line (the terminal message).

use serde::{Deserialize, Serialize};

use container::intent::{
    ContainerRunSpec, Endpoint, InstanceHandle, InstanceState, VappSpec,
};
use container::provisioner::ProvisionError;

// ---------------------------------------------------------------------------
// Commands (client → daemon)
// ---------------------------------------------------------------------------

/// Commands the daemon accepts. Unchanged from previous protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "data")]
pub enum VappCoreCommand {
    /// Health check; daemon responds with `Ok { data: Unit }`.
    Ping,
    Start {
        spec: VappSpec,
    },
    /// Run a single container from a generic spec. For debug/ad-hoc.
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
    /// Query network interface IP address (e.g., eth0, zt0).
    GetInterfaceIp {
        interface: String,
    },
}

// ---------------------------------------------------------------------------
// Structured errors
// ---------------------------------------------------------------------------

/// Error category — classifies the failure for the agent to act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCategory {
    /// Bad configuration (spec, templates). Not retryable.
    Config,
    /// Container/VM runtime failure. May be retryable.
    Runtime,
    /// Image pull/extract failure. Usually retryable.
    Image,
    /// Volume/disk error.
    Volume,
    /// Network connectivity issue. Usually retryable.
    Network,
    /// Bootstrap script/task failure. Usually not retryable.
    Bootstrap,
    /// Filesystem I/O error.
    Io,
    /// Bug or unexpected state. Not retryable.
    Internal,
    /// Operation timed out. Retryable.
    Timeout,
}

impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCategory::Config => write!(f, "Config"),
            ErrorCategory::Runtime => write!(f, "Runtime"),
            ErrorCategory::Image => write!(f, "Image"),
            ErrorCategory::Volume => write!(f, "Volume"),
            ErrorCategory::Network => write!(f, "Network"),
            ErrorCategory::Bootstrap => write!(f, "Bootstrap"),
            ErrorCategory::Io => write!(f, "IO"),
            ErrorCategory::Internal => write!(f, "Internal"),
            ErrorCategory::Timeout => write!(f, "Timeout"),
        }
    }
}

/// Structured error sent over the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireError {
    pub category: ErrorCategory,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    pub is_retryable: bool,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(phase) = &self.phase {
            write!(f, "[{}] {}: {}", phase, self.category, self.message)
        } else {
            write!(f, "{}: {}", self.category, self.message)
        }
    }
}

impl std::error::Error for WireError {}

impl From<ProvisionError> for WireError {
    fn from(e: ProvisionError) -> Self {
        match e {
            ProvisionError::Config(msg) => WireError {
                category: ErrorCategory::Config,
                message: msg,
                phase: None,
                is_retryable: false,
            },
            ProvisionError::Runtime(msg) => WireError {
                category: ErrorCategory::Runtime,
                message: msg,
                phase: None,
                is_retryable: true,
            },
            ProvisionError::Image(msg) => WireError {
                category: ErrorCategory::Image,
                message: msg,
                phase: None,
                is_retryable: true,
            },
            ProvisionError::Volume(msg) => WireError {
                category: ErrorCategory::Volume,
                message: msg,
                phase: None,
                is_retryable: false,
            },
            ProvisionError::Bundle(msg) => WireError {
                category: ErrorCategory::Bootstrap,
                message: msg,
                phase: None,
                is_retryable: false,
            },
            ProvisionError::Network(msg) => WireError {
                category: ErrorCategory::Network,
                message: msg,
                phase: None,
                is_retryable: true,
            },
            ProvisionError::Bootstrap(msg) => WireError {
                category: ErrorCategory::Bootstrap,
                message: msg,
                phase: None,
                is_retryable: false,
            },
            ProvisionError::Io(e) => WireError {
                category: ErrorCategory::Io,
                message: e.to_string(),
                phase: None,
                is_retryable: true,
            },
        }
    }
}

impl WireError {
    /// Create an internal error (bug / unexpected state).
    pub fn internal(message: String) -> Self {
        Self {
            category: ErrorCategory::Internal,
            message,
            phase: None,
            is_retryable: false,
        }
    }

    /// Create a timeout error.
    pub fn timeout(message: String) -> Self {
        Self {
            category: ErrorCategory::Timeout,
            message,
            phase: None,
            is_retryable: true,
        }
    }

    /// Attach a provisioning phase (e.g., "etcd", "kube-apiserver", "network").
    pub fn with_phase(mut self, phase: impl Into<String>) -> Self {
        self.phase = Some(phase.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Wire messages (daemon → client, NDJSON lines)
// ---------------------------------------------------------------------------

/// A single NDJSON line sent from daemon to client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "msg")]
pub enum WireMessage {
    /// Intermediate progress update (zero or more per streaming command).
    Progress {
        percentage: u32,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        phase: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        instance_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        task_name: Option<String>,
    },
    /// Successful final response (exactly one, terminates the response stream).
    Ok {
        #[serde(flatten)]
        data: ResponseData,
    },
    /// Error final response (exactly one, terminates the response stream).
    Error(WireError),
}

impl WireMessage {
    /// Is this the terminal message? (Ok or Error)
    pub fn is_terminal(&self) -> bool {
        !matches!(self, WireMessage::Progress { .. })
    }

    pub fn ok_handle(h: InstanceHandle) -> Self {
        WireMessage::Ok {
            data: ResponseData::Handle(h),
        }
    }
    pub fn ok_state(s: InstanceState) -> Self {
        WireMessage::Ok {
            data: ResponseData::State(s),
        }
    }
    pub fn ok_endpoint(e: Endpoint) -> Self {
        WireMessage::Ok {
            data: ResponseData::Endpoint(e),
        }
    }
    pub fn ok_unit() -> Self {
        WireMessage::Ok {
            data: ResponseData::Unit,
        }
    }
    pub fn ok_interface_ip(interface: String, ip: Option<String>) -> Self {
        WireMessage::Ok {
            data: ResponseData::InterfaceIp { interface, ip },
        }
    }
    pub fn err(error: WireError) -> Self {
        WireMessage::Error(error)
    }
    /// Convenience: create an Error from a plain message (Internal category).
    pub fn err_string(message: String) -> Self {
        WireMessage::Error(WireError::internal(message))
    }

    pub fn progress(
        percentage: u32,
        message: String,
        phase: Option<String>,
        instance_name: Option<String>,
        task_name: Option<String>,
    ) -> Self {
        WireMessage::Progress {
            percentage,
            message,
            phase,
            instance_name,
            task_name,
        }
    }
}

/// Response data payload (the `data` inside `WireMessage::Ok`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ResponseData {
    Handle(InstanceHandle),
    State(InstanceState),
    Endpoint(Endpoint),
    Unit,
    InterfaceIp {
        interface: String,
        ip: Option<String>,
    },
}

