//! vappc: minimal vappd and vappctl for 4lock-core. No dependency on 4lock-agent.

pub mod client;
pub mod daemon;
pub mod protocol;

pub use client::{ping_over_stream, VappcClient};
pub use daemon::run_daemon_server;
pub use protocol::{VappcCommand, VappcResponse};

// Re-export intent types so callers use a single crate.
pub use container::intent::{Endpoint, InstanceHandle, InstanceRole, InstanceState, VappSpec};
