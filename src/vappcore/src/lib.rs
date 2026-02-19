//! vapp-core: daemon and client for 4lock-core. No dependency on 4lock-agent.

pub mod client;
pub mod daemon;
pub mod protocol;

pub use client::{VappCorePing, VappCoreStream};
pub use protocol::{
    ContainerGroupResult, ContainerGroupSpec, DnsRecord, ErrorCategory, ResponseData,
    VappCoreCommand, WireError, WireMessage,
};
