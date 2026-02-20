//! Rootless OCI container runtime implementation
//!
//! This module provides rootless container management for Linux (user namespaces, subuid/subgid, etc.).

// Module declarations
pub mod bundle;
pub mod commands;
pub mod config;
pub mod error;
pub mod lifecycle;
pub mod orchestration;
pub mod runtime;
pub mod system_check;

// Re-exports for convenience
pub use commands::{load_container, ContainerStatus, LoadedContainer};
pub use config::ContainerConfig;
pub use orchestration::group::{
    ContainerGroup, ContainerInfo as OrchestrationContainerInfo,
    ContainerState as OrchestrationContainerState,
};
pub use orchestration::ContainerManager;
pub use runtime::RootlessContainerRuntime;
