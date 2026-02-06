//! Unified container crate
//!
//! This crate provides container runtime functionality for the 4Lock Agent.
//! It combines bootstrap (provisioner), common (types), and rootless (OCI runtime implementation) modules.
//! Intent and provisioner types are defined here so 4lock-core has no dependency on 4lock-agent runtime.

pub mod intent;
pub mod progress;
pub mod provisioner;

pub use intent::{
    ClusterSpec, ContainerRunSpec, Endpoint, InstanceHandle, InstanceRole, InstanceState,
    MountSpec, NetworkSpec, ResourceSpec, RuntimeIntent, StorageSpec, VappSpec,
};
pub use progress::RuntimeStartProgress;
pub use provisioner::{
    ChannelProgressReporter, ProgressReporter, ProvisionError, RuntimeProvisioner,
};

// Bootstrap (provisioner and workflow)
pub mod bootstrap;
pub use bootstrap::{
    check_system_requirements, get_k8s_components, get_k8s_components_secure,
    run_intent_command_loop, ContainerProvisioner, ContainerProvisionerConfig, K8sComponent,
    TemplateRenderer,
};
#[cfg(target_os = "linux")]
pub use bootstrap::{UtilityContainerConfig, UtilityContainerOutput, UtilityRunner};

// Common types and traits
pub mod common;
pub use common::*;

// Rootless OCI runtime implementation (only on Linux)
#[cfg(target_os = "linux")]
pub mod rootless;

#[cfg(target_os = "linux")]
pub use rootless::{
    load_container, ContainerConfig, ContainerManager, ContainerStatus, RootlessContainerRuntime,
    LoadedContainer,
};

// CRI server (only on Linux)
#[cfg(target_os = "linux")]
pub mod cri;
#[cfg(target_os = "linux")]
pub use cri::CriServer;
