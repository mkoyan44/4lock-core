//! Unified container crate
//!
//! This crate provides container runtime functionality for the 4Lock platform.
//! Combines app_runtime (lifecycle), bootstrap (tasks, templates), common (traits),
//! and rootless (OCI runtime) modules.
//! Intent and provisioner types are defined here so 4lock-core has no dependency on 4lock-agent runtime.

pub mod app_spec;
pub mod intent;
pub mod progress;
pub mod provisioner;

#[cfg(target_os = "linux")]
pub mod app_runtime;

pub use app_spec::{AppHandle, AppSpec, AppState, AppSummary};
pub use intent::RuntimeIntent;
pub use progress::RuntimeStartProgress;
pub use provisioner::{
    ChannelProgressReporter, ProgressReporter, ProvisionError,
};

// Bootstrap (tasks, templates, intent loop)
pub mod bootstrap;
pub use bootstrap::{
    check_system_requirements, run_intent_command_loop, ContainerProvisionerConfig,
    TemplateRenderer,
};

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

// CRI (Container Runtime Interface) server for debugging containers via crictl
#[cfg(target_os = "linux")]
pub mod cri;
