//! CRI (Container Runtime Interface) server implementation
//!
//! Provides gRPC server that implements Kubernetes CRI protocol,
//! allowing kubelet to use vapp's libcontainer runtime directly.

#[cfg(target_os = "linux")]
pub mod server;
#[cfg(target_os = "linux")]
pub mod runtime_service;
#[cfg(target_os = "linux")]
pub mod image_service;
#[cfg(target_os = "linux")]
pub mod sandbox;
#[cfg(target_os = "linux")]
pub mod container_registry;

#[cfg(target_os = "linux")]
pub use server::CriServer;
