pub mod image;
/// Container-specific types and traits
///
/// This module provides container-native abstractions for container lifecycle management.
/// All types use container terminology.
pub mod types;
pub mod volume;

pub use image::{ImageReference, RegistryAuth};
pub use types::{
    ContainerError, ContainerInfo, ContainerInstanceState, ContainerRuntime, ContainerState,
    ExecResult, StartContainerParams,
};
pub use volume::{VolumeMount, VolumeSpec};
