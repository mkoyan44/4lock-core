//! Container-specific error types
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContainerError {
    #[error("Container error: {0}")]
    Other(String),
    #[error("Container not found: {0}")]
    ContainerNotFound(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Libcontainer error: {0}")]
    LibcontainerError(String),
    #[error("Operation failed: {0}")]
    OperationFailed(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("Image not found: {0}")]
    ImageNotFound(String),
}

#[cfg(target_os = "linux")]
impl From<libcontainer::error::LibcontainerError> for ContainerError {
    fn from(e: libcontainer::error::LibcontainerError) -> Self {
        ContainerError::LibcontainerError(e.to_string())
    }
}

impl From<String> for ContainerError {
    fn from(s: String) -> Self {
        ContainerError::Other(s)
    }
}
