use thiserror::Error;

pub type Result<T> = std::result::Result<T, DockerProxyError>;

#[derive(Error, Debug)]
pub enum DockerProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Registry error: {0}")]
    Registry(String),
}
