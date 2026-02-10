pub mod cache;
pub mod certs;
pub mod config;
pub mod dns;
pub mod error;
pub mod helm;
pub mod prepull;
pub mod registry;
pub mod server;
pub mod tls;

pub use cache::CacheStorage;
pub use certs::{ensure_certificates, CertificateBundle};
pub use config::{Config, MirrorStrategy, RegistryConfig};
pub use error::{DockerProxyError, Result};

/// Start the docker-proxy server with the given configuration
pub async fn start_server(
    cache_dir: std::path::PathBuf,
    config: Config,
    server_cert_pem: Option<String>,
    server_key_pem: Option<String>,
) -> Result<tokio::task::JoinHandle<()>> {
    server::start_server(cache_dir, config, server_cert_pem, server_key_pem).await
}

/// Run pre-pull based on configuration
pub async fn run_pre_pull(cache_dir: std::path::PathBuf, config: &Config) -> Result<()> {
    prepull::run_pre_pull(cache_dir, config).await
}
