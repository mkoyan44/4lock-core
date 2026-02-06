use crate::config::{RegistryConfig, UpstreamTlsConfig};
use crate::error::{DockerProxyError, Result};
use reqwest::Client;

/// HTTP client for upstream registry requests with multi-mirror support
pub struct UpstreamClient {
    clients: Vec<Client>,
    mirrors: Vec<String>,
    auth: Option<(String, String)>,
}

impl UpstreamClient {
    pub fn new(
        mirrors: Vec<String>,
        upstream_tls: &UpstreamTlsConfig,
        registry_config: Option<&RegistryConfig>,
    ) -> Result<Self> {
        // Create one client per mirror (each with same TLS config)
        // Configure connection pooling and HTTP/2 support
        let clients: Result<Vec<Client>> = mirrors
            .iter()
            .map(|_| {
                // Get timeout from registry config or use default
                let timeout_secs = registry_config.map(|r| r.timeout_secs).unwrap_or(30);

                let client_builder = reqwest::Client::builder()
                    .danger_accept_invalid_certs(
                        upstream_tls.insecure_skip_verify
                            || registry_config.map(|r| r.insecure).unwrap_or(false),
                    )
                    // Connection pool configuration
                    .pool_max_idle_per_host(10) // Max idle connections per host
                    .pool_idle_timeout(std::time::Duration::from_secs(90)) // Keep connections alive for 90s
                    // Enable HTTP/2 where supported (but don't force it - let server negotiate)
                    // Removed http2_prior_knowledge() as it forces HTTP/2 and may cause issues
                    // HTTP/2 will be negotiated automatically if server supports it
                    // Timeout configuration - use config value instead of hardcoded
                    .timeout(std::time::Duration::from_secs(timeout_secs))
                    .connect_timeout(std::time::Duration::from_secs(10));

                // Configure TLS
                client_builder.build().map_err(DockerProxyError::Http)
            })
            .collect();

        let clients = clients?;

        let auth = registry_config
            .and_then(|r| r.auth.as_ref())
            .map(|a| (a.username.clone(), a.password.clone()));

        Ok(Self {
            clients,
            mirrors,
            auth,
        })
    }

    pub fn mirrors(&self) -> &[String] {
        &self.mirrors
    }

    pub fn client(&self, mirror_index: usize) -> &Client {
        &self.clients[mirror_index % self.clients.len()]
    }

    pub fn auth(&self) -> Option<&(String, String)> {
        self.auth.as_ref()
    }
}
