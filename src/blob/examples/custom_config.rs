//! Custom configuration example
//!
//! This example shows how to configure docker-proxy with custom registry settings.
//!
//! Run with:
//! ```bash
//! cargo run --example custom_config
//! ```

use blob::config::MirrorStrategy;
use blob::config::RegistryConfig;
use blob::{start_server, Config};
use std::path::PathBuf;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create cache directory
    let cache_dir = PathBuf::from("/tmp/docker-proxy-cache");

    // Create custom config
    let mut config = Config::default();
    config.server.port = 5050;
    config.cache.max_size_gb = 50;

    // Configure quay.io registry
    config.upstream.registries.insert(
        "quay.io".to_string(),
        RegistryConfig {
            mirrors: vec!["https://quay.io".to_string()],
            strategy: MirrorStrategy::Failover,
            max_parallel: 4,
            chunk_size: 16_777_216, // 16MB
            hedge_delay_ms: 100,
            timeout_secs: 30,
            auth: None,
            ca_cert_path: None,
            insecure: false,
        },
    );

    // Configure docker.io registry with multiple mirrors
    config.upstream.registries.insert(
        "docker.io".to_string(),
        RegistryConfig {
            mirrors: vec![
                "https://registry-1.docker.io".to_string(),
                "https://mirror.gcr.io".to_string(),
            ],
            strategy: MirrorStrategy::Hedged,
            max_parallel: 4,
            chunk_size: 16_777_216,
            hedge_delay_ms: 50,
            timeout_secs: 30,
            auth: None,
            ca_cert_path: None,
            insecure: false,
        },
    );

    tracing::info!("Starting docker-proxy server with custom configuration...");
    tracing::info!("  Port: {}", config.server.port);
    tracing::info!("  Cache size: {} GB", config.cache.max_size_gb);
    tracing::info!("  Configured registries:");
    for (name, reg_config) in &config.upstream.registries {
        tracing::info!(
            "    {}: {} mirror(s), strategy: {:?}",
            name,
            reg_config.mirrors.len(),
            reg_config.strategy
        );
    }
    tracing::info!("  Press Ctrl+C to stop");

    // Start server
    let _server_handle = start_server(cache_dir, config, None, None)
        .await
        .expect("Failed to start server");

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    tracing::info!("\nShutting down...");

    Ok(())
}
