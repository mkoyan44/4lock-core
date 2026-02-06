//! HTTPS docker-proxy server example
//!
//! This example shows how to start a docker-proxy server with HTTPS/TLS enabled.
//!
//! Run with:
//! ```bash
//! cargo run --example https_server
//! ```

use blob::{ensure_certificates, start_server, Config};
use std::path::PathBuf;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create cache directory
    let cache_dir = PathBuf::from("/tmp/docker-proxy-cache");

    // Create certs directory
    let certs_dir = PathBuf::from("/tmp/docker-proxy-certs");
    std::fs::create_dir_all(&certs_dir)?;

    // Generate certificates using vault callbacks (simplified for example)
    tracing::info!("Generating TLS certificates...");
    let hostnames = vec!["docker-proxy.internal".to_string(), "localhost".to_string()];
    let ip_addresses = vec!["127.0.0.1".to_string()];

    let cert_bundle = ensure_certificates(
        || {
            // Load from vault (simplified - return None to generate new)
            Ok(None)
        },
        |_bundle| {
            // Store to vault (simplified - do nothing)
            Ok(())
        },
        hostnames,
        ip_addresses,
    )
    .expect("Failed to generate certificates");

    // Load config
    let mut config = Config::default();
    config.server.port = 5050;

    tracing::info!("Starting docker-proxy server with HTTPS...");
    tracing::info!("  Port: {}", config.server.port);
    tracing::info!("  Cache directory: {:?}", cache_dir);
    tracing::info!("  CA certificate expiry: {}", cert_bundle.ca_expiry);
    tracing::info!("  Server certificate expiry: {}", cert_bundle.server_expiry);
    tracing::info!("  Press Ctrl+C to stop");

    // Use certificate PEM strings directly
    let server_cert_pem = cert_bundle.server_cert_pem;
    let server_key_pem = cert_bundle.server_key_pem;

    // Start server with TLS
    let _server_handle = start_server(
        cache_dir,
        config,
        Some(server_cert_pem),
        Some(server_key_pem),
    )
    .await
    .expect("Failed to start server");

    tracing::info!("\nServer is running on https://localhost:5050");
    tracing::info!("Note: You may need to trust the CA certificate for clients to connect");

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    tracing::info!("\nShutting down...");

    Ok(())
}
