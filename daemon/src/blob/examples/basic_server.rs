//! Basic docker-proxy server example
//!
//! This example shows how to start a docker-proxy server with default configuration.
//!
//! Run with:
//! ```bash
//! cargo run --example basic_server
//! ```

use blob::{start_server, Config};
use std::path::PathBuf;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create cache directory
    let cache_dir = PathBuf::from("/tmp/docker-proxy-cache");

    // Load or create default config
    let mut config = Config::default();
    config.server.port = 5050;

    tracing::info!("Starting docker-proxy server...");
    tracing::info!("  Port: {}", config.server.port);
    tracing::info!("  Cache directory: {:?}", cache_dir);
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
