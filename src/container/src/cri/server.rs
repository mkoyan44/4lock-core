


//! CRI gRPC server implementation
//!
//! This module provides a gRPC server that implements the Kubernetes CRI protocol.

use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::{TcpListener, UnixListener};
use tokio_stream::wrappers::{TcpListenerStream, UnixListenerStream};
use tonic::transport::Server;

use super::image_service::ImageServiceImpl;
use super::runtime_service::RuntimeServiceImpl;
use super::sandbox::SandboxRegistry;

/// Generated protobuf types
pub mod runtime {
    pub mod v1 {
        tonic::include_proto!("runtime.v1");
    }
}

use runtime::v1::image_service_server::ImageServiceServer;
use runtime::v1::runtime_service_server::RuntimeServiceServer;

/// CRI Server configuration
pub struct CriServer {
    socket_path: PathBuf,
    tcp_port: Option<u16>,
    app_dir: PathBuf,
}

impl CriServer {
    /// Create a new CRI server
    pub fn new(socket_path: PathBuf, tcp_port: Option<u16>, app_dir: PathBuf) -> Self {
        Self {
            socket_path,
            tcp_port,
            app_dir,
        }
    }

    /// Start the CRI server
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            "[CRI] Starting CRI server on socket: {:?}",
            self.socket_path
        );

        // Create shared state
        let image_cache_dir = self.app_dir.join("containers/images");
        let sandbox_registry = Arc::new(tokio::sync::Mutex::new(SandboxRegistry::new(
            self.app_dir.clone(),
        )));

        // Create service implementations
        let runtime_service = RuntimeServiceImpl::new(
            self.app_dir.clone(),
            image_cache_dir.clone(),
            Arc::clone(&sandbox_registry),
        );
        let image_service = ImageServiceImpl::new(image_cache_dir.clone());

        // Ensure socket parent directory exists
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Remove existing socket file
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        // Bind Unix socket
        let unix_listener = UnixListener::bind(&self.socket_path)?;
        tracing::info!(
            "[CRI] CRI server listening on Unix socket: {:?}",
            self.socket_path
        );

        // Set socket permissions (rw-rw----)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o660))?;
        }
        tracing::info!("[CRI] Socket permissions set, ready to accept connections");

        let unix_stream = UnixListenerStream::new(unix_listener);

        // Build gRPC server with interceptor for debugging
        let server = Server::builder()
            .trace_fn(|_| tracing::info_span!("[CRI] request"))
            .add_service(RuntimeServiceServer::new(runtime_service))
            .add_service(ImageServiceServer::new(image_service));

        tracing::info!("[CRI] Starting gRPC server...");

        // Start TCP server if port is configured
        if let Some(port) = self.tcp_port {
            let tcp_addr = format!("127.0.0.1:{}", port);
            tracing::info!("[CRI] Also starting TCP endpoint on: {}", tcp_addr);

            let tcp_listener = TcpListener::bind(&tcp_addr).await?;
            tracing::info!("[CRI] TCP listener bound to: {}", tcp_addr);

            // Clone for TCP server
            let tcp_sandbox_registry = Arc::clone(&sandbox_registry);
            let tcp_app_dir = self.app_dir.clone();
            let tcp_image_cache_dir = self.app_dir.join("containers/images");

            let tcp_runtime_service =
                RuntimeServiceImpl::new(tcp_app_dir, tcp_image_cache_dir.clone(), tcp_sandbox_registry);
            let tcp_image_service = ImageServiceImpl::new(tcp_image_cache_dir);

            let tcp_server = Server::builder()
                .add_service(RuntimeServiceServer::new(tcp_runtime_service))
                .add_service(ImageServiceServer::new(tcp_image_service));

            // Spawn TCP server in separate task
            tokio::spawn(async move {
                let tcp_incoming = TcpListenerStream::new(tcp_listener);
                if let Err(e) = tcp_server.serve_with_incoming(tcp_incoming).await {
                    tracing::error!("[CRI] TCP server error: {}", e);
                }
            });
        }

        tracing::info!(
            "[CRI] Server ready on Unix socket: {:?} and TCP: {:?}",
            self.socket_path,
            self.tcp_port.map(|p| format!("127.0.0.1:{}", p))
        );

        tracing::info!(
            "[CRI] kubelet should use: unix://{:?}",
            self.socket_path
        );
        if let Some(port) = self.tcp_port {
            tracing::info!("[CRI] crictl should use: tcp://127.0.0.1:{}", port);
        }

        // Run Unix socket server
        server.serve_with_incoming(unix_stream).await?;

        Ok(())
    }
}
