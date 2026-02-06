//! Minimal daemon server for vappc (4lock-core). Handles VappcCommand and forwards to container intent loop.
//! Supports Unix socket, VSOCK (--socket vsock:PORT), and TCP on loopback (for SSH port-forward from hosts without VSOCK, e.g. Windows).

use crate::protocol::{VappcCommand, VappcResponse};
use container::intent::RuntimeIntent;
use container::progress::RuntimeStartProgress;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(target_os = "linux")]
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::{debug, error, info};

fn cmd_short_label(cmd: &VappcCommand) -> &'static str {
    match cmd {
        VappcCommand::Ping => "Ping",
        VappcCommand::Start { .. } => "Start",
        VappcCommand::RunContainer { .. } => "RunContainer",
        VappcCommand::Stop { .. } => "Stop",
        VappcCommand::GetState { .. } => "GetState",
        VappcCommand::GetEndpoint { .. } => "GetEndpoint",
        VappcCommand::GetInterfaceIp { .. } => "GetInterfaceIp",
    }
}

/// Get IP address of a network interface by parsing `ip addr show <interface>` output
#[cfg(target_os = "linux")]
fn get_interface_ip(interface: &str) -> Result<String, String> {
    use std::process::Command;

    let output = Command::new("ip")
        .args(["addr", "show", interface])
        .output()
        .map_err(|e| format!("Failed to run ip addr: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "ip addr show {} failed: {}",
            interface,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") && !trimmed.contains("inet6") {
            // Format: inet 192.168.1.100/24 brd ...
            if let Some(ip_cidr) = trimmed.split_whitespace().nth(1) {
                // Remove CIDR suffix
                let ip = ip_cidr.split('/').next().unwrap_or("");
                if !ip.is_empty() {
                    return Ok(ip.to_string());
                }
            }
        }
    }
    Err(format!("No IPv4 address found for interface {}", interface))
}

#[cfg(not(target_os = "linux"))]
fn get_interface_ip(_interface: &str) -> Result<String, String> {
    Err("GetInterfaceIp only supported on Linux".to_string())
}

async fn handle_client<S>(mut stream: S, peer: String, intent_tx: mpsc::Sender<RuntimeIntent>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let mut buffer = vec![0u8; 65536];
    match stream.read(&mut buffer).await {
        Ok(0) => return,
        Ok(n) => {
            let request = &buffer[..n];
            debug!("Daemon: request from {} ({} bytes)", peer, n);

            let cmd: Result<VappcCommand, _> = serde_json::from_slice(request);
            if let Ok(ref c) = cmd {
                info!("Daemon: command from {}: {}", peer, cmd_short_label(c));
            }
            let response = match cmd {
                Ok(VappcCommand::Ping) => VappcResponse::ok_unit(),
                Ok(VappcCommand::Start { spec }) => {
                    let (progress_tx, _progress_rx) = mpsc::channel::<RuntimeStartProgress>(4);
                    let (callback_tx, callback_rx) = oneshot::channel();
                    let intent = RuntimeIntent::Start {
                        spec: Box::new(spec),
                        progress: progress_tx,
                        callback: callback_tx,
                    };
                    if intent_tx.send(intent).await.is_err() {
                        VappcResponse::err("Intent loop disconnected".to_string())
                    } else {
                        match callback_rx.await {
                            Ok(Ok(handle)) => VappcResponse::ok_handle(handle),
                            Ok(Err(e)) => VappcResponse::err(e),
                            Err(_) => VappcResponse::err("Intent loop dropped callback".to_string()),
                        }
                    }
                }
                Ok(VappcCommand::RunContainer { spec }) => {
                    let (progress_tx, _progress_rx) = mpsc::channel::<RuntimeStartProgress>(4);
                    let (callback_tx, callback_rx) = oneshot::channel();
                    let intent = RuntimeIntent::RunContainer {
                        spec,
                        progress: progress_tx,
                        callback: callback_tx,
                    };
                    if intent_tx.send(intent).await.is_err() {
                        VappcResponse::err("Intent loop disconnected".to_string())
                    } else {
                        match callback_rx.await {
                            Ok(Ok(handle)) => VappcResponse::ok_handle(handle),
                            Ok(Err(e)) => VappcResponse::err(e),
                            Err(_) => VappcResponse::err("Intent loop dropped callback".to_string()),
                        }
                    }
                }
                Ok(VappcCommand::Stop { instance_id }) => {
                    let intent = RuntimeIntent::Stop { instance_id };
                    if intent_tx.send(intent).await.is_err() {
                        VappcResponse::err("Intent loop disconnected".to_string())
                    } else {
                        VappcResponse::ok_unit()
                    }
                }
                Ok(VappcCommand::GetState { instance_id }) => {
                    let (reply_tx, mut reply_rx) = mpsc::channel::<container::intent::InstanceState>(1);
                    let intent = RuntimeIntent::GetState {
                        instance_id,
                        reply: reply_tx,
                    };
                    if intent_tx.send(intent).await.is_err() {
                        VappcResponse::err("Intent loop disconnected".to_string())
                    } else {
                        match reply_rx.recv().await {
                            Some(state) => VappcResponse::ok_state(state),
                            None => VappcResponse::err("Intent loop did not reply".to_string()),
                        }
                    }
                }
                Ok(VappcCommand::GetEndpoint { instance_id }) => {
                    let (callback_tx, callback_rx) = oneshot::channel();
                    let intent = RuntimeIntent::GetEndpoint {
                        instance_id,
                        callback: callback_tx,
                    };
                    if intent_tx.send(intent).await.is_err() {
                        VappcResponse::err("Intent loop disconnected".to_string())
                    } else {
                        match callback_rx.await {
                            Ok(Ok(ep)) => VappcResponse::ok_endpoint(ep),
                            Ok(Err(e)) => VappcResponse::err(e),
                            Err(_) => VappcResponse::err("Intent loop dropped callback".to_string()),
                        }
                    }
                }
                Ok(VappcCommand::GetInterfaceIp { interface }) => {
                    match get_interface_ip(&interface) {
                        Ok(ip) => VappcResponse::ok_interface_ip(interface, Some(ip)),
                        Err(_) => VappcResponse::ok_interface_ip(interface, None),
                    }
                }
                Err(e) => {
                    error!("Daemon: invalid command JSON: {}", e);
                    VappcResponse::err(format!("Invalid command: {}", e))
                }
            };

            let serialized = match serde_json::to_vec(&response) {
                Ok(b) => b,
                Err(e) => {
                    error!("Daemon: failed to serialize response: {}", e);
                    serde_json::to_vec(&VappcResponse::err(e.to_string())).unwrap_or_default()
                }
            };
            if let Err(e) = stream.write_all(&serialized).await {
                error!("Daemon: failed to send response to {}: {}", peer, e);
            }
        }
        Err(e) => {
            error!("Daemon: read error from {}: {}", peer, e);
        }
    }
}

/// Run the minimal Unix socket daemon. Uses `intent_tx` to send commands to the container intent loop.
/// Unix only; on Windows returns an error (daemon is Linux-only in practice).
pub async fn run_daemon_server(
    socket_path: &str,
    intent_tx: mpsc::Sender<RuntimeIntent>,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path)?;
        info!("vappc daemon listening on {}", socket_path);
        eprintln!("vappc daemon listening on {}", socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let peer = stream
                        .peer_addr()
                        .ok()
                        .map(|a| format!("{:?}", a))
                        .unwrap_or_else(|| "<unix>".into());
                    info!("Daemon: connection accepted from {}", peer);
                    let intent_tx = intent_tx.clone();
                    tokio::spawn(handle_client(stream, peer, intent_tx));
                }
                Err(e) => {
                    error!("Daemon accept error: {}", e);
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (socket_path, intent_tx);
        anyhow::bail!("Unix socket daemon is not supported on this platform (Windows); use the Linux daemon")
    }
}

/// Run the minimal TCP daemon (Linux only). Binds to loopback only (e.g. 127.0.0.1:49163).
/// Intended for host access via SSH port-forward when the host has no VSOCK (e.g. Windows):
/// host runs `ssh -L local:127.0.0.1:49163 guest`, then connects to localhost:local.
#[cfg(target_os = "linux")]
pub async fn run_daemon_server_tcp(
    addr: &str,
    intent_tx: mpsc::Sender<RuntimeIntent>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("vappc daemon listening on TCP {}", addr);
    eprintln!("vappc daemon listening on TCP {} (for SSH port-forward)", addr);

    loop {
        match listener.accept().await {
            Ok((stream, remote_addr)) => {
                let peer = format!("tcp:{}", remote_addr);
                info!("Daemon: connection accepted from {}", peer);
                let intent_tx = intent_tx.clone();
                tokio::spawn(handle_client(stream, peer, intent_tx));
            }
            Err(e) => {
                error!("Daemon TCP accept error: {}", e);
            }
        }
    }
}

/// Run the minimal VSOCK daemon (Linux only). Listens on VMADDR_CID_ANY and the given port.
/// Used when vappd runs inside a VM and the host connects via VSOCK (e.g. --socket vsock:49163).
#[cfg(target_os = "linux")]
pub async fn run_daemon_server_vsock(
    port: u32,
    intent_tx: mpsc::Sender<RuntimeIntent>,
) -> anyhow::Result<()> {
    use tokio_vsock::VsockListener;

    const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
    let mut listener = VsockListener::bind(VMADDR_CID_ANY, port)?;
    info!("vappc daemon listening on VSOCK port {}", port);
    eprintln!("vappc daemon listening on VSOCK port {}", port);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let peer = format!("vsock:{}", addr);
                info!("Daemon: connection accepted from {}", peer);
                let intent_tx = intent_tx.clone();
                tokio::spawn(handle_client(stream, peer, intent_tx));
            }
            Err(e) => {
                error!("Daemon VSOCK accept error: {}", e);
            }
        }
    }
}
