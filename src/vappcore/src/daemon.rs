//! Daemon server for vapp-core (4lock-core). Handles VappCoreCommand via NDJSON and forwards to container intent loop.
//! Supports Unix socket, VSOCK (--socket vsock:PORT), and TCP on loopback.
//!
//! ## Wire Format
//!
//! NDJSON (newline-delimited JSON). Each request/response is one JSON line terminated by `\n`.
//! For streaming commands (Start, RunContainer), the daemon sends zero or more `Progress` lines
//! followed by exactly one terminal `Ok` or `Error` line.

use crate::protocol::{VappCoreCommand, WireError, WireMessage};
use container::intent::RuntimeIntent;
use container::progress::RuntimeStartProgress;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(target_os = "linux")]
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::{debug, error, info};

/// Maximum time to wait for a Start/RunContainer provisioning to complete (10 minutes).
const PROVISIONING_TIMEOUT_SECS: u64 = 600;

fn cmd_short_label(cmd: &VappCoreCommand) -> &'static str {
    match cmd {
        VappCoreCommand::Ping => "Ping",
        VappCoreCommand::Start { .. } => "Start",
        VappCoreCommand::RunContainer { .. } => "RunContainer",
        VappCoreCommand::Stop { .. } => "Stop",
        VappCoreCommand::GetState { .. } => "GetState",
        VappCoreCommand::GetEndpoint { .. } => "GetEndpoint",
        VappCoreCommand::GetInterfaceIp { .. } => "GetInterfaceIp",
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

/// Write one NDJSON line to an async writer.
async fn write_ndjson_async<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &WireMessage,
) -> Result<(), String> {
    let json = serde_json::to_string(msg).map_err(|e| format!("Serialize: {}", e))?;
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| format!("Write: {}", e))?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|e| format!("Write newline: {}", e))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("Flush: {}", e))?;
    Ok(())
}

/// Handle multiple requests on the same connection (NDJSON: read line → parse → respond → write line).
/// For Start/RunContainer: streams progress messages before the final response.
async fn handle_client<S>(stream: S, peer: String, intent_tx: mpsc::Sender<RuntimeIntent>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let (reader_half, mut writer_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader_half);
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        let n = match reader.read_line(&mut line_buf).await {
            Ok(0) => break, // Client closed connection
            Ok(n) => n,
            Err(e) => {
                error!("Daemon: read error from {}: {}", peer, e);
                break;
            }
        };
        debug!("Daemon: request from {} ({} bytes)", peer, n);

        let cmd: Result<VappCoreCommand, _> = serde_json::from_str(line_buf.trim_end());
        if let Ok(ref c) = cmd {
            info!("Daemon: command from {}: {}", peer, cmd_short_label(c));
        }

        match cmd {
            Ok(VappCoreCommand::Ping) => {
                if let Err(e) = write_ndjson_async(&mut writer_half, &WireMessage::ok_unit()).await {
                    error!("Daemon: failed to send Ping response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::Start { spec }) => {
                let (progress_tx, mut progress_rx) = mpsc::channel::<RuntimeStartProgress>(32);
                let (callback_tx, callback_rx) = oneshot::channel();
                let intent = RuntimeIntent::Start {
                    spec: Box::new(spec),
                    progress: progress_tx,
                    callback: callback_tx,
                };
                if intent_tx.send(intent).await.is_err() {
                    let msg = WireMessage::err(WireError::internal("Intent loop disconnected".into()));
                    let _ = write_ndjson_async(&mut writer_half, &msg).await;
                    continue;
                }

                // Stream progress and wait for final result using select! with overall timeout.
                // IMPORTANT: Use `biased` to prefer draining progress events before checking
                // the callback. Without this, select! randomly picks a ready branch and may
                // skip buffered progress events when provisioning completes quickly.
                let mut callback_future = callback_rx;
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(PROVISIONING_TIMEOUT_SECS);
                let final_msg = loop {
                    tokio::select! {
                        biased;

                        progress = progress_rx.recv() => {
                            if let Some(p) = progress {
                                let msg = WireMessage::progress(
                                    p.percentage,
                                    p.message,
                                    p.phase,
                                    p.instance_name,
                                    p.task_name,
                                );
                                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                                    error!("Daemon: failed to send progress to {}: {}", peer, e);
                                    break WireMessage::err(WireError::internal(
                                        format!("Failed to send progress: {}", e),
                                    ));
                                }
                            }
                            // progress channel closed — keep waiting for callback
                        }
                        result = &mut callback_future => {
                            // Drain any remaining progress events before sending the terminal message.
                            // The provisioner may have emitted events between the last recv() and now.
                            while let Ok(p) = progress_rx.try_recv() {
                                let msg = WireMessage::progress(
                                    p.percentage, p.message, p.phase, p.instance_name, p.task_name,
                                );
                                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                                    error!("Daemon: failed to send remaining progress to {}: {}", peer, e);
                                    break;
                                }
                            }
                            break match result {
                                Ok(Ok(handle)) => WireMessage::ok_handle(handle),
                                Ok(Err(e)) => WireMessage::err_string(e),
                                Err(_) => WireMessage::err(WireError::internal(
                                    "Intent loop dropped callback".into(),
                                )),
                            };
                        }
                        _ = tokio::time::sleep_until(deadline) => {
                            error!("Daemon: Start command timed out after {}s for {}", PROVISIONING_TIMEOUT_SECS, peer);
                            break WireMessage::err(WireError::timeout(
                                format!("Provisioning timed out after {}s", PROVISIONING_TIMEOUT_SECS),
                            ));
                        }
                    }
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &final_msg).await {
                    error!("Daemon: failed to send Start response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::RunContainer { spec }) => {
                let (progress_tx, mut progress_rx) = mpsc::channel::<RuntimeStartProgress>(32);
                let (callback_tx, callback_rx) = oneshot::channel();
                let intent = RuntimeIntent::RunContainer {
                    spec,
                    progress: progress_tx,
                    callback: callback_tx,
                };
                if intent_tx.send(intent).await.is_err() {
                    let msg = WireMessage::err(WireError::internal("Intent loop disconnected".into()));
                    let _ = write_ndjson_async(&mut writer_half, &msg).await;
                    continue;
                }

                let mut callback_future = callback_rx;
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(PROVISIONING_TIMEOUT_SECS);
                let final_msg = loop {
                    tokio::select! {
                        biased;

                        progress = progress_rx.recv() => {
                            if let Some(p) = progress {
                                let msg = WireMessage::progress(
                                    p.percentage, p.message, p.phase, p.instance_name, p.task_name,
                                );
                                let _ = write_ndjson_async(&mut writer_half, &msg).await;
                            }
                        }
                        result = &mut callback_future => {
                            while let Ok(p) = progress_rx.try_recv() {
                                let msg = WireMessage::progress(
                                    p.percentage, p.message, p.phase, p.instance_name, p.task_name,
                                );
                                let _ = write_ndjson_async(&mut writer_half, &msg).await;
                            }
                            break match result {
                                Ok(Ok(handle)) => WireMessage::ok_handle(handle),
                                Ok(Err(e)) => WireMessage::err_string(e),
                                Err(_) => WireMessage::err(WireError::internal(
                                    "Intent loop dropped callback".into(),
                                )),
                            };
                        }
                        _ = tokio::time::sleep_until(deadline) => {
                            error!("Daemon: RunContainer command timed out after {}s for {}", PROVISIONING_TIMEOUT_SECS, peer);
                            break WireMessage::err(WireError::timeout(
                                format!("RunContainer timed out after {}s", PROVISIONING_TIMEOUT_SECS),
                            ));
                        }
                    }
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &final_msg).await {
                    error!("Daemon: failed to send RunContainer response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::Stop { instance_id }) => {
                let intent = RuntimeIntent::Stop { instance_id };
                let msg = if intent_tx.send(intent).await.is_err() {
                    WireMessage::err(WireError::internal("Intent loop disconnected".into()))
                } else {
                    WireMessage::ok_unit()
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!("Daemon: failed to send Stop response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::GetState { instance_id }) => {
                let (reply_tx, mut reply_rx) = mpsc::channel::<container::intent::InstanceState>(1);
                let intent = RuntimeIntent::GetState {
                    instance_id,
                    reply: reply_tx,
                };
                let msg = if intent_tx.send(intent).await.is_err() {
                    WireMessage::err(WireError::internal("Intent loop disconnected".into()))
                } else {
                    match reply_rx.recv().await {
                        Some(state) => WireMessage::ok_state(state),
                        None => WireMessage::err(WireError::internal("Intent loop did not reply".into())),
                    }
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!("Daemon: failed to send GetState response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::GetEndpoint { instance_id }) => {
                let (callback_tx, callback_rx) = oneshot::channel();
                let intent = RuntimeIntent::GetEndpoint {
                    instance_id,
                    callback: callback_tx,
                };
                let msg = if intent_tx.send(intent).await.is_err() {
                    WireMessage::err(WireError::internal("Intent loop disconnected".into()))
                } else {
                    match callback_rx.await {
                        Ok(Ok(ep)) => WireMessage::ok_endpoint(ep),
                        Ok(Err(e)) => WireMessage::err_string(e),
                        Err(_) => WireMessage::err(WireError::internal("Intent loop dropped callback".into())),
                    }
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!("Daemon: failed to send GetEndpoint response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::GetInterfaceIp { interface }) => {
                let msg = match get_interface_ip(&interface) {
                    Ok(ip) => WireMessage::ok_interface_ip(interface, Some(ip)),
                    Err(_) => WireMessage::ok_interface_ip(interface, None),
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!("Daemon: failed to send GetInterfaceIp response to {}: {}", peer, e);
                    break;
                }
            }
            Err(e) => {
                error!("Daemon: invalid command JSON: {}", e);
                let msg = WireMessage::err(WireError::internal(format!("Invalid command: {}", e)));
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!("Daemon: failed to send error response to {}: {}", peer, e);
                    break;
                }
            }
        }
    }
}

/// Run the minimal Unix socket daemon. Uses `intent_tx` to send commands to the container intent loop.
pub async fn run_daemon_server(
    socket_path: &str,
    intent_tx: mpsc::Sender<RuntimeIntent>,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path)?;
        info!("vapp-core daemon listening on {}", socket_path);
        eprintln!("vapp-core daemon listening on {}", socket_path);

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
#[cfg(target_os = "linux")]
pub async fn run_daemon_server_tcp(
    addr: &str,
    intent_tx: mpsc::Sender<RuntimeIntent>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("vapp-core daemon listening on TCP {}", addr);
    eprintln!("vapp-core daemon listening on TCP {} (for SSH port-forward)", addr);

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
#[cfg(target_os = "linux")]
pub async fn run_daemon_server_vsock(
    port: u32,
    intent_tx: mpsc::Sender<RuntimeIntent>,
) -> anyhow::Result<()> {
    use tokio_vsock::VsockListener;

    const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
    let mut listener = VsockListener::bind(VMADDR_CID_ANY, port)?;
    info!("vapp-core daemon listening on VSOCK port {}", port);
    eprintln!("vapp-core daemon listening on VSOCK port {}", port);

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
