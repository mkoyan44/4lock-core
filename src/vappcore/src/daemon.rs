//! Daemon server for vapp-core (4lock-core). Handles VappCoreCommand via NDJSON and forwards to app runtime intent loop.
//! Supports Unix socket, VSOCK (--socket vsock:PORT), and TCP on loopback.
//!
//! ## Wire Format
//!
//! NDJSON (newline-delimited JSON). Each request/response is one JSON line terminated by `\n`.
//! For streaming commands (StartApp), the daemon sends zero or more `Progress` lines
//! followed by exactly one terminal `Ok` or `Error` line.

use container::intent::RuntimeIntent;
use tokio::sync::mpsc;

#[cfg(unix)]
use crate::protocol::{ContainerGroupResult, VappCoreCommand, WireError, WireMessage};
#[cfg(unix)]
use container::progress::RuntimeStartProgress;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(target_os = "linux")]
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::sync::oneshot;
#[cfg(unix)]
use tracing::{debug, error, info};

/// Maximum time to wait for a StartApp provisioning to complete (10 minutes).
#[cfg(unix)]
const PROVISIONING_TIMEOUT_SECS: u64 = 600;

#[cfg(unix)]
fn cmd_short_label(cmd: &VappCoreCommand) -> &'static str {
    match cmd {
        VappCoreCommand::Ping => "Ping",
        VappCoreCommand::StartApp { .. } => "StartApp",
        VappCoreCommand::StopApp { .. } => "StopApp",
        VappCoreCommand::AppState { .. } => "AppState",
        VappCoreCommand::ListApps => "ListApps",
        VappCoreCommand::GetInterfaceIp { .. } => "GetInterfaceIp",
        VappCoreCommand::StartContainerGroup { .. } => "StartContainerGroup",
        VappCoreCommand::RunDiagnostic => "RunDiagnostic",
        VappCoreCommand::UpdateDnsRecords { .. } => "UpdateDnsRecords",
    }
}

/// Get IP address of a network interface by parsing `ip addr show` output.
/// Supports prefix matching: if `interface` ends with `*`, matches any interface
/// starting with that prefix (e.g., "zt*" matches "ztrfyjzrge").
#[cfg(target_os = "linux")]
fn get_interface_ip(interface: &str) -> Result<String, String> {
    use std::process::Command;

    // Check if this is a prefix query (e.g., "zt*")
    if let Some(prefix) = interface.strip_suffix('*') {
        // List all interfaces and find one matching the prefix
        let output = Command::new("ip")
            .args(["addr", "show"])
            .output()
            .map_err(|e| format!("Failed to run ip addr: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_iface: Option<String> = None;

        for line in stdout.lines() {
            let trimmed = line.trim();
            // Interface header line: "3: ztrfyjzrge: <FLAGS> ..."
            if !trimmed.starts_with(' ') && trimmed.contains(": ") {
                let parts: Vec<&str> = trimmed.splitn(3, ": ").collect();
                if parts.len() >= 2 {
                    let iface_name = parts[1].split('@').next().unwrap_or(parts[1]);
                    if iface_name.starts_with(prefix) {
                        current_iface = Some(iface_name.to_string());
                    } else {
                        current_iface = None;
                    }
                }
            }
            // IP line under a matching interface
            if current_iface.is_some() && trimmed.starts_with("inet ") && !trimmed.contains("inet6") {
                if let Some(ip_cidr) = trimmed.split_whitespace().nth(1) {
                    let ip = ip_cidr.split('/').next().unwrap_or("");
                    if !ip.is_empty() {
                        return Ok(ip.to_string());
                    }
                }
            }
        }
        return Err(format!("No interface matching prefix '{}' found", prefix));
    }

    // Exact interface name match
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
            if let Some(ip_cidr) = trimmed.split_whitespace().nth(1) {
                let ip = ip_cidr.split('/').next().unwrap_or("");
                if !ip.is_empty() {
                    return Ok(ip.to_string());
                }
            }
        }
    }
    Err(format!("No IPv4 address found for interface {}", interface))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn get_interface_ip(_interface: &str) -> Result<String, String> {
    Err("GetInterfaceIp only supported on Linux".to_string())
}

/// Run diagnostic commands on the VM host and return results as a map.
#[cfg(target_os = "linux")]
async fn run_diagnostic() -> WireMessage {
    use std::collections::HashMap;
    use std::process::Command;

    let mut report = HashMap::new();

    let commands: Vec<(&str, Vec<&str>)> = vec![
        ("ip_link", vec!["ip", "link", "show"]),
        ("ip_addr", vec!["ip", "addr", "show"]),
        ("dev_net_tun", vec!["ls", "-la", "/dev/net/tun"]),
        ("ps_zerotier", vec!["sh", "-c", "ps aux | grep -i zerotier | grep -v grep"]),
        ("zt_pid_file", vec!["sh", "-c", "cat /var/lib/zerotier-one/zerotier-one.pid 2>&1 || echo 'not found'"]),
        ("zt_status", vec!["sh", "-c", "zerotier-cli status 2>&1 || echo 'zerotier-cli not found or failed'"]),
        ("zt_listnetworks", vec!["sh", "-c", "zerotier-cli listnetworks 2>&1 || echo 'failed'"]),
        ("zt_listpeers", vec!["sh", "-c", "zerotier-cli listpeers 2>&1 | head -20 || echo 'failed'"]),
        ("containers_running", vec!["sh", "-c", "ls /run/youki/ 2>/dev/null || echo 'no /run/youki'"]),
        ("proc_namespaces", vec!["sh", "-c", "ls -la /proc/1/ns/ 2>&1"]),
        ("kernel_tun", vec!["sh", "-c", "grep -i tun /proc/modules 2>/dev/null || echo 'not in modules (may be builtin)'"]),
        ("dmesg_tun", vec!["sh", "-c", "dmesg 2>/dev/null | grep -i tun | tail -5 || echo 'no tun dmesg'"]),
    ];

    for (key, args) in commands {
        let result = Command::new(args[0])
            .args(&args[1..])
            .output();
        match result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let combined = if stderr.is_empty() {
                    stdout
                } else {
                    format!("{}\nSTDERR: {}", stdout, stderr)
                };
                report.insert(key.to_string(), combined);
            }
            Err(e) => {
                report.insert(key.to_string(), format!("exec error: {}", e));
            }
        }
    }

    WireMessage::ok_diagnostic(report)
}

#[cfg(all(unix, not(target_os = "linux")))]
async fn run_diagnostic() -> WireMessage {
    let mut report = std::collections::HashMap::new();
    report.insert("error".to_string(), "RunDiagnostic only supported on Linux".to_string());
    WireMessage::ok_diagnostic(report)
}

/// Write DNS records to a hosts file that CoreDNS watches and auto-reloads.
/// Uses atomic write (temp file + rename) to avoid partial reads.
#[cfg(unix)]
fn write_dns_hosts_file(records: &[crate::protocol::DnsRecord]) -> Result<usize, String> {
    use std::path::Path;

    let dns_dir = Path::new("/var/lib/vapp/dns");
    std::fs::create_dir_all(dns_dir).map_err(|e| format!("create_dir_all: {}", e))?;

    let mut content = String::from("# Managed by 4lock-agent — do not edit manually\n");
    for r in records {
        content.push_str(&format!("{} {}\n", r.ip, r.hostname));
    }

    // Atomic write: temp file + rename
    let tmp_path = dns_dir.join("hosts.tmp");
    let final_path = dns_dir.join("hosts");
    std::fs::write(&tmp_path, &content).map_err(|e| format!("write: {}", e))?;
    std::fs::rename(&tmp_path, &final_path).map_err(|e| format!("rename: {}", e))?;

    info!(
        "[DNS] Wrote {} records to {}",
        records.len(),
        final_path.display()
    );
    Ok(records.len())
}

/// Write one NDJSON line to an async writer.
#[cfg(unix)]
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
/// For StartApp: streams progress messages before the final response.
#[cfg(unix)]
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
            Ok(0) => break,
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
            Ok(VappCoreCommand::StartApp { spec }) => {
                let (progress_tx, mut progress_rx) = mpsc::channel::<RuntimeStartProgress>(32);
                let (callback_tx, callback_rx) = oneshot::channel();
                let intent = RuntimeIntent::StartApp {
                    spec,
                    progress: progress_tx,
                    callback: callback_tx,
                };
                if intent_tx.send(intent).await.is_err() {
                    let msg = WireMessage::err(WireError::internal("Intent loop disconnected".into()));
                    let _ = write_ndjson_async(&mut writer_half, &msg).await;
                    continue;
                }

                // Two-phase approach: first drain ALL progress events (guaranteed order),
                // then read the callback result.
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(PROVISIONING_TIMEOUT_SECS);

                // Phase 1: Stream all progress events until channel closes or timeout
                let mut timed_out = false;
                loop {
                    tokio::select! {
                        progress = progress_rx.recv() => {
                            match progress {
                                Some(p) => {
                                    let msg = WireMessage::progress(
                                        p.percentage, p.message, p.phase, p.instance_name, p.task_name,
                                    );
                                    if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                                        error!("Daemon: failed to send progress to {}: {}", peer, e);
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                        _ = tokio::time::sleep_until(deadline) => {
                            error!("Daemon: StartApp timed out after {}s for {}", PROVISIONING_TIMEOUT_SECS, peer);
                            timed_out = true;
                            break;
                        }
                    }
                }

                // Phase 2: Get the result
                let final_msg = if timed_out {
                    WireMessage::err(WireError::timeout(
                        format!("StartApp timed out after {}s", PROVISIONING_TIMEOUT_SECS),
                    ))
                } else {
                    match tokio::time::timeout(std::time::Duration::from_secs(5), callback_rx).await {
                        Ok(Ok(Ok(handle))) => WireMessage::ok_app_handle(handle),
                        Ok(Ok(Err(e))) => WireMessage::err_string(e),
                        Ok(Err(_)) => WireMessage::err(WireError::internal(
                            "Intent loop dropped callback".into(),
                        )),
                        Err(_) => WireMessage::err(WireError::internal(
                            "Callback not received after progress channel closed".into(),
                        )),
                    }
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &final_msg).await {
                    error!("Daemon: failed to send StartApp response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::StopApp { app_id }) => {
                let intent = RuntimeIntent::StopApp { app_id };
                let msg = if intent_tx.send(intent).await.is_err() {
                    WireMessage::err(WireError::internal("Intent loop disconnected".into()))
                } else {
                    WireMessage::ok_unit()
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!("Daemon: failed to send StopApp response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::AppState { app_id }) => {
                let (reply_tx, reply_rx) = oneshot::channel();
                let intent = RuntimeIntent::AppState {
                    app_id,
                    reply: reply_tx,
                };
                let msg = if intent_tx.send(intent).await.is_err() {
                    WireMessage::err(WireError::internal("Intent loop disconnected".into()))
                } else {
                    match reply_rx.await {
                        Ok(state) => WireMessage::ok_app_state(state),
                        Err(_) => WireMessage::err(WireError::internal("Intent loop did not reply".into())),
                    }
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!("Daemon: failed to send AppState response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::ListApps) => {
                let (reply_tx, reply_rx) = oneshot::channel();
                let intent = RuntimeIntent::ListApps { reply: reply_tx };
                let msg = if intent_tx.send(intent).await.is_err() {
                    WireMessage::err(WireError::internal("Intent loop disconnected".into()))
                } else {
                    match reply_rx.await {
                        Ok(apps) => WireMessage::ok_app_list(apps),
                        Err(_) => WireMessage::err(WireError::internal("Intent loop did not reply".into())),
                    }
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!("Daemon: failed to send ListApps response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::GetInterfaceIp { interface }) => {
                let msg = match get_interface_ip(&interface) {
                    Ok(ip) => WireMessage::ok_interface_ip(interface, Some(ip)),
                    Err(e) => {
                        debug!("GetInterfaceIp({}): {}", interface, e);
                        WireMessage::ok_interface_ip(interface, None)
                    }
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!("Daemon: failed to send GetInterfaceIp response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::StartContainerGroup { group }) => {
                let group_name = group.group_name.clone();
                let total_specs = group.specs.len();
                info!(
                    "Daemon: StartContainerGroup '{}' with {} specs from {}",
                    group_name, total_specs, peer
                );

                if group.specs.is_empty() {
                    let result = ContainerGroupResult {
                        group_name,
                        handles: Vec::new(),
                        error: None,
                    };
                    let msg = WireMessage::ok_container_group(result);
                    if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                        error!("Daemon: failed to send empty group response to {}: {}", peer, e);
                        break;
                    }
                    continue;
                }

                let mut handles = Vec::new();
                let mut group_error: Option<WireError> = None;
                let mut write_failed = false;

                for (idx, spec) in group.specs.into_iter().enumerate() {
                    let spec_app_id = spec.app_id.clone();
                    info!(
                        "Daemon: StartContainerGroup[{}] starting spec {}/{}: {}",
                        group_name,
                        idx + 1,
                        total_specs,
                        spec_app_id
                    );

                    let (progress_tx, mut progress_rx) = mpsc::channel::<RuntimeStartProgress>(32);
                    let (callback_tx, callback_rx) = oneshot::channel();
                    let intent = RuntimeIntent::StartApp {
                        spec,
                        progress: progress_tx,
                        callback: callback_tx,
                    };

                    if intent_tx.send(intent).await.is_err() {
                        group_error = Some(WireError::internal("Intent loop disconnected".into()));
                        break;
                    }

                    // Drain progress (same pattern as StartApp)
                    let deadline = tokio::time::Instant::now()
                        + std::time::Duration::from_secs(PROVISIONING_TIMEOUT_SECS);
                    let mut timed_out = false;

                    loop {
                        tokio::select! {
                            progress = progress_rx.recv() => {
                                match progress {
                                    Some(p) => {
                                        let msg = WireMessage::progress(
                                            p.percentage, p.message, p.phase,
                                            p.instance_name, p.task_name,
                                        );
                                        if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                                            error!("Daemon: failed to send group progress to {}: {}", peer, e);
                                            write_failed = true;
                                            break;
                                        }
                                    }
                                    None => break, // channel closed, spec finished
                                }
                            }
                            _ = tokio::time::sleep_until(deadline) => {
                                timed_out = true;
                                break;
                            }
                        }
                    }

                    if write_failed {
                        break;
                    }

                    if timed_out {
                        group_error = Some(WireError::timeout(format!(
                            "StartContainerGroup: spec {} ({}) timed out after {}s",
                            idx, spec_app_id, PROVISIONING_TIMEOUT_SECS
                        )));
                        break; // fail-fast
                    }

                    // Read callback result
                    match tokio::time::timeout(std::time::Duration::from_secs(5), callback_rx).await
                    {
                        Ok(Ok(Ok(handle))) => {
                            info!(
                                "Daemon: StartContainerGroup[{}] spec {}/{} ({}) succeeded",
                                group_name,
                                idx + 1,
                                total_specs,
                                spec_app_id
                            );
                            handles.push(handle);
                        }
                        Ok(Ok(Err(e))) => {
                            group_error = Some(
                                WireError::internal(e)
                                    .with_phase(format!("spec[{}]:{}", idx, spec_app_id)),
                            );
                            break; // fail-fast
                        }
                        Ok(Err(_)) => {
                            group_error = Some(WireError::internal(
                                "Intent loop dropped callback".into(),
                            ));
                            break;
                        }
                        Err(_) => {
                            group_error = Some(WireError::internal(
                                "Callback not received after progress channel closed".into(),
                            ));
                            break;
                        }
                    }
                }

                if write_failed {
                    break; // connection lost, exit client loop
                }

                let result = ContainerGroupResult {
                    group_name: group_name.clone(),
                    handles,
                    error: group_error,
                };
                info!(
                    "Daemon: StartContainerGroup '{}' complete: {} handles, error={}",
                    group_name,
                    result.handles.len(),
                    result.error.is_some()
                );
                let msg = WireMessage::ok_container_group(result);
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!(
                        "Daemon: failed to send group result to {}: {}",
                        peer, e
                    );
                    break;
                }
            }
            Ok(VappCoreCommand::RunDiagnostic) => {
                info!("Daemon: running VM diagnostics for {}", peer);
                let msg = run_diagnostic().await;
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!("Daemon: failed to send RunDiagnostic response to {}: {}", peer, e);
                    break;
                }
            }
            Ok(VappCoreCommand::UpdateDnsRecords { records }) => {
                let msg = match write_dns_hosts_file(&records) {
                    Ok(count) => WireMessage::ok_dns_records_updated(count),
                    Err(e) => WireMessage::err_string(format!("DNS update failed: {}", e)),
                };
                if let Err(e) = write_ndjson_async(&mut writer_half, &msg).await {
                    error!("Daemon: failed to send UpdateDnsRecords response to {}: {}", peer, e);
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
