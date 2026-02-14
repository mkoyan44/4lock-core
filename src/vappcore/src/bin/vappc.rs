//! vapp-core-daemon binary (4lock-core). Linux only. No dependency on 4lock-agent.
//! Supports hot-reload: daemon watches its own binary and re-execs on change.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("vapp-core-daemon from 4lock-core is Linux-only. Use vapp on other platforms.");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    use clap::Parser;
    use notify::{Event, EventKind, RecursiveMode, Watcher};
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use tokio::sync::mpsc;
    use tracing::info;
    use vappcore::daemon;

    /// Watch the daemon binary and re-exec when it changes (hot-reload via virtio-fs)
    async fn watch_binary_for_reload() {
        let exe_path = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Cannot get exe path for hot-reload: {}", e);
                return;
            }
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

        let mut watcher = match notify::recommended_watcher(move |res: Result<Event, _>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    let _ = tx.blocking_send(());
                }
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!("Cannot create file watcher for hot-reload: {}", e);
                return;
            }
        };

        if let Err(e) = watcher.watch(&exe_path, RecursiveMode::NonRecursive) {
            tracing::warn!("Cannot watch binary for hot-reload: {}", e);
            return;
        }

        tracing::info!("Hot-reload enabled: watching {}", exe_path.display());

        // Wait for binary change
        if rx.recv().await.is_some() {
            // Small delay to ensure write is complete
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            tracing::info!("Binary changed - restarting daemon...");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            eprintln!("  HOT-RELOAD: Binary changed, restarting...");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            // Re-exec with same arguments
            let args: Vec<String> = std::env::args().collect();
            let err = std::process::Command::new(&args[0])
                .args(&args[1..])
                .exec();

            tracing::error!("Failed to re-exec: {}", err);
        }
    }

    #[derive(Parser, Debug)]
    #[command(name = "vapp-core-daemon", version, about = "vapp-core daemon (4lock-core, Linux only)")]
    struct Args {


        #[arg(short = 's', long = "socket", default_value = "/tmp/vapp-core.sock")]
        socket: String,

        #[arg(long = "app-dir", help = "App directory (default: ~/.vapp)")]
        app_dir: Option<PathBuf>,
    }

    // Default to info level if RUST_LOG not set
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();

    let args = Args::parse();
    let app_dir = args.app_dir.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".vapp")
    });

    // Always print startup banner (visible even without RUST_LOG)
    eprintln!("╔════════════════════════════════════════════════════════════════╗");
    eprintln!("║  vapp-core-daemon starting                                     ║");
    eprintln!("╚════════════════════════════════════════════════════════════════╝");
    eprintln!("  Socket: {}", args.socket);
    eprintln!("  App directory: {}", app_dir.display());
    eprintln!("  User: {} (UID {})", std::env::var("USER").unwrap_or_else(|_| "unknown".into()), unsafe { libc::getuid() });

    info!("vapp-core-daemon starting...");
    info!("Socket: {}", args.socket);
    info!("App directory: {}", app_dir.display());

    if let Err(e) = container::check_system_requirements() {
        eprintln!("System requirements not met: {}", e);
        std::process::exit(1);
    }

    eprintln!("  System requirements: OK");

    std::fs::create_dir_all(&app_dir).expect("create app_dir");

    // Create runtime FIRST, then spawn tasks within it
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let result: anyhow::Result<()> = rt.block_on(async {
        let (intent_tx, intent_rx) = mpsc::channel(32);

        // Ensure docker-proxy.internal resolves to the correct host.
        // On Linux (same host as agent): 127.0.0.1
        // On VM (macOS/Windows guest): default gateway IP (host runs blob on 0.0.0.0:5050)
        {
            let target_ip = detect_gateway_ip().unwrap_or_else(|| "127.0.0.1".to_string());
            if let Err(e) = add_hosts_entry(&target_ip, "docker-proxy.internal") {
                tracing::warn!("Failed to add docker-proxy.internal to /etc/hosts: {}", e);
                eprintln!("  WARNING: Could not add docker-proxy.internal -> {} to /etc/hosts: {}", target_ip, e);
            } else {
                eprintln!("  DNS: docker-proxy.internal -> {}", target_ip);
            }
        }

        // Wait for the host-level blob (docker-proxy) server started by 4lock-agent.
        // The agent starts blob on the host before booting VMs; this daemon just
        // needs to confirm it is reachable before accepting image-pull commands.
        // docker-proxy.internal resolves to the gateway IP (VM) or 127.0.0.1 (Linux).
        {
            let proxy_url = "http://docker-proxy.internal:5050/health";
            eprintln!("  Blob (docker-proxy): waiting for host server at {}", proxy_url);

            const BLOB_READY_TIMEOUT_MS: u64 = 30_000;
            const BLOB_READY_POLL_MS: u64 = 500;
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(2_000))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_millis(BLOB_READY_TIMEOUT_MS);

            let mut ready = false;
            while tokio::time::Instant::now() < deadline {
                if client.get(proxy_url).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
                    info!("Blob (docker-proxy) host server ready at {}", proxy_url);
                    eprintln!("  Blob (docker-proxy): host server ready");
                    ready = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(BLOB_READY_POLL_MS)).await;
            }
            if !ready {
                tracing::warn!(
                    "Blob (docker-proxy) host server not reachable at {} within {}ms; image pulls may fail",
                    proxy_url, BLOB_READY_TIMEOUT_MS
                );
                eprintln!("  Blob (docker-proxy): WARNING — host server not reachable, image pulls may fail");
            }
        }

        // Spawn hot-reload watcher (watches binary via virtio-fs mount)
        tokio::spawn(watch_binary_for_reload());

        // Spawn intent command loop (routes commands to AppRuntime)
        let intent_app_dir = app_dir.clone();
        tokio::spawn(async move {
            container::run_intent_command_loop(intent_rx, intent_app_dir).await;
        });

        // Spawn CRI server (for debugging containers via crictl)
        let cri_socket = app_dir.join("cri.sock");
        let cri_app_dir = app_dir.clone();
        eprintln!("  CRI server: {} + TCP 127.0.0.1:10000", cri_socket.display());
        tokio::spawn(async move {
            let server = container::cri::CriServer::new(cri_socket, Some(10000), cri_app_dir);
            if let Err(e) = server.run().await {
                tracing::error!("CRI server error: {}", e);
            }
        });

        // Run the main daemon server(s) in background so we can listen for Ctrl+C
        if args.socket.starts_with("vsock:") {
            let port: u32 = args.socket["vsock:".len()..]
                .trim()
                .parse()
                .unwrap_or_else(|_| {
                    eprintln!("Invalid vsock port in --socket (expected vsock:PORT, e.g. vsock:49163)");
                    std::process::exit(1);
                });
            let tcp_addr = format!("127.0.0.1:{}", port);
            eprintln!("  VSOCK listener: port {}", port);
            eprintln!("  TCP listener: {} (for SSH port-forward, e.g. ssh -L local:127.0.0.1:{})", tcp_addr, port);
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            eprintln!("  vapp-core-daemon ready and listening! (Ctrl+C to exit)");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            tokio::spawn(daemon::run_daemon_server_vsock(port, intent_tx.clone()));
            tokio::spawn(async move { daemon::run_daemon_server_tcp(&tcp_addr, intent_tx).await });
            tokio::signal::ctrl_c().await.expect("failed to listen for Ctrl+C");
        } else {
            eprintln!("  Unix socket: {}", args.socket);
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            eprintln!("  vapp-core-daemon ready and listening! (Ctrl+C to exit)");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            let socket = args.socket.clone();
            tokio::spawn(async move { daemon::run_daemon_server(&socket, intent_tx).await });
            tokio::signal::ctrl_c().await.expect("failed to listen for Ctrl+C");
        }
        info!("Received Ctrl+C, shutting down");
        Ok(())
    });

    if let Err(e) = result {
        tracing::error!("Daemon failed: {}", e);
        std::process::exit(1);
    }

    /// Detect the default gateway IP from `ip route`.
    fn detect_gateway_ip() -> Option<String> {
        let output = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse: "default via 192.168.64.1 dev eth0 ..."
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
                return Some(parts[2].to_string());
            }
        }
        None
    }

    /// Add a hostname entry to /etc/hosts if not already present.
    fn add_hosts_entry(ip: &str, hostname: &str) -> std::io::Result<()> {
        let contents = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
        // Check if already present
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1..].contains(&hostname) {
                // Already present
                return Ok(());
            }
        }
        // Append entry
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open("/etc/hosts")?;
        writeln!(file, "{}\t{}", ip, hostname)?;
        Ok(())
    }
}
