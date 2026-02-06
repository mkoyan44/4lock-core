//! Shared network namespace for container networking
//!
//! This module provides a shared network namespace that all containers join,
//! enabling direct localhost communication between containers without port forwarding.
//!
//! Architecture:
//! - One holder process creates a user+network namespace at runtime (no root required)
//! - pasta runs inside the same user namespace to provide internet connectivity
//! - Namespace is accessed via /proc/{holder_pid}/ns/net
//! - All containers join this shared namespace via namespace path
//! - Containers communicate via localhost (127.0.0.1)

use super::error::ContainerError;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Global shared network namespace instance
static SHARED_NETNS: Mutex<Option<SharedNetworkNamespace>> = Mutex::new(None);
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Manages a shared network namespace for all containers
pub struct SharedNetworkNamespace {
    /// Path to the namespace (e.g., /proc/{pid}/ns/net)
    pub path: PathBuf,
    /// PID of the holder process (keeps namespace alive and runs pasta)
    pub holder_pid: u32,
    /// Whether the namespace was successfully created
    pub active: bool,
}

impl std::fmt::Debug for SharedNetworkNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedNetworkNamespace")
            .field("path", &self.path)
            .field("holder_pid", &self.holder_pid)
            .field("active", &self.active)
            .finish()
    }
}

impl SharedNetworkNamespace {
    /// Create a new shared network namespace
    ///
    /// Creates a network namespace at runtime by:
    /// 1. Spawning a holder process in a user+network namespace
    /// 2. The holder starts pasta for internet connectivity
    /// 3. Using /proc/{pid}/ns/net as the namespace path
    pub fn create() -> Result<Self, ContainerError> {
        tracing::info!("[SharedNetNS] Creating shared network namespace");

        // Find pasta binary first
        let pasta_bin = Self::find_pasta_binary()?;

        // Spawn a holder process that creates a new namespace and runs pasta
        let holder_pid = Self::spawn_namespace_holder(&pasta_bin)?;

        // The namespace path is /proc/{pid}/ns/net
        let ns_path = PathBuf::from(format!("/proc/{}/ns/net", holder_pid));

        // Verify the namespace exists
        if !ns_path.exists() {
            return Err(ContainerError::Other(format!(
                "Namespace path {} does not exist",
                ns_path.display()
            )));
        }

        tracing::info!(
            "[SharedNetNS] Namespace created at {} (holder PID: {})",
            ns_path.display(),
            holder_pid
        );

        Ok(Self {
            path: ns_path,
            holder_pid,
            active: true,
        })
    }

    /// Spawn a holder process that creates the namespace and runs pasta
    fn spawn_namespace_holder(pasta_bin: &str) -> Result<u32, ContainerError> {
        // Create a script that:
        // 1. Is run inside a new user+network namespace
        // 2. Configures loopback
        // 3. Starts pasta in the background
        // 4. Sleeps forever to keep the namespace alive
        //
        // We use pasta in "slirp" mode (no arguments except -4 for IPv4 only)
        // which provides outbound connectivity through the host.
        let script = format!(
            r#"
            # Configure loopback
            ip link set lo up 2>/dev/null || true
            
            # Start pasta in background for outbound connectivity
            # -4: IPv4 only (IPv6 may be disabled)
            # pasta auto-detects the namespace since we're already in it
            {} -4 &
            
            # Wait a moment for pasta to start
            sleep 0.5
            
            # Stay alive to keep the namespace open
            exec sleep infinity
            "#,
            pasta_bin
        );

        let child = Command::new("unshare")
            .args([
                "--user",
                "--net",
                "--map-root-user", // Map current user to root inside namespace
                "--",
                "sh",
                "-c",
                &script,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                ContainerError::Other(format!("Failed to spawn namespace holder: {}", e))
            })?;

        let pid = child.id();

        // Wait for the namespace and pasta to be set up
        std::thread::sleep(std::time::Duration::from_millis(800));

        // Verify the holder is still running
        if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
            return Err(ContainerError::Other(
                "Namespace holder process died. Check if user namespaces are enabled.".to_string(),
            ));
        }

        // Verify the namespace exists
        let ns_path = format!("/proc/{}/ns/net", pid);
        if !std::path::Path::new(&ns_path).exists() {
            return Err(ContainerError::Other(format!(
                "Namespace {} does not exist after holder started",
                ns_path
            )));
        }

        tracing::info!("[SharedNetNS] Namespace holder started (PID: {})", pid);

        Ok(pid)
    }

    /// Find the pasta binary
    fn find_pasta_binary() -> Result<String, ContainerError> {
        let output = Command::new("which")
            .arg("pasta")
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    String::from_utf8(output.stdout)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                } else {
                    None
                }
            });

        match output {
            Some(path) => Ok(path),
            None => Err(ContainerError::Other(
                "pasta not available: binary not found in PATH. \
                Install passt for rootless container internet connectivity. \
                (e.g., apt-get install passt or dnf install passt)"
                    .to_string(),
            )),
        }
    }

    /// Get the namespace path for container config
    pub fn namespace_path(&self) -> &str {
        self.path.to_str().unwrap_or("")
    }

    /// Stop processes and cleanup
    pub fn cleanup(&mut self) {
        // Kill the holder process - this also kills pasta and destroys the namespace
        tracing::info!(
            "[SharedNetNS] Stopping namespace holder (PID: {})",
            self.holder_pid
        );
        Self::kill_process(self.holder_pid as i32);
        self.active = false;
    }

    fn kill_process(pid: i32) {
        if kill(Pid::from_raw(pid), Signal::SIGTERM).is_ok() {
            for _ in 0..10 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                    return;
                }
            }
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
    }
}

impl Drop for SharedNetworkNamespace {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Initialize the global shared network namespace
///
/// This should be called once during provisioner initialization.
/// Returns the namespace path for container configs to use.
pub fn initialize_shared_namespace() -> Result<String, ContainerError> {
    if INITIALIZED.load(Ordering::SeqCst) {
        let guard = SHARED_NETNS
            .lock()
            .map_err(|e| ContainerError::Other(format!("Failed to acquire lock: {}", e)))?;

        if let Some(ref ns) = *guard {
            return Ok(ns.namespace_path().to_string());
        }
    }

    let mut guard = SHARED_NETNS
        .lock()
        .map_err(|e| ContainerError::Other(format!("Failed to acquire lock: {}", e)))?;

    if let Some(ref ns) = *guard {
        return Ok(ns.namespace_path().to_string());
    }

    // Create new shared namespace (pasta is started inside)
    let ns = SharedNetworkNamespace::create()?;

    let path = ns.namespace_path().to_string();
    *guard = Some(ns);
    INITIALIZED.store(true, Ordering::SeqCst);

    tracing::info!(
        "[SharedNetNS] Global shared network namespace initialized: {}",
        path
    );

    Ok(path)
}

/// Get the shared namespace path (if initialized)
pub fn get_shared_namespace_path() -> Option<String> {
    let guard = match SHARED_NETNS.lock() {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!("[SharedNetNS] Failed to acquire lock in get_shared_namespace_path: {}", e);
            return None;
        }
    };
    
    match guard.as_ref() {
        Some(ns) => {
            let path = ns.namespace_path().to_string();
            tracing::debug!("[SharedNetNS] get_shared_namespace_path returning: {}", path);
            Some(path)
        }
        None => {
            tracing::warn!("[SharedNetNS] get_shared_namespace_path called but namespace not initialized");
            None
        }
    }
}

/// Cleanup the global shared network namespace
pub fn cleanup_shared_namespace() {
    if let Ok(mut guard) = SHARED_NETNS.lock() {
        if let Some(ref mut ns) = *guard {
            tracing::info!("[SharedNetNS] Cleaning up shared network namespace");
            ns.cleanup();
        }
        *guard = None;
        INITIALIZED.store(false, Ordering::SeqCst);
    }
}

/// Clean up orphaned processes from previous runs
pub fn cleanup_orphaned_pasta() {
    tracing::info!("[SharedNetNS] Cleaning up orphaned processes");

    let mut cleaned_count = 0;
    let current_pid = std::process::id();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_string_lossy().to_string();

            // Skip non-numeric entries and our own process
            let pid = match pid_str.parse::<u32>() {
                Ok(p) if p != current_pid => p,
                _ => continue,
            };

            let cmdline_path = entry.path().join("cmdline");
            if let Ok(mut file) = fs::File::open(&cmdline_path) {
                let mut cmdline = String::new();
                if file.read_to_string(&mut cmdline).is_ok() {
                    let cmdline = cmdline.replace('\0', " ");

                    // Check for our orphaned holder processes (unshare + sleep infinity)
                    let is_holder =
                        cmdline.contains("unshare") && cmdline.contains("sleep infinity");

                    if is_holder {
                        tracing::info!("[SharedNetNS] Found orphaned holder process {}", pid);

                        if kill(Pid::from_raw(pid as i32), Signal::SIGTERM).is_ok() {
                            for _ in 0..10 {
                                std::thread::sleep(std::time::Duration::from_millis(100));
                                if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                                    cleaned_count += 1;
                                    break;
                                }
                            }

                            if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
                                cleaned_count += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    if cleaned_count > 0 {
        tracing::info!(
            "[SharedNetNS] Cleaned up {} orphaned process(es)",
            cleaned_count
        );
    } else {
        tracing::debug!("[SharedNetNS] No orphaned processes found");
    }
}
