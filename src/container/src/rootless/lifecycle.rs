//! Container lifecycle operations (create, start, stop, delete)
//!
//! Containers use host networking (no per-container network namespace).

use super::error::ContainerError;
use serde_json;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

/// Options for creating a container
#[derive(Default, Clone)]
pub struct CreateContainerOptions {
    /// Override systemd cgroup manager usage.
    /// - `None`: Auto-detect (but may fall back to cgroupfs in Tauri process)
    /// - `Some(true)`: Force systemd (use when calling from dedicated thread where D-Bus works)
    /// - `Some(false)`: Force cgroupfs
    pub use_systemd: Option<bool>,
}

pub fn create_container(
    container_id: &str,
    bundle_dir: &Path,
    root_path: &Path,
) -> Result<(), ContainerError> {
    create_container_with_options(
        container_id,
        bundle_dir,
        root_path,
        CreateContainerOptions::default(),
    )
}

/// Create a container via subprocess to avoid GTK/WebKit init process hang.
///
/// The libcontainer init process hangs in INTER state when running inside Tauri/GTK context
/// due to a deadlock in parent-child Unix socket communication. By spawning a clean subprocess
/// (vapp --container-create), we get a process without GTK's threads and state, which allows
/// libcontainer to work correctly.
#[cfg(target_os = "linux")]
fn create_container_via_subprocess(
    container_id: &str,
    bundle_dir: &Path,
    root_path: &Path,
) -> Result<(), ContainerError> {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    // Find the vapp binary - it should be the current executable
    let vapp_binary = std::env::current_exe().map_err(|e| {
        ContainerError::Other(format!("Failed to get current executable path: {}", e))
    })?;

    tracing::info!(
        "[ContainerLifecycle] Spawning subprocess for container creation: {} --container-create {} {:?} {:?}",
        vapp_binary.display(),
        container_id,
        bundle_dir,
        root_path
    );

    // Spawn the subprocess with environment marker to prevent infinite recursion
    let mut child = Command::new(&vapp_binary)
        .arg("--container-create")
        .arg(container_id)
        .arg(bundle_dir)
        .arg(root_path)
        .env("VAPP_CONTAINER_HELPER", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            ContainerError::Other(format!(
                "Failed to spawn container creation subprocess: {}",
                e
            ))
        })?;

    // Wait for the subprocess to complete with timeout
    let timeout = Duration::from_secs(60); // 60 second timeout for container creation
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process exited
                if status.success() {
                    tracing::info!(
                        "[ContainerLifecycle] Subprocess container creation succeeded for {}",
                        container_id
                    );
                    return Ok(());
                } else {
                    // Get stderr for error details
                    let stderr = child
                        .stderr
                        .take()
                        .and_then(|mut s| {
                            let mut buf = String::new();
                            std::io::Read::read_to_string(&mut s, &mut buf).ok()?;
                            Some(buf)
                        })
                        .unwrap_or_default();

                    let stdout = child
                        .stdout
                        .take()
                        .and_then(|mut s| {
                            let mut buf = String::new();
                            std::io::Read::read_to_string(&mut s, &mut buf).ok()?;
                            Some(buf)
                        })
                        .unwrap_or_default();

                    tracing::error!(
                        "[ContainerLifecycle] Subprocess container creation failed for {}: exit_code={:?}, stderr={}, stdout={}",
                        container_id,
                        status.code(),
                        stderr,
                        stdout
                    );

                    return Err(ContainerError::Other(format!(
                        "Container creation subprocess failed with exit code {:?}: {}",
                        status.code(),
                        stderr
                    )));
                }
            }
            Ok(None) => {
                // Still running - check timeout
                if start.elapsed() > timeout {
                    // Kill the subprocess
                    let _ = child.kill();
                    tracing::error!(
                        "[ContainerLifecycle] Subprocess container creation timed out for {} after {:?}",
                        container_id,
                        timeout
                    );
                    return Err(ContainerError::Other(format!(
                        "Container creation subprocess timed out after {:?}",
                        timeout
                    )));
                }
                // Sleep briefly before checking again
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(ContainerError::Other(format!(
                    "Failed to wait for container creation subprocess: {}",
                    e
                )));
            }
        }
    }
}

/// Create a container with explicit options.
/// Use this when calling from a dedicated thread to override Tauri detection.
pub fn create_container_with_options(
    container_id: &str,
    bundle_dir: &Path,
    root_path: &Path,
    options: CreateContainerOptions,
) -> Result<(), ContainerError> {
    // CRITICAL: In Tauri context, use subprocess-based container creation
    // The libcontainer init process hangs due to a deadlock in parent-child IPC
    // when running inside GTK/WebKit's process context.
    // By spawning a separate process (vapp --container-create), we get a clean
    // process without GTK's threads and state, which allows libcontainer to work correctly.
    let is_tauri_context = std::env::var("TAURI_FAMILY").is_ok()
        || std::env::var("TAURI_PLATFORM").is_ok()
        || std::process::Command::new("ps")
            .arg("-p")
            .arg(std::process::id().to_string())
            .arg("-o")
            .arg("comm=")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim() == "vapp")
            .unwrap_or(false);

    // Check if we're already in helper mode (to avoid infinite recursion)
    let is_helper_mode = std::env::var("VAPP_CONTAINER_HELPER").is_ok();

    if is_tauri_context && !is_helper_mode {
        tracing::info!(
            "[ContainerLifecycle] Tauri context detected - using subprocess for container creation: {}",
            container_id
        );
        return create_container_via_subprocess(container_id, bundle_dir, root_path);
    }

    // CRITICAL: Clean up any stale systemd scopes before creating container
    // Stale scopes (especially failed ones) cause libcontainer to hang when trying to apply properties
    // This is the root cause of the Tauri hang issue
    #[cfg(target_os = "linux")]
    {
        let scope_name = format!("youki-{}.scope", container_id);
        // Check if scope exists and is not active
        let scope_name_clone = scope_name.clone();
        if let Ok(output) = std::process::Command::new("systemctl")
            .arg("--user")
            .arg("is-active")
            .arg(&scope_name_clone)
            .output()
        {
            // Scope exists - check if it's active, failed, or inactive
            let status_str = String::from_utf8_lossy(&output.stdout);
            let status = status_str.trim();
            if status != "active" {
                // Scope exists but is not active (failed, inactive, etc.) - clean it up
                tracing::info!(
                    "[ContainerLifecycle] Cleaning up stale systemd scope '{}' (status: {})",
                    scope_name,
                    status
                );
                let scope_name_for_stop = scope_name.clone();
                let _ = std::process::Command::new("systemctl")
                    .arg("--user")
                    .arg("stop")
                    .arg(&scope_name_for_stop)
                    .output();
                // Also try to reset-failed to clear failed state
                let scope_name_for_reset = scope_name.clone();
                let _ = std::process::Command::new("systemctl")
                    .arg("--user")
                    .arg("reset-failed")
                    .arg(&scope_name_for_reset)
                    .output();
                // Wait for systemd to fully clean up the scope
                // CRITICAL: Wait longer to ensure scope is fully removed before creating a new one
                // This prevents race conditions where systemd hasn't fully cleaned up the old scope
                // Increased wait time to 1 second to ensure complete cleanup
                std::thread::sleep(std::time::Duration::from_millis(1000));

                // CRITICAL: Verify scope is actually gone before proceeding
                // This prevents libcontainer from trying to apply properties to a stale scope
                let scope_name_for_final_check = scope_name.clone();
                let mut retries = 0;
                while retries < 5 {
                    let check_output = std::process::Command::new("systemctl")
                        .arg("--user")
                        .arg("is-active")
                        .arg(&scope_name_for_final_check)
                        .output();

                    match check_output {
                        Ok(output) => {
                            let check_status_str = String::from_utf8_lossy(&output.stdout);
                            let check_status = check_status_str.trim();
                            if check_status == "inactive"
                                || check_status == "failed"
                                || output.status.code() != Some(0)
                            {
                                // Scope is gone or inactive - safe to proceed
                                break;
                            } else {
                                // Scope still exists - wait longer
                                tracing::warn!(
                                    "[ContainerLifecycle] Scope '{}' still exists after cleanup (status: {}), waiting...",
                                    scope_name,
                                    check_status
                                );
                                std::thread::sleep(std::time::Duration::from_millis(500));
                                retries += 1;
                            }
                        }
                        Err(_) => {
                            // Command failed - assume scope is gone
                            break;
                        }
                    }
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        use anyhow::Context;
        use libcontainer::container::builder::ContainerBuilder;
        use libcontainer::syscall::syscall::SyscallType;
        use liboci_cli::Create;
        use std::fs::File;
        use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

        tracing::info!(
            "[ContainerLifecycle] Creating container: {} from bundle: {:?}",
            container_id,
            bundle_dir
        );

        // Pre-creation validation: Check bundle directory exists
        if !bundle_dir.exists() {
            return Err(ContainerError::Other(format!(
                "Bundle directory does not exist: {:?}",
                bundle_dir
            )));
        }

        // Validate config.json exists and is valid JSON
        let config_path = bundle_dir.join("config.json");
        if !config_path.exists() {
            return Err(ContainerError::Other(format!(
                "config.json not found in bundle: {:?}",
                config_path
            )));
        }

        // Validate config.json is valid JSON
        let config_content =
            std::fs::read_to_string(&config_path).map_err(ContainerError::IoError)?;
        let config_json: serde_json::Value = serde_json::from_str(&config_content)
            .map_err(|e| ContainerError::Other(format!("Invalid JSON in config.json: {}", e)))?;

        tracing::debug!(
            "[ContainerLifecycle] Validated config.json for container {}",
            container_id
        );

        // Validate rootfs exists
        let rootfs_path = bundle_dir.join("rootfs");
        if !rootfs_path.exists() {
            return Err(ContainerError::Other(format!(
                "Rootfs directory does not exist: {:?}",
                rootfs_path
            )));
        }

        // Check for essential directories in rootfs (warn if missing, but don't fail)
        let required_dirs = ["bin", "etc", "usr"];
        for dir in &required_dirs {
            if !rootfs_path.join(dir).exists() {
                tracing::warn!(
                    "[ContainerLifecycle] Rootfs missing directory: {:?} (container may still work)",
                    rootfs_path.join(dir)
                );
            }
        }

        // Validate volume mount sources exist (if specified in config)
        if let Some(_linux) = config_json.get("linux") {
            if let Some(mounts) = config_json.get("mounts").and_then(|m| m.as_array()) {
                for mount in mounts {
                    if let Some(source) = mount.get("source").and_then(|s| s.as_str()) {
                        if mount.get("type").and_then(|t| t.as_str()) == Some("bind")
                            && !std::path::Path::new(source).exists()
                        {
                            tracing::warn!(
                                "[ContainerLifecycle] Bind mount source does not exist: {:?} (mount will fail)",
                                source
                            );
                        }
                    }
                }
            }
        }

        // Create container using libcontainer's ContainerBuilder
        // libcontainer stores containers at <root_path>/<container_id>
        // We want to store them at root_path/containers/<container_id>
        // So we pass root_path/containers as the root_path to libcontainer
        // and libcontainer will create the container at root_path/containers/<container_id>
        let containers_root = root_path.join("containers");

        // Ensure containers root directory exists
        std::fs::create_dir_all(&containers_root).map_err(ContainerError::IoError)?;

        // Check if container already exists - if so, delete it first (idempotent operation)
        // libcontainer checks for directory existence, so we check for the directory itself
        let container_root = containers_root.join(container_id);
        if container_root.exists() {
            tracing::info!(
                "[ContainerLifecycle] Container {} already exists at {:?}, deleting before recreation",
                container_id,
                container_root
            );
            // Try to stop the container first if it's running
            let _ = stop_container(root_path, container_id);
            // Delete the container directory (libcontainer stores containers at <root_path>/<container_id>)
            std::fs::remove_dir_all(&container_root).map_err(ContainerError::IoError)?;
            tracing::info!(
                "[ContainerLifecycle] Deleted existing container directory: {:?}",
                container_root
            );
        }

        // Check if we're in Tauri context (where init process might hang during pivot_root)
        let is_tauri_for_pivot = std::env::var("TAURI_FAMILY").is_ok()
            || std::env::var("TAURI_PLATFORM").is_ok()
            || std::process::Command::new("ps")
                .arg("-p")
                .arg(std::process::id().to_string())
                .arg("-o")
                .arg("comm=")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim() == "vapp")
                .unwrap_or(false);

        // CRITICAL: Try pivot_root first (no_pivot=false) to avoid EACCES in user namespace
        // The EACCES error occurs with chroot (no_pivot=true) in user namespace + network namespace
        // Pivot_root is the recommended approach for rootless containers per libcontainer docs
        // Only use chroot if pivot_root causes hangs (Tauri context issue)
        let use_no_pivot = is_tauri_for_pivot;
        if use_no_pivot {
            tracing::warn!(
                "[ContainerLifecycle] Using chroot (no_pivot=true) for container {} in Tauri context - may cause EACCES",
                container_id
            );
        } else {
            tracing::info!(
                "[ContainerLifecycle] Using pivot_root (no_pivot=false) for container {} - recommended for rootless",
                container_id
            );
        }

        let create_args = Create {
            container_id: container_id.to_string(),
            bundle: bundle_dir.to_path_buf(),
            pid_file: None,
            console_socket: None,
            preserve_fds: 0,
            no_new_keyring: false,
            no_pivot: use_no_pivot, // Use chroot in Tauri context to avoid pivot_root hang
        };

        // Use default executor (implicit) - the EACCES issue is fixed at the OCI spec level
        // by using a busybox sh wrapper that can exec the command
        let mut builder =
            ContainerBuilder::new(create_args.container_id.clone(), SyscallType::default())
                .with_pid_file(create_args.pid_file.as_ref())
                .map_err(|e| ContainerError::LibcontainerError(e.to_string()))?
                .with_console_socket(create_args.console_socket.as_ref())
                .with_root_path(containers_root)
                .map_err(|e| ContainerError::LibcontainerError(e.to_string()))?
                .with_preserved_fds(create_args.preserve_fds)
                .validate_id()
                .map_err(|e| ContainerError::LibcontainerError(e.to_string()))?;

        // CRITICAL: Redirect stdout/stderr to log files for debugging
        // This allows us to see why containers fail (especially apiserver, etcd)
        if create_args.console_socket.is_none() {
            let dev_null_in = File::open("/dev/null").map_err(ContainerError::IoError)?;
            
            // Create log files in bundle directory for stdout/stderr
            let bundle_log_dir = create_args.bundle.join("logs");
            std::fs::create_dir_all(&bundle_log_dir).map_err(ContainerError::IoError)?;
            
            let stdout_log = bundle_log_dir.join("stdout.log");
            let stderr_log = bundle_log_dir.join("stderr.log");
            
            // Open log files for writing (append mode)
            let stdout_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&stdout_log)
                .map_err(|e| ContainerError::IoError(std::io::Error::other(format!(
                    "Failed to create stdout log file {:?}: {}",
                    stdout_log, e
                ))))?;
            
            let stderr_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&stderr_log)
                .map_err(|e| ContainerError::IoError(std::io::Error::other(format!(
                    "Failed to create stderr log file {:?}: {}",
                    stderr_log, e
                ))))?;

            unsafe {
                builder.stdin = Some(OwnedFd::from_raw_fd(dev_null_in.into_raw_fd()));
                builder.stdout = Some(OwnedFd::from_raw_fd(stdout_file.into_raw_fd()));
                builder.stderr = Some(OwnedFd::from_raw_fd(stderr_file.into_raw_fd()));
            }
            
            tracing::info!(
                "[ContainerLifecycle] Redirecting container {} stdout/stderr to log files: {:?}",
                container_id,
                bundle_log_dir
            );
        }

        // Detect if systemd is available for cgroup management
        // Systemd cgroups are required on modern Linux systems with systemd
        //
        // CRITICAL: libcontainer's systemd cgroup manager requires D-Bus to communicate with systemd
        // If D-Bus is not available, it will hang indefinitely waiting for a connection
        // We must check D-Bus availability and fall back to cgroupfs if D-Bus is not accessible
        let systemd_available = std::path::Path::new("/run/systemd/system").exists()
            || std::path::Path::new("/sys/fs/cgroup/systemd").exists()
            || std::process::Command::new("systemctl")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

        tracing::info!(
            "[ContainerLifecycle] Systemd detection for container {}: systemd_available={}",
            container_id,
            systemd_available
        );

        // Check if D-Bus is accessible (required for systemd cgroup manager)
        // libcontainer's systemd cgroup manager uses D-Bus to communicate with systemd
        // If D-Bus is not available, it will hang waiting for a connection
        let dbus_available = if systemd_available {
            // CRITICAL: Ensure D-Bus environment variables are available for the dbus-send command
            // The environment variables may not be inherited from the parent process
            let mut dbus_cmd = std::process::Command::new("dbus-send");
            dbus_cmd
                .arg("--session")
                .arg("--print-reply")
                .arg("--dest=org.freedesktop.DBus")
                .arg("/org/freedesktop/DBus")
                .arg("org.freedesktop.DBus.ListNames");

            // Explicitly set D-Bus environment variables if available
            let mut dbus_addr_set = false;
            if let Ok(dbus_addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
                dbus_cmd.env("DBUS_SESSION_BUS_ADDRESS", &dbus_addr);
                dbus_addr_set = true;
                tracing::info!(
                    "[ContainerLifecycle] Setting DBUS_SESSION_BUS_ADDRESS for dbus-send check: {}",
                    dbus_addr
                );
            } else {
                // Try to get D-Bus address from common locations
                let xdg_runtime = std::env::var("XDG_RUNTIME_DIR")
                    .unwrap_or_else(|_| format!("/run/user/{}", std::process::id()));
                let dbus_path = format!("unix:path={}/bus", xdg_runtime);
                if std::path::Path::new(&format!("{}/bus", xdg_runtime)).exists() {
                    dbus_cmd.env("DBUS_SESSION_BUS_ADDRESS", &dbus_path);
                    dbus_addr_set = true;
                    tracing::info!(
                        "[ContainerLifecycle] Setting DBUS_SESSION_BUS_ADDRESS from XDG_RUNTIME_DIR: {}",
                        dbus_path
                    );
                }
            }

            if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
                dbus_cmd.env("XDG_RUNTIME_DIR", &xdg_runtime);
                tracing::info!(
                    "[ContainerLifecycle] Setting XDG_RUNTIME_DIR for dbus-send check: {}",
                    xdg_runtime
                );
            } else {
                let uid = std::process::id();
                let xdg_runtime = format!("/run/user/{}", uid);
                if std::path::Path::new(&xdg_runtime).exists() {
                    dbus_cmd.env("XDG_RUNTIME_DIR", &xdg_runtime);
                    tracing::info!(
                        "[ContainerLifecycle] Setting XDG_RUNTIME_DIR from default: {}",
                        xdg_runtime
                    );
                }
            }

            // Check if D-Bus session bus is accessible
            tracing::info!(
                "[ContainerLifecycle] Checking D-Bus accessibility for container {} (DBUS_SESSION_BUS_ADDRESS set: {})",
                container_id,
                dbus_addr_set
            );
            let dbus_check = dbus_cmd.output();

            let dbus_ok = match &dbus_check {
                Ok(output) => {
                    let success = output.status.success();
                    if !success {
                        tracing::warn!(
                            "[ContainerLifecycle] dbus-send check failed for container {}: exit_code={:?}, stderr={:?}",
                            container_id,
                            output.status.code(),
                            String::from_utf8_lossy(&output.stderr)
                        );
                    } else {
                        tracing::info!(
                            "[ContainerLifecycle] dbus-send check succeeded for container {}",
                            container_id
                        );
                    }
                    success
                }
                Err(e) => {
                    tracing::warn!(
                        "[ContainerLifecycle] dbus-send check error for container {}: {}",
                        container_id,
                        e
                    );
                    false
                }
            };

            if !dbus_ok {
                tracing::warn!(
                    "[ContainerLifecycle] Systemd detected but D-Bus not accessible for container {} - will use cgroupfs instead",
                    container_id
                );
                tracing::warn!(
                    "[ContainerLifecycle] This prevents libcontainer from hanging when systemd cgroup manager tries to use D-Bus"
                );
            }

            dbus_ok
        } else {
            false
        };

        // CRITICAL: Ensure D-Bus environment variables are set in this thread context before builder.build()
        // Even if set in parent process (Tauri async task), they may not be inherited in this thread
        // Use the same logic as utility_runner.rs to ensure variables are set
        if systemd_available && dbus_available {
            // Method 1: Try to get from systemd user session
            if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
                if let Ok(output) = std::process::Command::new("systemd-run")
                    .arg("--user")
                    .arg("--pipe")
                    .arg("printenv")
                    .arg("DBUS_SESSION_BUS_ADDRESS")
                    .output()
                {
                    if let Ok(addr) = String::from_utf8(output.stdout) {
                        let addr = addr.trim();
                        if !addr.is_empty() {
                            std::env::set_var("DBUS_SESSION_BUS_ADDRESS", addr);
                            tracing::info!(
                                "[ContainerLifecycle] Set DBUS_SESSION_BUS_ADDRESS in thread (method 1): {}",
                                addr
                            );
                        }
                    }
                }
            }

            // Method 2: Try to get from shell environment
            if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
                if let Ok(output) = std::process::Command::new("sh")
                    .arg("-c")
                    .arg("echo $DBUS_SESSION_BUS_ADDRESS")
                    .output()
                {
                    if let Ok(addr) = String::from_utf8(output.stdout) {
                        let addr = addr.trim();
                        if !addr.is_empty() {
                            std::env::set_var("DBUS_SESSION_BUS_ADDRESS", addr);
                            tracing::info!(
                                "[ContainerLifecycle] Set DBUS_SESSION_BUS_ADDRESS in thread (method 2): {}",
                                addr
                            );
                        }
                    }
                }
            }

            // Method 3: Try default path based on XDG_RUNTIME_DIR
            if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
                let xdg_runtime = std::env::var("XDG_RUNTIME_DIR")
                    .unwrap_or_else(|_| format!("/run/user/{}", std::process::id()));
                let dbus_path = format!("unix:path={}/bus", xdg_runtime);
                if std::path::Path::new(&format!("{}/bus", xdg_runtime)).exists() {
                    std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &dbus_path);
                    tracing::info!(
                        "[ContainerLifecycle] Set DBUS_SESSION_BUS_ADDRESS in thread (method 3): {}",
                        dbus_path
                    );
                }
            }

            // Set XDG_RUNTIME_DIR if not set
            if std::env::var("XDG_RUNTIME_DIR").is_err() {
                if let Ok(output) = std::process::Command::new("systemd-run")
                    .arg("--user")
                    .arg("--pipe")
                    .arg("printenv")
                    .arg("XDG_RUNTIME_DIR")
                    .output()
                {
                    if let Ok(dir) = String::from_utf8(output.stdout) {
                        let dir = dir.trim();
                        if !dir.is_empty() {
                            std::env::set_var("XDG_RUNTIME_DIR", dir);
                            tracing::info!(
                                "[ContainerLifecycle] Set XDG_RUNTIME_DIR in thread: {}",
                                dir
                            );
                        }
                    }
                }

                // Fallback to default
                if std::env::var("XDG_RUNTIME_DIR").is_err() {
                    let uid = std::process::id();
                    let xdg_runtime = format!("/run/user/{}", uid);
                    if std::path::Path::new(&xdg_runtime).exists() {
                        std::env::set_var("XDG_RUNTIME_DIR", &xdg_runtime);
                        tracing::info!(
                            "[ContainerLifecycle] Set XDG_RUNTIME_DIR in thread (fallback): {}",
                            xdg_runtime
                        );
                    }
                }
            }
        }

        let use_systemd = systemd_available && dbus_available;

        // Determine final systemd usage based on options override or auto-detection
        let use_systemd_final = match options.use_systemd {
            // Explicit override from caller (e.g., utility_runner.rs calling from dedicated thread)
            Some(force_systemd) => {
                if force_systemd && !use_systemd {
                    tracing::warn!(
                        "[ContainerLifecycle] Caller requested systemd for container {} but systemd/D-Bus not available (systemd_available={}, dbus_available={})",
                        container_id,
                        systemd_available,
                        dbus_available
                    );
                }
                let result = force_systemd && use_systemd; // Only use systemd if both requested AND available
                tracing::info!(
                    "[ContainerLifecycle] Using caller-specified systemd={} for container {} (effective={})",
                    force_systemd,
                    container_id,
                    result
                );
                result
            }
            // Auto-detect: Check for Tauri context and fall back to cgroupfs
            None => {
                // CRITICAL: Detect Tauri context - systemd cgroup manager hangs in Tauri context
                // even when D-Bus is properly configured. This is a known Tauri-specific issue.
                // Force cgroupfs in Tauri context to avoid the hang.
                // Systemd cgroup manager works perfectly in daemon context (vappd).
                // NOTE: Callers running in dedicated threads should pass use_systemd=Some(true) to bypass this.
                let is_tauri_context = std::env::var("TAURI_FAMILY").is_ok()
                    || std::env::var("TAURI_PLATFORM").is_ok()
                    || std::process::Command::new("ps")
                        .arg("-p")
                        .arg(std::process::id().to_string())
                        .arg("-o")
                        .arg("comm=")
                        .output()
                        .ok()
                        .and_then(|o| String::from_utf8(o.stdout).ok())
                        .map(|s| s.trim() == "vapp")
                        .unwrap_or(false);

                if is_tauri_context {
                    tracing::warn!(
                        "[ContainerLifecycle] Tauri context detected for container {} - forcing cgroupfs (use_systemd=false) to avoid systemd cgroup manager hang. Systemd works in daemon context but hangs in Tauri context. Caller can pass use_systemd=Some(true) if running in dedicated thread.",
                        container_id
                    );
                    false // Force cgroupfs in Tauri context to avoid hang
                } else {
                    use_systemd // Use systemd in daemon context where it works perfectly
                }
            }
        };

        if use_systemd_final {
            tracing::info!(
                "[ContainerLifecycle] Using systemd cgroup manager for container {} (systemd_available={}, dbus_available={})",
                container_id,
                systemd_available,
                dbus_available
            );
        } else {
            tracing::info!(
                "[ContainerLifecycle] Using cgroupfs for container {} (systemd_available={}, dbus_available={})",
                container_id,
                systemd_available,
                dbus_available
            );
        }

        tracing::info!(
            "[ContainerLifecycle] Systemd cgroup manager decision for {}: systemd_available={}, dbus_available={}, use_systemd={}, use_systemd_final={}",
            container_id,
            systemd_available,
            dbus_available,
            use_systemd,
            use_systemd_final
        );

        // ENHANCED DIAGNOSTICS: Log comprehensive thread and process context before builder.build()
        let thread_id = std::thread::current().id();
        let process_id = std::process::id();
        let thread_name = std::thread::current()
            .name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unnamed".to_string());

        // Get parent process ID
        let parent_pid = std::fs::read_to_string(format!("/proc/{}/stat", process_id))
            .ok()
            .and_then(|s| {
                s.split_whitespace()
                    .nth(3)
                    .and_then(|ppid_str| ppid_str.parse::<u32>().ok())
            });

        tracing::info!(
            "[ContainerLifecycle] Thread context for container {}: thread_id={:?}, thread_name={}, process_id={}, parent_pid={:?}",
            container_id,
            thread_id,
            thread_name,
            process_id,
            parent_pid
        );

        // Check if we're in a tokio runtime context
        let has_runtime = tokio::runtime::Handle::try_current().is_ok();
        let runtime_thread_id = if has_runtime {
            tokio::runtime::Handle::try_current().ok().and_then(|_h| {
                // Try to get runtime thread ID if possible
                Some(std::thread::current().id())
            })
        } else {
            None
        };

        tracing::info!(
            "[ContainerLifecycle] Tokio runtime context for container {}: has_runtime={}, runtime_thread_id={:?}",
            container_id,
            has_runtime,
            runtime_thread_id
        );

        // ENHANCED: Log D-Bus environment variables in current thread context
        let dbus_addr = std::env::var("DBUS_SESSION_BUS_ADDRESS");
        let xdg_runtime = std::env::var("XDG_RUNTIME_DIR");

        tracing::info!(
            "[ContainerLifecycle] D-Bus environment in thread for container {}: DBUS_SESSION_BUS_ADDRESS={:?}, XDG_RUNTIME_DIR={:?}",
            container_id,
            dbus_addr.as_ref().map(|s| s.as_str()).unwrap_or("not set"),
            xdg_runtime.as_ref().map(|s| s.as_str()).unwrap_or("not set")
        );

        // ENHANCED: Check if D-Bus socket file is accessible
        let dbus_socket_accessible = if let Ok(ref addr) = dbus_addr {
            // Parse unix:path=/run/user/XXX/bus format
            if let Some(path) = addr.strip_prefix("unix:path=") {
                std::path::Path::new(path).exists()
            } else {
                false
            }
        } else if let Ok(ref xdg) = xdg_runtime {
            let dbus_path = format!("{}/bus", xdg);
            std::path::Path::new(&dbus_path).exists()
        } else {
            let default_path = format!("/run/user/{}/bus", process_id);
            std::path::Path::new(&default_path).exists()
        };

        tracing::info!(
            "[ContainerLifecycle] D-Bus socket accessibility for container {}: accessible={}",
            container_id,
            dbus_socket_accessible
        );

        // ENHANCED: Test direct D-Bus connection (not just dbus-send command)
        // This verifies actual connectivity that libcontainer will use
        let direct_dbus_test = if use_systemd {
            // Try to connect to D-Bus socket directly
            let socket_path = if let Ok(ref addr) = dbus_addr {
                if let Some(path) = addr.strip_prefix("unix:path=") {
                    Some(path.to_string())
                } else {
                    None
                }
            } else if let Ok(ref xdg) = xdg_runtime {
                Some(format!("{}/bus", xdg))
            } else {
                Some(format!("/run/user/{}/bus", process_id))
            };

            if let Some(ref path) = socket_path {
                let accessible = std::path::Path::new(path).exists();
                if accessible {
                    // Try to read from socket to verify it's actually a D-Bus socket
                    // This is a basic check - full connection would require D-Bus protocol
                    let metadata = std::fs::metadata(path).ok();
                    let is_socket = metadata
                        .as_ref()
                        .map(|m| m.file_type().is_socket())
                        .unwrap_or(false);

                    tracing::info!(
                        "[ContainerLifecycle] Direct D-Bus socket test for container {}: path={}, exists={}, is_socket={}",
                        container_id,
                        path,
                        accessible,
                        is_socket
                    );

                    accessible && is_socket
                } else {
                    tracing::warn!(
                        "[ContainerLifecycle] D-Bus socket path does not exist for container {}: {}",
                        container_id,
                        path
                    );
                    false
                }
            } else {
                tracing::warn!(
                    "[ContainerLifecycle] Could not determine D-Bus socket path for container {}",
                    container_id
                );
                false
            }
        } else {
            // Not using systemd, skip test
            true
        };

        if use_systemd_final && !direct_dbus_test {
            tracing::warn!(
                "[ContainerLifecycle] Direct D-Bus connection test failed for container {} - systemd cgroup manager may hang",
                container_id
            );
        }

        // CRITICAL: builder.build() can hang in Tauri's async runtime context
        // Even in a dedicated std::thread, builder.build() might wait for systemd/D-Bus operations
        // Add explicit logging before and after to identify where it hangs
        //
        // NOTE: builder.build() with .with_detach(true) should return immediately after spawning init,
        // but it may wait for the init process to signal readiness or for cgroup operations to complete
        //
        // libcgroups systemd cgroup manager may make async D-Bus calls internally that need runtime context
        // Ensure we're in a runtime context before calling builder.build()
        let build_start = std::time::Instant::now();

        tracing::info!(
            "[ContainerLifecycle] About to call builder.build() for container {}: thread_id={:?}, has_runtime={}, use_systemd={}, use_systemd_final={}, direct_dbus_test={}",
            container_id,
            thread_id,
            has_runtime,
            use_systemd,
            use_systemd_final,
            direct_dbus_test
        );

        // CRITICAL: builder.build() can hang after cgroup operation even with D-Bus accessible
        // The cgroup operation succeeds, but builder.build() may wait for additional operations
        //
        // HYPOTHESIS: libcontainer may be making additional D-Bus calls after creating the scope
        // that are blocking. Even though the scope is created successfully, libcontainer might be:
        // 1. Waiting for the scope to transition to a specific state
        // 2. Making additional D-Bus calls to verify/configure the scope
        // 3. Waiting for the init process to signal readiness
        //
        // Since we're using .with_detach(true), it should return immediately after spawning init,
        // but libcontainer's systemd cgroup manager may have additional blocking operations.
        //
        // Wrap in panic::catch_unwind to handle any panics gracefully
        tracing::info!(
            "[ContainerLifecycle] Calling builder.build() for container {} - this may take time if libcontainer makes additional D-Bus calls",
            container_id
        );

        // CRITICAL: For rootless containers in Tauri context, ALWAYS remove the resources section
        // from the OCI spec. This is necessary because:
        //
        // 1. libcgroups with systemd feature ALWAYS uses systemd cgroup manager
        // 2. When resources are present, libcgroups tries to enable cgroup controllers via D-Bus
        // 3. These controller enablement D-Bus calls hang in Tauri context
        // 4. When resources are removed, libcgroups skips controller operations and just creates
        //    the scope - which works!
        //
        // The hang happens DURING cgroup creation when resources are present, but AFTER cgroup
        // creation when resources are absent. Removing resources allows the scope to be created
        // successfully.
        //
        // This MUST run regardless of use_systemd_final because libcgroups always uses systemd.
        let is_rootless = nix::unistd::Uid::current().as_raw() != 0;

        // Check if we're in Tauri context (where D-Bus operations for controllers hang)
        let is_tauri_context = std::env::var("TAURI_FAMILY").is_ok()
            || std::env::var("TAURI_PLATFORM").is_ok()
            || std::process::Command::new("ps")
                .arg("-p")
                .arg(std::process::id().to_string())
                .arg("-o")
                .arg("comm=")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim() == "vapp")
                .unwrap_or(false);

        if is_rootless && is_tauri_context {
            let spec_path = create_args.bundle.join("config.json");
            if let Ok(spec_content) = std::fs::read_to_string(&spec_path) {
                if let Ok(mut spec) = serde_json::from_str::<serde_json::Value>(&spec_content) {
                    let mut needs_update = false;

                    if let Some(linux) = spec.get_mut("linux") {
                        if let Some(linux_obj) = linux.as_object_mut() {
                            // CRITICAL: Remove resources to prevent D-Bus controller enablement
                            // which hangs in Tauri context. This is the KEY fix.
                            if linux_obj.contains_key("resources") {
                                linux_obj.remove("resources");
                                needs_update = true;
                                tracing::info!(
                                    "[ContainerLifecycle] Removed linux.resources from OCI spec for rootless Tauri container {} (prevents D-Bus controller hang)",
                                    container_id
                                );
                            }
                            // Also remove cgroupsPath if it exists (let libcgroups handle it)
                            if linux_obj.contains_key("cgroupsPath") {
                                linux_obj.remove("cgroupsPath");
                                needs_update = true;
                                tracing::info!(
                                    "[ContainerLifecycle] Removed cgroupsPath from OCI spec for rootless container {} (letting libcgroups auto-generate)",
                                    container_id
                                );
                            }
                        }
                    }

                    // Write updated spec back to file if we modified it
                    if needs_update {
                        if let Ok(updated_spec_json) = serde_json::to_string_pretty(&spec) {
                            if let Err(e) = std::fs::write(&spec_path, updated_spec_json) {
                                tracing::warn!(
                                    "[ContainerLifecycle] Failed to write updated OCI spec: {}",
                                    e
                                );
                            } else {
                                tracing::info!(
                                    "[ContainerLifecycle] Updated OCI spec for rootless Tauri container"
                                );
                            }
                        }
                    }
                }
            }
        } else if !use_systemd_final && !is_rootless {
            // For privileged containers with cgroupfs, set explicit path
            let spec_path = create_args.bundle.join("config.json");
            if let Ok(spec_content) = std::fs::read_to_string(&spec_path) {
                if let Ok(mut spec) = serde_json::from_str::<serde_json::Value>(&spec_content) {
                    if let Some(linux) = spec.get_mut("linux") {
                        if let Some(linux_obj) = linux.as_object_mut() {
                            let cgroups_path =
                                format!("/sys/fs/cgroup/4lock-agent/{}", container_id);
                            linux_obj
                                .insert("cgroupsPath".to_string(), serde_json::json!(cgroups_path));
                            tracing::info!(
                                "[ContainerLifecycle] Set cgroupsPath={} for privileged container {}",
                                cgroups_path,
                                container_id
                            );
                            if let Ok(updated_spec_json) = serde_json::to_string_pretty(&spec) {
                                let _ = std::fs::write(&spec_path, updated_spec_json);
                            }
                        }
                    }
                }
            }
        }

        // DIAGNOSTIC: Log that we're about to enter the build phase
        // The cgroup has been created at this point, so any hang is in the init process setup
        tracing::info!(
            "[ContainerLifecycle] Cgroup setup complete, entering container init phase for {} - init process will set up namespaces",
            container_id
        );

        // ENHANCED DIAGNOSTIC: Log OCI spec details before builder.build()
        // This helps diagnose "failed to prepare rootfs" errors
        let spec_path = create_args.bundle.join("config.json");
        if let Ok(spec_content) = std::fs::read_to_string(&spec_path) {
            if let Ok(spec) = serde_json::from_str::<serde_json::Value>(&spec_content) {
                // Log namespaces
                if let Some(linux) = spec.get("linux") {
                    if let Some(namespaces) = linux.get("namespaces").and_then(|n| n.as_array()) {
                        let namespace_types: Vec<String> = namespaces
                            .iter()
                            .filter_map(|n| n.get("type").and_then(|t| t.as_str()))
                            .map(|s| s.to_string())
                            .collect();
                        tracing::info!(
                            "[ContainerLifecycle] OCI spec namespaces for {}: {:?}",
                            container_id,
                            namespace_types
                        );
                    } else {
                        tracing::warn!(
                            "[ContainerLifecycle] No namespaces found in OCI spec for {}",
                            container_id
                        );
                    }
                }

                // Log mount points
                if let Some(mounts) = spec.get("mounts").and_then(|m| m.as_array()) {
                    let mount_info: Vec<String> = mounts
                        .iter()
                        .filter_map(|m| {
                            let dest = m.get("destination").and_then(|d| d.as_str())?;
                            let typ = m.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
                            Some(format!("{}:{}", typ, dest))
                        })
                        .collect();
                    tracing::info!(
                        "[ContainerLifecycle] OCI spec mounts for {}: {:?}",
                        container_id,
                        mount_info
                    );
                } else {
                    tracing::warn!(
                        "[ContainerLifecycle] No mounts found in OCI spec for {}",
                        container_id
                    );
                }
            }
        }

        // Log rootfs path and permissions
        use std::os::unix::fs::PermissionsExt;
        if let Ok(rootfs_meta) = std::fs::metadata(&rootfs_path) {
            let rootfs_perms = rootfs_meta.permissions();
            tracing::info!(
                "[ContainerLifecycle] Rootfs path for {}: {:?}, permissions: {:o}, exists: {}",
                container_id,
                rootfs_path,
                rootfs_perms.mode(),
                rootfs_path.exists()
            );

            // Log parent directory permissions (required for user namespace path resolution)
            if let Some(parent) = rootfs_path.parent() {
                if let Ok(parent_meta) = std::fs::metadata(parent) {
                    let parent_perms = parent_meta.permissions();
                    tracing::info!(
                        "[ContainerLifecycle] Rootfs parent directory for {}: {:?}, permissions: {:o}",
                        container_id,
                        parent,
                        parent_perms.mode()
                    );
                }
            }
        } else {
            tracing::warn!(
                "[ContainerLifecycle] Could not read rootfs metadata for {}: {:?}",
                container_id,
                rootfs_path
            );
        }

        let build_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            builder
                .as_init(&create_args.bundle)
                .with_systemd(use_systemd_final)
                .with_detach(true)
                .with_no_pivot(create_args.no_pivot)
                .build()
        }));

        let build_duration = build_start.elapsed();
        let has_runtime_after = tokio::runtime::Handle::try_current().is_ok();

        // ENHANCED: Log comprehensive diagnostics after builder.build() returns
        tracing::info!(
            "[ContainerLifecycle] builder.build() returned after {:?} for container {}: thread_id={:?}, has_runtime={}, use_systemd_final={}",
            build_duration,
            container_id,
            thread_id,
            has_runtime_after,
            use_systemd_final
        );

        // Log if builder.build() took too long (potential hang indicator)
        if build_duration.as_secs() > 1 {
            tracing::warn!(
                "[ContainerLifecycle] builder.build() took longer than expected for container {}: {:?} (this may indicate a hang or slow D-Bus operation)",
                container_id,
                build_duration
            );
        }

        let build_result = match build_result {
            Ok(result) => result,
            Err(panic) => {
                let panic_msg = if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = panic.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "Unknown panic".to_string()
                };
                tracing::error!(
                    "[ContainerLifecycle] builder.build() panicked for container {}: {}",
                    container_id,
                    panic_msg
                );
                return Err(ContainerError::LibcontainerError(format!(
                    "builder.build() panicked: {}",
                    panic_msg
                )));
            }
        };

        tracing::debug!(
            "[ContainerLifecycle] builder.build() completed for container {}",
            container_id
        );

        build_result
            .context(format!("failed to create container {}", container_id))
            .map_err(|e| {
                // Capture full error chain for detailed diagnostics
                let error_chain: Vec<String> = e.chain().map(|err| err.to_string()).collect();
                let error_message = if error_chain.len() > 1 {
                    format!("{} (chain: {:?})", error_chain[0], error_chain)
                } else {
                    error_chain[0].clone()
                };

                tracing::error!(
                    "[ContainerLifecycle] Failed to create container {}: {}",
                    container_id,
                    error_message
                );
                tracing::error!(
                    "[ContainerLifecycle] Full error chain for {}: {:?}",
                    container_id,
                    error_chain
                );
                tracing::error!(
                    "[ContainerLifecycle] Bundle path: {:?}, Rootfs: {:?}",
                    bundle_dir,
                    rootfs_path
                );

                ContainerError::LibcontainerError(format!(
                    "failed to create container {}: {}",
                    container_id, error_message
                ))
            })?;

        tracing::info!(
            "[ContainerLifecycle] Container {} created successfully",
            container_id
        );

        // Containers use host networking. No per-container networking setup needed.

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = container_id;
        let _ = bundle_dir;
        let _ = root_path;
        Err(ContainerError::Other(
            "Container operations only available on Linux".to_string(),
        ))
    }
}

/// Start a container via subprocess to avoid GTK/WebKit process context issues.
#[cfg(target_os = "linux")]
fn start_container_via_subprocess(
    root_path: &Path,
    container_id: &str,
) -> Result<(), ContainerError> {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    // Find the vapp binary - it should be the current executable
    let vapp_binary = std::env::current_exe().map_err(|e| {
        ContainerError::Other(format!("Failed to get current executable path: {}", e))
    })?;

    tracing::info!(
        "[ContainerLifecycle] Spawning subprocess for container start: {} --container-start {} {:?}",
        vapp_binary.display(),
        container_id,
        root_path
    );

    // Spawn the subprocess with environment marker to prevent infinite recursion
    let mut child = Command::new(&vapp_binary)
        .arg("--container-start")
        .arg(container_id)
        .arg(root_path)
        .env("VAPP_CONTAINER_HELPER", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            ContainerError::Other(format!("Failed to spawn container start subprocess: {}", e))
        })?;

    // Wait for the subprocess to complete with timeout
    let timeout = Duration::from_secs(30); // 30 second timeout for container start
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    tracing::info!(
                        "[ContainerLifecycle] Subprocess container start succeeded for {}",
                        container_id
                    );
                    return Ok(());
                } else {
                    let stderr = child
                        .stderr
                        .take()
                        .and_then(|mut s| {
                            let mut buf = String::new();
                            std::io::Read::read_to_string(&mut s, &mut buf).ok()?;
                            Some(buf)
                        })
                        .unwrap_or_default();

                    tracing::error!(
                        "[ContainerLifecycle] Subprocess container start failed for {}: exit_code={:?}, stderr={}",
                        container_id,
                        status.code(),
                        stderr
                    );

                    return Err(ContainerError::Other(format!(
                        "Container start subprocess failed with exit code {:?}: {}",
                        status.code(),
                        stderr
                    )));
                }
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    tracing::error!(
                        "[ContainerLifecycle] Subprocess container start timed out for {} after {:?}",
                        container_id,
                        timeout
                    );
                    return Err(ContainerError::Other(format!(
                        "Container start subprocess timed out after {:?}",
                        timeout
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(ContainerError::Other(format!(
                    "Failed to wait for container start subprocess: {}",
                    e
                )));
            }
        }
    }
}

pub fn start_container(root_path: &Path, container_id: &str) -> Result<(), ContainerError> {
    #[cfg(target_os = "linux")]
    {
        use anyhow::Context;
        use libcontainer::container::Container;

        // CRITICAL: In Tauri context, use subprocess-based container start
        // to avoid potential process context issues
        let is_tauri_context = std::env::var("TAURI_FAMILY").is_ok()
            || std::env::var("TAURI_PLATFORM").is_ok()
            || std::process::Command::new("ps")
                .arg("-p")
                .arg(std::process::id().to_string())
                .arg("-o")
                .arg("comm=")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim() == "vapp")
                .unwrap_or(false);

        // Check if we're already in helper mode (to avoid infinite recursion)
        let is_helper_mode = std::env::var("VAPP_CONTAINER_HELPER").is_ok();

        if is_tauri_context && !is_helper_mode {
            tracing::info!(
                "[ContainerLifecycle] Tauri context detected - using subprocess for container start: {}",
                container_id
            );
            return start_container_via_subprocess(root_path, container_id);
        }

        tracing::info!("[ContainerLifecycle] Starting container: {}", container_id);

        // Construct container root path
        // libcontainer stores containers at root_path/<container_id> or root_path/containers/<container_id>
        // Check both locations to find the container
        let container_root_v1 = root_path.join("containers").join(container_id);
        let container_root_v2 = root_path.join(container_id);

        let container_root = if container_root_v1.join("state.json").exists()
            || container_root_v1.join("youki_config.json").exists()
        {
            container_root_v1
        } else if container_root_v2.join("state.json").exists()
            || container_root_v2.join("youki_config.json").exists()
        {
            container_root_v2
        } else {
            return Err(ContainerError::ContainerNotFound(format!(
                "Container {} not found at {:?} or {:?}",
                container_id, container_root_v1, container_root_v2
            )));
        };

        tracing::debug!(
            "[ContainerLifecycle] Loading container from: {:?}",
            container_root
        );

        // Load container using libcontainer (Container::load expects PathBuf, not &Path)
        let mut container = Container::load(container_root)
            .context(format!(
                "could not load state for container {}",
                container_id
            ))
            .map_err(|e| ContainerError::LibcontainerError(e.to_string()))?;

        tracing::debug!(
            "[ContainerLifecycle] Container {} loaded, starting...",
            container_id
        );

        // Start the container
        container
            .start()
            .context(format!("failed to start container {}", container_id))
            .map_err(|e| ContainerError::LibcontainerError(e.to_string()))?;

        tracing::info!(
            "[ContainerLifecycle] Container {} started successfully",
            container_id
        );

        // Containers use host networking. No per-container networking setup needed.

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = root_path;
        let _ = container_id;
        Err(ContainerError::Other(
            "Container operations only available on Linux".to_string(),
        ))
    }
}

pub fn stop_container(root_path: &Path, container_id: &str) -> Result<(), ContainerError> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    use serde_json::Value;
    use std::fs;

    // Load container state to get PID
    let state_file = root_path
        .join("containers")
        .join(container_id)
        .join("state.json");

    if !state_file.exists() {
        return Err(ContainerError::Other(format!(
            "Container state file not found: {:?}",
            state_file
        )));
    }

    // Read state.json to get PID
    let content = fs::read_to_string(&state_file).map_err(|e| {
        ContainerError::Other(format!("Failed to read state file {:?}: {}", state_file, e))
    })?;

    let mut state: Value = serde_json::from_str(&content).map_err(|e| {
        ContainerError::Other(format!(
            "Failed to parse state file {:?}: {}",
            state_file, e
        ))
    })?;

    // Check if container is already stopped
    let status = state["status"].as_str().unwrap_or("stopped");

    if status != "running" {
        // Already stopped
        return Ok(());
    }

    // Get PID
    let pid = state["pid"]
        .as_u64()
        .ok_or_else(|| ContainerError::Other("Missing or invalid PID in state file".to_string()))?
        as i32;

    // Containers use host networking. No per-container networking to clean up.

    // Try graceful shutdown with SIGTERM
    match kill(Pid::from_raw(pid), Signal::SIGTERM) {
        Ok(_) => {
            // Wait up to 5 seconds for process to exit
            for _ in 0..50 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                // Check if process still exists
                if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                    // Process exited gracefully
                    break;
                }
            }

            // If still running, force kill with SIGKILL
            if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
                // Wait a bit more
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        Err(nix::errno::Errno::ESRCH) => {
            // Process doesn't exist (already stopped)
            // This is fine, just update state
        }
        Err(e) => {
            return Err(ContainerError::Other(format!(
                "Failed to send SIGTERM to process {}: {}",
                pid, e
            )));
        }
    }

    // Update state.json to mark container as stopped
    state["status"] = serde_json::Value::String("stopped".to_string());
    state["pid"] = serde_json::Value::Null;

    let updated_content = serde_json::to_string_pretty(&state)
        .map_err(|e| ContainerError::Other(format!("Failed to serialize updated state: {}", e)))?;

    fs::write(&state_file, updated_content).map_err(|e| {
        ContainerError::Other(format!(
            "Failed to update state file {:?}: {}",
            state_file, e
        ))
    })?;

    Ok(())
}

pub fn delete_container(
    root_path: &Path,
    container_id: &str,
    force: bool,
) -> Result<(), ContainerError> {
    #[cfg(target_os = "linux")]
    {
        tracing::info!(
            "[ContainerLifecycle] Deleting container: {} (force: {})",
            container_id,
            force
        );

        // Stop container first if not forced
        if !force {
            let _ = stop_container(root_path, container_id);
        }

        // Construct container root path - check both possible locations
        let container_root_v1 = root_path.join("containers").join(container_id);
        let container_root_v2 = root_path.join(container_id);

        let container_root = if container_root_v1.join("state.json").exists()
            || container_root_v1.join("youki_config.json").exists()
        {
            container_root_v1
        } else if container_root_v2.join("state.json").exists()
            || container_root_v2.join("youki_config.json").exists()
        {
            container_root_v2
        } else {
            // Container doesn't exist - that's OK for delete operation
            tracing::info!(
                "[ContainerLifecycle] Container {} does not exist, nothing to delete",
                container_id
            );
            return Ok(());
        };

        // Delete the container directory (this removes state.json, youki_config.json, etc.)
        if container_root.exists() {
            std::fs::remove_dir_all(&container_root).map_err(ContainerError::IoError)?;
            tracing::info!(
                "[ContainerLifecycle] Container {} deleted successfully (removed directory: {:?})",
                container_id,
                container_root
            );
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = root_path;
        let _ = container_id;
        let _ = force;
        Err(ContainerError::Other(
            "Container operations only available on Linux".to_string(),
        ))
    }
}
