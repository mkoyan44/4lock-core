/// UtilityRunner - runs ephemeral operational containers for specific tasks
/// Examples: certificate generation, manifest application, diagnostics
/// Linux-only: uses crate::rootless (libcontainer, lifecycle, etc.)
#[cfg(target_os = "linux")]

use crate::bootstrap::image_manager::ImageManager;
use crate::rootless::bundle;
use crate::rootless::config::ContainerConfig;
use crate::rootless::error::ContainerError as LinuxError;
use crate::rootless::lifecycle;
use crate::provisioner::ProvisionError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;

/// Configuration for a utility container
pub struct UtilityContainerConfig {
    pub name: String,                     // Container name (prefix: utility-)
    pub image: String,                    // Image to use (alpine, kubectl, etc.)
    pub command: Vec<String>,             // Command to execute
    pub volumes: HashMap<String, String>, // Host:Container mounts
    pub env: HashMap<String, String>,     // Environment variables
    pub network_mode: String,             // "host" or "none"
}

/// Output from utility container execution
pub struct UtilityContainerOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// UtilityRunner - runs ephemeral operational containers for specific tasks
pub struct UtilityRunner {
    app_dir: PathBuf,
    container_manager: crate::rootless::orchestration::ContainerManager,
}

impl UtilityRunner {
    /// Create a new UtilityRunner
    pub fn new(
        app_dir: PathBuf,
        container_manager: crate::rootless::orchestration::ContainerManager,
    ) -> Self {
        tracing::debug!(
            "[UtilityRunner] Initializing with app_dir: {}",
            app_dir.display()
        );
        Self {
            app_dir,
            container_manager,
        }
    }

    /// Run a utility container and wait for completion
    pub async fn run(
        &self,
        image_manager: &ImageManager,
        config: UtilityContainerConfig,
    ) -> Result<UtilityContainerOutput, ProvisionError> {
        let container_name = if config.name.starts_with("utility-") {
            config.name.clone()
        } else {
            format!("utility-{}", config.name)
        };

        tracing::info!(
            "[UtilityRunner] Running utility container: {} with image: {}",
            container_name,
            config.image
        );

        // CRITICAL: In Tauri context, libcontainer's init process hangs due to a deadlock
        // in parent-child communication. The init process gets stuck in INTER state waiting
        // for the parent, while the parent waits for the child. This is a fundamental issue
        // with how libcontainer works in GTK/WebKit's process environment.
        //
        // As a workaround, we run utility commands directly on the host without containerization.
        // This is safe for utility containers because:
        // 1. They run short-lived commands (CA generation, etc.)
        // 2. They don't need network isolation
        // 3. They operate on mounted volumes which we can access directly
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
            tracing::info!(
                "[UtilityRunner] Tauri context detected - running utility command directly without containerization for {}",
                container_name
            );
            return self.run_direct(&config).await;
        }

        // 1. Ensure image is available
        let image_dir = image_manager
            .ensure_image(&config.image)
            .await
            .map_err(|e| {
                ProvisionError::Image(format!(
                    "Failed to ensure image {} for utility container: {}",
                    config.image, e
                ))
            })?;

        let image_rootfs = image_dir.join("rootfs");

        tracing::debug!(
            "[UtilityRunner] Image rootfs path: {:?}, exists: {}",
            image_rootfs,
            image_rootfs.exists()
        );

        // 2. Create bundle directory (clean up existing one first to avoid stale config.json)
        let bundle_dir = self
            .app_dir
            .join("containers/bundles")
            .join(&container_name);

        // Clean up existing bundle directory to ensure fresh config.json
        // This prevents stale cgroupsPath from previous runs from causing issues
        if bundle_dir.exists() {
            tracing::debug!(
                "[UtilityRunner] Cleaning up existing bundle directory to ensure fresh config: {:?}",
                bundle_dir
            );
            let _ = std::fs::remove_dir_all(&bundle_dir);
        }

        std::fs::create_dir_all(&bundle_dir).map_err(|e| {
            ProvisionError::Io(std::io::Error::other(format!(
                "Failed to create bundle directory {:?}: {}",
                bundle_dir, e
            )))
        })?;

        let bundle_rootfs = bundle_dir.join("rootfs");

        tracing::debug!("[UtilityRunner] Bundle rootfs path: {:?}", bundle_rootfs);

        // 3. Copy image rootfs to bundle rootfs
        if image_rootfs.exists() {
            if bundle_rootfs.exists() {
                tracing::debug!(
                    "[UtilityRunner] Removing existing bundle rootfs: {:?}",
                    bundle_rootfs
                );
                std::fs::remove_dir_all(&bundle_rootfs).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to remove existing bundle rootfs {:?}: {}",
                        bundle_rootfs, e
                    )))
                })?;
            }
            tracing::debug!(
                "[UtilityRunner] Copying image rootfs {:?} to bundle rootfs {:?}",
                image_rootfs,
                bundle_rootfs
            );
            self.copy_dir_recursive(&image_rootfs, &bundle_rootfs)
                .map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to copy rootfs from {:?} to {:?}: {}",
                        image_rootfs, bundle_rootfs, e
                    )))
                })?;
            tracing::debug!("[UtilityRunner] Successfully copied rootfs");
        } else {
            return Err(ProvisionError::Image(format!(
                "Image rootfs not found at {:?}",
                image_rootfs
            )));
        }

        // 4. Create bundle structure
        bundle::create_bundle_structure(&bundle_dir, &bundle_rootfs).map_err(|e| {
            ProvisionError::Bundle(format!("Failed to create bundle structure: {}", e))
        })?;

        // 5. Create output directories for stdout/stderr
        // Use a directory INSIDE the rootfs to avoid bind mount issues in rootless containers
        let output_dir = self
            .app_dir
            .join("containers/utility-output")
            .join(&container_name);
        std::fs::create_dir_all(&output_dir).map_err(ProvisionError::Io)?;
        let stdout_file = output_dir.join("stdout.log");
        let stderr_file = output_dir.join("stderr.log");

        // Create empty log files on host (for reading after container exits)
        std::fs::File::create(&stdout_file).map_err(ProvisionError::Io)?;
        std::fs::File::create(&stderr_file).map_err(ProvisionError::Io)?;

        // Also create the output directory inside rootfs itself (not relying on bind mount)
        // This ensures the container can always write to it regardless of mount issues
        let rootfs_output_dir = bundle_rootfs.join("tmp/utility-output");
        std::fs::create_dir_all(&rootfs_output_dir).map_err(|e| {
            ProvisionError::Io(std::io::Error::other(format!(
                "Failed to create rootfs output directory: {}",
                e
            )))
        })?;
        // Pre-create empty log files in rootfs
        std::fs::File::create(rootfs_output_dir.join("stdout.log")).map_err(ProvisionError::Io)?;
        std::fs::File::create(rootfs_output_dir.join("stderr.log")).map_err(ProvisionError::Io)?;

        tracing::debug!(
            "[UtilityRunner] Created output directory in rootfs: {:?}",
            rootfs_output_dir
        );

        // Mount output directory into container (backup - may not work in all rootless scenarios)
        let output_mount = "/tmp/utility-output".to_string();
        let mut volumes_with_output = config.volumes.clone();
        volumes_with_output.insert(
            output_dir.to_string_lossy().to_string(),
            output_mount.clone(),
        );

        // Attempt to mount host openssl binary and its shared libraries into the utility container
        // to avoid package installation inside user-namespaced containers.
        // This is safe for ephemeral utility tasks and avoids network/permission issues.
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            if let Ok(which_out) = Command::new("which").arg("openssl").output() {
                if which_out.status.success() {
                    let host_openssl_path = String::from_utf8_lossy(&which_out.stdout)
                        .trim()
                        .to_string();
                    if !host_openssl_path.is_empty() {
                        // Mount host openssl to a well-known path inside container
                        // Prefer /usr/bin/openssl which is in PATH
                        volumes_with_output
                            .insert(host_openssl_path.clone(), "/usr/bin/openssl".to_string());

                        // Discover and mount required shared libraries reported by ldd
                        if let Ok(ldd_out) = Command::new("ldd").arg(&host_openssl_path).output() {
                            if ldd_out.status.success() {
                                let text = String::from_utf8_lossy(&ldd_out.stdout);
                                for line in text.lines() {
                                    // Patterns:
                                    //   libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x...)
                                    //   /lib64/ld-linux-x86-64.so.2 (0x...)
                                    if let Some(idx) = line.find("=>") {
                                        let rest = line[idx + 2..].trim();
                                        let path = rest.split_whitespace().next().unwrap_or("");
                                        if path.starts_with('/') {
                                            volumes_with_output
                                                .insert(path.to_string(), path.to_string());
                                        }
                                    } else {
                                        // Handle lines without "=>", first token may be path
                                        let first = line.split_whitespace().next().unwrap_or("");
                                        if first.starts_with('/') {
                                            volumes_with_output
                                                .insert(first.to_string(), first.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 5.5. Create mount target directories in rootfs
        // CRITICAL: Bind mounts require the target path (or its parent directory) to exist
        // For file mounts, we create the parent directory and touch the file
        // For directory mounts, we create the directory
        for (_host_path, container_path) in &volumes_with_output {
            let target_path = bundle_rootfs.join(container_path.trim_start_matches('/'));

            // Check if host path is a file or directory
            let host_path_obj = std::path::Path::new(_host_path);
            if host_path_obj.is_file() {
                // For file mounts, create parent directory and touch the file
                if let Some(parent) = target_path.parent() {
                    if !parent.exists() {
                        tracing::debug!(
                            "[UtilityRunner] Creating parent directory for file mount: {:?}",
                            parent
                        );
                        std::fs::create_dir_all(parent).map_err(|e| {
                            ProvisionError::Io(std::io::Error::other(format!(
                                "Failed to create parent directory {:?}: {}",
                                parent, e
                            )))
                        })?;
                    }
                }
                if !target_path.exists() {
                    tracing::debug!(
                        "[UtilityRunner] Creating mount target file: {:?}",
                        target_path
                    );
                    std::fs::File::create(&target_path).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to create mount target file {:?}: {}",
                            target_path, e
                        )))
                    })?;
                }
            } else {
                // For directory mounts, create the directory
                if !target_path.exists() {
                    tracing::debug!(
                        "[UtilityRunner] Creating mount target directory: {:?}",
                        target_path
                    );
                    std::fs::create_dir_all(&target_path).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to create mount target directory {:?}: {}",
                            target_path, e
                        )))
                    })?;
                }
            }
        }

        // 6. Create ContainerConfig
        let mut container_config =
            ContainerConfig::new(container_name.clone(), "utility".to_string())
                .with_base_image(config.image.clone());

        container_config.network_mode = config.network_mode.clone();

        // Add volume mounts (including output directory)
        for (host_path, container_path) in &volumes_with_output {
            container_config
                .volumes
                .insert(host_path.clone(), container_path.clone());
        }

        // Add environment variables
        for (key, value) in &config.env {
            container_config
                .environment
                .insert(key.clone(), value.clone());
        }

        // 7. Modify command to redirect stdout/stderr to mounted output directory
        let mut command_with_redirect = config.command.clone();

        // Detect which shell is available in the image
        // Different images have different shell binaries:
        // - Alpine: /bin/busybox (provides sh via symlink)
        // - Bitnami/kubectl: /bin/bash
        // - Debian-based: /bin/sh or /bin/bash
        let shell_binary = if bundle_rootfs.join("bin/busybox").exists() {
            "/bin/busybox".to_string()
        } else if bundle_rootfs.join("bin/bash").exists() {
            "/bin/bash".to_string()
        } else if bundle_rootfs.join("bin/sh").exists() {
            "/bin/sh".to_string()
        } else {
            tracing::warn!("[UtilityRunner] No shell found in rootfs, trying /bin/sh as fallback");
            "/bin/sh".to_string()
        };

        let uses_busybox = shell_binary == "/bin/busybox";

        tracing::debug!(
            "[UtilityRunner] Using shell: {} for container {}",
            shell_binary,
            container_name
        );

        // Convert shell commands to use the detected shell
        if !command_with_redirect.is_empty()
            && (command_with_redirect[0] == "/bin/sh"
                || command_with_redirect[0] == "sh"
                || command_with_redirect[0] == "/bin/bash"
                || command_with_redirect[0] == "bash")
        {
            tracing::debug!(
                "[UtilityRunner] Converting shell to {}. Original command: {:?}",
                shell_binary,
                command_with_redirect
            );
            command_with_redirect[0] = shell_binary.clone();
            if uses_busybox
                && (command_with_redirect.len() == 1 || command_with_redirect[1] != "sh")
            {
                command_with_redirect.insert(1, "sh".to_string());
            }
            tracing::debug!(
                "[UtilityRunner] Converted command: {:?}",
                command_with_redirect
            );
        }

        if command_with_redirect.len() > 1 {
            // Handle commands that are already "sh -c 'command'" or similar
            let full_command = if command_with_redirect.len() >= 3
                && (command_with_redirect[0] == "sh" || command_with_redirect[0].ends_with("sh"))
                && command_with_redirect[1] == "-c"
            {
                // Already a sh -c command, extract the command part and add redirection
                let inner_command = &command_with_redirect[2..].join(" ");
                // Escape single quotes in the inner command for proper shell quoting
                let escaped_command = inner_command.replace('\'', "'\"'\"'");
                // Wrap in parentheses to ensure redirection applies to entire command chain
                let cmd = format!(
                    "({}) > {}/stdout.log 2> {}/stderr.log",
                    escaped_command, output_mount, output_mount
                );
                tracing::debug!(
                    "[UtilityRunner] Wrapping existing sh -c command. Inner: {}, Final: {}",
                    inner_command,
                    cmd
                );
                cmd
            } else {
                // Simple command, wrap in sh -c with redirection
                let cmd = command_with_redirect.join(" ");
                let final_cmd = format!(
                    "{} > {}/stdout.log 2> {}/stderr.log",
                    cmd, output_mount, output_mount
                );
                tracing::debug!(
                    "[UtilityRunner] Wrapping simple command. Original: {}, Final: {}",
                    cmd,
                    final_cmd
                );
                final_cmd
            };

            // Build final command based on detected shell
            command_with_redirect = if uses_busybox {
                vec![
                    shell_binary,
                    "sh".to_string(),
                    "-c".to_string(),
                    full_command,
                ]
            } else {
                vec![shell_binary, "-c".to_string(), full_command]
            };

            tracing::debug!(
                "[UtilityRunner] Final command array: {:?}",
                command_with_redirect
            );
        }

        // 8. Generate OCI spec with custom command
        self.generate_utility_oci_spec(
            &container_config,
            &bundle_rootfs,
            &bundle_dir,
            &command_with_redirect,
        )?;

        // 8.5. CRITICAL: When D-Bus is not available, we must force cgroupfs usage by setting cgroupsPath
        // This MUST happen AFTER generate_utility_oci_spec creates the bundle config.json
        // libcontainer/libcgroups auto-detects systemd even when use_systemd=false is passed
        // Setting cgroupsPath in the bundle config.json forces cgroupfs usage
        // Check if we're in a context where D-Bus might not be available (Tauri UI mode)
        let is_tauri_context = std::env::var("TAURI_PLATFORM").is_ok()
            || std::env::var("TAURI_FAMILY").is_ok()
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

        tracing::info!(
            "[UtilityRunner] Tauri context detection for {}: is_tauri_context={}",
            container_name,
            is_tauri_context
        );

        // Check D-Bus availability (same check as in lifecycle.rs)
        // CRITICAL: Even if D-Bus is accessible from shell, it might not be accessible from Tauri's thread context
        // We need to check D-Bus availability in the same thread context where builder.build() will run
        let _dbus_available_check = if is_tauri_context {
            tracing::info!(
                "[UtilityRunner] Checking D-Bus availability for container {}",
                container_name
            );

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
            if let Ok(dbus_addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
                dbus_cmd.env("DBUS_SESSION_BUS_ADDRESS", &dbus_addr);
                tracing::info!(
                    "[UtilityRunner] Setting DBUS_SESSION_BUS_ADDRESS for dbus-send check: {}",
                    dbus_addr
                );
            } else {
                // Try to get D-Bus address from common locations
                let xdg_runtime = std::env::var("XDG_RUNTIME_DIR")
                    .unwrap_or_else(|_| format!("/run/user/{}", std::process::id()));
                let dbus_path = format!("unix:path={}/bus", xdg_runtime);
                if std::path::Path::new(&format!("{}/bus", xdg_runtime)).exists() {
                    dbus_cmd.env("DBUS_SESSION_BUS_ADDRESS", &dbus_path);
                    tracing::info!(
                        "[UtilityRunner] Setting DBUS_SESSION_BUS_ADDRESS from XDG_RUNTIME_DIR: {}",
                        dbus_path
                    );
                }
            }

            if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
                dbus_cmd.env("XDG_RUNTIME_DIR", &xdg_runtime);
            } else {
                let uid = std::process::id();
                let xdg_runtime = format!("/run/user/{}", uid);
                if std::path::Path::new(&xdg_runtime).exists() {
                    dbus_cmd.env("XDG_RUNTIME_DIR", &xdg_runtime);
                }
            }

            let dbus_check = dbus_cmd.output();

            let dbus_ok = match &dbus_check {
                Ok(output) => {
                    let success = output.status.success();
                    if !success {
                        tracing::warn!(
                            "[UtilityRunner] dbus-send check failed for container {}: exit_code={:?}, stderr={:?}",
                            container_name,
                            output.status.code(),
                            String::from_utf8_lossy(&output.stderr)
                        );
                    } else {
                        tracing::info!(
                            "[UtilityRunner] dbus-send check succeeded for container {}",
                            container_name
                        );
                    }
                    success
                }
                Err(e) => {
                    tracing::warn!(
                        "[UtilityRunner] dbus-send check error for container {}: {}",
                        container_name,
                        e
                    );
                    false
                }
            };

            tracing::info!(
                "[UtilityRunner] D-Bus availability check for {}: dbus_available={}",
                container_name,
                dbus_ok
            );

            dbus_ok
        } else {
            true // Assume D-Bus is available in non-Tauri context
        };

        // CRITICAL: cgroupsPath handling to force cgroupfs (not systemd):
        // - Tauri context: Set cgroupsPath to force cgroupfs (libcgroups auto-detects systemd otherwise)
        //   Use simple container name as path - cgroupfs will create it under user's delegated slice
        // - Daemon context: Remove cgroupsPath (systemd creates it automatically and rejects manual paths)
        let config_path = bundle_dir.join("config.json");

        if let Ok(config_content) = std::fs::read_to_string(&config_path) {
            if let Ok(mut config_json) = serde_json::from_str::<serde_json::Value>(&config_content)
            {
                if let Some(linux) = config_json.get_mut("linux") {
                    if let Some(linux_obj) = linux.as_object_mut() {
                        // CRITICAL: With systemd feature disabled, libcgroups will use cgroupfs
                        // Don't set cgroupsPath - let cgroupfs create it automatically
                        // Setting cgroupsPath with paths that look like systemd slices causes libcgroups
                        // to try using systemd (even though feature is disabled), leading to errors.
                        //
                        // By not setting cgroupsPath, cgroupfs will create the cgroup automatically.
                        // However, libcgroups (cgroupfs) still tries to write to root cgroup to enable
                        // controllers, which requires root permissions for rootless containers.
                        //
                        // This is a known limitation of libcgroups (cgroupfs) - it doesn't properly
                        // support rootless containers without modifications.
                        if linux_obj.contains_key("cgroupsPath") {
                            linux_obj.remove("cgroupsPath");
                            if is_tauri_context {
                                tracing::info!(
                                    "[UtilityRunner] Removed cgroupsPath from bundle config.json (Tauri context: cgroupfs will create cgroup automatically, but may still try to write to root cgroup)"
                                );
                            } else {
                                tracing::info!(
                                    "[UtilityRunner] Removed cgroupsPath from bundle config.json (daemon context: cgroupfs will create cgroup automatically)"
                                );
                            }
                        }

                        // Write updated config back to file
                        if let Ok(updated_config) = serde_json::to_string_pretty(&config_json) {
                            if let Err(e) = std::fs::write(&config_path, updated_config) {
                                tracing::warn!(
                                    "[UtilityRunner] Failed to update config.json: {}",
                                    e
                                );
                            } else {
                                tracing::info!("[UtilityRunner] Successfully updated config.json");
                            }
                        } else {
                            tracing::warn!("[UtilityRunner] Failed to serialize config.json");
                        }
                    } else {
                        tracing::warn!(
                            "[UtilityRunner] linux object is not a JSON object in config.json"
                        );
                    }
                } else {
                    tracing::warn!("[UtilityRunner] linux section not found in config.json");
                }
            } else {
                tracing::warn!("[UtilityRunner] Failed to parse config.json as JSON");
            }
        } else {
            tracing::warn!(
                "[UtilityRunner] Failed to read config.json: {:?}",
                config_path
            );
        }

        // 9. Clean up any existing container with the same name
        let container_id = container_name.clone();
        let root_path = self.container_manager.root_path().to_path_buf();

        // Try to delete existing container if it exists (ignore errors)
        let _ = lifecycle::delete_container(&root_path, &container_id, true);

        // 9.5. Diagnostic logging before container creation
        let bundle_rootfs = bundle_dir.join("rootfs");
        let config_path = bundle_dir.join("config.json");

        tracing::debug!(
            "[UtilityRunner] Pre-creation diagnostics for container {}:",
            container_name
        );
        tracing::debug!(
            "[UtilityRunner]   Bundle directory: {:?} (exists: {})",
            bundle_dir,
            bundle_dir.exists()
        );
        tracing::debug!(
            "[UtilityRunner]   Rootfs path: {:?} (exists: {})",
            bundle_rootfs,
            bundle_rootfs.exists()
        );
        tracing::debug!(
            "[UtilityRunner]   Config path: {:?} (exists: {})",
            config_path,
            config_path.exists()
        );
        tracing::debug!("[UtilityRunner]   Container root path: {:?}", root_path);

        // Log config.json content if it exists (for debugging)
        if config_path.exists() {
            if let Ok(config_content) = std::fs::read_to_string(&config_path) {
                if let Ok(config_json) = serde_json::from_str::<serde_json::Value>(&config_content)
                {
                    // Log key configuration details
                    if let Some(linux) = config_json.get("linux") {
                        if let Some(namespaces) = linux.get("namespaces").and_then(|n| n.as_array())
                        {
                            tracing::debug!(
                                "[UtilityRunner]   Namespaces: {:?}",
                                namespaces
                                    .iter()
                                    .filter_map(|n| n.get("type").and_then(|t| t.as_str()))
                                    .collect::<Vec<_>>()
                            );
                        }
                        if let Some(uid_mappings) =
                            linux.get("uidMappings").and_then(|m| m.as_array())
                        {
                            tracing::debug!(
                                "[UtilityRunner]   UID mappings count: {}",
                                uid_mappings.len()
                            );
                        }
                    }
                    if let Some(mounts) = config_json.get("mounts").and_then(|m| m.as_array()) {
                        tracing::debug!("[UtilityRunner]   Mount points: {}", mounts.len());
                        for mount in mounts {
                            if let Some(source) = mount.get("source").and_then(|s| s.as_str()) {
                                if mount.get("type").and_then(|t| t.as_str()) == Some("bind") {
                                    tracing::debug!(
                                        "[UtilityRunner]     Bind mount: {:?} -> {:?} (exists: {})",
                                        source,
                                        mount.get("destination").and_then(|d| d.as_str()),
                                        std::path::Path::new(source).exists()
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // 10. Create container
        // CRITICAL: Run container creation in a dedicated std::thread to avoid hanging Tauri's async runtime
        // libcontainer's builder.build() can block waiting for systemd/D-Bus operations
        // Using a dedicated thread ensures libcontainer has full access to system resources
        // NOTE: Matching vappd/provisioner.rs approach - simple std::thread::spawn without runtime setup
        // The daemon works perfectly with this approach, so we match it exactly
        let (tx, rx) = tokio::sync::oneshot::channel();
        let container_id_for_thread = container_id.clone();
        let bundle_dir_for_thread = bundle_dir.clone();
        let root_path_for_thread = root_path.clone();

        std::thread::spawn(move || {
            // CRITICAL: Set D-Bus environment variables in this thread before calling lifecycle::create_container
            // The D-Bus check in lifecycle.rs runs in this thread context, so env vars must be set here
            // Try multiple methods to get D-Bus session bus address
            if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
                // Method 1: Try to get from systemd user session
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
                                "[UtilityRunner] Set DBUS_SESSION_BUS_ADDRESS in dedicated thread (method 1): {}",
                                addr
                            );
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
                                    "[UtilityRunner] Set DBUS_SESSION_BUS_ADDRESS in dedicated thread (method 2): {}",
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
                            "[UtilityRunner] Set DBUS_SESSION_BUS_ADDRESS in dedicated thread (method 3): {}",
                            dbus_path
                        );
                    }
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
                                "[UtilityRunner] Set XDG_RUNTIME_DIR in dedicated thread: {}",
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
                            "[UtilityRunner] Set XDG_RUNTIME_DIR in dedicated thread (fallback): {}",
                            xdg_runtime
                        );
                    }
                }
            }

            // Log final D-Bus state for debugging
            if let Ok(dbus_addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
                tracing::info!(
                    "[UtilityRunner] DBUS_SESSION_BUS_ADDRESS in dedicated thread before create_container: {}",
                    dbus_addr
                );
            } else {
                tracing::warn!(
                    "[UtilityRunner] DBUS_SESSION_BUS_ADDRESS not set in dedicated thread - systemd cgroup manager may not work"
                );
            }

            // Call lifecycle::create_container_with_options with use_systemd=Some(true)
            // Force systemd cgroup manager since D-Bus is accessible in the dedicated thread.
            //
            // IMPORTANT: We tested that D-Bus cgroup creation works (logs show "Process X
            // successfully added to cgroup"). The issue was a mismatch when using use_systemd=None:
            // - lifecycle.rs detected Tauri context and set use_systemd_final=false
            // - This removed linux.resources and cgroupsPath from OCI spec
            // - builder.with_systemd(false) was called
            // - BUT libcgroups (with systemd feature) still used systemd for cgroups
            // - This caused inconsistent behavior and hangs in post-cgroup operations
            //
            // By forcing systemd, we ensure consistent behavior:
            // - D-Bus environment variables are set up above (verified by dbus-send check)
            // - libcgroups uses systemd cgroup manager (session bus)
            // - libcontainer uses systemd-compatible settings
            // - OCI spec keeps linux.resources (systemd needs it for proper scope creation)
            let options = lifecycle::CreateContainerOptions {
                use_systemd: Some(true), // Force systemd - D-Bus works in dedicated thread
            };
            let result = lifecycle::create_container_with_options(
                &container_id_for_thread,
                &bundle_dir_for_thread,
                &root_path_for_thread,
                options,
            );

            let _ = tx.send(result);
        });

        // Wait for the result asynchronously with timeout
        // CRITICAL: Add timeout to detect if builder.build() hangs indefinitely
        // This prevents the app from hanging forever if libcontainer gets stuck
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(result) => result
                .map_err(|e| ProvisionError::Runtime(format!("Thread communication error: {}", e)))?
                .map_err(|e| {
                    ProvisionError::Runtime(format!(
                        "Failed to create utility container {}: {}",
                        container_name, e
                    ))
                })?,
            Err(_) => {
                tracing::error!(
                    "[UtilityRunner] Container creation timed out after 30s for {} - builder.build() may be hanging",
                    container_name
                );
                return Err(ProvisionError::Runtime(format!(
                    "Container creation timed out for {} - builder.build() hung (this may indicate a D-Bus/systemd issue in Tauri context)",
                    container_name
                )));
            }
        }

        tracing::debug!(
            "[UtilityRunner] Container creation task completed for: {}",
            container_name
        );

        // 11. Start container
        // CRITICAL: Run container start in a dedicated std::thread to avoid hanging Tauri's async runtime
        let (tx, rx) = tokio::sync::oneshot::channel();
        let container_id_for_thread = container_id.clone();
        let root_path_for_thread = root_path.clone();

        std::thread::spawn(move || {
            tracing::debug!(
                "[UtilityRunner] Inside dedicated thread - calling lifecycle::start_container for: {}",
                container_id_for_thread
            );
            let result =
                lifecycle::start_container(&root_path_for_thread, &container_id_for_thread);
            tracing::debug!(
                "[UtilityRunner] Inside dedicated thread - lifecycle::start_container completed for: {}",
                container_id_for_thread
            );
            let _ = tx.send(result);
        });

        // Wait for the result asynchronously
        rx.await
            .map_err(|e| ProvisionError::Runtime(format!("Thread communication error: {}", e)))?
            .map_err(|e| {
                ProvisionError::Runtime(format!(
                    "Failed to start utility container {}: {}",
                    container_name, e
                ))
            })?;

        tracing::debug!(
            "[UtilityRunner] Container start task completed for: {}",
            container_name
        );

        tracing::info!(
            "[UtilityRunner] Utility container {} started, waiting for completion...",
            container_name
        );

        // 12. Wait for container to exit
        let exit_code = self
            .wait_for_container_exit(&root_path, &container_id, &stderr_file)
            .await?;

        // 13. Read stdout and stderr
        // Wait a brief moment to ensure files are flushed
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Try reading from rootfs first (more reliable in rootless scenarios),
        // then fall back to host output directory
        let rootfs_stdout = bundle_rootfs.join("tmp/utility-output/stdout.log");
        let rootfs_stderr = bundle_rootfs.join("tmp/utility-output/stderr.log");

        let stdout = std::fs::read_to_string(&rootfs_stdout)
            .or_else(|_| std::fs::read_to_string(&stdout_file))
            .unwrap_or_else(|_| String::from("(stdout file not found)"));
        let stderr = std::fs::read_to_string(&rootfs_stderr)
            .or_else(|_| std::fs::read_to_string(&stderr_file))
            .unwrap_or_else(|_| String::from("(stderr file not found)"));

        tracing::info!(
            "[UtilityRunner] Container {} output - stdout length: {}, stderr length: {}",
            container_name,
            stdout.len(),
            stderr.len()
        );

        // Always log stdout/stderr at info level for debugging (even if empty, log the fact)
        if !stdout.is_empty() {
            tracing::info!("[UtilityRunner] stdout: {}", stdout);
        } else {
            tracing::debug!("[UtilityRunner] stdout: (empty)");
        }
        if !stderr.is_empty() {
            tracing::info!("[UtilityRunner] stderr: {}", stderr);
        } else {
            tracing::debug!("[UtilityRunner] stderr: (empty)");
        }

        // 14. Clean up container
        let _ = self.cleanup(&container_id);

        tracing::info!(
            "[UtilityRunner] Utility container {} completed with exit code: {}",
            container_name,
            exit_code
        );

        Ok(UtilityContainerOutput {
            exit_code,
            stdout,
            stderr,
        })
    }

    /// Wait for container to exit and return exit code
    async fn wait_for_container_exit(
        &self,
        root_path: &Path,
        container_id: &str,
        stderr_file: &PathBuf,
    ) -> Result<i32, ProvisionError> {
        use crate::rootless::commands::load_container;

        let max_wait = Duration::from_secs(300); // 5 minutes timeout
        let check_interval = Duration::from_millis(500);
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > max_wait {
                return Err(ProvisionError::Runtime(format!(
                    "Utility container {} did not exit within timeout",
                    container_id
                )));
            }

            match load_container(root_path, container_id) {
                Ok(container) => {
                    use crate::rootless::commands::ContainerStatus;
                    let status = container.status();
                    tracing::debug!(
                        "[UtilityRunner] Container {} status check: {:?}, PID: {:?}",
                        container_id,
                        status,
                        container.pid()
                    );
                    match status {
                        ContainerStatus::Stopped => {
                            // Container has exited
                            tracing::info!(
                                "[UtilityRunner] Container {} has stopped",
                                container_id
                            );
                            // Wait a moment for files to flush
                            tokio::time::sleep(Duration::from_millis(200)).await;

                            // Check stderr file for errors
                            if stderr_file.exists() {
                                if let Ok(stderr_content) = std::fs::read_to_string(stderr_file) {
                                    // Check for common error patterns
                                    let stderr_lower = stderr_content.to_lowercase();
                                    if stderr_lower.contains("error:")
                                        || stderr_lower.contains("failed")
                                        || stderr_lower.contains("fatal")
                                        || stderr_lower.contains("cannot")
                                        || stderr_lower.contains("not found")
                                        || stderr_lower.contains("permission denied")
                                    {
                                        tracing::warn!(
                                            "[UtilityRunner] Container {} stderr contains errors, assuming failure",
                                            container_id
                                        );
                                        return Ok(1);
                                    }
                                }
                            }

                            // No errors detected in stderr, assume success
                            return Ok(0);
                        }
                        ContainerStatus::Running | ContainerStatus::Created => {
                            // Still running, wait and check again
                            sleep(check_interval).await;
                            continue;
                        }
                    }
                }
                Err(_) => {
                    // Container not found, might have already been cleaned up
                    // Wait a moment and check stderr for errors before assuming success
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    if stderr_file.exists() {
                        if let Ok(stderr_content) = std::fs::read_to_string(stderr_file) {
                            let stderr_lower = stderr_content.to_lowercase();
                            if stderr_lower.contains("error:")
                                || stderr_lower.contains("failed")
                                || stderr_lower.contains("fatal")
                            {
                                return Ok(1);
                            }
                        }
                    }
                    return Ok(0);
                }
            }
        }
    }

    /// Clean up utility container after execution
    pub fn cleanup(&self, container_id: &str) -> Result<(), ProvisionError> {
        let root_path = self.container_manager.root_path().to_path_buf();

        // Stop and delete container
        let _ = lifecycle::stop_container(&root_path, container_id);
        lifecycle::delete_container(&root_path, container_id, true).map_err(|e: LinuxError| {
            ProvisionError::Runtime(format!(
                "Failed to delete utility container {}: {}",
                container_id, e
            ))
        })?;

        // Clean up bundle directory
        let bundle_dir = self.app_dir.join("containers/bundles").join(container_id);
        if bundle_dir.exists() {
            let _ = std::fs::remove_dir_all(&bundle_dir);
        }

        tracing::info!(
            "[UtilityRunner] Cleaned up utility container: {}",
            container_id
        );
        Ok(())
    }

    /// Run utility command directly without containerization (Tauri fallback)
    ///
    /// This method runs utility commands directly on the host system to avoid
    /// the libcontainer init process hang that occurs in Tauri/GTK context.
    /// The hang is caused by a deadlock in the parent-child communication
    /// where the init process gets stuck in INTER state.
    async fn run_direct(
        &self,
        config: &UtilityContainerConfig,
    ) -> Result<UtilityContainerOutput, ProvisionError> {
        use std::process::Command;

        let container_name = if config.name.starts_with("utility-") {
            config.name.clone()
        } else {
            format!("utility-{}", config.name)
        };

        tracing::info!(
            "[UtilityRunner] Running direct (non-containerized) command for: {}",
            container_name
        );

        // Create output directory for stdout/stderr capture
        let output_dir = self
            .app_dir
            .join("containers/utility-output")
            .join(&container_name);
        std::fs::create_dir_all(&output_dir).map_err(ProvisionError::Io)?;
        let stdout_file = output_dir.join("stdout.log");
        let stderr_file = output_dir.join("stderr.log");

        // Clear any existing output files
        let _ = std::fs::remove_file(&stdout_file);
        let _ = std::fs::remove_file(&stderr_file);

        // Build the command
        // The command is expected to be ["/bin/sh", "/scripts/script.sh"] or similar
        // We need to translate the container paths to host paths using the volumes mapping
        let mut cmd_args = config.command.clone();

        // Create a reverse mapping: container_path -> host_path
        let mut path_mapping: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for (host_path, container_path) in &config.volumes {
            path_mapping.insert(container_path.clone(), host_path.clone());
        }

        // Replace container paths with host paths in the command
        for arg in cmd_args.iter_mut() {
            for (container_path, host_path) in &path_mapping {
                if arg.contains(container_path) {
                    *arg = arg.replace(container_path, host_path);
                    tracing::debug!(
                        "[UtilityRunner] Mapped path in command: {} -> {}",
                        container_path,
                        host_path
                    );
                }
            }
        }

        tracing::info!(
            "[UtilityRunner] Direct command (after path mapping): {:?}",
            cmd_args
        );

        // For shell scripts, we need to modify the script to use host paths
        // Check if the command is running a shell script
        let is_shell_script = cmd_args.len() >= 2
            && (cmd_args[0].contains("sh") || cmd_args[0] == "/bin/sh")
            && cmd_args.last().map(|s| s.ends_with(".sh")).unwrap_or(false);

        if is_shell_script {
            // Read the script and replace container paths with host paths
            let script_path = cmd_args.last().unwrap();
            if let Ok(script_content) = std::fs::read_to_string(script_path) {
                let mut modified_script = script_content;

                // Replace container paths with host paths in the script content
                for (container_path, host_path) in &path_mapping {
                    modified_script = modified_script.replace(container_path, host_path);
                }

                // Also set up the /tmp/utility-output directory
                let host_output_dir = output_dir.to_string_lossy().to_string();
                modified_script = modified_script.replace("/tmp/utility-output", &host_output_dir);

                // Write the modified script to a temporary location
                let temp_script_path = output_dir.join("run-script.sh");
                std::fs::write(&temp_script_path, &modified_script).map_err(ProvisionError::Io)?;

                // Make it executable
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = std::fs::metadata(&temp_script_path)
                        .map_err(ProvisionError::Io)?
                        .permissions();
                    perms.set_mode(0o755);
                    std::fs::set_permissions(&temp_script_path, perms)
                        .map_err(ProvisionError::Io)?;
                }

                // Update command to use the modified script
                *cmd_args.last_mut().unwrap() = temp_script_path.to_string_lossy().to_string();

                tracing::info!(
                    "[UtilityRunner] Created modified script at: {:?}",
                    temp_script_path
                );
            }
        }

        // Run the command
        let shell = if cmd_args[0].contains("sh") {
            cmd_args.remove(0)
        } else {
            "/bin/sh".to_string()
        };

        let shell_args: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();

        tracing::info!("[UtilityRunner] Executing: {} {:?}", shell, shell_args);

        let output = Command::new(&shell)
            .args(&shell_args)
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("TERM", "xterm")
            .envs(config.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .output()
            .map_err(|e| ProvisionError::Runtime(format!("Failed to execute command: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        // Also read from the output files if they exist (script might have written there)
        let file_stdout = std::fs::read_to_string(&stdout_file).unwrap_or_default();
        let file_stderr = std::fs::read_to_string(&stderr_file).unwrap_or_default();

        let combined_stdout = if file_stdout.is_empty() {
            stdout
        } else {
            format!("{}\n{}", stdout, file_stdout)
        };

        let combined_stderr = if file_stderr.is_empty() {
            stderr
        } else {
            format!("{}\n{}", stderr, file_stderr)
        };

        tracing::info!(
            "[UtilityRunner] Direct command completed for {}: exit_code={}, stdout_len={}, stderr_len={}",
            container_name,
            exit_code,
            combined_stdout.len(),
            combined_stderr.len()
        );

        if exit_code != 0 {
            tracing::warn!(
                "[UtilityRunner] Direct command failed for {}: exit_code={}, stderr={}",
                container_name,
                exit_code,
                combined_stderr
            );
        }

        Ok(UtilityContainerOutput {
            exit_code,
            stdout: combined_stdout,
            stderr: combined_stderr,
        })
    }

    /// Generate OCI spec for utility container with custom command
    fn generate_utility_oci_spec(
        &self,
        config: &ContainerConfig,
        _rootfs: &std::path::Path,
        bundle_path: &std::path::Path,
        command: &[String],
    ) -> Result<PathBuf, ProvisionError> {
        use serde_json::json;

        let spec_path = bundle_path.join("config.json");

        // Build environment variables
        let mut env = vec![
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            "TERM=xterm".to_string(),
            format!("CONTAINER_NAME={}", config.container_name),
            format!("CONTAINER_TYPE={}", config.container_type),
        ];

        for (key, value) in &config.environment {
            env.push(format!("{}={}", key, value));
        }

        // Build mounts
        let mut mounts = Vec::new();
        for (host_path, container_path) in &config.volumes {
            mounts.push(json!({
                "destination": container_path,
                "type": "bind",
                "source": host_path,
                "options": ["rbind", "rw"]
            }));
        }

        // NOTE: For utility containers, we skip standard mounts (proc, dev, sys)
        // These can cause issues in rootless user namespaces
        // The container will use the rootfs as-is, which already has /proc, /dev, etc.
        // from the Alpine image

        // Namespace configuration for utility containers
        // User namespace is REQUIRED by libcontainer for rootless containers
        //
        // CRITICAL: Network namespace is REMOVED for utility containers because:
        // 1. CA generation doesn't need network access - it's just file operations
        // 2. Creating a new network namespace in libcontainer's init process was causing
        //    a hang after cgroup creation succeeded - the init process would hang for
        //    ~29 seconds during namespace setup
        // 3. By removing network namespace, we simplify the init process and avoid the hang
        //
        // If network is needed in the future, we should investigate why network namespace
        // creation hangs in Tauri context (possibly related to netlink operations or
        // loopback interface setup in the new namespace)
        let linux_namespaces = vec![
            json!({"type": "user"}),  // Required for rootless containers
            json!({"type": "mount"}), // Required for container filesystem isolation
            json!({"type": "ipc"}),   // IPC isolation
            json!({"type": "uts"}),   // Hostname isolation
                                      // NOTE: Network namespace removed to prevent init process hang
        ];

        // Get current user's UID/GID for user namespace mapping
        #[cfg(target_os = "linux")]
        let current_uid = nix::unistd::getuid().as_raw();
        #[cfg(target_os = "linux")]
        let current_gid = nix::unistd::getgid().as_raw();

        #[cfg(target_os = "linux")]
        {
            tracing::debug!(
                "[UtilityRunner] Container diagnostics for {}:",
                config.container_name
            );
            tracing::debug!(
                "[UtilityRunner]   Current user: UID={}, GID={}",
                current_uid,
                current_gid
            );
        }

        #[cfg(not(target_os = "linux"))]
        let (current_uid, current_gid) = (0u32, 0u32);

        // Simple UID/GID mapping - map container root to current user
        let uid_mappings = vec![json!({
            "containerID": 0,
            "hostID": current_uid,
            "size": 1
        })];
        let gid_mappings = vec![json!({
            "containerID": 0,
            "hostID": current_gid,
            "size": 1
        })];

        // Create OCI spec for utility containers
        let oci_spec = json!({
            "ociVersion": "1.0.0",
            "process": {
                "terminal": false,
                "user": {
                    // Run as root inside container (mapped to current user via user namespace)
                    "uid": 0,
                    "gid": 0,
                    "additionalGids": []
                },
                "args": command,
                "env": env,
                "cwd": "/",
                // Disable AppArmor for utility containers
                "apparmorProfile": null,
                // Minimal capabilities for rootless containers
                "capabilities": {
                    "bounding": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_KILL"],
                    "effective": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_KILL"],
                    "inheritable": [],
                    "permitted": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_KILL"]
                }
            },
            "root": {
                "path": "rootfs",
                "readonly": false
            },
            "hostname": config.container_name,
            "mounts": mounts,
            "linux": {
                "namespaces": linux_namespaces,
                "uidMappings": uid_mappings,
                "gidMappings": gid_mappings,
                "resources": {
                    "devices": []
                },
                // Disable seccomp for utility containers
                "seccomp": null
            }
        });

        // NOTE: Loopback hook is no longer needed since we removed network namespace
        // Without a network namespace, the container inherits the host's network stack
        // where loopback is already configured and available
        tracing::debug!(
            "[UtilityRunner] Skipping loopback hook for {} - no network namespace",
            config.container_name
        );

        // Write spec to file
        std::fs::write(&spec_path, serde_json::to_string_pretty(&oci_spec).unwrap())
            .map_err(ProvisionError::Io)?;

        Ok(spec_path)
    }

    /// Recursively copy directory
    fn copy_dir_recursive(
        &self,
        src: &std::path::Path,
        dst: &std::path::Path,
    ) -> Result<(), ProvisionError> {
        use std::fs;
        use std::os::unix::fs::symlink;

        if !src.is_dir() {
            return Err(ProvisionError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Source {:?} is not a directory", src),
            )));
        }

        fs::create_dir_all(dst).map_err(ProvisionError::Io)?;

        for entry in fs::read_dir(src).map_err(|e| {
            ProvisionError::Io(std::io::Error::other(format!(
                "Failed to read directory {:?}: {}",
                src, e
            )))
        })? {
            let entry = entry.map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to read directory entry in {:?}: {}",
                    src, e
                )))
            })?;
            let path = entry.path();
            let name = entry.file_name();
            let dst_path = dst.join(&name);

            // Use symlink_metadata to avoid following symlinks
            let metadata = fs::symlink_metadata(&path).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to get metadata for {:?}: {}",
                    path, e
                )))
            })?;

            if metadata.is_dir() {
                self.copy_dir_recursive(&path, &dst_path)?;
            } else if metadata.file_type().is_symlink() {
                // Preserve symlinks instead of copying their targets
                let link_target = fs::read_link(&path).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to read symlink {:?}: {}",
                        path, e
                    )))
                })?;
                // Remove destination if it exists (might be from previous failed copy)
                if dst_path.exists() {
                    fs::remove_file(&dst_path).map_err(|e| {
                        ProvisionError::Io(std::io::Error::other(format!(
                            "Failed to remove existing destination {:?}: {}",
                            dst_path, e
                        )))
                    })?;
                }
                symlink(&link_target, &dst_path).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to create symlink {:?} -> {:?}: {}",
                        dst_path, link_target, e
                    )))
                })?;
            } else {
                // Regular file - copy it
                fs::copy(&path, &dst_path).map_err(|e| {
                    ProvisionError::Io(std::io::Error::other(format!(
                        "Failed to copy file {:?} to {:?}: {}",
                        path, dst_path, e
                    )))
                })?;
            }
        }

        Ok(())
    }
}
