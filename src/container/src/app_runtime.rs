//! AppRuntime — lean container runtime for standardized app lifecycle.
//!
//! Replaces the 6,240-line ContainerProvisioner with a ~300-line direct container launch path:
//! pull image → copy rootfs → OCI spec → create → start → render templates → run setup tasks.

use crate::app_spec::{AppHandle, AppSpec, AppState, AppSummary};
use crate::bootstrap::image_manager::ImageManager;
use crate::bootstrap::template_renderer::TemplateRenderer;
use crate::common::ContainerRuntime;
use crate::provisioner::{ProgressReporter, ProvisionError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Lean app runtime — 5 fields, no K8s baggage.
pub struct AppRuntime {
    runtime: Arc<dyn ContainerRuntime>,
    image_manager: ImageManager,
    template_renderer: TemplateRenderer,
    app_dir: PathBuf,
    /// Tracks running apps by app_id
    apps: HashMap<String, RunningApp>,
}

struct RunningApp {
    app_id: String,
    name: String,
    container_id: String,
}

impl AppRuntime {
    /// Initialize: system check, shared network namespace, runtime, image manager, template renderer.
    pub fn new(app_dir: PathBuf) -> Result<Self, String> {
        tracing::info!("[AppRuntime] Initializing...");
        tracing::info!("[AppRuntime] App directory: {}", app_dir.display());

        #[cfg(not(target_os = "linux"))]
        {
            let _ = app_dir;
            Err("AppRuntime only available on Linux".to_string())
        }

        #[cfg(target_os = "linux")]
        {
            // Check system requirements for rootless containers
            let system_check = crate::rootless::system_check::check_system_requirements();
            if !system_check.passed {
                if let Some(error_msg) = system_check.error_message() {
                    tracing::error!("{}", error_msg);
                    return Err("System requirements not met for rootless containers".to_string());
                }
            }

            // Clean up orphaned pasta processes
            crate::rootless::cleanup_orphaned_pasta();

            // Initialize shared network namespace (pasta for internet)
            let ns_path = crate::rootless::initialize_shared_namespace().map_err(|e| {
                format!("Failed to initialize shared network namespace: {}", e)
            })?;
            tracing::info!("[AppRuntime] Shared network namespace: {}", ns_path);

            // Load config (for image settings)
            let config =
                crate::bootstrap::config::ContainerProvisionerConfig::load(&app_dir)?;

            // Initialize rootless OCI runtime
            let runtime: Arc<dyn ContainerRuntime> = Arc::new(
                crate::rootless::RootlessContainerRuntime::new(app_dir.clone())
                    .map_err(|e| format!("Failed to init container runtime: {}", e))?,
            );

            // Initialize image manager
            let image_manager = ImageManager::new(&config.image, app_dir.clone())
                .map_err(|e| format!("Failed to init image manager: {}", e))?;

            // Initialize platform-specific container_dir
            crate::rootless::config::container_dir::init_app_dir(app_dir.clone());

            // Initialize template renderer (embedded or filesystem)
            let template_renderer = if let Ok(dir) = std::env::var("VAPPC_TEMPLATES_DIR") {
                TemplateRenderer::new(PathBuf::from(dir))
            } else {
                TemplateRenderer::from_embedded()
            }
            .map_err(|e| format!("Failed to init template renderer: {}", e))?;

            tracing::info!("[AppRuntime] Initialized successfully");

            Ok(Self {
                runtime,
                image_manager,
                template_renderer,
                app_dir,
                apps: HashMap::new(),
            })
        }
    }

    /// Start an app: pull image → create container → render templates → run setup tasks.
    pub async fn start(
        &mut self,
        spec: &AppSpec,
        progress: Arc<dyn ProgressReporter>,
    ) -> Result<AppHandle, ProvisionError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (spec, progress);
            return Err(ProvisionError::Config("Only available on Linux".to_string()));
        }

        #[cfg(target_os = "linux")]
        {
            use crate::rootless::lifecycle;

            let app_id = &spec.app_id;
            let container_id = app_id.clone();

            // 1. Pull image (5-20%)
            progress.emit_detailed(
                5,
                format!("Pulling image: {}", spec.image),
                Some("image".into()),
                Some(app_id.clone()),
            );
            let image_dir = self
                .image_manager
                .ensure_image(&spec.image)
                .await
                .map_err(|e| ProvisionError::Image(e.to_string()))?;
            let image_rootfs = image_dir.join("rootfs");
            if !image_rootfs.exists() {
                return Err(ProvisionError::Image(format!(
                    "Image rootfs not found at {:?}",
                    image_rootfs
                )));
            }

            // 2. Copy rootfs → bundle (20-30%)
            progress.emit_detailed(
                20,
                "Copying rootfs...".to_string(),
                Some("bundle".into()),
                Some(app_id.clone()),
            );
            let bundles_dir = self.app_dir.join("containers/bundles");
            let bundle_dir = bundles_dir.join(&container_id);
            std::fs::create_dir_all(&bundle_dir).map_err(ProvisionError::Io)?;
            let bundle_rootfs = bundle_dir.join("rootfs");
            if bundle_rootfs.exists() {
                std::fs::remove_dir_all(&bundle_rootfs).map_err(ProvisionError::Io)?;
            }
            copy_dir_recursive(&image_rootfs, &bundle_rootfs)?;

            // 3. Write OCI spec (30-35%)
            progress.emit_detailed(
                30,
                "Creating container spec...".to_string(),
                Some("spec".into()),
                Some(app_id.clone()),
            );
            write_oci_spec(&bundle_dir.join("config.json"), spec, &image_dir)?;

            // Chown rootfs for user namespace (rootless containers)
            if !spec.privileged {
                chown_rootfs_to_uid0(&bundle_rootfs)?;
            }

            // 4. Create + start container (35-45%)
            progress.emit_detailed(
                35,
                "Creating container...".to_string(),
                Some("container".into()),
                Some(app_id.clone()),
            );
            lifecycle::create_container(&container_id, &bundle_dir, &self.app_dir)
                .map_err(|e| ProvisionError::Runtime(e.to_string()))?;

            progress.emit_detailed(
                40,
                "Starting container...".to_string(),
                Some("container".into()),
                Some(app_id.clone()),
            );
            lifecycle::start_container(&self.app_dir, &container_id)
                .map_err(|e| ProvisionError::Runtime(e.to_string()))?;

            // 5. Render config templates into container (45-55%)
            if !spec.config_templates.is_empty() {
                progress.emit_detailed(
                    45,
                    "Rendering config templates...".to_string(),
                    Some("templates".into()),
                    Some(app_id.clone()),
                );

                let ctx = build_app_context(spec);
                for tmpl in &spec.config_templates {
                    let rendered = self
                        .template_renderer
                        .render_with_context(&tmpl.template, &ctx)
                        .map_err(|e| {
                            ProvisionError::Config(format!(
                                "Template render '{}': {}",
                                tmpl.template, e
                            ))
                        })?;

                    // Write rendered content into container via exec
                    let write_cmd = vec![
                        "sh".to_string(),
                        "-c".to_string(),
                        format!(
                            "mkdir -p \"$(dirname '{}')\" && cat > '{}'",
                            tmpl.destination, tmpl.destination
                        ),
                    ];
                    // Use tee approach: pipe content via exec stdin
                    // Fallback: write to bundle rootfs directly
                    let rootfs_dest = bundle_rootfs.join(
                        tmpl.destination.strip_prefix('/').unwrap_or(&tmpl.destination),
                    );
                    if let Some(parent) = rootfs_dest.parent() {
                        std::fs::create_dir_all(parent).map_err(ProvisionError::Io)?;
                    }
                    std::fs::write(&rootfs_dest, &rendered).map_err(ProvisionError::Io)?;

                    tracing::info!(
                        "[AppRuntime] Rendered template '{}' → '{}'",
                        tmpl.template,
                        tmpl.destination
                    );

                    let _ = write_cmd; // exec approach can be added later if rootfs write doesn't work
                }
            }

            // 6. Run setup tasks (55-90%)
            if !spec.setup_tasks.is_empty() {
                let total_tasks = spec.setup_tasks.len();
                for (i, task) in spec.setup_tasks.iter().enumerate() {
                    let pct = 55 + (35 * i as u32) / total_tasks.max(1) as u32;
                    progress.emit_detailed(
                        pct,
                        format!("Running task: {}", task.name),
                        Some("setup".into()),
                        Some(app_id.clone()),
                    );

                    let result = self
                        .runtime
                        .exec(&container_id, &task.command)
                        .await
                        .map_err(|e| {
                            ProvisionError::Runtime(format!(
                                "Setup task '{}' exec failed: {}",
                                task.name, e
                            ))
                        })?;

                    if result.exit_code != 0 {
                        return Err(ProvisionError::Runtime(format!(
                            "Setup task '{}' failed (exit {}): {}",
                            task.name, result.exit_code, result.stderr
                        )));
                    }

                    tracing::info!(
                        "[AppRuntime] Task '{}' completed (exit {})",
                        task.name,
                        result.exit_code
                    );
                }
            }

            // 7. Done (100%)
            progress.emit_detailed(
                100,
                "App running".to_string(),
                Some("done".into()),
                Some(app_id.clone()),
            );

            // Track running app
            self.apps.insert(
                app_id.clone(),
                RunningApp {
                    app_id: app_id.clone(),
                    name: spec.name.clone(),
                    container_id: container_id.clone(),
                },
            );

            Ok(AppHandle {
                app_id: app_id.clone(),
                name: spec.name.clone(),
            })
        }
    }

    /// Stop a running app.
    pub async fn stop(&mut self, app_id: &str) -> Result<(), String> {
        if let Some(app) = self.apps.remove(app_id) {
            self.runtime
                .stop(&app.container_id, std::time::Duration::from_secs(30))
                .await
                .map_err(|e| e.to_string())?;
            tracing::info!("[AppRuntime] Stopped app: {}", app_id);
            Ok(())
        } else {
            // Try stopping by app_id as container_id anyway
            self.runtime
                .stop(app_id, std::time::Duration::from_secs(30))
                .await
                .map_err(|e| e.to_string())?;
            Ok(())
        }
    }

    /// Get app state.
    pub async fn state(&self, app_id: &str) -> Result<AppState, String> {
        let container_id = self
            .apps
            .get(app_id)
            .map(|a| a.container_id.as_str())
            .unwrap_or(app_id);

        let state = self
            .runtime
            .state(container_id)
            .await
            .map_err(|e| e.to_string())?;

        Ok(match state {
            crate::common::ContainerState::Creating => AppState::Starting,
            crate::common::ContainerState::Running => AppState::Running,
            crate::common::ContainerState::Stopped => AppState::Stopped,
            crate::common::ContainerState::Failed => AppState::Failed {
                reason: "Container failed".to_string(),
            },
            crate::common::ContainerState::Paused => AppState::Stopped,
        })
    }

    /// List running apps.
    pub fn list(&self) -> Vec<AppSummary> {
        self.apps
            .values()
            .map(|app| AppSummary {
                app_id: app.app_id.clone(),
                name: app.name.clone(),
                state: AppState::Running, // All tracked apps are assumed running
            })
            .collect()
    }
}

// --- Helper functions extracted from provisioner.rs ---

/// Build Tera template context from AppSpec.
fn build_app_context(spec: &AppSpec) -> tera::Context {
    let mut ctx = tera::Context::new();
    ctx.insert("app_id", &spec.app_id);
    ctx.insert("app_name", &spec.name);
    ctx.insert("image", &spec.image);
    for (k, v) in &spec.template_vars {
        ctx.insert(k.as_str(), v);
    }
    ctx
}

/// Read Entrypoint and Cmd from the OCI image config (image_config.json).
/// Returns (entrypoint, cmd) where each is a Vec<String>.
fn read_image_entrypoint_cmd(image_dir: &Path) -> (Vec<String>, Vec<String>) {
    let config_path = image_dir.join("image_config.json");
    let config_text = match std::fs::read_to_string(&config_path) {
        Ok(t) => t,
        Err(_) => return (vec![], vec![]),
    };
    let config: serde_json::Value = match serde_json::from_str(&config_text) {
        Ok(v) => v,
        Err(_) => return (vec![], vec![]),
    };
    // OCI image config: .config.Entrypoint and .config.Cmd
    let container_config = config.get("config").or_else(|| config.get("container_config"));
    let parse_str_array = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let (entrypoint, cmd) = match container_config {
        Some(cc) => (
            cc.get("Entrypoint").map(|v| parse_str_array(v)).unwrap_or_default(),
            cc.get("Cmd").map(|v| parse_str_array(v)).unwrap_or_default(),
        ),
        None => (vec![], vec![]),
    };
    tracing::debug!(
        "[write_oci_spec] Image entrypoint={:?}, cmd={:?}",
        entrypoint,
        cmd
    );
    (entrypoint, cmd)
}

/// Write OCI config.json for an AppSpec.
/// Based on existing write_oci_spec_for_run, enhanced with resource limits.
#[cfg(target_os = "linux")]
fn write_oci_spec(spec_path: &Path, spec: &AppSpec, image_dir: &Path) -> Result<(), ProvisionError> {
    use serde_json::json;

    // Docker-compatible args resolution:
    // 1. command set   → command + args (overrides both Entrypoint and Cmd)
    // 2. args set only → image Entrypoint + args (overrides Cmd, keeps Entrypoint)
    // 3. neither set   → image Entrypoint + image Cmd
    // 4. fallback      → /bin/sh
    let (entrypoint, img_cmd) = read_image_entrypoint_cmd(image_dir);
    let args: Vec<String> = if spec.command.is_some() {
        // Case 1: explicit command overrides everything
        spec.command.clone().unwrap_or_default()
            .into_iter()
            .chain(spec.args.clone().unwrap_or_default())
            .collect()
    } else if spec.args.is_some() {
        // Case 2: args only → prepend image Entrypoint (like `docker run image arg`)
        let mut combined = entrypoint;
        combined.extend(spec.args.clone().unwrap_or_default());
        combined
    } else {
        // Case 3: neither → use image Entrypoint + Cmd
        if !entrypoint.is_empty() {
            let mut combined = entrypoint;
            combined.extend(img_cmd);
            combined
        } else if !img_cmd.is_empty() {
            img_cmd
        } else {
            vec!["/bin/sh".to_string()]
        }
    };

    let mut env_vars = vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "TERM=xterm".to_string(),
    ];
    env_vars.extend(spec.env.clone());

    // Mounts
    let mut oci_mounts = Vec::new();
    for m in &spec.mounts {
        let options: Vec<String> = if m.read_only {
            vec!["ro".to_string(), "rbind".to_string()]
        } else {
            vec!["rw".to_string(), "rbind".to_string()]
        };
        oci_mounts.push(json!({
            "destination": m.container_path,
            "type": "bind",
            "source": m.host_path,
            "options": options
        }));
    }
    oci_mounts.push(json!({
        "destination": "/tmp",
        "type": "tmpfs",
        "source": "tmpfs",
        "options": ["nosuid", "nodev", "size=1048576k"]
    }));

    // Namespace + capabilities: privileged vs rootless
    let (namespaces, uid_mappings, gid_mappings, capabilities) =
        if spec.privileged && nix::unistd::Uid::current().as_raw() == 0 {
            (
                vec![
                    json!({"type": "ipc"}),
                    json!({"type": "uts"}),
                    json!({"type": "mount"}),
                ],
                vec![],
                vec![],
                json!({
                    "bounding": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "effective": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "inheritable": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "permitted": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"]
                }),
            )
        } else {
            let uid_mappings = vec![json!({
                "containerID": 0,
                "hostID": nix::unistd::Uid::current().as_raw(),
                "size": 1
            })];
            let gid_mappings = vec![json!({
                "containerID": 0,
                "hostID": nix::unistd::Gid::current().as_raw(),
                "size": 1
            })];
            (
                vec![
                    json!({"type": "user"}),
                    json!({"type": "ipc"}),
                    json!({"type": "uts"}),
                    json!({"type": "mount"}),
                ],
                uid_mappings,
                gid_mappings,
                json!({
                    "bounding": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "effective": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "inheritable": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"],
                    "permitted": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE", "CAP_AUDIT_WRITE"]
                }),
            )
        };

    // Resource limits
    let resources = match &spec.resources {
        Some(res) => {
            let mut r = serde_json::Map::new();
            if let Some(cpu) = res.cpu_cores {
                r.insert(
                    "cpu".to_string(),
                    json!({
                        "shares": cpu as u64 * 1024,
                        "quota": cpu as i64 * 100000,
                        "period": 100000_u64
                    }),
                );
            }
            if let Some(mem) = res.memory_mb {
                let bytes = mem * 1024 * 1024;
                r.insert(
                    "memory".to_string(),
                    json!({
                        "limit": bytes,
                        "swap": bytes
                    }),
                );
            }
            serde_json::Value::Object(r)
        }
        None => json!({}),
    };

    let cwd = spec
        .working_dir
        .as_deref()
        .unwrap_or("/");

    // Devices: privileged containers get /dev/net/tun for TUN/TAP (needed by ZeroTier, VPNs, etc.)
    let linux_devices = if spec.privileged {
        vec![json!({
            "path": "/dev/net/tun",
            "type": "c",
            "major": 10,
            "minor": 200,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
        })]
    } else {
        vec![]
    };

    let oci = json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "env": env_vars,
            "cwd": cwd,
            "args": args,
            "apparmorProfile": null,
            "capabilities": capabilities
        },
        "root": { "path": "rootfs", "readonly": false },
        "mounts": oci_mounts,
        "linux": {
            "namespaces": namespaces,
            "uidMappings": uid_mappings,
            "gidMappings": gid_mappings,
            "devices": linux_devices,
            "resources": resources,
            "seccomp": null
        },
        "annotations": {},
        "labels": {}
    });

    let json = serde_json::to_string_pretty(&oci)
        .map_err(|e| ProvisionError::Config(format!("OCI spec serialize: {}", e)))?;
    std::fs::write(spec_path, json).map_err(ProvisionError::Io)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn write_oci_spec(_spec_path: &Path, _spec: &AppSpec, _image_dir: &Path) -> Result<(), ProvisionError> {
    Err(ProvisionError::Config(
        "OCI spec generation only on Linux".to_string(),
    ))
}

/// Recursively copy a directory tree, preserving symlinks and permissions.
/// Extracted from ContainerProvisioner::copy_dir_recursive.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), ProvisionError> {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    if !src.is_dir() {
        return Err(ProvisionError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Source path is not a directory: {:?}", src),
        )));
    }

    fs::create_dir_all(dst).map_err(ProvisionError::Io)?;

    let entries = fs::read_dir(src).map_err(|e| {
        ProvisionError::Io(std::io::Error::other(format!(
            "Failed to read directory {:?}: {}",
            src, e
        )))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            ProvisionError::Io(std::io::Error::other(format!(
                "Failed to read entry in {:?}: {}",
                src, e
            )))
        })?;
        let path = entry.path();
        let dst_path = dst.join(entry.file_name());

        let metadata = fs::symlink_metadata(&path).map_err(|e| {
            ProvisionError::Io(std::io::Error::other(format!(
                "Failed to get metadata for {:?}: {}",
                path, e
            )))
        })?;

        if metadata.is_dir() {
            // Clean up non-directory at destination
            if dst_path.exists() {
                if let Ok(m) = fs::symlink_metadata(&dst_path) {
                    if !m.is_dir() {
                        let _ = fs::remove_file(&dst_path);
                    }
                }
            }
            copy_dir_recursive(&path, &dst_path)?;
        } else if metadata.file_type().is_symlink() {
            let link_target = fs::read_link(&path).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to read symlink {:?}: {}",
                    path, e
                )))
            })?;
            // Remove existing destination
            if dst_path.exists() || dst_path.symlink_metadata().is_ok() {
                if let Ok(m) = fs::symlink_metadata(&dst_path) {
                    if m.is_dir() {
                        let _ = fs::remove_dir_all(&dst_path);
                    } else {
                        let _ = fs::remove_file(&dst_path);
                    }
                }
            }
            #[cfg(unix)]
            symlink(&link_target, &dst_path).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to create symlink {:?} -> {:?}: {}",
                    dst_path, link_target, e
                )))
            })?;
        } else {
            // Regular file — clean up directory at destination
            if dst_path.exists() {
                if let Ok(m) = fs::symlink_metadata(&dst_path) {
                    if m.is_dir() {
                        let _ = fs::remove_dir_all(&dst_path);
                    }
                }
            }
            fs::copy(&path, &dst_path).map_err(|e| {
                ProvisionError::Io(std::io::Error::other(format!(
                    "Failed to copy {:?} to {:?}: {}",
                    path, dst_path, e
                )))
            })?;
            // Preserve permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let (Ok(src_meta), Ok(dst_meta)) =
                    (fs::metadata(&path), fs::metadata(&dst_path))
                {
                    let mut perms = dst_meta.permissions();
                    perms.set_mode(src_meta.permissions().mode());
                    let _ = fs::set_permissions(&dst_path, perms);
                }
            }
        }
    }

    Ok(())
}

/// Chown all files in rootfs to current user's UID/GID for user namespace mapping.
/// Extracted from ContainerProvisioner::chown_rootfs_to_uid0.
#[cfg(target_os = "linux")]
fn chown_rootfs_to_uid0(rootfs_path: &Path) -> Result<(), ProvisionError> {
    use nix::libc::{c_char, chown};
    use nix::unistd::{Gid, Uid};

    let uid = Uid::current();
    let gid = Gid::current();

    fn chown_recursive(
        path: &Path,
        uid: Uid,
        gid: Gid,
    ) -> Result<(), std::io::Error> {
        let path_cstr = std::ffi::CString::new(path.to_string_lossy().as_ref())
            .map_err(|e| std::io::Error::other(format!("Invalid path: {}", e)))?;
        unsafe {
            let _ = chown(
                path_cstr.as_ptr() as *const c_char,
                uid.as_raw(),
                gid.as_raw(),
            );
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path)? {
                chown_recursive(&entry?.path(), uid, gid)?;
            }
        }
        Ok(())
    }

    chown_recursive(rootfs_path, uid, gid).map_err(|e| {
        ProvisionError::Io(std::io::Error::other(format!(
            "Failed to chown rootfs: {}",
            e
        )))
    })
}

#[cfg(not(target_os = "linux"))]
fn chown_rootfs_to_uid0(_rootfs_path: &Path) -> Result<(), ProvisionError> {
    Ok(())
}
