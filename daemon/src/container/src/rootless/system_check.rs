//! System requirements checker for Linux container runtime
//!
//! This module verifies that the system is properly configured for rootless containers.
//! It checks:
//! - AppArmor user namespace restrictions
//! - subuid/subgid mappings
//! - Required binaries (newuidmap, newgidmap, pasta)

use std::fs;
use std::path::Path;
use std::process::Command;

use nix::libc;

/// Result of system requirements check
#[derive(Debug, Clone)]
pub struct SystemCheckResult {
    pub passed: bool,
    pub checks: Vec<CheckItem>,
    pub setup_instructions: Option<String>,
}

/// Individual check item
#[derive(Debug, Clone)]
pub struct CheckItem {
    pub name: String,
    pub passed: bool,
    pub message: String,
    pub fix_command: Option<String>,
}

impl SystemCheckResult {
    /// Returns a formatted error message if checks failed
    pub fn error_message(&self) -> Option<String> {
        if self.passed {
            return None;
        }

        let failed_checks: Vec<_> = self.checks.iter().filter(|c| !c.passed).collect();

        let mut msg = String::from(
            "\n╔════════════════════════════════════════════════════════════════╗\n\
             ║  Container Runtime - System Requirements Not Met               ║\n\
             ╚════════════════════════════════════════════════════════════════╝\n\n",
        );

        msg.push_str("The following requirements are not satisfied:\n\n");

        for (i, check) in failed_checks.iter().enumerate() {
            msg.push_str(&format!(
                "  {}. {} - {}\n",
                i + 1,
                check.name,
                check.message
            ));
            if let Some(fix) = &check.fix_command {
                msg.push_str(&format!("     Fix: {}\n", fix));
            }
            msg.push('\n');
        }

        msg.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        msg.push_str("Quick Fix: Run the setup script as root:\n\n");
        msg.push_str("  sudo ./scripts/linux-container-setup.sh\n\n");
        msg.push_str("Then log out and back in for changes to take effect.\n");
        msg.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        Some(msg)
    }
}

/// Check all system requirements for rootless containers
pub fn check_system_requirements() -> SystemCheckResult {
    // When running as root (UID 0), skip rootless-specific checks
    // Root can run privileged containers without user namespace mappings
    let is_root = unsafe { libc::getuid() } == 0;

    let checks = if is_root {
        // Root mode: only check for pasta (network namespace tool)
        vec![
            CheckItem {
                name: "Running as root".to_string(),
                passed: true,
                message: "Privileged container mode enabled".to_string(),
                fix_command: None,
            },
            check_binary("pasta", "pasta", false),
        ]
    } else {
        // Rootless mode: full checks
        vec![
            check_apparmor_userns(),
            // Check subuid/subgid
            check_subuid(),
            check_subgid(),
            // Check required binaries
            check_binary("newuidmap", "/usr/bin/newuidmap", true),
            check_binary("newgidmap", "/usr/bin/newgidmap", true),
            check_binary("pasta", "pasta", false),
            // NOTE: Host containerd is no longer required - kubelet uses vapp CRI server
        ]
    };

    let passed = checks.iter().all(|c| c.passed);

    SystemCheckResult {
        passed,
        checks,
        setup_instructions: if passed {
            None
        } else {
            Some("Run: sudo ./scripts/linux-container-setup.sh".to_string())
        },
    }
}

/// Check if AppArmor restricts unprivileged user namespaces
fn check_apparmor_userns() -> CheckItem {
    let sysctl_path = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

    if !Path::new(sysctl_path).exists() {
        // Older kernel or non-Ubuntu - not applicable
        return CheckItem {
            name: "AppArmor userns".to_string(),
            passed: true,
            message: "Not applicable (older kernel)".to_string(),
            fix_command: None,
        };
    }

    match fs::read_to_string(sysctl_path) {
        Ok(content) => {
            let value = content.trim();
            if value == "0" {
                CheckItem {
                    name: "AppArmor userns".to_string(),
                    passed: true,
                    message: "User namespace restriction disabled".to_string(),
                    fix_command: None,
                }
            } else {
                CheckItem {
                    name: "AppArmor userns".to_string(),
                    passed: false,
                    message: "User namespace restriction ENABLED (blocks rootless containers)".to_string(),
                    fix_command: Some(
                        "echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-vapp-userns.conf && sudo sysctl --system".to_string()
                    ),
                }
            }
        }
        Err(e) => CheckItem {
            name: "AppArmor userns".to_string(),
            passed: false,
            message: format!("Cannot read sysctl: {}", e),
            fix_command: None,
        },
    }
}

/// Check if current user has subuid mapping
fn check_subuid() -> CheckItem {
    check_subid_file("/etc/subuid", "subuid")
}

/// Check if current user has subgid mapping
fn check_subgid() -> CheckItem {
    check_subid_file("/etc/subgid", "subgid")
}

fn check_subid_file(path: &str, name: &str) -> CheckItem {
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    match fs::read_to_string(path) {
        Ok(content) => {
            let has_entry = content
                .lines()
                .any(|line| line.starts_with(&format!("{}:", username)));

            if has_entry {
                CheckItem {
                    name: name.to_string(),
                    passed: true,
                    message: format!("User '{}' has {} mapping", username, name),
                    fix_command: None,
                }
            } else {
                CheckItem {
                    name: name.to_string(),
                    passed: false,
                    message: format!("User '{}' missing from {}", username, path),
                    fix_command: Some(format!(
                        "echo '{}:100000:65536' | sudo tee -a {}",
                        username, path
                    )),
                }
            }
        }
        Err(e) => CheckItem {
            name: name.to_string(),
            passed: false,
            message: format!("Cannot read {}: {}", path, e),
            fix_command: Some("sudo apt install uidmap".to_string()),
        },
    }
}

/// Check if a required binary exists
fn check_binary(name: &str, path_or_cmd: &str, check_setuid: bool) -> CheckItem {
    // Try to find the binary
    let binary_path = if path_or_cmd.starts_with('/') {
        if Path::new(path_or_cmd).exists() {
            Some(path_or_cmd.to_string())
        } else {
            None
        }
    } else {
        // Use `which` to find the binary
        Command::new("which")
            .arg(path_or_cmd)
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    String::from_utf8(output.stdout)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
    };

    match binary_path {
        Some(path) => {
            if check_setuid {
                // Check if setuid bit is set
                match fs::metadata(&path) {
                    Ok(meta) => {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = meta.permissions().mode();
                        let has_setuid = (mode & 0o4000) != 0;

                        if has_setuid {
                            CheckItem {
                                name: name.to_string(),
                                passed: true,
                                message: format!("Found at {} (setuid enabled)", path),
                                fix_command: None,
                            }
                        } else {
                            CheckItem {
                                name: name.to_string(),
                                passed: false,
                                message: format!("Found at {} but setuid NOT set", path),
                                fix_command: Some(format!("sudo chmod u+s {}", path)),
                            }
                        }
                    }
                    Err(e) => CheckItem {
                        name: name.to_string(),
                        passed: false,
                        message: format!("Cannot stat {}: {}", path, e),
                        fix_command: None,
                    },
                }
            } else {
                CheckItem {
                    name: name.to_string(),
                    passed: true,
                    message: format!("Found at {}", path),
                    fix_command: None,
                }
            }
        }
        None => CheckItem {
            name: name.to_string(),
            passed: false,
            message: "Not installed".to_string(),
            fix_command: Some(format!(
                "sudo apt install {}",
                if name == "pasta" { "passt" } else { "uidmap" }
            )),
        },
    }
}
