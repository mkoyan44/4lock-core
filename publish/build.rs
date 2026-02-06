// Build script: build vappc-linux-daemon for Linux targets, then PUT to Nexus.
// Run from 4lock-core root: cargo build --manifest-path publish/Cargo.toml
// Env: NEXUS_URL, NEXUS_REPO, NEXUS_USERNAME, NEXUS_PASSWORD (no hardcoded credentials)

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // publish/ -> .. = 4lock-core root
    let core_root = manifest_dir.join("..").canonicalize().expect("core root");
    let daemon_manifest = core_root.join("daemon").join("Cargo.toml");
    if !daemon_manifest.exists() {
        panic!("Daemon manifest not found: {}", daemon_manifest.display());
    }

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    // Version: vappc crate version + short git rev (e.g. 0.1.0-90ccccc)
    let version = version_string(&core_root, &daemon_manifest, &cargo);
    eprintln!("Publish version: {}", version);

    let targets = [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
    ];

    let wants_upload = env::var("NEXUS_USERNAME").is_ok() && env::var("NEXUS_PASSWORD").is_ok();
    let mut any_build_ok = false;
    let mut any_upload_ok = false;
    for target in &targets {
        eprintln!("Building vappc-linux-daemon for {}...", target);
        let cargo_build_args = [
            "build",
            "-p",
            "vappc",
            "--bin",
            "vappc-linux-daemon",
            "--release",
            "--manifest-path",
            daemon_manifest.to_str().expect("manifest path"),
            "--target",
            target,
        ];
        let status = Command::new(&cargo)
            .args(&cargo_build_args)
            .current_dir(&core_root)
            .status();
        let succeeded = match status {
            Ok(s) => s.success(),
            Err(e) => {
                eprintln!("Warning: cargo build failed to execute for {}: {}", target, e);
                false
            }
        };
        if !succeeded {
            // On non-Linux, native cross-compile fails (e.g. OpenSSL for target). Use cross (nerdctl/Docker).
            // cross mounts core_root; use args without --manifest-path so container sees Cargo.toml in working dir.
            if which_cross().is_some() {
                eprintln!("Trying cross build for {} (use CROSS_CONTAINER_ENGINE=nerdctl for nerdctl)...", target);
                let cross_args = [
                    "build",
                    "-p",
                    "vappc",
                    "--bin",
                    "vappc-linux-daemon",
                    "--release",
                    "--target",
                    target,
                ];
                let cross_config = core_root.join("daemon").join("Cross.toml");
                let daemon_dir = core_root.join("daemon");
                let cross_status = Command::new("cross")
                    .env("CROSS_CONFIG", cross_config)
                    .args(&cross_args)
                    .current_dir(&daemon_dir)
                    .status();
                if let Ok(s) = cross_status {
                    if !s.success() {
                        eprintln!("Warning: cross build for target {} failed", target);
                        continue;
                    }
                } else {
                    eprintln!("Warning: cross build failed to execute for {}", target);
                    continue;
                }
            } else {
                eprintln!("Warning: cargo build for target {} failed. Install cross (cargo install cross) and set CROSS_CONTAINER_ENGINE=nerdctl for nerdctl.", target);
                continue;
            }
        }

        let binary = core_root
            .join("daemon")
            .join("target")
            .join(target)
            .join("release")
            .join("vappc-linux-daemon");
        if !binary.exists() {
            eprintln!("Warning: binary not found after build: {}", binary.display());
            continue;
        }

        any_build_ok = true;
        if upload_to_nexus(&binary, &version, target) {
            any_upload_ok = true;
        }
    }

    if !any_build_ok {
        panic!(
            "No target built. On non-Linux: install cross (cargo install cross), \
             set CROSS_CONTAINER_ENGINE=nerdctl for nerdctl (or leave unset for Docker), then re-run."
        );
    }
    if wants_upload && !any_upload_ok {
        panic!(
            "NEXUS_USERNAME/NEXUS_PASSWORD are set but no artifact was uploaded. \
             Ensure Nexus is reachable and credentials are correct so data is available on the repo."
        );
    }
    eprintln!("Publish complete.");
}

fn which_cross() -> Option<()> {
    Command::new("cross")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| ())
}

fn version_string(core_root: &PathBuf, daemon_manifest: &PathBuf, cargo: &str) -> String {
    // cargo pkgid -p vappc --manifest-path daemon/Cargo.toml -> "file:///path#0.1.0"
    let out = Command::new(cargo)
        .args(["pkgid", "-p", "vappc", "--manifest-path", daemon_manifest.to_str().expect("manifest path")])
        .current_dir(core_root)
        .output()
        .expect("cargo pkgid");
    let base = String::from_utf8_lossy(&out.stdout);
    let base = base.trim();
    let version_base = base.rsplit('#').next().unwrap_or("0.1.0");
    // git rev-parse --short HEAD from core root
    let rev_out = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(core_root)
        .output();
    let rev = rev_out
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    format!("{}-{}", version_base, rev)
}

/// Returns true if upload was performed, false if skipped (no credentials).
fn upload_to_nexus(binary_path: &PathBuf, version: &str, target: &str) -> bool {
    let username = match env::var("NEXUS_USERNAME") {
        Ok(u) => u,
        Err(_) => {
            eprintln!("NEXUS_USERNAME not set; skipping upload for {}", target);
            return false;
        }
    };
    let password = match env::var("NEXUS_PASSWORD") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("NEXUS_PASSWORD not set; skipping upload for {}", target);
            return false;
        }
    };
    let base_url = env::var("NEXUS_URL").unwrap_or_else(|_| "https://nexus.4lock.net".to_string());
    let repo = env::var("NEXUS_REPO").unwrap_or_else(|_| "4lock-core".to_string());
    let path = format!(
        "vappc-linux-daemon/{}/{}/vappc-linux-daemon",
        version, target
    );
    let url = format!(
        "{}/repository/{}/{}",
        base_url.trim_end_matches('/'),
        repo,
        path
    );
    eprintln!("Uploading {} to Nexus...", target);

    let body = std::fs::read(binary_path).expect("read binary");
    let client = reqwest::blocking::Client::builder()
        .build()
        .expect("reqwest client");
    let resp = client
        .put(&url)
        .basic_auth(&username, Some(&password))
        .body(body)
        .send()
        .expect("PUT request");
    if !resp.status().is_success() {
        panic!(
            "Nexus PUT failed: {} {}",
            resp.status(),
            resp.text().unwrap_or_default()
        );
    }
    eprintln!("Uploaded {} OK", target);
    true
}
