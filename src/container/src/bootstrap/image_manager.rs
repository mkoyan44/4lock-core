/// Image manager for pulling and caching OCI images
use crate::common::{ContainerError, ImageReference};
use futures::StreamExt;
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing;

/// Image manager for container images
pub struct ImageManager {
    cache_dir: PathBuf,
    docker_proxy_url: Mutex<Option<String>>, // Cached docker-proxy URL
}

impl ImageManager {
    /// Create a new image manager
    pub fn new(
        _image_config: &crate::bootstrap::config::ImageConfig,
        app_dir: PathBuf,
    ) -> Result<Self, String> {
        let cache_dir = app_dir.join("containers/images");

        std::fs::create_dir_all(&cache_dir)
            .map_err(|e| format!("Failed to create image cache directory: {}", e))?;

        tracing::info!("[ImageManager] Initialized with cache dir: {:?}", cache_dir);

        Ok(Self {
            cache_dir,
            docker_proxy_url: Mutex::new(None),
        })
    }

    /// Detect docker-proxy URL by trying both ports
    ///
    /// Docker-proxy runs on:
    /// - Port 5051 (HTTP) if HTTPS is enabled on 5050
    /// - Port 5050 (HTTP) if no HTTPS (HTTP-only mode)
    ///
    /// Returns the first working URL, or defaults to http://localhost:5050
    async fn detect_docker_proxy_url(&self) -> String {
        // Return cached URL if available
        {
            let cached = self.docker_proxy_url.lock().unwrap();
            if let Some(ref url) = *cached {
                return url.clone();
            }
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        // Try port 5051 first (HTTP when HTTPS is enabled)
        let test_url_5051 = "http://localhost:5051/health";
        if client.get(test_url_5051).send().await.is_ok() {
            let url = "http://localhost:5051".to_string();
            tracing::info!("[ImageManager] Docker-proxy detected on port 5051 (HTTP)");
            *self.docker_proxy_url.lock().unwrap() = Some(url.clone());
            return url;
        }

        // Try port 5050 (HTTP when no HTTPS, or HTTPS if certs available)
        let test_url_5050_http = "http://localhost:5050/health";
        if client.get(test_url_5050_http).send().await.is_ok() {
            let url = "http://localhost:5050".to_string();
            tracing::info!("[ImageManager] Docker-proxy detected on port 5050 (HTTP)");
            *self.docker_proxy_url.lock().unwrap() = Some(url.clone());
            return url;
        }

        // Try port 5050 with HTTPS (if certs available)
        let test_url_5050_https = "https://localhost:5050/health";
        let https_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true) // Accept self-signed certs
            .timeout(std::time::Duration::from_secs(2))
            .build();
        if let Ok(https_client) = https_client {
            if https_client.get(test_url_5050_https).send().await.is_ok() {
                let url = "https://localhost:5050".to_string();
                tracing::info!("[ImageManager] Docker-proxy detected on port 5050 (HTTPS)");
                *self.docker_proxy_url.lock().unwrap() = Some(url.clone());
                return url;
            }
        }

        // Default to HTTP port 5050 (most common case)
        tracing::warn!(
            "[ImageManager] Could not detect docker-proxy port, defaulting to http://localhost:5050"
        );
        let url = "http://localhost:5050".to_string();
        *self.docker_proxy_url.lock().unwrap() = Some(url.clone());
        url
    }

    /// Ensure image is available (pull if needed)
    pub async fn ensure_image(&self, image_ref: &str) -> Result<PathBuf, ContainerError> {
        tracing::info!("[ImageManager] Ensuring image is available: {}", image_ref);

        // Parse image reference
        let image = ImageReference::parse(image_ref)
            .map_err(|e| ContainerError::Config(format!("Invalid image reference: {}", e)))?;

        // Create image directory with tag for cache key
        let image_cache_key = format!("{}_{}", image.name.replace("/", "_"), image.tag);
        let image_dir = self.cache_dir.join(&image_cache_key);
        let rootfs_path = image_dir.join("rootfs");
        let manifest_path = image_dir.join("manifest.json");

        // Check if image is already cached (has rootfs and manifest)
        if rootfs_path.exists() && manifest_path.exists() {
            tracing::info!("[ImageManager] Image found in cache: {:?}", image_dir);
            return Ok(image_dir);
        }

        tracing::info!("[ImageManager] Image not in cache, pulling: {}", image_ref);

        // Pull via docker-proxy ONLY - no fallbacks
        tracing::info!(
            "[ImageManager] Pulling image via docker-proxy: {}",
            image_ref
        );
        self.pull_via_docker_proxy(image_ref, &image_dir).await?;

        // Save manifest for cache validation
        let manifest_path = image_dir.join("manifest.json");
        fs::write(&manifest_path, b"{}")
            .await
            .map_err(ContainerError::Io)?;

        tracing::info!(
            "[ImageManager] Successfully pulled image via docker-proxy: {:?}",
            image_dir
        );
        Ok(image_dir)
    }

    /// Download a single layer blob with error handling
    async fn download_layer_blob(
        client: &reqwest::Client,
        blob_url: &str,
        temp_layer_path: &std::path::Path,
        digest: &str,
    ) -> Result<(), ContainerError> {
        // Fetch layer blob
        let blob_response = client.get(blob_url).send().await.map_err(|e| {
            ContainerError::Runtime(format!("Failed to fetch layer blob {}: {}", digest, e))
        })?;

        if !blob_response.status().is_success() {
            let status = blob_response.status();
            let error_body = blob_response.text().await.unwrap_or_default();
            return Err(ContainerError::Runtime(format!(
                "Docker-proxy returned error {} for layer {}: {}",
                status, digest, error_body
            )));
        }

        // Stream layer data to temporary file
        let mut file = fs::File::create(temp_layer_path)
            .await
            .map_err(ContainerError::Io)?;

        let mut stream = blob_response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                ContainerError::Runtime(format!("Failed to read layer chunk: {}", e))
            })?;
            file.write_all(&chunk).await.map_err(ContainerError::Io)?;
        }

        file.sync_all().await.map_err(ContainerError::Io)?;
        Ok(())
    }

    /// Pull image via docker-proxy HTTP API
    async fn pull_via_docker_proxy(
        &self,
        image_ref: &str,
        image_dir: &std::path::Path,
    ) -> Result<(), ContainerError> {
        tracing::info!(
            "[ImageManager] Pulling image via docker-proxy: {}",
            image_ref
        );

        // Parse image reference
        let image = ImageReference::parse(image_ref)
            .map_err(|e| ContainerError::Config(format!("Invalid image reference: {}", e)))?;

        // Build repository name for docker-proxy API
        // Format: {registry}/{repository} or just {repository} for docker.io
        // Docker Hub: official images use "library/" prefix (e.g., nginx -> library/nginx)
        //             user images use "user/repo" format (e.g., zyclonite/zerotier -> zyclonite/zerotier)
        let repository = if let Some(registry) = &image.registry {
            if registry == "docker.io" {
                // Check if image name already contains a slash (user repository)
                // If it does, use it as-is (e.g., "zyclonite/zerotier" -> "zyclonite/zerotier")
                // If not, add "library/" prefix (e.g., "nginx" -> "library/nginx")
                if image.name.contains('/') {
                    image.name.clone()
                } else {
                    format!("library/{}", image.name)
                }
            } else {
                format!("{}/{}", registry, image.name)
            }
        } else {
            // Default to docker.io - check if name contains slash
            if image.name.contains('/') {
                image.name.clone()
            } else {
                format!("library/{}", image.name)
            }
        };

        let rootfs_path = image_dir.join("rootfs");
        fs::create_dir_all(&rootfs_path)
            .await
            .map_err(ContainerError::Io)?;

        // Docker-proxy port detection:
        // - If HTTPS is enabled: runs on 5050 (HTTPS) and 5051 (HTTP)
        // - If no HTTPS: runs on 5050 (HTTP only)
        // Try both ports and use whichever is available
        let docker_proxy_base = self.detect_docker_proxy_url().await;

        // 1. Fetch manifest
        let manifest_url = format!(
            "{}/v2/{}/manifests/{}",
            docker_proxy_base, repository, image.tag
        );

        tracing::debug!(
            "[ImageManager] Fetching manifest from docker-proxy: {}",
            manifest_url
        );

        let client = reqwest::Client::new();
        let manifest_response = client
            .get(&manifest_url)
            .header(
                "Accept",
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .send()
            .await
            .map_err(|e| {
                ContainerError::Runtime(format!(
                    "Failed to fetch manifest from docker-proxy: {}",
                    e
                ))
            })?;

        if !manifest_response.status().is_success() {
            let status = manifest_response.status();
            let error_body = manifest_response.text().await.unwrap_or_default();
            return Err(ContainerError::Runtime(format!(
                "Docker-proxy returned error {}: {}",
                status, error_body
            )));
        }

        let mut manifest_json: serde_json::Value = manifest_response.json().await.map_err(|e| {
            ContainerError::Runtime(format!("Failed to parse manifest JSON: {}", e))
        })?;

        tracing::info!("[ImageManager] Fetched manifest from docker-proxy");

        // Check if this is a manifest list (multi-platform)
        let media_type = manifest_json
            .get("mediaType")
            .and_then(|m| m.as_str())
            .unwrap_or("");

        if media_type.contains("manifest.list") || media_type.contains("image.index") {
            tracing::info!(
                "[ImageManager] Manifest list detected, resolving to platform-specific manifest"
            );

            // Get manifests array
            let manifests = manifest_json
                .get("manifests")
                .and_then(|m| m.as_array())
                .ok_or_else(|| {
                    ContainerError::Config("Manifest list missing manifests array".to_string())
                })?;

            // Detect platform (default to linux/amd64, fallback to first available)
            let target_arch = std::env::consts::ARCH;
            let target_os = std::env::consts::OS;

            tracing::debug!(
                "[ImageManager] Looking for platform: {}/{}",
                target_os,
                target_arch
            );

            // Try to find matching platform manifest
            let mut selected_manifest: Option<&serde_json::Value> = None;
            for manifest in manifests {
                if let Some(platform) = manifest.get("platform") {
                    let arch = platform
                        .get("architecture")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let os = platform.get("os").and_then(|v| v.as_str()).unwrap_or("");

                    // Normalize architecture names
                    let normalized_arch = match target_arch {
                        "x86_64" => "amd64",
                        "aarch64" => "arm64",
                        _ => target_arch,
                    };

                    if os == target_os && arch == normalized_arch {
                        selected_manifest = Some(manifest);
                        tracing::info!(
                            "[ImageManager] Found matching platform manifest: {}/{}",
                            os,
                            arch
                        );
                        break;
                    }
                }
            }

            // Fallback: use first manifest if no exact match
            let selected_manifest =
                selected_manifest
                    .or_else(|| manifests.first())
                    .ok_or_else(|| {
                        ContainerError::Config("Manifest list has no manifests".to_string())
                    })?;

            // Get digest of selected manifest
            let platform_digest = selected_manifest
                .get("digest")
                .and_then(|d| d.as_str())
                .ok_or_else(|| {
                    ContainerError::Config("Platform manifest missing digest".to_string())
                })?;

            tracing::info!(
                "[ImageManager] Fetching platform-specific manifest: {}",
                platform_digest
            );

            // Fetch platform-specific manifest
            let platform_manifest_url = format!(
                "{}/v2/{}/manifests/{}",
                docker_proxy_base, repository, platform_digest
            );

            let platform_response = client
                .get(&platform_manifest_url)
                .header(
                    "Accept",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                .send()
                .await
                .map_err(|e| {
                    ContainerError::Runtime(format!("Failed to fetch platform manifest: {}", e))
                })?;

            if !platform_response.status().is_success() {
                let status = platform_response.status();
                return Err(ContainerError::Runtime(format!(
                    "Docker-proxy returned error {} for platform manifest",
                    status
                )));
            }

            manifest_json = platform_response.json().await.map_err(|e| {
                ContainerError::Runtime(format!("Failed to parse platform manifest JSON: {}", e))
            })?;

            tracing::info!("[ImageManager] Fetched platform-specific manifest");
        }

        // 2. Extract layer digests from manifest
        let layers = manifest_json
            .get("layers")
            .and_then(|l| l.as_array())
            .ok_or_else(|| ContainerError::Config("Manifest missing layers array".to_string()))?;

        tracing::info!("[ImageManager] Found {} layers to extract", layers.len());

        // 3. Fetch and extract each layer
        for (index, layer) in layers.iter().enumerate() {
            let digest = layer
                .get("digest")
                .and_then(|d| d.as_str())
                .ok_or_else(|| ContainerError::Config("Layer missing digest".to_string()))?;

            let _media_type = layer
                .get("mediaType")
                .and_then(|m| m.as_str())
                .unwrap_or("application/vnd.docker.image.rootfs.diff.tar.gzip");

            tracing::debug!(
                "[ImageManager] Fetching layer {}/{}: {}",
                index + 1,
                layers.len(),
                digest
            );

            // Fetch layer blob with retry logic
            let blob_url = format!("{}/v2/{}/blobs/{}", docker_proxy_base, repository, digest);
            let temp_layer_path = image_dir.join(format!("layer_{}.tar.gz", index));

            // Retry layer download with exponential backoff
            const MAX_RETRIES: u32 = 3;
            let mut last_error = None;
            let mut success = false;

            for attempt in 0..=MAX_RETRIES {
                if attempt > 0 {
                    let delay_ms = 1000 * (1 << (attempt - 1)); // Exponential backoff: 1s, 2s, 4s
                    tracing::warn!(
                        "[ImageManager] Retrying layer download (attempt {}/{}): {} (waiting {}ms)",
                        attempt + 1,
                        MAX_RETRIES + 1,
                        digest,
                        delay_ms
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }

                // Clean up any partial file from previous attempt
                let _ = fs::remove_file(&temp_layer_path).await;

                match Self::download_layer_blob(&client, &blob_url, &temp_layer_path, digest).await
                {
                    Ok(()) => {
                        success = true;
                        break;
                    }
                    Err(e) => {
                        last_error = Some(e);
                        if attempt < MAX_RETRIES {
                            tracing::warn!(
                                "[ImageManager] Layer download attempt {} failed: {}",
                                attempt + 1,
                                last_error.as_ref().unwrap()
                            );
                        }
                    }
                }
            }

            if !success {
                return Err(last_error.unwrap_or_else(|| {
                    ContainerError::Runtime(format!(
                        "Failed to download layer {} after {} retries",
                        digest, MAX_RETRIES
                    ))
                }));
            }

            // Extract layer
            tracing::debug!(
                "[ImageManager] Extracting layer {}/{}",
                index + 1,
                layers.len()
            );
            self.extract_layer(&temp_layer_path, &rootfs_path).await?;

            // Cleanup temp layer file
            let _ = fs::remove_file(&temp_layer_path).await;
        }

        tracing::info!("[ImageManager] Successfully pulled and extracted image via docker-proxy");

        Ok(())
    }

    /// Extract a single layer (tar.gz)
    ///
    /// CRITICAL: We don't preserve original permissions because container images
    /// often have root-owned files that would be inaccessible to the current user.
    /// Instead, we extract with current user's umask and then fix permissions.
    async fn extract_layer(
        &self,
        layer_path: &std::path::Path,
        rootfs_path: &std::path::Path,
    ) -> Result<(), ContainerError> {
        use flate2::read::GzDecoder;
        use std::fs::File;
        use tar::Archive;

        tracing::debug!("[ImageManager] Extracting layer: {:?}", layer_path);

        let file = File::open(layer_path).map_err(ContainerError::Io)?;
        let tar = GzDecoder::new(file);
        let mut archive = Archive::new(tar);

        // CRITICAL: Don't preserve original permissions from container image
        // Container images have root-owned files that would be inaccessible
        // in rootless container extraction
        archive.set_preserve_permissions(false);
        archive.set_preserve_ownerships(false);

        // Extract entries individually to handle errors gracefully
        // Some container images have entries that can't be extracted in rootless mode
        // (device nodes, files with special attributes, etc.)
        for entry_result in archive.entries().map_err(ContainerError::Io)? {
            match entry_result {
                Ok(mut entry) => {
                    entry.set_preserve_permissions(false);

                    let path = match entry.path() {
                        Ok(p) => p.to_path_buf(),
                        Err(e) => {
                            tracing::warn!(
                                "[ImageManager] Failed to get entry path, skipping: {}",
                                e
                            );
                            continue;
                        }
                    };

                    // Skip whiteout files (used for layer deletion markers)
                    let path_str = path.to_string_lossy();
                    if path_str.contains(".wh.") {
                        continue;
                    }

                    let target = rootfs_path.join(&path);

                    // Ensure parent directory exists
                    if let Some(parent) = target.parent() {
                        if !parent.exists() {
                            if let Err(e) = std::fs::create_dir_all(parent) {
                                tracing::warn!(
                                    "[ImageManager] Failed to create parent dir {:?}: {}",
                                    parent,
                                    e
                                );
                                continue;
                            }
                        }
                    }

                    // Try to unpack, skip entries that fail (e.g., device nodes, special files)
                    if let Err(e) = entry.unpack(&target) {
                        // Only warn for unexpected errors, some files just can't be extracted
                        // in rootless mode (device nodes, fifos with wrong permissions, etc.)
                        let error_str = e.to_string();
                        if !error_str.contains("Permission denied")
                            && !error_str.contains("Operation not permitted")
                        {
                            tracing::warn!(
                                "[ImageManager] Failed to extract {:?}: {} (continuing)",
                                path,
                                e
                            );
                        }
                        continue;
                    }
                }
                Err(e) => {
                    tracing::warn!("[ImageManager] Failed to read tar entry, skipping: {}", e);
                    continue;
                }
            }
        }

        // Fix permissions on extracted files to ensure they're readable
        // This is necessary because some container images have restrictive permissions
        self.fix_extracted_permissions(rootfs_path)?;

        Ok(())
    }

    /// Fix permissions on extracted rootfs to ensure all files are readable
    ///
    /// Container images often have files owned by root with restrictive permissions.
    /// In rootless container mode, we need all files to be readable by the current user.
    /// Binary files also need execute permissions to be runnable.
    /// Unix-only: uses `PermissionsExt` (mode/set_mode). On Windows this is a no-op.
    fn fix_extracted_permissions(
        &self,
        rootfs_path: &std::path::Path,
    ) -> Result<(), ContainerError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            /// Check if a file should be executable based on its content and location
            fn should_be_executable(path: &std::path::Path) -> bool {
                // Check if file is in standard binary directories
                // Container rootfs paths are absolute, so we can check for these directory patterns
                let path_str = path.to_string_lossy();
                let binary_dir_patterns = [
                    "/bin/",
                    "/sbin/",
                    "/usr/bin/",
                    "/usr/sbin/",
                    "/usr/local/bin/",
                    "/usr/local/sbin/",
                ];
                if binary_dir_patterns
                    .iter()
                    .any(|pattern| path_str.contains(pattern))
                {
                    return true;
                }

                // Check file content for ELF magic bytes or shebang
                if let Ok(mut file) = std::fs::File::open(path) {
                    use std::io::Read;
                    let mut buffer = [0u8; 4];
                    if file.read_exact(&mut buffer).is_ok() {
                        // Check for ELF magic bytes: \x7fELF
                        if buffer == [0x7f, 0x45, 0x4c, 0x46] {
                            return true;
                        }
                        // Check for shebang: #!
                        if buffer[0..2] == [0x23, 0x21] {
                            return true;
                        }
                    }
                }

                false
            }

            fn fix_permissions_recursive(path: &std::path::Path) -> std::io::Result<()> {
                let metadata = std::fs::symlink_metadata(path)?;

                // Don't modify symlinks
                if metadata.file_type().is_symlink() {
                    return Ok(());
                }

                let mut perms = metadata.permissions();
                let mode = perms.mode();

                if metadata.is_dir() {
                    // CRITICAL: In user namespaces, directories must be fully traversable
                    // Set to 0o755 (rwxr-xr-x) to ensure execute permission for all
                    // This is necessary for user namespace permission checks
                    if mode != 0o755 {
                        perms.set_mode(0o755);
                        std::fs::set_permissions(path, perms)?;
                    }

                    // Recurse into directory
                    for entry in std::fs::read_dir(path)? {
                        let entry = entry?;
                        fix_permissions_recursive(&entry.path())?;
                    }
                } else {
                    // For files: check if it should be executable
                    if should_be_executable(path) {
                        // CRITICAL: In user namespaces, ensure binary is executable by owner, group, and others
                        // Always set to 0o755 (rwxr-xr-x) for user namespace compatibility
                        // The file is owned by the mapped user (host UID 1000 = container UID 0),
                        // but we need explicit permissions for user namespace execution checks
                        perms.set_mode(0o755);
                        std::fs::set_permissions(path, perms)?;
                    } else {
                        // Regular files just need read permission
                        // Ensure at least 0o644 (rw-r--r--) for user namespace compatibility
                        if mode & 0o444 != 0o444 {
                            perms.set_mode(0o644);
                            std::fs::set_permissions(path, perms)?;
                        }
                    }
                }

                Ok(())
            }

            fix_permissions_recursive(rootfs_path).map_err(|e| {
                ContainerError::Runtime(format!(
                    "Failed to fix permissions on extracted rootfs: {}",
                    e
                ))
            })
        }

        #[cfg(not(unix))]
        {
            let _ = rootfs_path;
            Ok(())
        }
    }

    /// Get cache directory
    pub fn cache_dir(&self) -> &PathBuf {
        &self.cache_dir
    }
}
