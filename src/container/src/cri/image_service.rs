//! CRI ImageService implementation
//!
//! This module implements the Kubernetes CRI ImageService gRPC interface.

use std::path::PathBuf;
use tonic::{Request, Response, Status};

use super::server::runtime::v1::image_service_server::ImageService;
use super::server::runtime::v1::*;

/// ImageService implementation
pub struct ImageServiceImpl {
    cache_dir: PathBuf,
}

impl ImageServiceImpl {
    pub fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }
}

#[tonic::async_trait]
impl ImageService for ImageServiceImpl {
    async fn list_images(
        &self,
        _request: Request<ListImagesRequest>,
    ) -> Result<Response<ListImagesResponse>, Status> {
        let mut images = Vec::new();

        // Scan cache directory for images
        if let Ok(entries) = std::fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                        // Parse directory name to get image info
                        // Format: registry_repo_tag (underscores replacing special chars)
                        let parts: Vec<&str> = dir_name.rsplitn(2, '_').collect();
                        let (tag, image_name) = if parts.len() == 2 {
                            (parts[0], parts[1].replace('_', "/"))
                        } else {
                            ("latest", dir_name.replace('_', "/"))
                        };

                        // Check if rootfs exists
                        let rootfs = path.join("rootfs");
                        if rootfs.exists() {
                            let size = calculate_dir_size(&rootfs).unwrap_or(0);
                            images.push(Image {
                                id: format!("sha256:{}", dir_name),
                                repo_tags: vec![format!("{}:{}", image_name, tag)],
                                repo_digests: vec![],
                                size,
                                uid: None,
                                username: String::new(),
                                spec: None,
                                pinned: false,
                            });
                        }
                    }
                }
            }
        }

        Ok(Response::new(ListImagesResponse { images }))
    }

    async fn image_status(
        &self,
        request: Request<ImageStatusRequest>,
    ) -> Result<Response<ImageStatusResponse>, Status> {
        let image_spec = request
            .into_inner()
            .image
            .ok_or_else(|| Status::invalid_argument("Missing image spec"))?;

        let image_ref = if !image_spec.image.is_empty() {
            image_spec.image.clone()
        } else {
            image_spec.user_specified_image.clone()
        };

        // Normalize image reference to directory name
        let normalized = image_ref
            .replace("://", "_")
            .replace('/', "_")
            .replace(':', "_");
        let image_dir = self.cache_dir.join(&normalized);
        let rootfs = image_dir.join("rootfs");

        if rootfs.exists() {
            let size = calculate_dir_size(&rootfs).unwrap_or(0);
            let id = format!("sha256:{}", normalized);
            let repo_tag = if image_ref.contains(':') {
                image_ref.clone()
            } else {
                format!("{}:latest", image_ref)
            };

            Ok(Response::new(ImageStatusResponse {
                image: Some(Image {
                    id,
                    repo_tags: vec![repo_tag],
                    repo_digests: vec![],
                    size,
                    uid: None,
                    username: String::new(),
                    spec: None,
                    pinned: false,
                }),
                info: std::collections::HashMap::new(),
            }))
        } else {
            Ok(Response::new(ImageStatusResponse {
                image: None,
                info: std::collections::HashMap::new(),
            }))
        }
    }

    async fn pull_image(
        &self,
        request: Request<PullImageRequest>,
    ) -> Result<Response<PullImageResponse>, Status> {
        let req = request.into_inner();
        let image_spec = req
            .image
            .ok_or_else(|| Status::invalid_argument("Missing image spec"))?;

        let image_ref = if !image_spec.image.is_empty() {
            image_spec.image
        } else {
            image_spec.user_specified_image
        };

        tracing::info!("[CRI ImageService] Pulling image: {}", image_ref);

        // For now, just ensure the directory exists
        // The actual pulling should be done through the ImageManager in the provisioner
        let normalized = image_ref
            .replace("://", "_")
            .replace('/', "_")
            .replace(':', "_");
        let image_dir = self.cache_dir.join(&normalized);
        std::fs::create_dir_all(&image_dir)
            .map_err(|e| Status::internal(format!("Failed to create image dir: {}", e)))?;

        let normalized = image_ref
            .replace("://", "_")
            .replace('/', "_")
            .replace(':', "_");

        Ok(Response::new(PullImageResponse {
            image_ref: format!("sha256:{}", normalized),
        }))
    }

    async fn remove_image(
        &self,
        request: Request<RemoveImageRequest>,
    ) -> Result<Response<RemoveImageResponse>, Status> {
        let image_spec = request
            .into_inner()
            .image
            .ok_or_else(|| Status::invalid_argument("Missing image spec"))?;

        let image_ref = if !image_spec.image.is_empty() {
            image_spec.image
        } else {
            image_spec.user_specified_image
        };

        let normalized = image_ref
            .replace("://", "_")
            .replace('/', "_")
            .replace(':', "_");
        let image_dir = self.cache_dir.join(&normalized);

        if image_dir.exists() {
            std::fs::remove_dir_all(&image_dir)
                .map_err(|e| Status::internal(format!("Failed to remove image: {}", e)))?;
        }

        Ok(Response::new(RemoveImageResponse {}))
    }

    async fn image_fs_info(
        &self,
        _request: Request<ImageFsInfoRequest>,
    ) -> Result<Response<ImageFsInfoResponse>, Status> {
        Ok(Response::new(ImageFsInfoResponse {
            image_filesystems: vec![],
            container_filesystems: vec![],
        }))
    }
}

/// Calculate directory size recursively
fn calculate_dir_size(path: &std::path::Path) -> std::io::Result<u64> {
    let mut size = 0;
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                size += calculate_dir_size(&path)?;
            } else {
                size += entry.metadata()?.len();
            }
        }
    }
    Ok(size)
}
