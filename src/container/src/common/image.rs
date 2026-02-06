/// OCI image types
use serde::{Deserialize, Serialize};

/// OCI image reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageReference {
    /// Full image reference (e.g., "ghcr.io/4lock/agent-base:latest")
    pub reference: String,

    /// Registry URL (extracted or explicit)
    pub registry: Option<String>,

    /// Image name (without registry)
    pub name: String,

    /// Tag (defaults to "latest")
    pub tag: String,
}

impl ImageReference {
    /// Parse image reference string
    pub fn parse(reference: &str) -> Result<Self, String> {
        // Simple parser - can be enhanced
        if let Some((name_part, tag)) = reference.rsplit_once(':') {
            let (registry, name) = if let Some((reg, img)) = name_part.split_once('/') {
                if reg.contains('.') || reg == "localhost" {
                    (Some(reg.to_string()), img.to_string())
                } else {
                    (None, name_part.to_string())
                }
            } else {
                (None, name_part.to_string())
            };

            Ok(Self {
                reference: reference.to_string(),
                registry,
                name,
                tag: tag.to_string(),
            })
        } else {
            // No tag, default to latest
            Ok(Self {
                reference: reference.to_string(),
                registry: None,
                name: reference.to_string(),
                tag: "latest".to_string(),
            })
        }
    }
}

/// Registry authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryAuth {
    /// Username
    pub username: String,

    /// Password or token
    pub password: String,
}
