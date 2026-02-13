/// Template renderer using Tera for Jinja2-style template rendering
/// Supports full Jinja2 syntax: variables, conditionals, loops, filters
use super::embedded_templates;
use crate::provisioner::ProvisionError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tera::{Context, Tera};

/// Simple recursive directory walker
fn walkdir(dir: &Path) -> std::io::Result<Vec<std::io::Result<PathBuf>>> {
    let mut results = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                results.extend(walkdir(&path)?);
            } else {
                results.push(Ok(path));
            }
        }
    }
    Ok(results)
}

pub struct TemplateRenderer {
    tera: Tera,
    templates_dir: PathBuf,
}

impl TemplateRenderer {
    /// Create a TemplateRenderer from embedded templates (compiled into the binary).
    /// Use this for production - the daemon is self-contained and works when only
    /// the binary is available (e.g. inside a VM with virtio-fs share containing
    /// only the binary).
    pub fn from_embedded() -> Result<Self, ProvisionError> {
        tracing::debug!("[TemplateRenderer] Initializing Tera from embedded templates");

        let mut tera = Tera::default();
        let mut template_count = 0;

        for (name, content) in embedded_templates::ALL_TEMPLATES {
            if let Err(e) = tera.add_raw_template(name, content) {
                tracing::warn!(
                    "[TemplateRenderer] Failed to add embedded template {}: {}",
                    name,
                    e
                );
            } else {
                template_count += 1;
                tracing::debug!("[TemplateRenderer] Loaded embedded template: {}", name);
            }
        }

        tracing::info!(
            "[TemplateRenderer] Loaded {} embedded templates",
            template_count
        );

        Ok(Self {
            tera,
            templates_dir: PathBuf::from("(embedded)"),
        })
    }

    /// Create a new TemplateRenderer from filesystem (for local development/tests).
    pub fn new(templates_dir: PathBuf) -> Result<Self, ProvisionError> {
        tracing::debug!(
            "[TemplateRenderer] Initializing Tera with templates_dir: {}",
            templates_dir.display()
        );

        // Create empty Tera instance and add templates manually
        // This allows us to load multiple file types (.j2, .sh, .yaml, etc.)
        let mut tera = Tera::default();

        // Walk the templates directory and add all template files
        let extensions = [".j2", ".sh", ".yaml", ".yml", ".toml", ".json"];
        let mut template_count = 0;

        if let Ok(entries) = walkdir(&templates_dir) {
            for entry in entries {
                if let Ok(path) = entry {
                    if path.is_file() {
                        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if extensions.iter().any(|ext| file_name.ends_with(ext)) {
                            // Get relative path from templates_dir
                            if let Ok(rel_path) = path.strip_prefix(&templates_dir) {
                                let template_name = rel_path.to_string_lossy().replace('\\', "/");
                                if let Ok(content) = std::fs::read_to_string(&path) {
                                    if let Err(e) = tera.add_raw_template(&template_name, &content)
                                    {
                                        tracing::warn!(
                                            "[TemplateRenderer] Failed to add template {}: {}",
                                            template_name,
                                            e
                                        );
                                    } else {
                                        template_count += 1;
                                        tracing::debug!(
                                            "[TemplateRenderer] Loaded template: {}",
                                            template_name
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        tracing::info!(
            "[TemplateRenderer] Loaded {} templates from {}",
            template_count,
            templates_dir.display()
        );

        Ok(Self {
            tera,
            templates_dir,
        })
    }

    /// Render a template with variables using Tera context
    pub fn render(
        &self,
        template_name: &str,
        vars: &HashMap<String, String>,
    ) -> Result<String, ProvisionError> {
        // Build Tera context from variables
        let mut context = Context::new();
        for (key, value) in vars {
            context.insert(key, value);
        }

        // Render template
        let rendered = self.tera.render(template_name, &context).map_err(|e| {
            ProvisionError::Runtime(format!(
                "Failed to render template {}: {}",
                template_name, e
            ))
        })?;

        tracing::debug!(
            "[TemplateRenderer] Rendered template {} ({} bytes)",
            template_name,
            rendered.len()
        );

        Ok(rendered)
    }

    /// Render a template with a Tera Context directly
    pub fn render_with_context(
        &self,
        template_name: &str,
        context: &Context,
    ) -> Result<String, ProvisionError> {
        self.tera.render(template_name, context).map_err(|e| {
            ProvisionError::Runtime(format!(
                "Failed to render template {}: {}",
                template_name, e
            ))
        })
    }

    /// Write rendered template to a file
    pub fn render_to_file(
        &self,
        template_name: &str,
        vars: &HashMap<String, String>,
        output_path: &Path,
    ) -> Result<(), ProvisionError> {
        let rendered = self.render(template_name, vars)?;

        // Create parent directory if it doesn't exist
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent).map_err(ProvisionError::Io)?;
        }

        std::fs::write(output_path, rendered).map_err(ProvisionError::Io)?;

        tracing::info!(
            "[TemplateRenderer] Rendered template {} to {}",
            template_name,
            output_path.display()
        );

        Ok(())
    }

    /// List all loaded template names
    pub fn list_templates(&self) -> Vec<String> {
        self.tera.get_template_names().map(String::from).collect()
    }

    /// Get templates directory path
    pub fn templates_dir(&self) -> &Path {
        &self.templates_dir
    }

}
