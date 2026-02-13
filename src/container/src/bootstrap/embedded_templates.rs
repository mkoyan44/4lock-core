//! Embedded templates — compiled into the binary so the daemon is self-contained.
//!
//! Templates are loaded at compile time via `include_str!` and registered with the
//! TemplateRenderer. This allows the vappc daemon to run inside a VM where only
//! the binary is available (virtio-fs share contains no template files).
//!
//! App-specific templates are added here as the platform evolves.

/// All embedded templates as (name, content) pairs for registration with Tera.
/// App templates will be added as needed.
pub const ALL_TEMPLATES: &[(&str, &str)] = &[
    // Example: ("app/nginx.conf.j2", include_str!("templates/app/nginx.conf.j2")),
];
