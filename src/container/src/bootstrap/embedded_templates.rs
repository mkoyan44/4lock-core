//! Embedded bootstrap templates - compiled into the binary so the daemon is self-contained.
//!
//! Templates are loaded at compile time via `include_str!` and registered with the
//! TemplateRenderer. This allows the vappc daemon to run inside a VM where only
//! the binary is available (virtio-fs share contains no template files).

/// Cert templates
pub static CA_CERTIFICATE: &str = include_str!("templates/certs/10-ca-certificate.sh");
pub static API_CERTIFICATES: &str = include_str!("templates/certs/20-api-certificates.sh");

/// Containerd config
pub static CONTAINERD_CONFIG: &str = include_str!("templates/containerd/config.toml.j2");

/// Kubeconfig templates
pub static ADMIN_EXTERNAL_KUBECONFIG: &str =
    include_str!("templates/kubeconfig/admin.external.kubeconfig.j2");
pub static ADMIN_KUBECONFIG: &str = include_str!("templates/kubeconfig/admin.kubeconfig.j2");
pub static CONTROLLER_KUBECONFIG: &str =
    include_str!("templates/kubeconfig/controller.kubeconfig.j2");
pub static SCHEDULER_KUBECONFIG: &str = include_str!("templates/kubeconfig/scheduler.kubeconfig.j2");

/// Kubelet templates
pub static KUBELET_CONFIG: &str = include_str!("templates/kubelet/kubelet-config.yaml.j2");
pub static KUBELET_KUBECONFIG: &str = include_str!("templates/kubelet/kubelet.kubeconfig.j2");

/// Manifest templates
pub static CILIUM_YAML: &str = include_str!("templates/manifests/cilium.yaml.j2");
pub static COREDNS_YAML: &str = include_str!("templates/manifests/coredns.yaml.j2");
pub static RBAC_NODE_YAML: &str = include_str!("templates/manifests/rbac-node.yaml.j2");
pub static RUNTIME_CLASS_YAML: &str = include_str!("templates/manifests/runtime-class.yaml.j2");
pub static STORAGE_CLASS_YAML: &str = include_str!("templates/manifests/storage-class.yaml.j2");

/// All embedded templates as (name, content) pairs for registration with Tera.
pub const ALL_TEMPLATES: &[(&str, &str)] = &[
    ("certs/10-ca-certificate.sh", CA_CERTIFICATE),
    ("certs/20-api-certificates.sh", API_CERTIFICATES),
    ("containerd/config.toml.j2", CONTAINERD_CONFIG),
    ("kubeconfig/admin.external.kubeconfig.j2", ADMIN_EXTERNAL_KUBECONFIG),
    ("kubeconfig/admin.kubeconfig.j2", ADMIN_KUBECONFIG),
    ("kubeconfig/controller.kubeconfig.j2", CONTROLLER_KUBECONFIG),
    ("kubeconfig/scheduler.kubeconfig.j2", SCHEDULER_KUBECONFIG),
    ("kubelet/kubelet-config.yaml.j2", KUBELET_CONFIG),
    ("kubelet/kubelet.kubeconfig.j2", KUBELET_KUBECONFIG),
    ("manifests/cilium.yaml.j2", CILIUM_YAML),
    ("manifests/coredns.yaml.j2", COREDNS_YAML),
    ("manifests/rbac-node.yaml.j2", RBAC_NODE_YAML),
    ("manifests/runtime-class.yaml.j2", RUNTIME_CLASS_YAML),
    ("manifests/storage-class.yaml.j2", STORAGE_CLASS_YAML),
];
