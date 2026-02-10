/// Kubernetes component definitions for container-based provisioning
///
/// Defines the Kubernetes control plane components (etcd, apiserver, controller-manager, scheduler)
/// that will run as separate containers using official Kubernetes images.
use crate::intent::{ClusterSpec, NetworkSpec};

/// Kubernetes component configuration
pub struct K8sComponent {
    /// Suffix for container name (e.g., "etcd" -> "vapp-{uuid}-etcd")
    pub suffix: &'static str,
    /// Container image to use
    pub image: &'static str,
    /// Startup order (lower = earlier)
    pub order: isize,
    /// Command/entrypoint arguments for the container
    pub args: Vec<String>,
    /// Ports to expose
    pub ports: Vec<u16>,
    /// Container names this component depends on (must be started first)
    pub depends_on: Vec<&'static str>,
    /// Whether this container needs privileged mode (for ZeroTier TUN device)
    pub privileged: bool,
    /// Network namespace to join (if None, creates new namespace)
    pub network_namespace: Option<&'static str>,
}

/// Get Kubernetes components configuration for a cluster
///
/// Returns components in the correct startup order:
/// 1. etcd (datastore)
/// 2. kube-apiserver (API server)
/// 3. kube-controller-manager (controllers)
/// 4. kube-scheduler (scheduler)
///
/// All containers use host network mode for communication via 127.0.0.1.
pub fn get_k8s_components(cluster: &ClusterSpec) -> Vec<K8sComponent> {
    let service_cidr = cluster.service_cidr.clone();
    let _pod_cidr = cluster.pod_cidr.clone();
    let _cluster_name = cluster.name.clone();

    vec![
        K8sComponent {
            suffix: "etcd",
            image: "registry.k8s.io/etcd:v3.5.9",
            order: 0,
            args: vec![
                "/usr/local/bin/etcd".to_string(),
                "--data-dir=/var/lib/etcd".to_string(),
                "--name=etcd".to_string(),
                "--listen-client-urls=http://0.0.0.0:2379".to_string(),
                "--advertise-client-urls=http://localhost:2379".to_string(),
                "--listen-peer-urls=http://0.0.0.0:2380".to_string(),
                "--initial-advertise-peer-urls=http://localhost:2380".to_string(),
                "--initial-cluster=etcd=http://localhost:2380".to_string(),
                "--initial-cluster-token=etcd-cluster-1".to_string(),
                "--initial-cluster-state=new".to_string(),
            ],
            ports: vec![2379, 2380],
            depends_on: vec![],
            privileged: false,
            network_namespace: None,
        },
        K8sComponent {
            suffix: "apiserver",
            // Using Alpine Linux base image - we'll inject kube-apiserver binary during provisioning
            // The official registry.k8s.io images only contain go-runner without the actual binary
            image: "alpine:latest",
            order: 1,
            args: vec![
                "/usr/local/bin/kube-apiserver".to_string(),
                format!("--etcd-servers=http://127.0.0.1:2379"),
                format!("--service-cluster-ip-range={}", service_cidr),
                "--bind-address=0.0.0.0".to_string(),
                "--advertise-address=127.0.0.1".to_string(),
                "--allow-privileged=true".to_string(),
                "--authorization-mode=AlwaysAllow".to_string(), // No RBAC for testing
                "--anonymous-auth=true".to_string(),
                "--secure-port=6443".to_string(),
                "--insecure-port=8080".to_string(), // For testing without certs
                "--insecure-bind-address=0.0.0.0".to_string(),
            ],
            ports: vec![6443, 8080],
            depends_on: vec!["etcd"],
            privileged: false,
            network_namespace: None,
        },
        K8sComponent {
            suffix: "controller-manager",
            // Using Alpine Linux base image - we'll inject kube-controller-manager binary during provisioning
            // The official registry.k8s.io images only contain go-runner without the actual binary
            image: "alpine:latest",
            order: 2,
            args: vec![
                "/usr/local/bin/kube-controller-manager".to_string(),
                "--bind-address=127.0.0.1".to_string(),
                "--cluster-name=kubernetes".to_string(),
                format!("--master=http://127.0.0.1:8080"), // Insecure apiserver connection
                "--leader-elect=true".to_string(),
            ],
            ports: vec![],
            depends_on: vec!["apiserver"],
            privileged: false,
            network_namespace: None,
        },
        K8sComponent {
            suffix: "scheduler",
            // Using Alpine Linux base image - we'll inject kube-scheduler binary during provisioning
            // The official registry.k8s.io images only contain go-runner without the actual binary
            image: "alpine:latest",
            order: 3,
            args: vec![
                "/usr/local/bin/kube-scheduler".to_string(),
                "--bind-address=127.0.0.1".to_string(),
                format!("--master=http://127.0.0.1:8080"), // Insecure apiserver connection
                "--leader-elect=true".to_string(),
            ],
            ports: vec![],
            depends_on: vec!["apiserver"],
            privileged: false,
            network_namespace: None,
        },
    ]
}

/// Get K8s components with TLS certificates (secure mode)
///
/// Returns components configured with TLS certificates for secure communication.
/// Certificates should be mounted at /certs/ca, /certs/kubernetes, and /certs/etcd.
///
/// All containers share a network namespace and communicate via localhost (127.0.0.1).
/// This is enabled by the shared network namespace architecture with pasta providing
/// internet connectivity.
pub fn get_k8s_components_secure(
    cluster: &ClusterSpec,
    _network: &NetworkSpec,
    _zt_ip: Option<String>,
    _instance_id: &str, // Used in startup script template (created in provisioner)
) -> Vec<K8sComponent> {
    let service_cidr = cluster.service_cidr.clone();

    vec![
        K8sComponent {
            suffix: "etcd",
            image: "registry.k8s.io/etcd:v3.5.9",
            order: 0,
            args: vec![
                "/usr/local/bin/etcd".to_string(),
                "--data-dir=/var/lib/etcd".to_string(),
                "--name=etcd".to_string(),
                // TLS configuration for secure mode
                "--cert-file=/certs/etcd/etcd-server.crt".to_string(),
                "--key-file=/certs/etcd/etcd-server.key".to_string(),
                "--trusted-ca-file=/certs/ca/ca.pem".to_string(),
                "--client-cert-auth=true".to_string(),
                "--peer-cert-file=/certs/etcd/etcd-peer.crt".to_string(),
                "--peer-key-file=/certs/etcd/etcd-peer.key".to_string(),
                "--peer-trusted-ca-file=/certs/ca/ca.pem".to_string(),
                "--peer-client-cert-auth=true".to_string(),
                "--listen-client-urls=https://0.0.0.0:2379".to_string(),
                "--advertise-client-urls=https://127.0.0.1:2379".to_string(),
                "--listen-peer-urls=https://0.0.0.0:2380".to_string(),
                "--initial-advertise-peer-urls=https://127.0.0.1:2380".to_string(),
                "--initial-cluster=etcd=https://127.0.0.1:2380".to_string(),
                "--initial-cluster-token=etcd-cluster-1".to_string(),
                "--initial-cluster-state=new".to_string(),
            ],
            ports: vec![2379, 2380],
            depends_on: vec![],
            privileged: false,
            network_namespace: None, // Joins shared namespace configured by provisioner
        },
        K8sComponent {
            suffix: "apiserver",
            // Using Alpine Linux base image - we'll inject kube-apiserver binary during provisioning
            // The official registry.k8s.io images only contain go-runner without the actual binary
            image: "alpine:latest",
            order: 1,
            args: vec![
                "/usr/local/bin/kube-apiserver".to_string(),
                // All containers share the same network namespace
                // apiserver reaches etcd via localhost
                "--etcd-servers=https://127.0.0.1:2379".to_string(),
                "--etcd-cafile=/certs/ca/ca.pem".to_string(),
                "--etcd-certfile=/certs/etcd/apiserver-etcd-client.crt".to_string(),
                "--etcd-keyfile=/certs/etcd/apiserver-etcd-client.key".to_string(),
                "--tls-cert-file=/certs/kubernetes/kube-apiserver.crt".to_string(),
                "--tls-private-key-file=/certs/kubernetes/kube-apiserver.key".to_string(),
                "--client-ca-file=/certs/ca/ca.pem".to_string(),
                "--service-account-key-file=/certs/kubernetes/service-account.pub".to_string(),
                "--service-account-signing-key-file=/certs/kubernetes/service-account.key"
                    .to_string(),
                "--service-account-issuer=https://kubernetes.default.svc".to_string(),
                format!("--service-cluster-ip-range={}", service_cidr),
                "--bind-address=0.0.0.0".to_string(),
                "--advertise-address=127.0.0.1".to_string(),
                "--allow-privileged=true".to_string(),
                "--authorization-mode=Node,RBAC".to_string(),
                "--secure-port=6443".to_string(),
                "--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname".to_string(),
            ],
            ports: vec![6443],
            depends_on: vec!["etcd"],
            privileged: false,
            network_namespace: None, // Joins shared namespace configured by provisioner
        },
        K8sComponent {
            suffix: "controller-manager",
            // Using Alpine Linux base image - we'll inject kube-controller-manager binary during provisioning
            // The official registry.k8s.io images only contain go-runner without the actual binary
            image: "alpine:latest",
            order: 2,
            args: vec![
                "/usr/local/bin/kube-controller-manager".to_string(),
                "--bind-address=127.0.0.1".to_string(),
                "--cluster-name=kubernetes".to_string(),
                "--kubeconfig=/certs/kubernetes/controller.kubeconfig".to_string(),
                "--leader-elect=true".to_string(),
                "--use-service-account-credentials=true".to_string(),
                "--controllers=*,bootstrapsigner,tokencleaner".to_string(),
            ],
            ports: vec![],
            depends_on: vec!["apiserver"],
            privileged: false,
            network_namespace: None, // Joins shared namespace configured by provisioner
        },
        K8sComponent {
            suffix: "scheduler",
            // Using Alpine Linux base image - we'll inject kube-scheduler binary during provisioning
            // The official registry.k8s.io images only contain go-runner without the actual binary
            image: "alpine:latest",
            order: 3,
            args: vec![
                "/usr/local/bin/kube-scheduler".to_string(),
                "--bind-address=127.0.0.1".to_string(),
                "--kubeconfig=/certs/kubernetes/scheduler.kubeconfig".to_string(),
                "--leader-elect=true".to_string(),
            ],
            ports: vec![],
            depends_on: vec!["apiserver"],
            privileged: false,
            network_namespace: None, // Joins shared namespace configured by provisioner
        },
        // Kubelet - node agent that registers with API server and runs pods via host containerd
        // Uses host's containerd socket (requires containerd installed on host)
        K8sComponent {
            suffix: "kubelet",
            // Using rancher/hyperkube - public image with kubelet binary pre-installed
            // registry.k8s.io/kubelet doesn't exist (empty repository)
            // rancher/hyperkube is a public all-in-one Kubernetes binary image
            image: "rancher/hyperkube:v1.27.16-rancher1",
            order: 4, // After scheduler
            // Args will be set by provisioner to execute kubelet with proper arguments
            args: vec!["/bin/sh".to_string(), "/start-kubelet.sh".to_string()],
            ports: vec![10250, 10248],     // kubelet API, healthz
            depends_on: vec!["apiserver"], // Kubelet depends on apiserver; uses vapp CRI socket
            privileged: true,              // Required for CAP_SYS_ADMIN (bind-mount operations for volume management)
            network_namespace: None,       // Joins shared namespace configured by provisioner
        },
    ]
}
