//! Integration tests for K8s component definitions.

use container::{get_k8s_components, ClusterSpec};

fn test_cluster() -> ClusterSpec {
    ClusterSpec {
        name: "test-cluster".to_string(),
        service_cidr: "10.96.0.0/12".to_string(),
        pod_cidr: "10.244.0.0/16".to_string(),
        dns_address: "10.96.0.10".to_string(),
        upstream_api: None,
    }
}

#[test]
fn test_get_k8s_components() {
    let cluster = test_cluster();
    let components = get_k8s_components(&cluster);

    assert_eq!(components.len(), 4);
    assert_eq!(components[0].suffix, "etcd");
    assert_eq!(components[1].suffix, "apiserver");
    assert_eq!(components[2].suffix, "controller-manager");
    assert_eq!(components[3].suffix, "scheduler");
}

#[test]
fn test_component_ordering() {
    let cluster = test_cluster();
    let components = get_k8s_components(&cluster);

    assert_eq!(components[0].order, 0); // etcd
    assert_eq!(components[1].order, 1); // apiserver
    assert_eq!(components[2].order, 2); // controller-manager
    assert_eq!(components[3].order, 3); // scheduler
}

#[test]
fn test_component_dependencies() {
    let cluster = test_cluster();
    let components = get_k8s_components(&cluster);

    assert!(components[0].depends_on.is_empty());

    assert_eq!(components[1].depends_on, vec!["etcd"]);

    assert_eq!(components[2].depends_on, vec!["apiserver"]);
    assert_eq!(components[3].depends_on, vec!["apiserver"]);
}
