/// Infrastructure workflow - plans and executes K8s infrastructure deployment
/// Uses task-based approach similar to vm-bootstrap
use crate::bootstrap::image_manager::ImageManager;
use crate::bootstrap::tasks::{ContainerTask, KubectlTask};
use crate::bootstrap::template_renderer::TemplateRenderer;
use crate::bootstrap::utility_runner::{UtilityContainerConfig, UtilityRunner};
use crate::bootstrap::workflows::ops::{run_ops, TaskExecutor};
use crate::intent::ClusterSpec;
use crate::provisioner::ProvisionError;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tera::Context;

/// Planned operation with metadata
pub struct PlannedOperation {
    pub task: ContainerTask,
    pub metadata: Option<Value>,
}

/// Manifest specification for ordering
struct ManifestSpec {
    name: &'static str,
    template: &'static str,
    wait_after: bool,
    description: &'static str,
}

/// Ordered list of infrastructure manifests
const INFRA_MANIFESTS: &[ManifestSpec] = &[
    ManifestSpec {
        name: "rbac-node",
        template: "manifests/rbac-node.yaml.j2",
        wait_after: false,
        description: "Node RBAC authorization",
    },
    ManifestSpec {
        name: "runtime-class",
        template: "manifests/runtime-class.yaml.j2",
        wait_after: false,
        description: "Runtime class for containers",
    },
    ManifestSpec {
        name: "storage-class",
        template: "manifests/storage-class.yaml.j2",
        wait_after: false,
        description: "Storage class for PVs",
    },
    ManifestSpec {
        name: "cilium",
        template: "manifests/cilium.yaml.j2",
        wait_after: true,
        description: "Cilium CNI network plugin",
    },
    ManifestSpec {
        name: "coredns",
        template: "manifests/coredns.yaml.j2",
        wait_after: false,
        description: "CoreDNS cluster DNS",
    },
];

/// Plan infrastructure operations (returns tasks to execute)
pub fn plan_infra_ops(
    renderer: &TemplateRenderer,
    cluster: &ClusterSpec,
    instance_id: &str,
) -> Result<Vec<PlannedOperation>, ProvisionError> {
    tracing::info!(
        "[InfraWorkflow] Planning infrastructure operations for {}",
        instance_id
    );

    let mut ops = Vec::new();
    let available_templates = renderer.list_templates();

    // Build template context
    let context = build_cluster_context(cluster, instance_id);

    for manifest in INFRA_MANIFESTS {
        // Check if template exists
        if !available_templates.iter().any(|t| t == manifest.template) {
            tracing::warn!(
                "[InfraWorkflow] Template {} not found, skipping {}",
                manifest.template,
                manifest.name
            );
            continue;
        }

        // Render template
        let content = renderer.render_with_context(manifest.template, &context)?;

        tracing::debug!(
            "[InfraWorkflow] Rendered {} template: {} bytes",
            manifest.name,
            content.len()
        );

        // Create kubectl apply task
        let task = ContainerTask::kubectl(KubectlTask::apply(manifest.name, content.clone()));

        // Log first 200 chars for debugging
        if content.len() < 500 {
            tracing::debug!(
                "[InfraWorkflow] Manifest content for {}: {}",
                manifest.name,
                content
            );
        }

        let metadata = json!({
            "type": "kubectl_apply",
            "name": manifest.name,
            "template": manifest.template,
            "wait_after": manifest.wait_after,
            "description": manifest.description,
        });

        ops.push(PlannedOperation {
            task,
            metadata: Some(metadata),
        });

        tracing::debug!(
            "[InfraWorkflow] Planned: {} ({})",
            manifest.name,
            manifest.description
        );
    }

    tracing::info!(
        "[InfraWorkflow] Planned {} infrastructure operations",
        ops.len()
    );

    Ok(ops)
}

/// Execute infrastructure operations
pub async fn run_infra_ops<F>(
    ops: &[PlannedOperation],
    executor: &TaskExecutor<'_>,
    progress_start: u32,
    progress_end: u32,
    progress_fn: F,
) -> Result<(), ProvisionError>
where
    F: Fn(u32, &str),
{
    if ops.is_empty() {
        tracing::info!("[InfraWorkflow] No infrastructure operations to execute");
        return Ok(());
    }

    tracing::info!(
        "[InfraWorkflow] Executing {} infrastructure operations",
        ops.len()
    );

    // Extract tasks from planned operations
    let tasks: Vec<ContainerTask> = ops.iter().map(|op| op.task.clone()).collect();

    // Run all tasks
    run_ops(
        &tasks,
        executor,
        progress_start,
        progress_end,
        progress_fn,
        "Infrastructure",
    )
    .await
}

/// Wait for node to become Ready after CNI deployment
pub async fn wait_for_node_ready(
    instance_id: &str,
    utility_runner: &UtilityRunner,
    image_manager: &ImageManager,
    kubeconfig_path: &PathBuf,
    certs_path: &PathBuf,
    timeout: Duration,
) -> Result<(), ProvisionError> {
    tracing::info!(
        "[InfraWorkflow] Waiting for node {} to become Ready",
        instance_id
    );

    let start = std::time::Instant::now();
    let check_interval = Duration::from_secs(5);

    loop {
        if start.elapsed() > timeout {
            return Err(ProvisionError::Runtime(format!(
                "Timeout waiting for node {} to become Ready after {:?}",
                instance_id, timeout
            )));
        }

        // Run kubectl to check node status
        let mut volumes = HashMap::new();
        volumes.insert(
            kubeconfig_path.to_string_lossy().to_string(),
            "/kubeconfig".to_string(),
        );
        volumes.insert(
            certs_path.to_string_lossy().to_string(),
            "/certs".to_string(),
        );

        let config = UtilityContainerConfig {
            name: format!("node-check-{}", start.elapsed().as_secs()),
            image: "bitnami/kubectl:latest".to_string(),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "kubectl --kubeconfig /kubeconfig/config get nodes -o jsonpath='{.items[0].status.conditions[?(@.type==\"Ready\")].status}'".to_string(),
            ],
            volumes,
            env: HashMap::new(),
            network_mode: "host".to_string(),
        };

        match utility_runner.run(image_manager, config).await {
            Ok(output) => {
                let status = output.stdout.trim().trim_matches('\'');
                // Log at info level to see what's happening
                if status.is_empty() {
                    tracing::info!(
                        "[InfraWorkflow] Node {} check: stdout empty (exit_code={}, stderr_len={}) - API server may not be ready or no nodes registered yet",
                        instance_id,
                        output.exit_code,
                        output.stderr.len()
                    );
                    if !output.stderr.is_empty() {
                        tracing::info!("[InfraWorkflow] Node {} check stderr: {}", instance_id, output.stderr);
                    }
                } else {
                    tracing::info!(
                        "[InfraWorkflow] Node {} Ready status: '{}' (exit_code={})",
                        instance_id,
                        status,
                        output.exit_code
                    );
                }

                if status == "True" {
                    tracing::info!(
                        "[InfraWorkflow] Node {} is Ready (took {:?})",
                        instance_id,
                        start.elapsed()
                    );
                    return Ok(());
                }
            }
            Err(e) => {
                tracing::warn!("[InfraWorkflow] Node check failed (retrying): {}", e);
            }
        }

        tokio::time::sleep(check_interval).await;
    }
}

/// Build Tera context from cluster configuration
fn build_cluster_context(cluster: &ClusterSpec, instance_id: &str) -> Context {
    let mut context = Context::new();
    context.insert("cluster_name", &cluster.name);
    context.insert("pod_cidr", &cluster.pod_cidr);
    context.insert("service_cidr", &cluster.service_cidr);
    context.insert("dns_address", &cluster.dns_address);
    context.insert("cluster_domain", "cluster.local");
    context.insert("cilium_version", "v1.15.0");
    context.insert("instance_id", instance_id);
    context.insert("node_name", instance_id);
    context
}
