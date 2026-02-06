/// Container bootstrap - implements RuntimeProvisioner for containers
///
/// This module provides the container-specific bootstrap implementation,
/// handling images, volumes, and container lifecycle.
pub mod config;
pub mod image_manager;
pub mod intent_loop;
pub mod k8s_components;
pub mod provisioner;
pub mod tasks;
pub mod template_renderer;
#[cfg(target_os = "linux")]
pub mod utility_runner;
pub mod volume_manager;
pub mod workflow;
pub mod workflows;

pub use config::ContainerProvisionerConfig;
pub use intent_loop::{check_system_requirements, run_intent_command_loop};
pub use k8s_components::{get_k8s_components, get_k8s_components_secure, K8sComponent};
pub use provisioner::ContainerProvisioner;
pub use tasks::{ContainerTask, KubectlAction, KubectlTask};
pub use template_renderer::TemplateRenderer;
#[cfg(target_os = "linux")]
pub use utility_runner::{UtilityContainerConfig, UtilityContainerOutput, UtilityRunner};
#[cfg(target_os = "linux")]
pub use workflows::{
    plan_infra_ops, run_infra_ops, run_ops, wait_for_node_ready, PlannedOperation, TaskExecutor,
    TaskResult,
};
