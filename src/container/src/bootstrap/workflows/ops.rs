/// Operations executor for container tasks (similar to vm-bootstrap/workflows/ops.rs)
use crate::bootstrap::image_manager::ImageManager;
use crate::bootstrap::tasks::{ContainerTask, KubectlAction};
use crate::bootstrap::utility_runner::{UtilityContainerConfig, UtilityRunner};
use crate::provisioner::ProvisionError;
use std::collections::HashMap;
use std::path::PathBuf;

/// Result of task execution
pub struct TaskResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl TaskResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Execution context for container tasks
pub struct TaskExecutor<'a> {
    utility_runner: &'a UtilityRunner,
    image_manager: &'a ImageManager,
    kubeconfig_path: PathBuf,
    certs_path: PathBuf,
    work_dir: PathBuf,
}

impl<'a> TaskExecutor<'a> {
    pub fn new(
        utility_runner: &'a UtilityRunner,
        image_manager: &'a ImageManager,
        kubeconfig_path: PathBuf,
        certs_path: PathBuf,
        work_dir: PathBuf,
    ) -> Self {
        Self {
            utility_runner,
            image_manager,
            kubeconfig_path,
            certs_path,
            work_dir,
        }
    }

    /// Execute a single task
    pub async fn execute(&self, task: &ContainerTask) -> Result<TaskResult, ProvisionError> {
        match task {
            ContainerTask::Kubectl(kubectl_task) => self.execute_kubectl(kubectl_task).await,
        }
    }

    /// Execute kubectl task
    async fn execute_kubectl(
        &self,
        task: &crate::bootstrap::tasks::KubectlTask,
    ) -> Result<TaskResult, ProvisionError> {
        tracing::info!(
            "[TaskExecutor] Executing {}: {}",
            task.action_str(),
            task.name
        );

        // Create temp directory for manifest file
        let manifest_dir = self.work_dir.join(format!("kubectl-{}", uuid_simple()));
        std::fs::create_dir_all(&manifest_dir).map_err(ProvisionError::Io)?;
        let manifest_file = manifest_dir.join("manifest.yaml");

        tracing::debug!(
            "[TaskExecutor] Writing manifest for {} ({} bytes) to {:?}",
            task.name,
            task.manifest_content.len(),
            manifest_file
        );

        std::fs::write(&manifest_file, &task.manifest_content).map_err(ProvisionError::Io)?;

        // Verify file was written
        match std::fs::metadata(&manifest_file) {
            Ok(meta) => tracing::debug!(
                "[TaskExecutor] Manifest file created: {:?}, size: {} bytes",
                manifest_file,
                meta.len()
            ),
            Err(e) => tracing::error!(
                "[TaskExecutor] Failed to verify manifest file {:?}: {}",
                manifest_file,
                e
            ),
        }

        // Build volumes
        let mut volumes = HashMap::new();
        volumes.insert(
            self.kubeconfig_path.to_string_lossy().to_string(),
            "/kubeconfig".to_string(),
        );
        volumes.insert(
            self.certs_path.to_string_lossy().to_string(),
            "/certs".to_string(),
        );
        volumes.insert(
            manifest_dir.to_string_lossy().to_string(),
            "/manifests".to_string(),
        );

        // Build kubectl command
        let action_args = match task.action {
            KubectlAction::Apply => "apply -f /manifests/manifest.yaml",
            KubectlAction::Delete => "delete --ignore-not-found=true -f /manifests/manifest.yaml",
        };

        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("kubectl --kubeconfig /kubeconfig/config {}", action_args),
        ];

        // Run kubectl container
        let config = UtilityContainerConfig {
            name: format!("kubectl-{}", task.name.replace('/', "-").replace(' ', "-")),
            image: "bitnami/kubectl:latest".to_string(),
            command,
            volumes,
            env: HashMap::new(),
            network_mode: "host".to_string(),
        };

        let output = self.utility_runner.run(self.image_manager, config).await?;

        // Cleanup temp directory
        let _ = std::fs::remove_dir_all(&manifest_dir);

        let result = TaskResult {
            exit_code: output.exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
        };

        if !result.success() {
            tracing::error!(
                "[TaskExecutor] {} failed with exit code {}: {}",
                task.display_name(),
                result.exit_code,
                result.stderr
            );
        } else {
            tracing::info!(
                "[TaskExecutor] {} completed successfully",
                task.display_name()
            );
        }

        Ok(result)
    }
}

/// Execute a sequence of container tasks with progress tracking
pub async fn run_ops<F>(
    tasks: &[ContainerTask],
    executor: &TaskExecutor<'_>,
    progress_start: u32,
    progress_end: u32,
    progress_fn: F,
    failure_context: &str,
) -> Result<(), ProvisionError>
where
    F: Fn(u32, &str),
{
    if tasks.is_empty() {
        return Ok(());
    }

    let total_tasks = tasks.len() as u32;
    let span = progress_end.saturating_sub(progress_start);

    for (index, task) in tasks.iter().enumerate() {
        let progress = progress_start + span.saturating_mul(index as u32) / total_tasks.max(1);
        let display_name = task.display_name();

        progress_fn(progress, &format!("Executing {}", display_name));

        let task_start = std::time::Instant::now();
        let result: TaskResult = executor.execute(task).await?;
        let task_duration = task_start.elapsed();

        if !result.success() {
            let last_line = result
                .stderr
                .lines()
                .last()
                .unwrap_or("No output available");
            let error_msg = format!(
                "{} operation {} failed with exit code {}: {}",
                failure_context, display_name, result.exit_code, last_line,
            );
            tracing::warn!(
                "[TIMING] Task {} failed after {}ms",
                display_name,
                task_duration.as_millis()
            );
            return Err(ProvisionError::Runtime(error_msg));
        }

        tracing::info!(
            "[TIMING] Task {} completed in {}ms",
            display_name,
            task_duration.as_millis()
        );

        // Emit completion progress
        let completion_progress = if index + 1 < tasks.len() {
            progress_start + span.saturating_mul((index + 1) as u32) / total_tasks.max(1)
        } else {
            progress_end
        };
        progress_fn(completion_progress, &format!("Completed {}", display_name));
    }

    Ok(())
}

/// Simple UUID generator
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}{:x}", duration.as_secs(), duration.subsec_nanos())
}
