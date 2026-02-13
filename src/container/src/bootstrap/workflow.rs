/// Generic workflow executor for container tasks.
///
/// Runs a sequence of ExecTasks inside a container with progress reporting.
/// Extracted from the K8s-specific ops.rs, generalized for any app lifecycle.
use crate::bootstrap::tasks::ContainerTask;
use crate::common::ContainerRuntime;
use crate::provisioner::ProvisionError;
use std::sync::Arc;

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

/// Execution context for container tasks — runs commands inside a target container via exec.
pub struct TaskExecutor {
    pub runtime: Arc<dyn ContainerRuntime>,
    pub container_id: String,
}

impl TaskExecutor {
    pub fn new(runtime: Arc<dyn ContainerRuntime>, container_id: String) -> Self {
        Self {
            runtime,
            container_id,
        }
    }

    /// Execute a single task
    pub async fn execute(&self, task: &ContainerTask) -> Result<TaskResult, ProvisionError> {
        match task {
            ContainerTask::Exec(exec_task) => {
                tracing::info!(
                    "[TaskExecutor] Executing task '{}' in container '{}'",
                    exec_task.name,
                    self.container_id,
                );
                let result = self
                    .runtime
                    .exec(&self.container_id, &exec_task.command)
                    .await
                    .map_err(|e| ProvisionError::Runtime(format!("Exec failed: {}", e)))?;

                let task_result = TaskResult {
                    exit_code: result.exit_code,
                    stdout: result.stdout,
                    stderr: result.stderr,
                };

                if task_result.success() {
                    tracing::info!(
                        "[TaskExecutor] Task '{}' completed successfully",
                        exec_task.name,
                    );
                } else {
                    tracing::error!(
                        "[TaskExecutor] Task '{}' failed (exit {}): {}",
                        exec_task.name,
                        task_result.exit_code,
                        task_result.stderr,
                    );
                }

                Ok(task_result)
            }
        }
    }
}

/// Execute a sequence of container tasks with progress tracking.
/// Fail-fast: stops on the first task failure.
pub async fn run_tasks<F>(
    tasks: &[ContainerTask],
    executor: &TaskExecutor,
    progress_start: u32,
    progress_end: u32,
    progress_fn: F,
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
        let result = executor.execute(task).await?;
        let task_duration = task_start.elapsed();

        if !result.success() {
            let last_line = result
                .stderr
                .lines()
                .last()
                .unwrap_or("No output available");
            tracing::warn!(
                "[TIMING] Task {} failed after {}ms",
                display_name,
                task_duration.as_millis()
            );
            return Err(ProvisionError::Runtime(format!(
                "Task '{}' failed (exit {}): {}",
                display_name, result.exit_code, last_line,
            )));
        }

        tracing::info!(
            "[TIMING] Task {} completed in {}ms",
            display_name,
            task_duration.as_millis()
        );

        let completion_progress = if index + 1 < tasks.len() {
            progress_start + span.saturating_mul((index + 1) as u32) / total_tasks.max(1)
        } else {
            progress_end
        };
        progress_fn(completion_progress, &format!("Completed {}", display_name));
    }

    Ok(())
}
