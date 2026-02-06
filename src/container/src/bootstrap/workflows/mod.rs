#[cfg(target_os = "linux")]
mod infra;
#[cfg(target_os = "linux")]
pub mod ops;

#[cfg(target_os = "linux")]
pub use infra::{plan_infra_ops, run_infra_ops, wait_for_node_ready, PlannedOperation};
#[cfg(target_os = "linux")]
pub use ops::{run_ops, TaskExecutor, TaskResult};
