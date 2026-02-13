/// Container bootstrap — tasks, templates, intent loop, and image/volume management.
pub mod config;
pub mod embedded_templates;
pub mod image_manager;
pub mod intent_loop;
pub mod tasks;
pub mod template_renderer;
pub mod volume_manager;
pub mod workflow;

pub use config::ContainerProvisionerConfig;
pub use intent_loop::{check_system_requirements, run_intent_command_loop};
pub use tasks::{ContainerTask, ExecTask};
pub use template_renderer::TemplateRenderer;
pub use workflow::{run_tasks, TaskExecutor, TaskResult};
