/// ContainerTask — unified task type for container operations
use super::exec_task::ExecTask;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum ContainerTask {
    Exec(ExecTask),
}

impl ContainerTask {
    pub fn display_name(&self) -> String {
        match self {
            ContainerTask::Exec(task) => task.display_name(),
        }
    }

    pub fn task_id(&self) -> String {
        match self {
            ContainerTask::Exec(task) => task.task_id(),
        }
    }

    pub fn get_timeout(&self) -> Duration {
        match self {
            ContainerTask::Exec(task) => task.get_timeout(),
        }
    }

    pub fn get_name(&self) -> String {
        self.display_name()
    }

    pub fn exec(task: ExecTask) -> Self {
        ContainerTask::Exec(task)
    }
}
