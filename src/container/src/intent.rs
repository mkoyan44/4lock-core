//! Intent types for the app runtime (4lock-core; no dependency on 4lock-agent runtime).
//!
//! RuntimeIntent is the internal message enum routed via mpsc channel from the daemon to the
//! intent loop / AppRuntime.

use crate::app_spec::{AppHandle, AppSpec, AppState, AppSummary};
use crate::progress::RuntimeStartProgress;
use tokio::sync::{mpsc, oneshot};

/// High-level intent — what the daemon/controller wants the runtime to do.
#[derive(Debug)]
pub enum RuntimeIntent {
    /// Start an app from an AppSpec. Streams progress, then returns AppHandle.
    StartApp {
        spec: AppSpec,
        progress: mpsc::Sender<RuntimeStartProgress>,
        callback: oneshot::Sender<Result<AppHandle, String>>,
    },
    /// Stop a running app.
    StopApp {
        app_id: String,
    },
    /// Query the state of an app.
    AppState {
        app_id: String,
        reply: oneshot::Sender<AppState>,
    },
    /// List all running apps.
    ListApps {
        reply: oneshot::Sender<Vec<AppSummary>>,
    },
}
