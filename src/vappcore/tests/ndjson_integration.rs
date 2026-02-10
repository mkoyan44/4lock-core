//! Integration test: daemon ↔ client NDJSON conversation over Unix socket.
//!
//! Spins up a mock intent loop + daemon on a temp Unix socket, then exercises
//! the client (VappCoreStream / send_command_streaming) against it.
//! No real containers — just verifies the wire protocol end-to-end.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use container::intent::{Endpoint, InstanceHandle, InstanceState, RuntimeIntent};
use container::progress::RuntimeStartProgress;
use tokio::sync::mpsc;
use vappcore::client::send_command_streaming;
use vappcore::protocol::{ErrorCategory, ResponseData, VappCoreCommand, WireMessage};
use vappcore::VappCoreStream;

/// Create a unique temp Unix socket path using PID + counter.
fn temp_socket_path() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    PathBuf::from(format!("/tmp/vappcore-test-{}-{}.sock", pid, id))
}

/// A mock intent loop that handles RuntimeIntent::Start by:
/// 1. Sending 3 progress messages
/// 2. Returning an InstanceHandle via callback
async fn mock_intent_loop(mut rx: mpsc::Receiver<RuntimeIntent>) {
    while let Some(intent) = rx.recv().await {
        match intent {
            RuntimeIntent::Start {
                spec,
                progress,
                callback,
            } => {
                // Send progress updates
                let _ = progress
                    .send(RuntimeStartProgress::new(
                        Some(spec.instance_id.clone()),
                        10,
                        "Pulling images...".into(),
                    ))
                    .await;
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                let _ = progress
                    .send(RuntimeStartProgress::new(
                        Some(spec.instance_id.clone()),
                        50,
                        "Starting etcd...".into(),
                    ))
                    .await;
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                let _ = progress
                    .send(RuntimeStartProgress::new(
                        Some(spec.instance_id.clone()),
                        90,
                        "Bootstrap complete".into(),
                    ))
                    .await;

                // Drop progress sender to signal no more progress
                drop(progress);

                // Return handle
                let handle = InstanceHandle {
                    instance_id: spec.instance_id.clone(),
                    endpoint: Endpoint::Socket(PathBuf::from("/tmp/mock.sock")),
                };
                let _ = callback.send(Ok(handle));
            }
            RuntimeIntent::Stop { .. } => {}
            RuntimeIntent::GetState { reply, .. } => {
                let _ = reply.send(InstanceState::Running).await;
            }
            RuntimeIntent::GetEndpoint { callback, .. } => {
                let _ = callback.send(Ok(Endpoint::Socket(PathBuf::from("/tmp/mock.sock"))));
            }
            RuntimeIntent::RunContainer { callback, .. } => {
                let _ = callback.send(Err("Not implemented in mock".into()));
            }
        }
    }
}

/// Build a minimal VappSpec for testing.
fn test_vapp_spec(instance_id: &str) -> container::intent::VappSpec {
    container::intent::VappSpec {
        instance_id: instance_id.into(),
        role: container::intent::InstanceRole::Device,
        cluster: container::intent::ClusterSpec {
            name: "test".into(),
            service_cidr: "10.96.0.0/12".into(),
            pod_cidr: "10.244.0.0/16".into(),
            dns_address: "10.96.0.10".into(),
            upstream_api: None,
        },
        network: container::intent::NetworkSpec {
            zt_network_id: "".into(),
            zt_token: "".into(),
            docker_proxy_ca_cert: None,
            docker_proxy_host: None,
            docker_proxy_port: None,
        },
        storage: vec![],
        resources: container::intent::ResourceSpec {
            memory_mb: 2048,
            cpu_cores: 2,
        },
        kubeconfig: None,
        app_name: None,
        app_type: None,
        app_config: None,
    }
}

/// Wait for a socket file to appear (up to 2s).
async fn wait_for_socket(path: &PathBuf) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }
    panic!("Daemon socket not created at {}", path.display());
}

// Must use multi_thread so the daemon tasks can run while the client does blocking I/O.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ndjson_ping_over_unix_socket() {
    let socket_path = temp_socket_path();
    let socket_str = socket_path.to_str().unwrap().to_string();

    let (intent_tx, intent_rx) = mpsc::channel(32);
    tokio::spawn(mock_intent_loop(intent_rx));

    let daemon_socket = socket_str.clone();
    tokio::spawn(async move {
        let _ = vappcore::daemon::run_daemon_server(&daemon_socket, intent_tx).await;
    });

    wait_for_socket(&socket_path).await;

    // Run blocking client I/O on a blocking thread
    let path = socket_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let stream = std::os::unix::net::UnixStream::connect(&path).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut wrapper = VappCoreStream::new(stream);
        wrapper.ping()
    })
    .await
    .unwrap();

    result.expect("Ping should succeed");
    let _ = std::fs::remove_file(&socket_path);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ndjson_get_state_over_unix_socket() {
    let socket_path = temp_socket_path();
    let socket_str = socket_path.to_str().unwrap().to_string();

    let (intent_tx, intent_rx) = mpsc::channel(32);
    tokio::spawn(mock_intent_loop(intent_rx));

    let daemon_socket = socket_str.clone();
    tokio::spawn(async move {
        let _ = vappcore::daemon::run_daemon_server(&daemon_socket, intent_tx).await;
    });

    wait_for_socket(&socket_path).await;

    let path = socket_path.clone();
    let msg = tokio::task::spawn_blocking(move || {
        let stream = std::os::unix::net::UnixStream::connect(&path).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut wrapper = VappCoreStream::new(stream);
        wrapper.send_command(VappCoreCommand::GetState {
            instance_id: "test-123".into(),
        })
    })
    .await
    .unwrap()
    .expect("GetState should succeed");

    match msg {
        WireMessage::Ok {
            data: ResponseData::State(s),
        } => assert_eq!(s, InstanceState::Running),
        other => panic!("Expected Ok/State(Running), got: {:?}", other),
    }

    let _ = std::fs::remove_file(&socket_path);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ndjson_streaming_start_with_progress() {
    let socket_path = temp_socket_path();
    let socket_str = socket_path.to_str().unwrap().to_string();

    let (intent_tx, intent_rx) = mpsc::channel(32);
    tokio::spawn(mock_intent_loop(intent_rx));

    let daemon_socket = socket_str.clone();
    tokio::spawn(async move {
        let _ = vappcore::daemon::run_daemon_server(&daemon_socket, intent_tx).await;
    });

    wait_for_socket(&socket_path).await;

    let spec = test_vapp_spec("vapp-stream-test");
    let path = socket_path.clone();
    let collected = Arc::new(Mutex::new(Vec::new()));
    let collected_clone = collected.clone();

    let result = tokio::task::spawn_blocking(move || {
        let mut stream = std::os::unix::net::UnixStream::connect(&path).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();

        send_command_streaming(
            &mut stream,
            VappCoreCommand::Start { spec },
            Some(&move |p| {
                collected_clone
                    .lock()
                    .unwrap()
                    .push((p.percentage, p.message.clone()));
            }),
        )
    })
    .await
    .unwrap();

    // Verify progress was received
    let progress = collected.lock().unwrap();
    assert!(
        progress.len() >= 2,
        "Expected at least 2 progress messages, got {}",
        progress.len()
    );
    assert_eq!(progress[0].0, 10);
    assert!(progress[0].1.contains("Pulling"));

    // Verify terminal response
    let msg = result.expect("Start should succeed");
    match msg {
        WireMessage::Ok {
            data: ResponseData::Handle(h),
        } => {
            assert_eq!(h.instance_id, "vapp-stream-test");
        }
        other => panic!("Expected Ok/Handle, got: {:?}", other),
    }

    let _ = std::fs::remove_file(&socket_path);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ndjson_error_response() {
    let socket_path = temp_socket_path();
    let socket_str = socket_path.to_str().unwrap().to_string();

    // Create intent channel but drop receiver immediately — daemon will get "Intent loop disconnected"
    let (intent_tx, _intent_rx) = mpsc::channel::<RuntimeIntent>(32);

    let daemon_socket = socket_str.clone();
    let daemon_intent_tx = intent_tx.clone();
    tokio::spawn(async move {
        let _ = vappcore::daemon::run_daemon_server(&daemon_socket, daemon_intent_tx).await;
    });

    // Drop both senders' receiver side so the daemon's send will fail
    drop(_intent_rx);
    drop(intent_tx);

    wait_for_socket(&socket_path).await;

    let path = socket_path.clone();
    let msg = tokio::task::spawn_blocking(move || {
        let stream = std::os::unix::net::UnixStream::connect(&path).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut wrapper = VappCoreStream::new(stream);
        wrapper.send_command(VappCoreCommand::GetState {
            instance_id: "nonexistent".into(),
        })
    })
    .await
    .unwrap()
    .expect("Should get a response even if intent loop is down");

    match msg {
        WireMessage::Error(e) => {
            assert_eq!(e.category, ErrorCategory::Internal);
            assert!(
                e.message.contains("Intent loop disconnected")
                    || e.message.contains("did not reply"),
                "Unexpected error: {}",
                e.message
            );
        }
        other => panic!("Expected Error, got: {:?}", other),
    }

    let _ = std::fs::remove_file(&socket_path);
}
