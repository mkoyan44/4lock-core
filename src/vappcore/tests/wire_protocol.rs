//! Tests for the NDJSON wire protocol: WireMessage, WireError, NDJSON transport.
//!
//! All tests are unit tests (no daemon required).

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use vappcore::protocol::{
    ErrorCategory, ResponseData, VappCoreCommand, WireError, WireMessage,
};
use vappcore::client::{read_ndjson_line, send_command_streaming, write_ndjson};
use container::app_spec::{AppHandle, AppState, AppSummary};
use container::provisioner::ProvisionError;

// ---------------------------------------------------------------------------
// ErrorCategory display
// ---------------------------------------------------------------------------

#[test]
fn error_category_display() {
    assert_eq!(format!("{}", ErrorCategory::Config), "Config");
    assert_eq!(format!("{}", ErrorCategory::Runtime), "Runtime");
    assert_eq!(format!("{}", ErrorCategory::Network), "Network");
    assert_eq!(format!("{}", ErrorCategory::Io), "IO");
    assert_eq!(format!("{}", ErrorCategory::Internal), "Internal");
    assert_eq!(format!("{}", ErrorCategory::Timeout), "Timeout");
}

// ---------------------------------------------------------------------------
// WireError serialization
// ---------------------------------------------------------------------------

#[test]
fn wire_error_roundtrip() {
    let err = WireError {
        category: ErrorCategory::Network,
        message: "Failed to pull image".to_string(),
        phase: Some("image-pull".to_string()),
        is_retryable: true,
    };

    let json = serde_json::to_string(&err).unwrap();
    assert!(json.contains("Network"));
    assert!(json.contains("pull image"));
    assert!(json.contains("image-pull"));

    let back: WireError = serde_json::from_str(&json).unwrap();
    assert_eq!(back.category, ErrorCategory::Network);
    assert_eq!(back.message, "Failed to pull image");
    assert_eq!(back.phase, Some("image-pull".to_string()));
    assert!(back.is_retryable);
}

#[test]
fn wire_error_display_with_phase() {
    let err = WireError {
        category: ErrorCategory::Runtime,
        message: "container crashed".to_string(),
        phase: Some("setup".to_string()),
        is_retryable: true,
    };
    assert_eq!(format!("{}", err), "[setup] Runtime: container crashed");
}

#[test]
fn wire_error_display_without_phase() {
    let err = WireError {
        category: ErrorCategory::Config,
        message: "invalid spec".to_string(),
        phase: None,
        is_retryable: false,
    };
    assert_eq!(format!("{}", err), "Config: invalid spec");
}

#[test]
fn wire_error_from_provision_error() {
    let cases: Vec<(ProvisionError, ErrorCategory, bool)> = vec![
        (ProvisionError::Config("bad".into()), ErrorCategory::Config, false),
        (ProvisionError::Runtime("fail".into()), ErrorCategory::Runtime, true),
        (ProvisionError::Image("pull".into()), ErrorCategory::Image, true),
        (ProvisionError::Volume("disk".into()), ErrorCategory::Volume, false),
        (ProvisionError::Bundle("unpack".into()), ErrorCategory::Bootstrap, false),
        (ProvisionError::Network("dns".into()), ErrorCategory::Network, true),
        (ProvisionError::Bootstrap("script".into()), ErrorCategory::Bootstrap, false),
    ];

    for (prov_err, expected_cat, expected_retryable) in cases {
        let wire: WireError = prov_err.into();
        assert_eq!(wire.category, expected_cat, "category mismatch for {:?}", expected_cat);
        assert_eq!(wire.is_retryable, expected_retryable, "retryable mismatch for {:?}", expected_cat);
    }
}

#[test]
fn wire_error_from_provision_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let prov_err = ProvisionError::Io(io_err);
    let wire: WireError = prov_err.into();
    assert_eq!(wire.category, ErrorCategory::Io);
    assert!(wire.is_retryable);
    assert!(wire.message.contains("file not found"));
}

#[test]
fn wire_error_with_phase() {
    let err = WireError::internal("bug".into()).with_phase("bootstrap");
    assert_eq!(err.phase, Some("bootstrap".to_string()));
    assert_eq!(err.category, ErrorCategory::Internal);
}

// ---------------------------------------------------------------------------
// WireMessage serialization
// ---------------------------------------------------------------------------

#[test]
fn wire_message_ok_unit_roundtrip() {
    let msg = WireMessage::ok_unit();
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"msg\":\"Ok\""));
    let back: WireMessage = serde_json::from_str(&json).unwrap();
    assert!(back.is_terminal());
    match back {
        WireMessage::Ok { data: ResponseData::Unit } => {}
        other => panic!("Expected Ok/Unit, got: {:?}", other),
    }
}

#[test]
fn wire_message_ok_app_handle_roundtrip() {
    let handle = AppHandle {
        app_id: "web-1".to_string(),
        name: "my-web-app".to_string(),
    };
    let msg = WireMessage::ok_app_handle(handle);
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("web-1"));
    assert!(json.contains("my-web-app"));

    let back: WireMessage = serde_json::from_str(&json).unwrap();
    match back {
        WireMessage::Ok {
            data: ResponseData::AppHandle(h),
        } => {
            assert_eq!(h.app_id, "web-1");
            assert_eq!(h.name, "my-web-app");
        }
        other => panic!("Expected Ok/AppHandle, got: {:?}", other),
    }
}

#[test]
fn wire_message_ok_app_state_roundtrip() {
    let msg = WireMessage::ok_app_state(AppState::Running);
    let json = serde_json::to_string(&msg).unwrap();
    let back: WireMessage = serde_json::from_str(&json).unwrap();
    match back {
        WireMessage::Ok {
            data: ResponseData::AppState(s),
        } => assert_eq!(s, AppState::Running),
        other => panic!("Expected Ok/AppState, got: {:?}", other),
    }
}

#[test]
fn wire_message_ok_app_state_failed_roundtrip() {
    let msg = WireMessage::ok_app_state(AppState::Failed { reason: "OOM".to_string() });
    let json = serde_json::to_string(&msg).unwrap();
    let back: WireMessage = serde_json::from_str(&json).unwrap();
    match back {
        WireMessage::Ok {
            data: ResponseData::AppState(AppState::Failed { reason }),
        } => assert_eq!(reason, "OOM"),
        other => panic!("Expected Ok/AppState(Failed), got: {:?}", other),
    }
}

#[test]
fn wire_message_ok_app_list_roundtrip() {
    let apps = vec![
        AppSummary {
            app_id: "web-1".to_string(),
            name: "nginx".to_string(),
            state: AppState::Running,
        },
        AppSummary {
            app_id: "zt-1".to_string(),
            name: "zerotier".to_string(),
            state: AppState::Starting,
        },
    ];
    let msg = WireMessage::ok_app_list(apps);
    let json = serde_json::to_string(&msg).unwrap();
    let back: WireMessage = serde_json::from_str(&json).unwrap();
    match back {
        WireMessage::Ok {
            data: ResponseData::AppList(list),
        } => {
            assert_eq!(list.len(), 2);
            assert_eq!(list[0].app_id, "web-1");
            assert_eq!(list[1].app_id, "zt-1");
            assert_eq!(list[1].state, AppState::Starting);
        }
        other => panic!("Expected Ok/AppList, got: {:?}", other),
    }
}

#[test]
fn wire_message_ok_interface_ip_roundtrip() {
    let msg = WireMessage::ok_interface_ip("eth0".into(), Some("192.168.1.100".into()));
    let json = serde_json::to_string(&msg).unwrap();
    let back: WireMessage = serde_json::from_str(&json).unwrap();
    match back {
        WireMessage::Ok {
            data: ResponseData::InterfaceIp { interface, ip },
        } => {
            assert_eq!(interface, "eth0");
            assert_eq!(ip, Some("192.168.1.100".to_string()));
        }
        other => panic!("Expected Ok/InterfaceIp, got: {:?}", other),
    }
}

#[test]
fn wire_message_error_roundtrip() {
    let err = WireError {
        category: ErrorCategory::Bootstrap,
        message: "setup task failed".to_string(),
        phase: Some("setup".to_string()),
        is_retryable: false,
    };
    let msg = WireMessage::err(err);
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"msg\":\"Error\""));

    let back: WireMessage = serde_json::from_str(&json).unwrap();
    assert!(back.is_terminal());
    match back {
        WireMessage::Error(e) => {
            assert_eq!(e.category, ErrorCategory::Bootstrap);
            assert_eq!(e.message, "setup task failed");
            assert!(!e.is_retryable);
        }
        other => panic!("Expected Error, got: {:?}", other),
    }
}

#[test]
fn wire_message_err_string() {
    let msg = WireMessage::err_string("something broke".into());
    match msg {
        WireMessage::Error(e) => {
            assert_eq!(e.category, ErrorCategory::Internal);
            assert_eq!(e.message, "something broke");
            assert!(!e.is_retryable);
        }
        other => panic!("Expected Error, got: {:?}", other),
    }
}

#[test]
fn wire_message_progress_roundtrip() {
    let msg = WireMessage::progress(
        42,
        "Pulling images...".into(),
        Some("image-pull".into()),
        Some("web-1".into()),
        Some("pull-nginx".into()),
    );
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"msg\":\"Progress\""));
    assert!(json.contains("42"));

    let back: WireMessage = serde_json::from_str(&json).unwrap();
    assert!(!back.is_terminal()); // Progress is NOT terminal
    match back {
        WireMessage::Progress {
            percentage,
            message,
            phase,
            instance_name,
            task_name,
        } => {
            assert_eq!(percentage, 42);
            assert_eq!(message, "Pulling images...");
            assert_eq!(phase, Some("image-pull".to_string()));
            assert_eq!(instance_name, Some("web-1".to_string()));
            assert_eq!(task_name, Some("pull-nginx".to_string()));
        }
        other => panic!("Expected Progress, got: {:?}", other),
    }
}

#[test]
fn wire_message_progress_minimal() {
    let msg = WireMessage::progress(0, "Starting...".into(), None, None, None);
    let json = serde_json::to_string(&msg).unwrap();
    // Optional fields should be omitted
    assert!(!json.contains("phase"));
    assert!(!json.contains("instance_name"));
    assert!(!json.contains("task_name"));

    let back: WireMessage = serde_json::from_str(&json).unwrap();
    match back {
        WireMessage::Progress { phase, instance_name, task_name, .. } => {
            assert_eq!(phase, None);
            assert_eq!(instance_name, None);
            assert_eq!(task_name, None);
        }
        other => panic!("Expected Progress, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// VappCoreCommand serialization
// ---------------------------------------------------------------------------

#[test]
fn command_ping_roundtrip() {
    let cmd = VappCoreCommand::Ping;
    let json = serde_json::to_string(&cmd).unwrap();
    assert!(json.contains("Ping"));
    let back: VappCoreCommand = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, VappCoreCommand::Ping));
}

#[test]
fn command_stop_app_roundtrip() {
    let cmd = VappCoreCommand::StopApp {
        app_id: "web-123".into(),
    };
    let json = serde_json::to_string(&cmd).unwrap();
    assert!(json.contains("web-123"));
    let back: VappCoreCommand = serde_json::from_str(&json).unwrap();
    match back {
        VappCoreCommand::StopApp { app_id } => assert_eq!(app_id, "web-123"),
        _ => panic!("Expected StopApp"),
    }
}

#[test]
fn command_app_state_roundtrip() {
    let cmd = VappCoreCommand::AppState {
        app_id: "zt-1".into(),
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let back: VappCoreCommand = serde_json::from_str(&json).unwrap();
    match back {
        VappCoreCommand::AppState { app_id } => assert_eq!(app_id, "zt-1"),
        _ => panic!("Expected AppState"),
    }
}

#[test]
fn command_list_apps_roundtrip() {
    let cmd = VappCoreCommand::ListApps;
    let json = serde_json::to_string(&cmd).unwrap();
    let back: VappCoreCommand = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, VappCoreCommand::ListApps));
}

// ---------------------------------------------------------------------------
// NDJSON write/read primitives
// ---------------------------------------------------------------------------

#[test]
fn ndjson_write_appends_newline() {
    let mut buf = Vec::new();
    write_ndjson(&mut buf, &WireMessage::ok_unit()).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.ends_with('\n'), "NDJSON line must end with \\n");
    assert_eq!(s.matches('\n').count(), 1, "Exactly one newline");
}

#[test]
fn ndjson_write_no_internal_newlines() {
    let handle = AppHandle {
        app_id: "web-test".into(),
        name: "test-app".into(),
    };
    let mut buf = Vec::new();
    write_ndjson(&mut buf, &WireMessage::ok_app_handle(handle)).unwrap();
    let s = String::from_utf8(buf).unwrap();
    // Only the trailing \n, no internal newlines
    assert_eq!(s.trim_end().matches('\n').count(), 0);
}

#[test]
fn ndjson_read_single_line() {
    let json = serde_json::to_string(&WireMessage::ok_unit()).unwrap();
    let data = format!("{}\n", json);
    let mut reader = std::io::BufReader::new(Cursor::new(data.as_bytes()));
    let msg: WireMessage = read_ndjson_line(&mut reader).unwrap();
    assert!(msg.is_terminal());
}

#[test]
fn ndjson_read_eof_error() {
    let mut reader = std::io::BufReader::new(Cursor::new(b"" as &[u8]));
    let result = read_ndjson_line::<_, WireMessage>(&mut reader);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("EOF"));
}

#[test]
fn ndjson_write_read_roundtrip() {
    let messages = vec![
        WireMessage::ok_unit(),
        WireMessage::ok_interface_ip("eth0".into(), Some("10.0.0.1".into())),
        WireMessage::err(WireError {
            category: ErrorCategory::Network,
            message: "timeout".into(),
            phase: None,
            is_retryable: true,
        }),
        WireMessage::progress(50, "halfway".into(), None, None, None),
    ];

    for original in &messages {
        let mut buf = Vec::new();
        write_ndjson(&mut buf, original).unwrap();
        let mut reader = std::io::BufReader::new(Cursor::new(&buf));
        let back: WireMessage = read_ndjson_line(&mut reader).unwrap();

        // Compare JSON representations (since WireMessage doesn't impl PartialEq)
        let json_orig = serde_json::to_string(original).unwrap();
        let json_back = serde_json::to_string(&back).unwrap();
        assert_eq!(json_orig, json_back);
    }
}

// ---------------------------------------------------------------------------
// Streaming: simulated daemon → client conversation
// ---------------------------------------------------------------------------

/// Build a buffer simulating a daemon that sends 3 progress messages then Ok.
fn build_streaming_response() -> Vec<u8> {
    let mut buf = Vec::new();
    write_ndjson(
        &mut buf,
        &WireMessage::progress(10, "Pulling image...".into(), Some("image".into()), None, None),
    )
    .unwrap();
    write_ndjson(
        &mut buf,
        &WireMessage::progress(50, "Running setup tasks...".into(), Some("setup".into()), None, None),
    )
    .unwrap();
    write_ndjson(
        &mut buf,
        &WireMessage::progress(90, "Finalizing...".into(), None, None, None),
    )
    .unwrap();
    write_ndjson(
        &mut buf,
        &WireMessage::ok_app_handle(AppHandle {
            app_id: "web-streamed".into(),
            name: "streamed-app".into(),
        }),
    )
    .unwrap();
    buf
}

/// A fake Read+Write stream: writes go to `written`, reads come from `response_data`.
struct FakeStream {
    response_data: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl std::io::Read for FakeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.response_data.read(buf)
    }
}

impl std::io::Write for FakeStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn streaming_collects_progress_and_returns_terminal() {
    let response_bytes = build_streaming_response();

    let mut stream = FakeStream {
        response_data: Cursor::new(response_bytes),
        written: Vec::new(),
    };

    let collected = Arc::new(Mutex::new(Vec::new()));
    let collected_clone = collected.clone();

    let result = send_command_streaming(
        &mut stream,
        VappCoreCommand::Ping, // command doesn't matter for this test
        Some(&move |progress| {
            collected_clone.lock().unwrap().push((progress.percentage, progress.message.clone()));
        }),
    );

    // Check that all 3 progress callbacks were invoked
    let progress = collected.lock().unwrap();
    assert_eq!(progress.len(), 3);
    assert_eq!(progress[0], (10, "Pulling image...".to_string()));
    assert_eq!(progress[1], (50, "Running setup tasks...".to_string()));
    assert_eq!(progress[2], (90, "Finalizing...".to_string()));

    // Check terminal response
    let msg = result.unwrap();
    assert!(msg.is_terminal());
    match msg {
        WireMessage::Ok { data: ResponseData::AppHandle(h) } => {
            assert_eq!(h.app_id, "web-streamed");
            assert_eq!(h.name, "streamed-app");
        }
        other => panic!("Expected Ok/AppHandle, got: {:?}", other),
    }

    // Check the command was written as NDJSON
    let written = String::from_utf8(stream.written).unwrap();
    assert!(written.ends_with('\n'));
    assert!(written.contains("Ping"));
}

#[test]
fn streaming_with_error_terminal() {
    let mut buf = Vec::new();
    write_ndjson(
        &mut buf,
        &WireMessage::progress(10, "Starting...".into(), None, None, None),
    )
    .unwrap();
    write_ndjson(
        &mut buf,
        &WireMessage::err(WireError {
            category: ErrorCategory::Network,
            message: "Failed to pull image".into(),
            phase: Some("image-pull".into()),
            is_retryable: true,
        }),
    )
    .unwrap();

    let mut stream = FakeStream {
        response_data: Cursor::new(buf),
        written: Vec::new(),
    };

    let progress_count = Arc::new(Mutex::new(0u32));
    let progress_count_clone = progress_count.clone();

    let result = send_command_streaming(
        &mut stream,
        VappCoreCommand::Ping,
        Some(&move |_| {
            *progress_count_clone.lock().unwrap() += 1;
        }),
    );

    assert_eq!(*progress_count.lock().unwrap(), 1);
    let msg = result.unwrap();
    match msg {
        WireMessage::Error(e) => {
            assert_eq!(e.category, ErrorCategory::Network);
            assert!(e.message.contains("pull image"));
            assert!(e.is_retryable);
        }
        other => panic!("Expected Error, got: {:?}", other),
    }
}

#[test]
fn streaming_no_progress_callback_still_works() {
    let mut buf = Vec::new();
    write_ndjson(
        &mut buf,
        &WireMessage::progress(50, "working...".into(), None, None, None),
    )
    .unwrap();
    write_ndjson(&mut buf, &WireMessage::ok_unit()).unwrap();

    let mut stream = FakeStream {
        response_data: Cursor::new(buf),
        written: Vec::new(),
    };

    // No callback — progress is silently discarded
    let result = send_command_streaming(&mut stream, VappCoreCommand::Ping, None);
    let msg = result.unwrap();
    match msg {
        WireMessage::Ok { data: ResponseData::Unit } => {}
        other => panic!("Expected Ok/Unit, got: {:?}", other),
    }
}

#[test]
fn streaming_immediate_terminal_no_progress() {
    let mut buf = Vec::new();
    write_ndjson(&mut buf, &WireMessage::ok_unit()).unwrap();

    let mut stream = FakeStream {
        response_data: Cursor::new(buf),
        written: Vec::new(),
    };

    let result = send_command_streaming(&mut stream, VappCoreCommand::Ping, None);
    assert!(result.is_ok());
}
