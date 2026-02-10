//! Public API tests for vappcore.
//!
//! Unit tests (protocol serialization) run without a daemon.
//! Integration tests (client/stream/ping) require a running daemon and socket.
//!
//! Run integration tests with daemon:
//!   make run-dev   # in one terminal (or background)
//!   VAPPC_CORE_TEST_SOCKET=/tmp/vapp-core/vapp-core.sock cargo test -p vappcore public_api
//!
//! Or skip integration tests (unit tests only):
//!   cargo test -p vappcore public_api -- --skip stream_ping --skip ping_call

use std::path::PathBuf;

use vappcore::{VappCoreCommand, VappCorePing, VappCoreStream, WireError, WireMessage};

fn test_socket() -> Option<PathBuf> {
    let p = std::env::var("VAPPC_CORE_TEST_SOCKET")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            let p = PathBuf::from("/tmp/vapp-core/vapp-core.sock");
            if p.exists() {
                Some(p)
            } else {
                None
            }
        })?;
    // Only use if socket exists (e.g. daemon running)
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

// -----------------------------------------------------------------------------
// Unit tests: protocol serialization (no daemon)
// -----------------------------------------------------------------------------

#[test]
fn protocol_command_ping_roundtrip() {
    let cmd = VappCoreCommand::Ping;
    let json = serde_json::to_string(&cmd).unwrap();
    assert!(json.contains("Ping") || json.contains("ping"));
    let back: VappCoreCommand = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, VappCoreCommand::Ping));
}

#[test]
fn protocol_command_get_state_roundtrip() {
    let cmd = VappCoreCommand::GetState {
        instance_id: "master-0".to_string(),
    };
    let json = serde_json::to_string(&cmd).unwrap();
    assert!(json.contains("master-0"));
    let back: VappCoreCommand = serde_json::from_str(&json).unwrap();
    match &back {
        VappCoreCommand::GetState { instance_id } => assert_eq!(instance_id, "master-0"),
        _ => panic!("expected GetState"),
    }
}

#[test]
fn protocol_response_ok_unit_roundtrip() {
    let r = WireMessage::ok_unit();
    let json = serde_json::to_string(&r).unwrap();
    let back: WireMessage = serde_json::from_str(&json).unwrap();
    assert!(back.is_terminal());
    assert!(matches!(back, WireMessage::Ok { .. }));
}

#[test]
fn protocol_response_err_roundtrip() {
    let r = WireMessage::err(WireError::internal("test error".to_string()));
    let json = serde_json::to_string(&r).unwrap();
    let back: WireMessage = serde_json::from_str(&json).unwrap();
    assert!(back.is_terminal());
    match back {
        WireMessage::Error(e) => {
            assert_eq!(e.message, "test error");
            assert!(!e.is_retryable);
        }
        _ => panic!("expected Error"),
    }
}

// -----------------------------------------------------------------------------
// Integration tests: require daemon
// -----------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn stream_ping() {
    let Some(socket) = test_socket() else {
        eprintln!("skip stream_ping: no VAPPC_CORE_TEST_SOCKET and /tmp/vapp-core/vapp-core.sock not found");
        return;
    };
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(&socket).expect("connect");
    let mut wrapper = VappCoreStream::new(stream);
    wrapper.ping().expect("VappCoreStream::ping");
}

#[cfg(unix)]
#[test]
fn ping_call() {
    let Some(socket) = test_socket() else {
        eprintln!("skip ping_call: no VAPPC_CORE_TEST_SOCKET and /tmp/vapp-core/vapp-core.sock not found");
        return;
    };
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(&socket).expect("connect");
    VappCorePing::call(&mut stream).expect("VappCorePing::call");
}
