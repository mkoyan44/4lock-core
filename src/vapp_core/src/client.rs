//! Stream wrapper and ping for vapp-core protocol. Raw JSON wire format (no length prefix).
//! VappCoreClient removed; use VappClient in 4lock-agent for high-level API.

use crate::protocol::{VappCoreCommand, VappCoreResponse};
use std::io::{Read, Write};

const RESPONSE_BUF_SIZE: usize = 65536;

/// Send a command over a stream and read the response. Crate-internal wire protocol.
fn send_command_on_stream<S>(
    stream: &mut S,
    command: VappCoreCommand,
) -> Result<VappCoreResponse, String>
where
    S: Read + Write,
{
    let json_bytes =
        serde_json::to_vec(&command).map_err(|e| format!("Serialize command: {}", e))?;
    stream
        .write_all(&json_bytes)
        .map_err(|e| format!("Write command: {}", e))?;
    stream.flush().map_err(|e| format!("Flush: {}", e))?;

    let mut buf = vec![0u8; RESPONSE_BUF_SIZE];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("Read response: {}", e))?;
    let response: VappCoreResponse = serde_json::from_slice(&buf[..n])
        .map_err(|e| format!("Deserialize response: {}", e))?;
    Ok(response)
}

/// Wraps a bidirectional stream for vapp-core protocol (Unix, VSOCK, TCP).
#[derive(Debug)]
pub struct VappCoreStream<S> {
    stream: S,
}

impl<S: Read + Write> VappCoreStream<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Send a command and read the response.
    pub fn send_command(&mut self, command: VappCoreCommand) -> Result<VappCoreResponse, String> {
        let r = send_command_on_stream(&mut self.stream, command)?;
        if r.is_err() {
            return Err(r.error_message().unwrap_or("unknown").to_string());
        }
        Ok(r)
    }

    /// Health check (sends Ping, expects OkUnit).
    pub fn ping(&mut self) -> Result<(), String> {
        self.send_command(VappCoreCommand::Ping)
            .map(|_| ())
    }
}

impl<S> VappCoreStream<S> {
    /// Send a command over an existing stream. Use when you have `&mut S` (e.g. VSOCK).
    pub fn send_command_on(stream: &mut S, command: VappCoreCommand) -> Result<VappCoreResponse, String>
    where
        S: Read + Write,
    {
        let r = send_command_on_stream(stream, command)?;
        if r.is_err() {
            return Err(r.error_message().unwrap_or("unknown").to_string());
        }
        Ok(r)
    }
}

/// Health check over an existing stream.
pub struct VappCorePing;

impl VappCorePing {
    /// Send Ping over stream, expect OkUnit.
    pub fn call<S: Read + Write>(stream: &mut S) -> Result<(), String> {
        let r = send_command_on_stream(stream, VappCoreCommand::Ping)?;
        if r.is_err() {
            return Err(r.error_message().unwrap_or("unknown").to_string());
        }
        Ok(())
    }
}
