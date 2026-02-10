//! NDJSON transport for vapp-core protocol.
//!
//! Wire format: newline-delimited JSON. Each message is one JSON object terminated by `\n`.
//! serde_json::to_string() never produces bare newlines, so `\n` is a safe delimiter.
//!
//! Reading uses `BufRead::read_line()` (sync) — no fixed-size buffer, handles arbitrarily
//! large messages.

use crate::protocol::{VappCoreCommand, WireMessage};
use container::progress::RuntimeStartProgress;
use std::io::{BufRead, BufReader, Read, Write};

// ---------------------------------------------------------------------------
// NDJSON primitives
// ---------------------------------------------------------------------------

/// Write one NDJSON line to a stream.
pub fn write_ndjson<W: Write, T: serde::Serialize>(writer: &mut W, msg: &T) -> Result<(), String> {
    let json = serde_json::to_string(msg).map_err(|e| format!("Serialize: {}", e))?;
    writer
        .write_all(json.as_bytes())
        .map_err(|e| format!("Write: {}", e))?;
    writer
        .write_all(b"\n")
        .map_err(|e| format!("Write newline: {}", e))?;
    writer.flush().map_err(|e| format!("Flush: {}", e))?;
    Ok(())
}

/// Read one NDJSON line from a buffered reader. Returns the deserialized value.
pub fn read_ndjson_line<R: BufRead, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> Result<T, String> {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .map_err(|e| format!("Read line: {}", e))?;
    if n == 0 {
        return Err("Connection closed (EOF)".to_string());
    }
    serde_json::from_str(line.trim_end()).map_err(|e| format!("Deserialize: {}", e))
}

// ---------------------------------------------------------------------------
// Sync command helpers (used by VappClient on the agent side)
// ---------------------------------------------------------------------------

/// Send a command as NDJSON and read a single response line (non-streaming).
fn send_command_ndjson<S: Read + Write>(
    stream: &mut S,
    command: VappCoreCommand,
) -> Result<WireMessage, String> {
    write_ndjson(stream, &command)?;
    let mut reader = BufReader::new(stream);
    read_ndjson_line::<_, WireMessage>(&mut reader)
}

/// Send a command and read a streaming response. Calls `progress_callback` for each
/// `WireMessage::Progress` line. Returns the terminal message (`Ok` or `Error`).
pub fn send_command_streaming<S: Read + Write>(
    stream: &mut S,
    command: VappCoreCommand,
    progress_callback: Option<&dyn Fn(RuntimeStartProgress)>,
) -> Result<WireMessage, String> {
    write_ndjson(stream, &command)?;
    let mut reader = BufReader::new(stream);
    loop {
        let msg: WireMessage = read_ndjson_line(&mut reader)?;
        match &msg {
            WireMessage::Progress {
                percentage,
                message,
                phase,
                instance_name,
                task_name,
            } => {
                if let Some(cb) = progress_callback {
                    cb(RuntimeStartProgress {
                        percentage: *percentage,
                        message: message.clone(),
                        phase: phase.clone(),
                        instance_name: instance_name.clone(),
                        task_name: task_name.clone(),
                    });
                }
            }
            WireMessage::Ok { .. } | WireMessage::Error(_) => return Ok(msg),
        }
    }
}


// ---------------------------------------------------------------------------
// VappCoreStream (high-level wrapper)
// ---------------------------------------------------------------------------

/// Wraps a bidirectional stream for vapp-core protocol (Unix, VSOCK, TCP).
#[derive(Debug)]
pub struct VappCoreStream<S> {
    stream: S,
}

impl<S: Read + Write> VappCoreStream<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Send a command and read a single response (non-streaming, NDJSON).
    pub fn send_command(&mut self, command: VappCoreCommand) -> Result<WireMessage, String> {
        send_command_ndjson(&mut self.stream, command)
    }

    /// Send a command and read a streaming response (NDJSON).
    /// Calls `progress_callback` for each Progress message.
    /// Returns the terminal response (Ok or Error).
    pub fn send_command_with_progress(
        &mut self,
        command: VappCoreCommand,
        progress_callback: Option<&dyn Fn(RuntimeStartProgress)>,
    ) -> Result<WireMessage, String> {
        send_command_streaming(&mut self.stream, command, progress_callback)
    }

    /// Health check (sends Ping, expects Ok { data: Unit }).
    pub fn ping(&mut self) -> Result<(), String> {
        let msg = self.send_command(VappCoreCommand::Ping)?;
        match msg {
            WireMessage::Ok { .. } => Ok(()),
            WireMessage::Error(e) => Err(e.to_string()),
            WireMessage::Progress { .. } => Err("Unexpected Progress for Ping".to_string()),
        }
    }

}

impl<S> VappCoreStream<S> {
    /// Send a command over an existing stream (NDJSON). Use when you have `&mut S`.
    pub fn send_command_on(
        stream: &mut S,
        command: VappCoreCommand,
    ) -> Result<WireMessage, String>
    where
        S: Read + Write,
    {
        send_command_ndjson(stream, command)
    }

    /// Send a streaming command over an existing stream (NDJSON).
    pub fn send_command_on_streaming(
        stream: &mut S,
        command: VappCoreCommand,
        progress_callback: Option<&dyn Fn(RuntimeStartProgress)>,
    ) -> Result<WireMessage, String>
    where
        S: Read + Write,
    {
        send_command_streaming(stream, command, progress_callback)
    }

}

/// Health check over an existing stream.
pub struct VappCorePing;

impl VappCorePing {
    /// Send Ping over stream using NDJSON, expect Ok.
    pub fn call<S: Read + Write>(stream: &mut S) -> Result<(), String> {
        let msg = send_command_ndjson(stream, VappCoreCommand::Ping)?;
        match msg {
            WireMessage::Ok { .. } => Ok(()),
            WireMessage::Error(e) => Err(e.to_string()),
            WireMessage::Progress { .. } => Err("Unexpected Progress for Ping".to_string()),
        }
    }
}
