//! Example: connect to vapp-core-daemon's VSOCK port (Linux only, e.g. from inside the VM).
//!
//! Usage:
//!   cargo test -p vappcore connect_vappc_vsock -- 49163
//!   Or set PORT env:  PORT=49163 cargo test -p vappcore connect_vappc_vsock
//!
//! The daemon listens on VSOCK when run as:
//!   vapp-core-daemon --socket vsock:49163 --app-dir /home/user/.4lock-agent

#![cfg(target_os = "linux")]

use std::env;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::VsockStream;
use vappcore::VappCoreCommand;

const VMADDR_CID_LOCAL: u32 = 1;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port: u32 = env::args()
        .nth(1)
        .or_else(|| env::var("PORT").ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(49163);

    let cmd = VappCoreCommand::GetState {
        instance_id: "master-0".to_string(),
    };
    let request = serde_json::to_vec(&cmd)?;

    let mut stream = VsockStream::connect(VMADDR_CID_LOCAL, port).await?;
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut response = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if n < buf.len() {
            break;
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    println!("Response ({} bytes): {}", response.len(), response_str);

    Ok(())
}
