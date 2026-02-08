//! Example: connect to vapp-core-daemon's exposed socket (Unix or VSOCK) and send a command.
//!
//! Usage:
//!   Unix socket (host or guest):  cargo test -p vapp_core connect_vappc_unix -- /path/to/socket.sock
//!   Or set SOCKET env:            SOCKET=/tmp/vapp-core.sock cargo test -p vapp_core connect_vappc_unix
//!
//! The daemon exposes the socket when run as:
//!   vapp-core-daemon --socket /tmp/vapp-core.sock
//!   vapp-core-daemon --socket vsock:49163   (inside VM; use connect_vappc_vsock on Linux)

use std::env;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vapp_core::VappCoreCommand;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket_path = env::args()
        .nth(1)
        .or_else(|| env::var("SOCKET").ok())
        .unwrap_or_else(|| {
            eprintln!("Usage: connect_vappc_unix <socket_path>");
            eprintln!("   or: SOCKET=/path/to.sock connect_vappc_unix");
            eprintln!("Example: connect_vappc_unix /tmp/vapp-core.sock");
            std::process::exit(1);
        });

    let cmd = VappCoreCommand::GetState {
        instance_id: "master-0".to_string(),
    };
    let request = serde_json::to_vec(&cmd)?;

    let mut stream = tokio::net::UnixStream::connect(&socket_path).await?;
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
