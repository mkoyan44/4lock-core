//! Example: connect to vappc-linux-daemon's exposed socket (Unix or VSOCK) and send a command.
//!
//! Usage:
//!   Unix socket (host or guest):  cargo run -p vappc --example connect_vappc_unix -- /path/to/socket.sock
//!   Or set SOCKET env:            SOCKET=/tmp/vappc.sock cargo run -p vappc --example connect_vappc_unix
//!
//! The daemon exposes the socket when run as:
//!   vappc-linux-daemon --socket /tmp/vappc.sock
//!   vappc-linux-daemon --socket vsock:49163   (inside VM; use connect_vappc_vsock on Linux)

use std::env;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vappc::VappcCommand;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket_path = env::args()
        .nth(1)
        .or_else(|| env::var("SOCKET").ok())
        .unwrap_or_else(|| {
            eprintln!("Usage: connect_vappc_unix <socket_path>");
            eprintln!("   or: SOCKET=/path/to.sock connect_vappc_unix");
            eprintln!("Example: connect_vappc_unix /tmp/vappc.sock");
            std::process::exit(1);
        });

    let cmd = VappcCommand::GetState {
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
