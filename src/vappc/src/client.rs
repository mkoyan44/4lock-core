//! Client for vappc-linux-daemon. Uses raw JSON wire format (no length prefix) to match the daemon.
//! On Unix: connects via Unix socket. On Windows: connects via TCP (host:port).

use crate::protocol::{VappcCommand, VappcResponse};
use container::intent::{
    ContainerRunSpec, Endpoint, InstanceHandle, InstanceState, VappSpec,
};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(windows)]
use std::net::TcpStream;

const RESPONSE_BUF_SIZE: usize = 65536;

/// Client for the vappc daemon (Unix socket). Wire format: raw JSON request, raw JSON response.
#[derive(Debug)]
pub struct VappcClient {
    socket_path: PathBuf,
    timeout: Duration,
}

impl VappcClient {
    pub fn with_socket_path(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    #[cfg(unix)]
    fn connect(&self) -> Result<UnixStream, String> {
        if !self.socket_path.exists() {
            return Err(format!(
                "The vappc daemon is not running. (Socket not found at {}.)",
                self.socket_path.display()
            ));
        }
        let stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            format!(
                "The vappc daemon is not running. (Failed to connect at {}: {}.)",
                self.socket_path.display(),
                e
            )
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;
        Ok(stream)
    }

    /// Send command (raw JSON), read response (raw JSON). Daemon uses one read, one write per connection.
    #[cfg(unix)]
    fn send_command(&self, command: VappcCommand) -> Result<VappcResponse, String> {
        let json_bytes =
            serde_json::to_vec(&command).map_err(|e| format!("Serialize command: {}", e))?;
        let mut stream = self.connect()?;
        stream
            .write_all(&json_bytes)
            .map_err(|e| format!("Write command: {}", e))?;
        stream.flush().map_err(|e| format!("Flush: {}", e))?;

        let mut buf = vec![0u8; RESPONSE_BUF_SIZE];
        let n = stream
            .read(&mut buf)
            .map_err(|e| format!("Read response: {}", e))?;
        let response: VappcResponse = serde_json::from_slice(&buf[..n])
            .map_err(|e| format!("Deserialize response: {}", e))?;
        if response.is_err() {
            return Err(response.error_message().unwrap_or("unknown").to_string());
        }
        Ok(response)
    }

    #[cfg(windows)]
    fn send_command(&self, command: VappcCommand) -> Result<VappcResponse, String> {
        let path_str = self.socket_path.to_string_lossy();
        let addr: std::net::SocketAddr = path_str.parse().map_err(|_| {
            format!(
                "Invalid vappc socket path '{}'; on Windows use host:port (e.g. 127.0.0.1:9876)",
                path_str
            )
        })?;

        let mut stream = TcpStream::connect_timeout(&addr, self.timeout).map_err(|e| {
            format!(
                "The vappc daemon is not running or not reachable. (Failed to connect to {}: {}.)",
                addr, e
            )
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Set write timeout: {}", e))?;

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
        let response: VappcResponse = serde_json::from_slice(&buf[..n])
            .map_err(|e| format!("Deserialize response: {}", e))?;
        if response.is_err() {
            return Err(response.error_message().unwrap_or("unknown").to_string());
        }
        Ok(response)
    }

    #[cfg(not(any(unix, windows)))]
    fn send_command(&self, _command: VappcCommand) -> Result<VappcResponse, String> {
        Err("Unix socket not supported on this platform. Use TCP (host:port) on Windows.".to_string())
    }

    /// Health check; daemon responds with OkUnit.
    pub fn ping(&self) -> Result<(), String> {
        let r = self.send_command(VappcCommand::Ping)?;
        if r.is_err() {
            return Err(r.error_message().unwrap_or("unknown").to_string());
        }
        Ok(())
    }

    /// Start an instance; returns handle on success.
    pub fn vapp_start(&self, spec: VappSpec) -> Result<InstanceHandle, String> {
        let r = self.send_command(VappcCommand::Start { spec })?;
        match r {
            VappcResponse::OkHandle(h) => Ok(h),
            _ => Err("Expected OkHandle".to_string()),
        }
    }

    /// Run a single container from a generic spec (image, command, args, env, mounts). For debug/ad-hoc.
    pub fn run_container(&self, spec: ContainerRunSpec) -> Result<InstanceHandle, String> {
        let r = self.send_command(VappcCommand::RunContainer { spec })?;
        match r {
            VappcResponse::OkHandle(h) => Ok(h),
            _ => Err("Expected OkHandle".to_string()),
        }
    }

    /// Stop an instance.
    pub fn vapp_stop(&self, instance_id: &str) -> Result<(), String> {
        self.send_command(VappcCommand::Stop {
            instance_id: instance_id.to_string(),
        })?;
        Ok(())
    }

    /// Get instance state.
    pub fn vapp_status(&self, instance_id: &str) -> Result<InstanceState, String> {
        let r = self.send_command(VappcCommand::GetState {
            instance_id: instance_id.to_string(),
        })?;
        match r {
            VappcResponse::OkState(s) => Ok(s),
            _ => Err("Expected OkState".to_string()),
        }
    }

    /// Get instance endpoint.
    pub fn get_endpoint(&self, instance_id: &str) -> Result<Endpoint, String> {
        let r = self.send_command(VappcCommand::GetEndpoint {
            instance_id: instance_id.to_string(),
        })?;
        match r {
            VappcResponse::OkEndpoint(e) => Ok(e),
            _ => Err("Expected OkEndpoint".to_string()),
        }
    }

    /// Get network interface IP address (e.g., eth0, zt0).
    /// Returns Ok(Some(ip)) if found, Ok(None) if interface exists but has no IP.
    pub fn get_interface_ip(&self, interface: &str) -> Result<Option<String>, String> {
        let r = self.send_command(VappcCommand::GetInterfaceIp {
            interface: interface.to_string(),
        })?;
        match r {
            VappcResponse::OkInterfaceIp { ip, .. } => Ok(ip),
            _ => Err("Expected OkInterfaceIp".to_string()),
        }
    }
}

/// Send Ping over an existing stream (raw JSON). Used after VSOCK connect to confirm daemon is ready.
pub fn ping_over_stream<S>(stream: &mut S) -> Result<(), String>
where
    S: Read + Write,
{
    let cmd = VappcCommand::Ping;
    let json_bytes = serde_json::to_vec(&cmd).map_err(|e| format!("Serialize Ping: {}", e))?;
    stream
        .write_all(&json_bytes)
        .map_err(|e| format!("Write Ping: {}", e))?;
    stream.flush().map_err(|e| format!("Flush: {}", e))?;

    let mut buf = [0u8; 4096];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("Read response: {}", e))?;
    let response: VappcResponse =
        serde_json::from_slice(&buf[..n]).map_err(|e| format!("Deserialize response: {}", e))?;
    if response.is_err() {
        return Err(response.error_message().unwrap_or("unknown").to_string());
    }
    Ok(())
}
