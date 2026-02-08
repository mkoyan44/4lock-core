# Naming Glossary (4lock platform)

This document clarifies naming for vapp-related components to avoid confusion.

| Term | Meaning |
|------|---------|
| **vapp** | Main Tauri desktop application (4lock-agent). The GUI that users interact with. Binary: `vapp`. |
| **vappd** | Background daemon (4lock-agent). Runs VM/container lifecycle without GUI. Binary: `vappd`. |
| **vappctl** | CLI control tool (4lock-agent). Manages VMs/containers from the command line. Binary: `vappctl`. |
| **vapp-core** | Linux-only core daemon and client library (4lock-core). Provides the Unix/VSOCK/TCP socket API for container runtime. Crate: `vapp_core`. Binary: `vapp-core-daemon`. |
| **vapp-core-daemon** | The Linux daemon binary built from 4lock-core. Runs inside the container/VM and drives the rootless OCI runtime, CRI server, and bootstrap. Socket default: `/tmp/vapp-core.sock`. |
| **VappClient** | Client in 4lock-agent. Connects to vapp-core-daemon (Unix socket or TCP). |
| **VappCoreStream** | Wraps a bidirectional stream (Unix, VSOCK, TCP) with `send_command()` and `ping()`. |
| **VappCorePing** | Health check: `VappCorePing::call(stream)` sends Ping and expects OkUnit. |
| **VappCoreCommand** | Wire protocol: command enum (Ping, Start, RunContainer, Stop, GetState, GetEndpoint, GetInterfaceIp). |
| **VappCoreResponse** | Wire protocol: response enum (OkHandle, OkState, OkEndpoint, OkUnit, OkInterfaceIp, Err). |

## Relationship

- **4lock-agent** builds vapp, vappd, vappctl. On Linux, it also builds and runs (or embeds) **vapp-core-daemon** from 4lock-core.
- **4lock-core** provides the vapp_core crate (client + daemon) and the container/blob crates. The vapp-core-daemon is the Linux-only socket server that 4lock-agent talks to for container operations.

## Socket paths

| Context | Default socket |
|---------|----------------|
| Docker/nerdctl (`make run`) | `/tmp/vapp-core.sock` (container mounts `/tmp/vapp-core:/tmp`) |
| systemd | `/run/vapp/vapp-core.sock` |
| VSOCK (inside VM) | `vsock:49163` (daemon listens; TCP 127.0.0.1:49163 for SSH port-forward) |
