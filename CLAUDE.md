# 4lock-core — AI Assistant Rules (Claude Code Entry Point)

This repository is configured for both **Cursor** and **Claude Code**:
- **Cursor**: Reads `.cursorrules` at repo root
- **Claude Code**: Reads this file (`CLAUDE.md`)

Both tools share the same documentation in `docs/`.

## Project Overview

4Lock Core is a Linux-only Rust workspace providing core crates for the 4lock platform: OCI registry proxy (blob), rootless container runtime (container), and daemon/client socket API (vappcore). No UI — consumed by 4lock-agent as a path/git dependency.

**Main Branch:** `master`
**Platform:** Linux-only (containerized build via Makefile on any host)
**Binary:** `vapp-core-daemon`

## Tech Stack
- **Rust** (Edition 2021) - Async/tokio
- **Cargo** - Workspace with 3 crates + virtual root
- **tokio** - Async runtime (multi-threaded)
- **axum** - HTTP server (blob registry proxy)
- **tonic/prost** - gRPC/protobuf (CRI server)
- **rustls** - TLS
- **youki** (libcontainer/libcgroups) - OCI rootless runtime
- **nerdctl** - Containerized build/run via Makefile

## Project Structure (Cargo Workspace)
- `src/blob/` - OCI registry proxy, image pull cache, mirror racing, prepull, Helm
- `src/container/` - Rootless OCI runtime, CRI gRPC server, K8s bootstrap, intent loop
- `src/vappcore/` - Daemon binary, client library, NDJSON wire protocol (Unix/VSOCK/TCP)
- `docker/` - Dockerfile.core (multi-stage), entrypoints
- `packaging/` - systemd unit file, install guide
- `docs/` - **Primary source of experience and knowledge**
  - `architecture/` - System overview, crate layout, naming glossary
  - `development/` - Build, run, test guide
  - `troubleshooting/` - Blob 502 diagnostics

## Documentation as Experience Source

**IMPORTANT**: The `docs/` directory contains the primary source of experience and knowledge for this project. Always consult documentation before making decisions.

When working on this project:
1. **First**: Read relevant documentation in `docs/` to understand existing patterns
2. **Then**: Apply the documented experience and best practices to your changes
3. **Finally**: Update documentation if you discover new patterns or make architectural changes

## Build Commands

### On Linux (native)
```bash
cargo build -p daemon                                    # All crates
cargo build -p vappcore --release --bin vapp-core-daemon  # Daemon only
cargo test --workspace                                    # All tests
cargo fmt && cargo clippy --all-targets --all-features    # Format + lint
```

### Any host (containerized via Makefile)
```bash
make                  # Default: build + run (release)
make from-scratch     # Same as above
make build            # Release build (BuildKit cache mounts)
make run              # Privileged container, Ctrl+C stops and removes
make build-dev        # Dev profile (fast recompile)
make run-dev          # Run dev build
make test             # Build + run tests in container
make push             # Push to GHCR (needs GH_OWNER/GH_TOKEN)
```

## Code Guidelines

### Crate Placement
- **blob** — Registry/cache, prepull, Helm, mirror racing
- **container** — OCI/CRI, bootstrap (intent loop, provisioner, templates, tasks)
- **vappcore** — Daemon, client, wire protocol

### Rust Style
- `Result<T, E>` with `thiserror` for errors; `tracing` for logging
- Async-first with tokio; `CString` for FFI operations
- Linux-only modules gated with `#[cfg(target_os = "linux")]`

### Bootstrap Rules
- Tasks must be **idempotent** (check before mutate)
- Validate template variables; fail fast with clear errors
- Numbered script ordering (10-*.sh, 20-*.sh)

### Protocol
- NDJSON (newline-delimited JSON) over Unix/VSOCK/TCP
- `VappCoreCommand` → `WireMessage` response
- Protocol changes must be backward-compatible (consumed by 4lock-agent)

### Critical — Do NOT Modify Without Care
- Proto definitions (`src/container/proto/`) — CRI contract
- `build.rs` in any crate
- Dockerfile and entrypoint — affects all builds
- Bootstrap template ordering

## Environment Variables

Optional in `.env`:
```bash
TARGET_ARCH=amd64      # or arm64; auto-detected from host
GH_OWNER=<github-owner>  # Required for push
GH_TOKEN=<github-token>  # Required for push
```

## Important Notes

- Linux-only runtime; containerized build/run via Makefile on macOS/Windows
- `--privileged` required for `make run` (rootless containers, pasta networking)
- Socket default: `/tmp/vapp-core.sock` (container) or `/run/vapp/vapp-core.sock` (systemd)
- Consumed by 4lock-agent as path/git dependency (vappcore client crate)
- Image: `ghcr.io/<GH_OWNER>/4lock-core-<arch>` or `4lock-core:latest` (local)
