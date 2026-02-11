# 4lock-core – Architecture Overview

## Introduction

4lock-core is a **Linux-only** Rust workspace that provides the core crates consumed by [4lock-agent](https://github.com/4lock/4lock-agent): registry proxy (blob), rootless OCI/CRI container runtime and bootstrap (container), and the vappc daemon/client (vappc). There is no UI; the agent talks to the daemon over Unix or VSOCK socket.

## System Purpose

- **blob** – OCI/registry proxy and image pull cache (docker-proxy style).
- **container** – Rootless OCI runtime, CRI server, Kubernetes bootstrap (etcd, apiserver, kubelet, etc.), provisioning and intent loop.
- **vappc** – Daemon binary and client library: Unix/VSOCK socket API used by 4lock-agent on Linux to drive container lifecycle and bootstrap.

## Technology Stack

- **Language**: Rust (async/tokio where used).
- **Build/run**: Cargo on Linux; Makefile + nerdctl for containerized build/run (any host).
- **Communication**: vappc protocol over Unix socket (`/tmp/vappc`) or VSOCK.
- **Container**: Rootless OCI (youki/libcontainer-style), CRI (gRPC), pasta for networking.

## Layout (High-Level)

```
4lock-core/
├── src/
│   ├── blob/        # Registry proxy, cache, prepull
│   ├── container/   # Rootless OCI, CRI, bootstrap, provisioner, intent loop
│   └── vappc/       # Daemon, client, protocol (Unix/VSOCK)
├── docker/          # Dockerfile.core, entrypoint
├── packaging/       # systemd unit, README
├── docs/            # User-facing README (build, run, packaging)
├── Makefile         # build, run, build-dev, run-dev, from-scratch, push
└── Cargo.toml       # Workspace (blob, container, vappc, daemon virtual crate)
```

## Design Principles

1. **Linux-only** – No Tauri, no VM layer; container runtime and daemon only. Cross-build from macOS/Windows is via `make` (nerdctl builds a Linux image).
2. **Consumed by 4lock-agent** – Agent depends on the vappc crate (client) and builds `vappc-linux-daemon` from this repo for Linux.
3. **Clear crate boundaries** – blob (registry/cache), container (OCI/CRI/bootstrap), vappc (daemon + protocol).
4. **Idempotent bootstrap** – Container bootstrap tasks (Jinja2, bash, kubectl) should be idempotent and validate template variables.

## Key Documentation

- **[Crate Architecture](docs/architecture/CRATE_ARCHITECTURE.md)** – Module layout for blob, container, vappc.
- **[Development Guide](docs/development/DEVELOPMENT_GUIDE.md)** – Cargo, Makefile, docker, testing.

All docs live under `docs/`.
