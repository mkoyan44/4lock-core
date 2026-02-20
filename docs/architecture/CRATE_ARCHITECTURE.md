# 4lock-core – Crate Architecture

This document describes the internal layout of each crate in the 4lock-core workspace. Workspace root is the repo root; crates live under `src/`.

## 1. src/blob – Registry Proxy and Image Cache

**Purpose**: OCI/registry proxy server (docker-proxy style): pull-through cache, mirror racing, prepull.

**Location**: `src/blob/`

### Notable modules

- **registry/** – v2 API, manifests, blob storage, upstream/mirror.
- **cache/** – Metadata and storage for cached layers.
- **server**, **tls/** – HTTP(s) server and TLS.
- **prepull**, **helm/** – Pre-pull and Helm index/chart support.

### Binaries

- `docker-proxy-server` – Main server binary.

### Integration

- Used by container runtime (image pull). 4lock-agent may point at this as registry cache.

---

## 2. src/container – Rootless OCI, CRI, and Bootstrap

**Purpose**: Rootless OCI container runtime, CRI server (for kubelet), Kubernetes node bootstrap (etcd, kube-apiserver, kubelet, etc.), intent-driven provisioning.

**Location**: `src/container/`

### Notable modules

- **rootless/** – OCI runtime (lifecycle, bundle, orchestration, system_check). Host networking; no per-container network namespace.
- **cri/** – CRI gRPC server: runtime_service, image_service, sandbox, container_registry.
- **bootstrap/** – Intent loop, provisioner, image_manager, workflow, templates (Jinja2), tasks (container_task, kubectl_task), certs, volume_manager.
- **common/** – Shared types, image, volume.

### Proto

- **proto/cri/** – CRI API protos (`api.proto`).

### Design

- **Intent loop** – Consumes intents (e.g. start cluster); provisioner turns them into container specs and CRI/OCI operations.
- **Bootstrap tasks** – Idempotent; template variables must be validated. Numbered scripts (e.g. 10-*.sh, 20-*.sh) for ordering.
- **CRI** – Implements RuntimeService and ImageService; kubelet talks to CRI socket; host networking and pivot_root as per Linux rootless rules.

### Integration

- vapp-core daemon starts and drives the container provisioner and intent loop; CRI socket is used by kubelet.

---

## 3. src/vappcore – Daemon and Client

**Purpose**: vapp-core daemon (Unix/VSOCK socket server) and client library. This is the API that 4lock-agent uses on Linux to control the core (start/stop containers, bootstrap, etc.).

**Location**: `src/vappcore/`

### Notable modules

- **daemon.rs** – Daemon process: socket listener, request handling, integration with container (provisioner, intent loop).
- **client.rs** – Stream wrapper and ping for protocol. Exposes `VappCoreStream`, `VappCorePing`. VappClient (in 4lock-agent) provides the high-level client API.
- **protocol.rs** – Wire protocol (messages, serialization): `VappCoreCommand`, `VappCoreResponse`.

### Binaries

- **vapp-core-daemon** – Main daemon binary (Linux only). Typically run via `make run` (container) or systemd.

### Integration

- 4lock-agent links the vappcore **client** crate and, on Linux, runs or embeds **vapp-core-daemon** (from this repo). Socket default: `/tmp/vapp-core.sock` (or `/run/vapp/vapp-core.sock` under systemd).

---

## Responsibility summary

| Area              | Crate      | Owner / notes                                      |
|-------------------|------------|----------------------------------------------------|
| Registry / cache  | blob       | Proxy, cache, prepull                              |
| OCI / CRI / K8s   | container  | Rootless runtime, CRI server, bootstrap, intents  |
| Daemon / protocol | vappcore  | Socket API, daemon, client                         |
| Build / run       | Makefile   | nerdctl, Dockerfile.core, TARGET_ARCH              |

When adding features: place registry/cache logic in blob; OCI/CRI/bootstrap in container; daemon protocol and client in vappcore. Keep shared types in the crate that owns the concept or in a small `common`-style module within that crate.
