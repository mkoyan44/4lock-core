# 4lock-core daemon

**Linux-only.** Core crates for the 4lock platform: container runtime, vappc daemon, and blob (docker-proxy) server. Build and run on Linux only; for cross-compilation from macOS/Windows (e.g. when building 4lock-agent), use the tooling in 4lock-agent that invokes Docker/nerdctl to build the Linux binary.

This repository is consumed by [4lock-agent](https://github.com/4lock/4lock-agent) as a path or git dependency.

## Workspace

- **src/blob** – Docker/OCI registry proxy server (image pull cache).
- **src/container** – Linux rootless OCI container runtime, CRI server, bootstrap, and provisioning.
- **src/vappc** – vappc daemon and client library; provides the Unix/VSOCK/TCP socket API used by 4lock-agent on Linux.

## Building

**Requires Linux.** Build from repo root or from this directory:

```bash
# From repo root – all workspace crates (daemon + publish)
cargo build --workspace

# From repo root – daemon crates only
cargo build -p blob -p container -p vappc

# From daemon/ – daemon crates only
cargo build --manifest-path daemon/Cargo.toml

# vappc-linux-daemon only
cargo build -p vappc --release --bin vappc-linux-daemon
```

Binary output: `target/release/vappc-linux-daemon` (or `target/debug/` for dev profile). On non-Linux hosts the build will fail with a clear message; use 4lock-agent’s build (which cross-compiles via Docker/nerdctl) to produce the daemon binary.

## Build and run with nerdctl (same approach as 4lock-api)

Use **Makefile** and **docker/** (same layout as 4lock-api):

- **docker/dockerfiles/Dockerfile.core** – multi-stage build, `TARGET_ARCH` (arm64/amd64)
- **docker/entrypoints/docker-entrypoint-core.sh** – entrypoint for vappc-linux-daemon
- **Makefile** – requires `.env` (GH_OWNER, GH_TOKEN, TARGET_ARCH); targets: `build`, `push`, `run`, `all`

```bash
cp .env.example .env   # set GH_OWNER, GH_TOKEN, TARGET_ARCH=amd64 or arm64
make build             # nerdctl build -f docker/dockerfiles/Dockerfile.core ...
make run               # run image (mounts /tmp/vappc for socket)
make all               # build + push to ghcr.io
```

Backward compatibility: you can still build with the root `Dockerfile` (single-arch, no .env):  
`nerdctl build -t 4lock-core .`

## Cross (nerdctl/Docker)

`Cross.toml` in this directory is used by **publish/** when building Linux binaries. Set `CROSS_CONTAINER_ENGINE=nerdctl` to use nerdctl.

## 4lock-agent integration

4lock-agent depends on the **vappc** crate (client library) and, when building the agent, builds **vappc-linux-daemon** from this repo and embeds it for Linux VMs/containers.

- Clone 4lock-core next to 4lock-agent (e.g. `platform/4lock-agent` and `platform/4lock-core`).
- Or set `LOCK4_CORE_DIR` to the path to 4lock-core when building 4lock-agent.

See 4lock-agent docs for full build and run instructions.

## Packaging

- **systemd**: `publish/packaging/systemd/vappc-linux-daemon.service` and `publish/packaging/README-vappc-systemd.md` for running vappc as a system service (vapp:vapp, socket at `/run/vapp/vappc.sock`).
- **4lock-de** Ansible playbooks can install the binary and unit from this repo or from a release artifact.
