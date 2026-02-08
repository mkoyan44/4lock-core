# 4lock-core daemon

**Linux-only.** Core crates for the 4lock platform: container runtime, vapp-core daemon, and blob (docker-proxy) server. Build and run on Linux only; for cross-compilation from macOS/Windows (e.g. when building 4lock-agent), use the tooling in 4lock-agent that invokes Docker/nerdctl to build the Linux binary.

This repository is consumed by [4lock-agent](https://github.com/4lock/4lock-agent) as a path or git dependency.

## Workspace

- **src/blob** – Docker/OCI registry proxy server (image pull cache).
- **src/container** – Linux rootless OCI container runtime, CRI server, bootstrap, and provisioning.
- **src/vappcore** – vapp-core daemon and client library; provides the Unix/VSOCK/TCP socket API used by 4lock-agent on Linux.

## Building

**Requires Linux.** Build from repo root:

```bash
# All daemon crates (blob, container, vappcore)
cargo build -p daemon

# vapp-core-daemon binary only
cargo build -p vappcore --release --bin vapp-core-daemon
```

Output: `target/release/vapp-core-daemon`. On non-Linux hosts use the Makefile (builds inside a Linux container via nerdctl).

## Build and run with nerdctl (same approach as 4lock-api)

Use **Makefile** and **docker/** (same layout as 4lock-api):

- **docker/dockerfiles/Dockerfile.core** – multi-stage build, `TARGET_ARCH` (arm64/amd64)
- **docker/entrypoints/docker-entrypoint-core.sh** – entrypoint for vapp-core-daemon
- **Makefile** – `TARGET_ARCH` auto-detected from host. Override in `.env` if needed. `GH_OWNER`/`GH_TOKEN` only for `push`. Targets: `build`, `run`, `build-dev`, `run-dev`, `from-scratch`, `push`, `all`. `build` uses BuildKit cache mounts (Cargo registry + `target/`) so only changed crates recompile. `build-dev` uses the dev-fast profile for faster compile when iterating on code in `src/`.

```bash
# From scratch
make from-scratch      # build then run (release)

make build             # release; cache mounts speed up later rebuilds
make run               # --privileged; socket at /tmp/vapp-core; runs detached + logs -f; Ctrl+C stops and removes container

# Fast iteration when changing code in src/
make build-dev && make run-dev

make push
make all
```

Without `GH_OWNER` in `.env`, image is tagged `4lock-core:latest` for local run. Root `Dockerfile`: `nerdctl build -t 4lock-core .` (single-arch).

## Cross (nerdctl/Docker)

`Cross.toml` in this directory is used by **publish/** when building Linux binaries. Set `CROSS_CONTAINER_ENGINE=nerdctl` to use nerdctl.

## 4lock-agent integration

4lock-agent depends on the **vappcore** crate (client library) and, when building the agent, builds **vapp-core-daemon** from this repo and embeds it for Linux VMs/containers.

- Clone 4lock-core next to 4lock-agent (e.g. `platform/4lock-agent` and `platform/4lock-core`).
- Or set `LOCK4_CORE_DIR` to the path to 4lock-core when building 4lock-agent.

See 4lock-agent docs for full build and run instructions.

## Packaging

- **systemd**: [packaging/systemd/vapp-core-daemon.service](../packaging/systemd/vapp-core-daemon.service) and [packaging/README-vapp-core-systemd.md](../packaging/README-vapp-core-systemd.md) – socket at `/run/vapp/vapp-core.sock`, user `vapp`.
- **4lock-de** Ansible can install the binary and unit from this repo or a release artifact.
