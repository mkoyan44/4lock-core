# 4lock-core – Development Guide

Practical guidance for building, running, and testing 4lock-core. **Linux-only** for native runs; use Makefile + nerdctl for containerized build/run on any host.

## Prerequisites

- **Rust** 1.71+ (for native Linux build).
- **Linux** for `cargo build` / `cargo test` of container/vappcore (rootless OCI is Linux-only).
- **nerdctl** (or Docker) for `make build` / `make run` when not on Linux or when using containerized workflow.

## Workspace layout

- **Crates**: `src/blob`, `src/container`, `src/vappcore`. Virtual package `daemon` for building all daemon-related crates.
- **Makefile**: `build`, `run`, `build-dev`, `run-dev`, `from-scratch`, `push`, `all`. Uses `docker/dockerfiles/Dockerfile.core` and `docker/entrypoints/docker-entrypoint-core.sh`.
- **.env** (optional): `TARGET_ARCH` (arm64/amd64), `GH_OWNER`, `GH_TOKEN` (for push). `TARGET_ARCH` is auto-detected from host if unset.

## Build and run

### On Linux (native)

```bash
# All daemon crates
cargo build -p daemon

# vapp-core daemon binary (release)
cargo build -p vappcore --release --bin vapp-core-daemon

# Run tests
cargo test
cargo test -p container
cargo test -p blob
cargo test -p vappcore
```

### Any host (container via Makefile)

```bash
# Default: build then run (release image)
make
# or explicitly:
make from-scratch

# Build and run separately
make build
make run

# Dev profile (faster recompile when changing src/)
make build-dev
make run-dev
```

- `make run` / `make run-dev`: container is `--privileged` and mounts `/tmp/vapp-core:/tmp` (daemon socket).
- Image name: `4lock-core` (local) or `ghcr.io/<GH_OWNER>/4lock-core-<TARGET_ARCH>` when `GH_OWNER` is set.

### Run behavior (Ctrl+C exit)

- The Makefile runs the container **detached** (`-d`) under a fixed name (`4lock-core-run`), then attaches with `nerdctl logs -f` so you see daemon output. **Ctrl+C** in the terminal stops the container and removes it, then exits the Make target. No need to use another terminal to stop the container.
- nerdctl does not allow `-d` and `--rm` together; the Makefile therefore omits `--rm` and runs `nerdctl stop` + `nerdctl rm -f` explicitly (in the trap on Ctrl+C and at the end of the recipe).
- The daemon binary also handles **SIGINT** (Ctrl+C) when run in the foreground; in the Makefile workflow the shell trap ensures the container is stopped and removed on interrupt.

## Development workflow

1. **Edit code** under `src/blob`, `src/container`, or `src/vappcore`.
2. **Check**: `cargo check --workspace` or `cargo check -p container` etc.
3. **Test**: `cargo test -p <crate>` for the crate you changed.
4. **Format/lint**: `cargo fmt`, `cargo clippy --all-targets --all-features` (or scoped by `-p`).
5. **Run in container**: `make build-dev && make run-dev` for fast iteration (BuildKit cache mounts + dev profile).

## Adding a feature

1. **Place in the right crate** – See `docs/architecture/CRATE_ARCHITECTURE.md` (blob vs container vs vappcore).
2. **Bootstrap tasks** – Keep idempotent; validate template variables; use numbered script names.
3. **CRI/OCI** – Follow existing patterns in `container/cri/` and `container/rootless/`.
4. **Protocol** – Any new daemon commands go in vappcore (protocol + daemon + client).

## Testing

- Unit tests live next to code or in `src/<crate>/tests/`.
- Integration tests: `src/blob/tests/`, `src/container/tests/`, `src/vappcore/tests/`.
- Run full workspace: `cargo test --workspace`.

## Packaging

- **systemd**: `packaging/systemd/vapp-core-daemon.service`, `packaging/README-vapp-core-systemd.md`.
- **4lock-de**: Ansible can deploy binary and unit from this repo or a release artifact.

## 4lock-agent integration

- Agent depends on 4lock-core (daemon package) and builds **vapp-core-daemon** from this repo for Linux. Agent provides **VappClient** for the high-level API.
- Clone 4lock-core next to 4lock-agent or set `LOCK4_CORE_DIR` when building the agent.
- See 4lock-agent docs for full flow.
