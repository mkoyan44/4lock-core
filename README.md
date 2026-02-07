# 4lock-core

Core crates and tooling for the 4lock platform (Linux only).

- **src/blob** – Registry proxy (image pull cache).
- **src/container** – Rootless OCI/CRI runtime, bootstrap, provisioning.
- **src/vappc** – vappc daemon and client (Unix/VSOCK socket API for 4lock-agent).
- **docs/** – [docs/README.md](docs/README.md) – build, run, packaging.
- **packaging/** – systemd unit and [README](packaging/README-vappc-systemd.md).

**Build** (from repo root, Linux only):

```bash
cargo build -p daemon
# or binary only:
cargo build -p vappc --release --bin vappc-linux-daemon
```

**Build and run with nerdctl** (Makefile + `docker/`):

```bash
# Default: build then run (no .env required; TARGET_ARCH auto-detected)
make                  # same as: make from-scratch

# Explicit from-scratch
make from-scratch     # or: make build && make run

# Release build (uses BuildKit cache; later rebuilds only recompile changed crates)
make build
make run               # --privileged; socket at /tmp/vappc; Ctrl+C stops container and exits

# Fast iteration when changing code in src/: dev profile + cache mounts
make build-dev && make run-dev

# Optional .env for push: GH_OWNER, GH_TOKEN
make push
make all
```

Consumed by [4lock-agent](https://github.com/4lock/4lock-agent) as a path or git dependency.
