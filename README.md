# 4lock-core

Core crates and tooling for the 4lock platform.

- **daemon/** – Primary code: blob (registry proxy), container (OCI/CRI runtime), vappc (daemon + client). See [daemon/README.md](daemon/README.md).
- **publish/** – Builds `vappc-linux-daemon` for Linux targets and uploads to Nexus (cargo/artifact repo). See [publish/README.md](publish/README.md).

**Build** (from repo root):

```bash
cargo build -p daemon          # or cargo build --release -p daemon
```

**Publish** (build Linux binaries and make data available on Nexus):

```bash
# Required for upload; without these, build still runs but nothing is uploaded
export NEXUS_USERNAME="..."
export NEXUS_PASSWORD="..."
cargo build --release -p publish
```

When `NEXUS_USERNAME` and `NEXUS_PASSWORD` are set, the publish step **requires** at least one successful upload so that artifacts are available on the repo. See [publish/README.md](publish/README.md) for cross/Docker and CI.

Consumed by [4lock-agent](https://github.com/4lock/4lock-agent) as a path or git dependency.
