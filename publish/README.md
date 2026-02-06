# Publish vappc-linux-daemon to Nexus

Separate crate in `publish/` used only to build `vappc-linux-daemon` for Linux (amd64 + arm64) and upload to Nexus (cargo/artifact repo). Main 4lock-core code is unchanged.

**To have data available on the repo**, set `NEXUS_USERNAME` and `NEXUS_PASSWORD`; the build will then require at least one successful upload.

## Run (from 4lock-core root)

```bash
# Clean, build daemon, then publish (build Linux binaries + upload to Nexus)
cargo clean
cargo build --release -p daemon

# Set credentials so artifacts are uploaded and available on the repo (never commit these)
export NEXUS_URL="${NEXUS_URL:-https://nexus.4lock.net}"
export NEXUS_REPO="${NEXUS_REPO:-4lock-core}"
export NEXUS_USERNAME="your-username"
export NEXUS_PASSWORD="your-password"

# Optional: use nerdctl instead of Docker
export CROSS_CONTAINER_ENGINE=nerdctl

cargo build --release -p publish
```

## Requirements

- **cross**: Required for building Linux binaries. Install with `cargo install cross`.
- **Container engine**: Either **Docker** (default) or **nerdctl** (set `CROSS_CONTAINER_ENGINE=nerdctl`). Ensure the engine is running (e.g. `nerdctl info` or `docker info`).
- **Linux**: If both target toolchains are installed natively, `cargo build` may succeed without cross; otherwise the script falls back to `cross build`.
- **macOS / Windows**: Uses `cross build` (no native Linux toolchain); nerdctl or Docker must be available.

## What it does

1. Builds `vappc-linux-daemon` for each Linux target (native `cargo build` when possible, else `cross build`). `daemon/Cross.toml` configures the cross build (e.g. OpenSSL for cross images).
2. Computes version string (vappc version + short git rev, e.g. `0.1.0-90ccccc`).
3. PUTs each binary to Nexus at `vappc-linux-daemon/<version>/<target_triple>/vappc-linux-daemon`.

## CI

Run `cargo build --manifest-path publish/Cargo.toml` with `NEXUS_USERNAME` and `NEXUS_PASSWORD` from secrets.
