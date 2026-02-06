# Docker-Proxy

A container registry proxy that caches images locally and provides a unified interface for multiple upstream registries.

## Features

- **Multi-Registry Support**: Proxy requests to docker.io, quay.io, ghcr.io, registry.k8s.io, and more
- **Local Caching**: Cache manifests and blobs locally to reduce upstream requests
- **Mirror Strategies**: Support for failover, hedged, striped, and adaptive mirror selection
- **Containerd Compatible**: Full support for containerd's image pull workflow (tag + digest caching)
- **HTTPS/TLS**: Optional TLS support with self-signed certificate generation
- **Embedded Registry Support**: Handle image URLs with embedded registry names (e.g., `docker-proxy:5050/quay.io/cilium/cilium:v1.17.7`)

## Structure

```
crates/technology/docker-proxy/
├── src/              # Source code (no inline tests)
├── tests/            # All tests (unit + integration)
│   ├── integration_test.rs
│   ├── manifest_test.rs
│   ├── mirror_racer_test.rs
│   ├── config_test.rs
│   └── cache_storage_test.rs
├── examples/         # Example usage code
│   ├── basic_server.rs
│   ├── custom_config.rs
│   └── https_server.rs
└── Cargo.toml
```

## Testing Rules

**All tests MUST be in the `tests/` directory, NOT in source files.**

- ✅ **Tests in `tests/`**: Unit tests and integration tests
- ❌ **No `#[cfg(test)]` modules in `src/`**: All tests moved to `tests/`
- ✅ **Examples in `examples/`**: Demonstration code

## Running Tests

```bash
# Run all tests
cargo test -p docker-proxy

# Run specific test file
cargo test --test integration_test
cargo test --test manifest_test

# Run specific test
cargo test --test manifest_test test_parse_repository_with_embedded_registry
```

## Running Examples

```bash
# Basic server
cargo run --example basic_server

# Custom configuration
cargo run --example custom_config

# HTTPS server
cargo run --example https_server
```

## Documentation

- **Tests**: See `tests/README.md` for test organization and coverage
- **Examples**: See `examples/README.md` for example usage

