# Docker-Proxy Tests

This directory contains all tests for the docker-proxy crate, organized by component.

## Test Organization

Tests are organized into separate files by component:

- **`integration_test.rs`** - Integration tests for complete server functionality
- **`manifest_test.rs`** - Unit tests for manifest handling and repository parsing
- **`mirror_racer_test.rs`** - Unit tests for mirror statistics and selection strategies
- **`config_test.rs`** - Unit tests for configuration parsing and validation
- **`cache_storage_test.rs`** - Unit tests for cache storage and blob deduplication
- **`cache_miss_test.rs`** - Unit tests for cache miss scenarios and race conditions

## Running Tests

Run all tests:

```bash
cargo test -p docker-proxy
```

Run a specific test file:

```bash
cargo test --test integration_test
cargo test --test manifest_test
cargo test --test mirror_racer_test
cargo test --test config_test
cargo test --test cache_storage_test
cargo test --test cache_miss_test
```

Run a specific test:

```bash
cargo test --test integration_test test_server_startup_and_health
```

## Test Coverage

### Integration Tests (`integration_test.rs`)

- **Server Startup**: Server initialization and health endpoint
- **Manifest Caching**: Caching by tag and digest (containerd compatibility)
- **Embedded Registry**: Image pulling with embedded registry names (Helm chart format)
- **Cache Persistence**: Cache behavior across server restarts
- **Blob Fetching**: Blob download and caching
- **Configuration**: Config file loading and validation

### Unit Tests

**Manifest Tests (`manifest_test.rs`):**
- Repository parsing with embedded registries
- Upstream client auto-detection
- Registry config auto-detection
- Path parsing for embedded registries
- Helm chart image URL format parsing
- Containerd request simulation
- Manifest caching by tag and digest

**Mirror Racer Tests (`mirror_racer_test.rs`):**
- Mirror statistics (default, success, error recording)
- Score calculation
- Error penalty
- Success rate
- Mirror selection strategies (Failover, Hedged, Striped, Adaptive)
- Stats updates

**Config Tests (`config_test.rs`):**
- Mirror strategy parsing (from_str, deserialize)
- Registry config validation
- Default values
- Strategy defaults

**Cache Storage Tests (`cache_storage_test.rs`):**
- Blob download deduplication (single request, concurrent requests)
- Different digests handling
- Error propagation
- Blob path handling
- Blob existence checks

**Cache Miss Tests (`cache_miss_test.rs`):**
- Pre-pull then immediate lookup scenarios
- Race conditions during atomic file writes (temp file handling)
- Filesystem sync issues (immediate visibility after write)
- Async metadata checks vs synchronous exists() checks
- Empty file detection and cleanup
- Concurrent write and read operations
- Parent directory sync after rename
- Multiple concurrent writes to the same blob
- Complete pre-pull workflow simulation

## Test Requirements

- Network access to upstream registries (quay.io, docker.io) for integration tests
- Temporary directory for cache storage
- Unique ports for parallel test execution (integration tests use ports 5050-5057)

## Notes

- Integration tests may fail if network is unavailable (401/404 responses are acceptable)
- All tests use temporary directories that are cleaned up automatically
- Integration tests use unique ports to avoid conflicts when running in parallel
- Unit tests do not require network access

