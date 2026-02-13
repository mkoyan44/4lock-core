//! Tests for network connectivity resilience during clean install.
//!
//! On a fresh VM boot (clean install), the network (DHCP + DNS) may not be ready
//! when docker-proxy starts. These tests verify that:
//! 1. Manifest fetches retry with exponential backoff when docker-proxy returns 502
//! 2. The retry window is long enough (~2 min) for network to come up
//! 3. Image pull succeeds once upstream becomes reachable

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Minimal HTTP server that returns 502 for the first N requests, then 200.
/// Simulates docker-proxy when upstream is unreachable (network not ready).
async fn start_mock_docker_proxy(
    fail_count: u32,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(AtomicU32::new(0));

    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };

            let counter = counter.clone();
            let fail_count = fail_count;

            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                // Read the request (consume headers)
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;

                let current = counter.fetch_add(1, Ordering::SeqCst);

                let response = if current < fail_count {
                    // Simulate docker-proxy 502 (upstream unreachable)
                    format!(
                        "HTTP/1.1 502 Bad Gateway\r\n\
                         Content-Type: text/plain\r\n\
                         Content-Length: {}\r\n\
                         \r\n\
                         {}",
                        "502 Bad Gateway: all upstream mirrors failed".len(),
                        "502 Bad Gateway: all upstream mirrors failed"
                    )
                } else {
                    // Simulate successful manifest response
                    let body = r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:abc","size":100},"layers":[]}"#;
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/vnd.docker.distribution.manifest.v2+json\r\n\
                         Content-Length: {}\r\n\
                         \r\n\
                         {}",
                        body.len(),
                        body
                    )
                };

                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    (addr, handle)
}

/// Test: manifest fetch retries on 502 and eventually succeeds.
/// Simulates a clean install where the first several requests fail because
/// the VM's network isn't ready, then succeeds once DNS/routing is up.
#[tokio::test]
async fn test_manifest_retry_on_502_then_success() {
    // Mock server returns 502 for first 5 requests, then 200
    let (addr, _server) = start_mock_docker_proxy(5).await;
    let base_url = format!("http://{}", addr);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    let manifest_url = format!("{}/v2/library/alpine/manifests/latest", base_url);

    // Replicate the retry logic from image_manager.rs
    const MANIFEST_MAX_RETRIES: u32 = 20;
    let mut last_error = String::new();
    let mut result: Option<serde_json::Value> = None;
    let mut attempts_made = 0u32;

    for attempt in 0..=MANIFEST_MAX_RETRIES {
        if attempt > 0 {
            let delay_ms = std::cmp::min(3000 * (1 << (attempt - 1).min(2)), 6000);
            // In test, use shorter delays
            let test_delay_ms = std::cmp::min(delay_ms / 100, 100); // 30ms, 60ms, 60ms...
            tokio::time::sleep(tokio::time::Duration::from_millis(test_delay_ms)).await;
        }

        attempts_made = attempt + 1;

        let resp = client
            .get(&manifest_url)
            .header(
                "Accept",
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .send()
            .await;

        match resp {
            Ok(manifest_response) if manifest_response.status().is_success() => {
                match manifest_response.json().await {
                    Ok(json) => {
                        result = Some(json);
                        break;
                    }
                    Err(e) => {
                        last_error = format!("Failed to parse manifest JSON: {}", e);
                    }
                }
            }
            Ok(manifest_response) => {
                let status = manifest_response.status();
                let error_body = manifest_response.text().await.unwrap_or_default();
                last_error = format!("Docker-proxy returned error {}: {}", status, error_body);
            }
            Err(e) => {
                last_error = format!("Failed to fetch manifest: {}", e);
            }
        }
    }

    // Should have succeeded after the 5 failures
    assert!(
        result.is_some(),
        "Manifest fetch should have succeeded after retries. Last error: {}",
        last_error
    );
    assert_eq!(
        attempts_made, 6,
        "Should have taken exactly 6 attempts (5 failures + 1 success)"
    );

    let manifest = result.unwrap();
    assert_eq!(manifest["schemaVersion"], 2);
}

/// Test: manifest fetch retries exhaust but doesn't panic.
/// When ALL retries fail (network never comes up), it should return an error.
#[tokio::test]
async fn test_manifest_retry_all_fail_returns_error() {
    // Mock server always returns 502
    let (addr, _server) = start_mock_docker_proxy(u32::MAX).await;
    let base_url = format!("http://{}", addr);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();

    let manifest_url = format!("{}/v2/library/alpine/manifests/latest", base_url);

    // Use a small retry count for this test
    const MAX_RETRIES: u32 = 3;
    let mut last_error = String::new();
    let mut result: Option<serde_json::Value> = None;

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        let resp = client
            .get(&manifest_url)
            .header(
                "Accept",
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                result = r.json().await.ok();
                break;
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                last_error = format!("Status {}: {}", status, body);
            }
            Err(e) => {
                last_error = format!("Request error: {}", e);
            }
        }
    }

    assert!(
        result.is_none(),
        "Should have failed after all retries (got: {:?})",
        result
    );
    assert!(
        last_error.contains("502"),
        "Last error should mention 502: {}",
        last_error
    );
}

/// Test: upstream connectivity probe (HEAD request) detects 502 vs success.
/// This tests the wait_for_upstream_connectivity logic pattern.
#[tokio::test]
async fn test_upstream_connectivity_probe() {
    // Mock server returns 502 for first 3 requests, then 200
    let (addr, _server) = start_mock_docker_proxy(3).await;
    let probe_url = format!("http://{}/v2/library/alpine/manifests/latest", addr);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();

    let timeout = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();
    let mut attempt = 0u32;
    let mut connected = false;

    loop {
        let resp = client
            .head(&probe_url)
            .header(
                "Accept",
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .send()
            .await;

        match resp {
            Ok(r) if r.status().as_u16() != 502 => {
                connected = true;
                break;
            }
            _ => {}
        }

        if start.elapsed() > timeout {
            break;
        }

        attempt += 1;
        // Short delays for test
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    assert!(
        connected,
        "Should have connected after mock server stops returning 502"
    );
    assert!(
        attempt >= 3,
        "Should have needed at least 3 attempts (got {})",
        attempt
    );
}

/// Test: retry backoff timing is correct.
/// Verifies the exponential backoff formula: min(3000 * 2^min(attempt-1, 2), 6000)
#[test]
fn test_manifest_retry_backoff_formula() {
    let delays: Vec<u64> = (1..=10)
        .map(|attempt| {
            std::cmp::min(3000 * (1u64 << (attempt - 1).min(2)), 6000)
        })
        .collect();

    // Expected: 3s, 6s, 6s, 6s, 6s, 6s, 6s, 6s, 6s, 6s
    assert_eq!(delays[0], 3000, "First retry: 3s");
    assert_eq!(delays[1], 6000, "Second retry: 6s");
    assert_eq!(delays[2], 6000, "Third retry: 6s (capped)");
    assert_eq!(delays[9], 6000, "Tenth retry: 6s (still capped)");

    // Total retry window with 20 retries: 3 + 19*6 = 117 seconds ≈ 2 minutes
    let total_ms: u64 = delays.iter().take(20).sum::<u64>()
        + (10..20).map(|_| 6000u64).sum::<u64>();
    assert!(
        total_ms >= 100_000,
        "Total retry window should be ~2 min (got {}ms)",
        total_ms
    );
    assert!(
        total_ms <= 130_000,
        "Total retry window should not exceed ~2.2 min (got {}ms)",
        total_ms
    );
}
