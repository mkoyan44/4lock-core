# Blob (Docker-Proxy) 502 Bad Gateway – Troubleshooting

## What the error means

When you see:

```text
Docker-proxy returned error 502 Bad Gateway for layer sha256:...
```

the **blob server is running** and the request reached it. The 502 is returned because the **upstream registry** (e.g. Docker Hub `registry-1.docker.io`) could not be reached from the VM. So the problem is **VM → internet** (or VM → registry), not “blob not starting”.

Typical log line from the VM when this happens:

```text
blob::registry::mirror_racer: All mirrors failed with no response ... error sending request for url (https://registry-1.docker.io/v2/library/alpine/blobs/sha256:...)
```

So: **blob is up; upstream (Docker Hub) is unreachable from the VM.**

---

## VM diagnostics (SSH into the VM)

Use the VM’s IP (e.g. `192.168.64.9`) and credentials (e.g. `devopsadmin` / `devopsadmin`).

### 1. Check that blob (docker-proxy) is listening

```bash
# Blob should listen on 0.0.0.0:5050
ss -tlnp | grep 5050
# or
netstat -tulpn | grep 5050
```

Expected: `0.0.0.0:5050` (or `:::5050`) with PID of `vappc-linux-daemon` / `vapp-core-daemon`.

### 2. Check blob health

```bash
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5050/health
# Expect: 200
```

### 3. Check registry API through blob (v2)

```bash
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5050/v2/
# Expect: 200 or 401 (both mean blob is responding)
```

### 4. Check VM → Docker Hub (upstream)

```bash
# Can the VM reach Docker Hub at all?
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://registry-1.docker.io/v2/
# Expect: 200 or 401. If timeout or connection error, VM has no route to Docker Hub.
```

### 5. Try nerdctl pull from the VM (optional)

If nerdctl/containerd are installed and configured to use the blob as a mirror:

```bash
# Use blob as insecure registry (localhost:5050)
nerdctl pull --insecure-registry localhost:5050 alpine:latest
# Or pull directly from Docker Hub (tests VM outbound)
nerdctl pull alpine:latest
```

If direct `nerdctl pull alpine:latest` fails with timeout/connection error, the VM cannot reach Docker Hub; fix network/DNS first.

### 6. When VM has internet (curl → 401) but blob still returns 502

If `curl -s -o /dev/null -w "%{http_code}" https://registry-1.docker.io/v2/` returns **401** (or 200) but pulls still fail with 502:

- **Retry provisioning** – the failure may be transient (Docker Hub rate limit or brief outage).
- **IPv6 vs IPv4** – `getent hosts registry-1.docker.io` may show only IPv6. From the VM run:
  - `curl -4 -s -o /dev/null -w "%{http_code}" https://registry-1.docker.io/v2/` (force IPv4)
  - `curl -6 -s -o /dev/null -w "%{http_code}" https://registry-1.docker.io/v2/` (force IPv6)
  If one of these fails (timeout/000) and the other succeeds, the blob’s client was using the failing family. **Fix applied in code**: the blob crate uses an **IPv4-prefer DNS resolver** for upstream registry connections (`src/blob/src/dns.rs`). It resolves hostnames and returns only IPv4 addresses when present, so VMs with IPv6-only DNS but no IPv6 route now pull over IPv4. Rebuild and redeploy the daemon (vapp-core-daemon) that embeds the blob to pick up the fix.

### 7. Capture daemon logs (vappd)

```bash
# If running under systemd
journalctl -u vappd -n 200 --no-pager

# Or if running in foreground, capture stderr
# Look for:
# - "Blob (docker-proxy) server started on 0.0.0.0:5050"
# - "Blob (docker-proxy) ready"
# - "Mirror request failed" / "All mirrors failed" (confirms upstream unreachable)
```

---

## Fix plan

### A. Ensure blob is ready before first pull (code)

The daemon now **waits for blob `/health`** (up to 15s) before printing “ready” and accepting commands. That avoids “connection refused” if a Start command arrives before blob has bound. It does **not** fix 502 when upstream is unreachable.

### B. Fix VM outbound connectivity (main fix for 502)

502 means blob cannot reach the registry. Fix one of:

1. **DNS (on the VM)**  
   - Ensure the VM can resolve `registry-1.docker.io`.  
   - Test: `getent hosts registry-1.docker.io` or `nslookup registry-1.docker.io`.

2. **Firewall / proxy**  
   - Allow outbound HTTPS (443) from the VM to the internet (or to your proxy).  
   - If you use an HTTP proxy, blob must be configured to use it (see blob/config and upstream TLS/proxy settings if supported).

3. **Network / NAT**  
   - Ensure the VM has a route to the internet and that NAT (if any) allows outbound HTTPS.

4. **Fallback mirrors (built-in)**  
   - The blob uses **Failover** for `docker.io`: primary `registry-1.docker.io`, then `docker.m.daocloud.io`, then `registry.dockermirror.com`. If the primary is unreachable (e.g. IPv6-only DNS), the blob tries the next mirror. **Anonymous pull is supported** (no login) for public images on the primary and on `docker.m.daocloud.io`; the blob obtains a Bearer token from each mirror’s auth endpoint when required. No config change needed; rebuild/redeploy the daemon to pick up the default.  
   - To check from the VM which upstreams respond:
     - `curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://registry-1.docker.io/v2/` → 200 or 401
     - `curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://docker.m.daocloud.io/v2/` → 200 or 401
     - `curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://registry.dockermirror.com/v2/` → 200 or 401 (when available)
   - These are third-party mirrors; availability may vary by region and over time.

### C. Verify after changes

1. From the VM: `curl -s -o /dev/null -w "%{http_code}" https://registry-1.docker.io/v2/` → 200 or 401 (and optionally the fallback URLs above).  
2. Restart the daemon and trigger a pull again; 502 should disappear if at least one upstream is reachable.

---

## Quick reference

| Symptom | Meaning | Action |
|--------|--------|--------|
| No process on 5050 | Blob not listening | Check daemon logs for “Blob (docker-proxy) failed to start”; fix bind/crash. |
| Connection refused to 5050 | Blob not ready yet or not started | Ensure daemon has blob readiness wait; check startup order. |
| 502 Bad Gateway from blob | Upstream (e.g. Docker Hub) unreachable from VM | Blob tries fallbacks (docker.m.daocloud.io, registry.dockermirror.com). Fix VM DNS/network; test with `curl https://registry-1.docker.io/v2/` and fallback URLs; nerdctl pull. |

---

## Related

- Blob server: `src/blob/`, started from `src/vappcore/src/bin/vappc.rs`.
- Image manager (pull path): `src/container/src/bootstrap/image_manager.rs` (detects blob URL, pulls via blob; surfaces “Docker-proxy returned error 502 …” when blob returns 502).
- Daemon startup: blob is spawned first, then daemon waits for `http://127.0.0.1:5050/health` before reporting ready.
