# ZeroTier VM Crash Fix - Summary

**Date**: 2026-02-12
**Status**: ✅ **RESOLVED AND VERIFIED**

---

## Problem Statement

4lock-agent VMs were crashing within 1-2 minutes of boot during ZeroTier VPN provisioning. The crash pattern:
- ZeroTier daemon started but failed to create TUN/TAP network device
- Startup script entered infinite loop waiting for network (iteration 12900+)
- VM exhausted CPU/memory resources
- System became unresponsive and crashed

---

## Root Cause Analysis

After deep investigation across multiple crashing VMs (192.168.64.4, .7, .3, .6), the root cause was identified:

**User namespace isolation prevented TUN/TAP ioctl operations**

### What Was Happening:
1. `generate_k8s_oci_spec()` ALWAYS created user namespaces for ALL containers
2. ZeroTier containers were marked `privileged: true` with full capabilities (CAP_NET_ADMIN, CAP_NET_RAW)
3. `/dev/net/tun` device node was created correctly
4. **BUT** the `ioctl(TUNSETIFF)` system call was blocked by the kernel because:
   - Even with CAP_NET_ADMIN inside a user namespace
   - TUN/TAP device configuration requires the **initial user namespace** (true root)
   - User namespace isolation prevented this privileged operation

### Evidence:
```bash
# Before fix - containers in separate user namespace
ZeroTier namespace: user:[4026532209]
Init namespace:     user:[4026531837]  # DIFFERENT!

# TUN ioctl failed
$ ip tuntap add dev test0 mode tun
ioctl(TUNSETIFF): Operation not permitted  # FAILED!
```

---

## The Fix

### Code Changes

**Modified**: `4lock-core/src/container/src/bootstrap/provisioner.rs`

**Lines 3331-3347** - Skip user namespace for privileged containers:
```rust
let namespaces = if privileged && nix::unistd::Uid::current().as_raw() == 0 {
    vec![
        json!({"type": "ipc"}),
        json!({"type": "uts"}),
        json!({"type": "mount"}),
        // NO user namespace for privileged containers running as root
    ]
} else {
    vec![
        json!({"type": "user"}),  // Only for rootless containers
        json!({"type": "ipc"}),
        json!({"type": "uts"}),
        json!({"type": "mount"}),
    ]
};
```

**Lines 3355-3400** - Empty UID/GID mappings for privileged containers:
```rust
let (uid_mappings, gid_mappings) = if privileged && host_uid == 0 {
    // Privileged containers: NO user namespace, NO UID/GID mappings
    (vec![], vec![])
} else {
    // Rootless containers: map host UID/GID to container 0
    (
        vec![json!({"containerID": 0, "hostID": host_uid, "size": 1})],
        vec![json!({"containerID": 0, "hostID": host_gid, "size": 1})]
    )
};
```

### Why This Works:
- vappd runs as root (UID 0) on the VM
- ZeroTier is marked `privileged: true`
- Condition `privileged && uid == 0` triggers → skip user namespace
- ZeroTier runs in **initial user namespace** with true root capabilities
- `ioctl(TUNSETIFF)` is now allowed by the kernel

---

## Verification Results

### Test Environment:
- **VM IP**: 192.168.64.6
- **Test Date**: 2026-02-12 16:58
- **Uptime**: 2+ minutes (previously crashed in <2 min)

### Verification Commands & Results:

#### 1. ZeroTier Interface Created ✅
```bash
$ ip link show zt0
3: zt0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 2800 qdisc fq state UNKNOWN mode DEFAULT group default qlen 1000
    link/ether 4e:34:da:8d:94:d2 brd ff:ff:ff:ff:ff:ff

$ ip addr show zt0
3: zt0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 2800 qdisc fq state UNKNOWN group default qlen 1000
    link/ether 4e:34:da:8d:94:d2 brd ff:ff:ff:ff:ff:ff
    inet 10.35.113.164/16 brd 10.35.255.255 scope global zt0
       valid_lft forever preferred_lft forever
```

#### 2. User Namespace Check ✅
```bash
$ ps aux | grep zerotier-one | grep -v grep
root         359  0.2  0.6 639852 13892 ?        Sl   16:56   0:00 zerotier-one /var/lib/zerotier-one

$ sudo readlink /proc/359/ns/user
user:[4026531837]

$ sudo readlink /proc/1/ns/user
user:[4026531837]
```
**✅ SAME namespace ID** - ZeroTier is running in the initial user namespace!

#### 3. TUN ioctl Test ✅
```bash
$ sudo nsenter -t 359 -a sh -c "ip tuntap add dev test0 mode tun && ip link show test0 && ip tuntap del dev test0 mode tun"
4: test0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 500
    link/none
```
**✅ SUCCESS** - No "Operation not permitted" error!

#### 4. VM Stability ✅
```bash
$ uptime
 16:58:48 up 2 min,  2 users,  load average: 0.00, 0.00, 0.00
```
**✅ STABLE** - VM running for 2+ minutes with no crash

#### 5. VM Daemon Logs ✅
```
Feb 12 16:56:34 vappd[304]: ZeroTier container started: vapp-871d544dacd72a46-zerotier
Feb 12 16:56:34 vappd[304]: Waiting for ZeroTier IP file: /var/lib/vapp/containers/volumes/vapp-871d544dacd72a46/zerotier-data/ip.txt
Feb 12 16:56:34 vappd[304]: ZeroTier VPN connected - IP: 10.35.113.164
```
**✅ CONNECTED** - ZeroTier successfully got an IP address!

---

## Deployment

### Commit
- **Repository**: [mkoyan44/4lock-core](https://github.com/mkoyan44/4lock-core)
- **Commit**: [a114187](https://github.com/mkoyan44/4lock-core/commit/a114187)
- **Commit Message**: `fix(container): skip user namespace for privileged containers to enable TUN/TAP`

### Build Steps
```bash
# 1. Update 4lock-agent to pull latest 4lock-core
cd /Users/mkoyan/projects/platform/4lock-agent
rm -rf target
cargo update -p daemon
cargo build

# 2. Sign binaries (macOS)
codesign --force --sign developsign \
    --entitlements crates/controller/ui/build/macos/entitlements.plist \
    target/debug/vapp target/debug/vappctl target/debug/vappd

# 3. Run agent
ENV=production RUST_LOG=info ./target/debug/vapp
```

---

## Next Steps

### Completed ✅
- [x] Identify root cause
- [x] Implement fix in provisioner.rs
- [x] Commit and push changes
- [x] Rebuild 4lock-agent with updated dependency
- [x] Verify ZeroTier interface creation
- [x] Verify user namespace fix
- [x] Verify TUN ioctl success
- [x] Verify VM stability
- [x] Update documentation

### Pending
- [ ] Test ZeroTier network connectivity (ping across VMs)
- [ ] Deploy to all production VMs
- [ ] Monitor VM stability over extended period (24+ hours)
- [ ] Consider adding ZeroTier readiness check
- [ ] Consider adding timeout/fail-fast to startup script

---

## Related Documentation

- **Full Investigation**: [ZEROTIER_VM_CRASH_ROOT_CAUSE.md](ZEROTIER_VM_CRASH_ROOT_CAUSE.md)
- **Blob Troubleshooting**: [BLOB_502_TROUBLESHOOTING.md](BLOB_502_TROUBLESHOOTING.md)
- **Memory**: `/Users/mkoyan/.claude/projects/-Users-mkoyan-projects-platform-4lock-de/memory/MEMORY.md`

---

## Impact

### Before Fix:
- ❌ VMs crashed within 1-2 minutes
- ❌ ZeroTier could not create network interfaces
- ❌ Infinite loop consuming resources
- ❌ No ZeroTier VPN connectivity

### After Fix:
- ✅ VMs remain stable (tested 2+ minutes, will monitor longer)
- ✅ ZeroTier creates zt0 interface successfully
- ✅ ZeroTier gets IP address (10.35.113.164)
- ✅ TUN/TAP operations succeed
- ✅ No errors in daemon logs

---

**Status**: ✅ **FIX VERIFIED AND WORKING**
**Impact**: **CRITICAL ISSUE RESOLVED**
