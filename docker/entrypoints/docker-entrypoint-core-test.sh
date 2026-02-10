#!/bin/sh
# Start daemon in background, wait for socket, run all tests, exit with test result.
set -e
SOCKET="${VAPPC_CORE_TEST_SOCKET:-/tmp/vapp-core/vapp-core.sock}"

echo "==> Running blob per-mirror auth tests (no daemon needed)..."
/usr/local/bin/per_mirror_auth_test || exit $?
echo "==> Blob tests passed!"

echo "==> Starting daemon for vappcore API tests..."
/usr/local/bin/vapp-core-daemon --socket /tmp/vapp-core.sock --app-dir /root/.vapp &
DAEMON_PID=$!

# Wait for socket (max 30s)
for i in $(seq 1 30); do
  if [ -S /tmp/vapp-core.sock ]; then
    break
  fi
  sleep 1
done

if ! [ -S /tmp/vapp-core.sock ]; then
  echo "Daemon socket not ready after 30s"
  kill $DAEMON_PID 2>/dev/null || true
  exit 1
fi

export VAPPC_CORE_TEST_SOCKET=/tmp/vapp-core.sock

echo "==> Running vappcore public API tests..."
RESULT=0
/usr/local/bin/public_api_test || RESULT=$?

if [ $RESULT -ne 0 ]; then
  echo "==> vappcore tests failed with exit code $RESULT"
  kill $DAEMON_PID 2>/dev/null || true
  exit $RESULT
fi

echo "==> vappcore tests passed!"

# Now test nerdctl integration (daemon already running with blob server on port 5050)
echo "==> Running nerdctl integration test..."
mkdir -p /var/lib/containerd

# Configure containerd to use blob server as mirror (BEFORE first start)
echo "==> Configuring containerd to use blob server as mirror (localhost:5050)..."
mkdir -p /etc/containerd
cat > /etc/containerd/config.toml <<'EOF'
version = 2
[plugins."io.containerd.grpc.v1.cri".registry]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
      endpoint = ["http://localhost:5050"]
EOF

# Now start containerd with the config already in place
echo "==> Starting containerd with blob server mirror configured..."
containerd > /tmp/containerd.log 2>&1 &
CONTAINERD_PID=$!

# Wait for containerd socket (containerd creates socket when ready)
echo "==> Waiting for containerd socket..."
for i in $(seq 1 15); do
  if [ -S /run/containerd/containerd.sock ]; then
    echo "==> containerd is ready (socket at /run/containerd/containerd.sock)"
    break
  fi
  sleep 1
done

if ! [ -S /run/containerd/containerd.sock ]; then
  echo "==> ERROR: containerd socket not ready after 15 seconds"
  echo "Containerd logs:"
  cat /tmp/containerd.log
  kill $CONTAINERD_PID $DAEMON_PID 2>/dev/null || true
  exit 1
fi

# Verify blob server is accessible
echo "==> Testing blob server connectivity..."
wget -q -O- http://localhost:5050/v2/ || {
  echo "==> ERROR: Blob server not responding on localhost:5050"
  kill $CONTAINERD_PID $DAEMON_PID 2>/dev/null || true
  exit 1
}

# Try to pull through blob server
echo "==> Attempting: nerdctl pull docker.io/library/alpine:latest"
echo "==> This will test the blob server's ability to fetch from upstream mirrors..."

if nerdctl pull docker.io/library/alpine:latest 2>&1 | tee /tmp/nerdctl-pull.log; then
  echo "==> nerdctl integration test PASSED!"
  RESULT=0
else
  echo ""
  echo "========================================"
  echo "==> nerdctl integration test FAILED"
  echo "========================================"
  echo ""
  echo "Blob server should be proxying to upstream Docker Hub mirrors."
  echo "Check logs above for 'error sending request' or auth failures."
  echo ""
  echo "nerdctl output:"
  cat /tmp/nerdctl-pull.log
  echo ""
  RESULT=1
fi

# Cleanup
kill $CONTAINERD_PID $DAEMON_PID 2>/dev/null || true

if [ $RESULT -eq 0 ]; then
  echo "==> All tests passed!"
else
  echo "==> Tests failed"
fi

exit $RESULT
