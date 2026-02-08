#!/bin/sh
# Start daemon in background, wait for socket, run public API tests, exit with test result.
set -e
SOCKET="${VAPPC_CORE_TEST_SOCKET:-/tmp/vapp-core/vapp-core.sock}"

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

RESULT=0
/usr/local/bin/public_api_test || RESULT=$?
kill $DAEMON_PID 2>/dev/null || true
exit $RESULT
