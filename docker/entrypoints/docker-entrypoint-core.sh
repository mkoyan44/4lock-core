#!/bin/sh
# Entrypoint for 4lock-core vapp-core-daemon (same approach as 4lock-api entrypoint).
# Exec daemon with CMD args; override by passing args to docker run.
set -e
if [ -n "$*" ]; then
    exec /usr/local/bin/vapp-core-daemon "$@"
else
    exec /usr/local/bin/vapp-core-daemon --socket /tmp/vapp-core.sock --app-dir /root/.vapp
fi
