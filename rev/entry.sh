#!/bin/sh
# rev sandbox entrypoint.
#
# Starts the `emulate` web GUI (a small convenience on top of the CLI), then
# hands PID 1 to the web terminal (ttyd). If the GUI dies the terminal keeps
# working; both live inside the isolated sandbox and are reached from the host
# through the localhost socat proxies only.
set -eu

EMULATE_HOST="${EMULATE_HOST:-0.0.0.0}" EMULATE_PORT="${EMULATE_PORT:-8080}" \
  emulate-web &

exec ttyd -W -p 7681 -t fontSize=14 bash -l
