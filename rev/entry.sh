#!/bin/sh
# rev sandbox entrypoint.
#
# Starts the `emulate` web GUI (a small convenience on top of the CLI), then
# hands PID 1 to the web terminal (ttyd). If the GUI dies the terminal keeps
# working; both live inside the isolated sandbox and are reached from the host
# through the localhost socat proxies only.
set -eu

REV_WEB_HOST="${REV_WEB_HOST:-0.0.0.0}" REV_WEB_PORT="${REV_WEB_PORT:-8080}" \
  rev-web &

exec ttyd -W -p 7681 -t fontSize=14 bash -l
