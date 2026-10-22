#!/bin/sh
# rev sandbox entrypoint.
#
# Starts the `emulate` web GUI (a small convenience on top of the CLI), then
# hands PID 1 to the web terminal (ttyd). If the GUI dies the terminal keeps
# working; both live inside the isolated sandbox and are reached from the host
# through the localhost socat proxies only.
#
# For panes/tabs use code-server (`term`, :19022): its `rev` terminal profile
# runs `docker exec` into this container.
set -eu

REV_WEB_HOST="${REV_WEB_HOST:-0.0.0.0}" REV_WEB_PORT="${REV_WEB_PORT:-8080}" \
  rev-web &

# house palette (green-on-black) so the terminal matches the rest of the toolbox
THEME='{"background":"#0c0e10","foreground":"#d7dde3","cursor":"#45e08c","selectionBackground":"#263138","black":"#14171a","red":"#ff6b6b","green":"#45e08c","yellow":"#e8c07d","blue":"#7aa2f7","magenta":"#c792ea","cyan":"#7dcfff","white":"#d7dde3","brightBlack":"#5b6570","brightRed":"#ff8a8a","brightGreen":"#63f08b","brightYellow":"#f0d39a","brightBlue":"#9ab8ff","brightMagenta":"#dbb0f5","brightCyan":"#a5e3ff","brightWhite":"#eef4f8"}'

exec ttyd -W -p 7681 -t fontSize=14 -t "theme=$THEME" bash -l
