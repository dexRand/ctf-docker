#!/bin/sh
# rev sandbox entrypoint (usato da due servizi).
#
#   rev   (:19018)  terminale semplice + GUI di emulazione (rev-web)
#   shell (:19021)  terminale "puro" con pane/tab (zellij), senza rev-web
#
# Selezione con l'ambiente:
#   REV_WEB_ENABLE=0   non avviare la GUI di emulazione
#   REV_MUX=zellij     terminale dentro una sessione zellij (split/tab/persistenza)
#
# Entrambi vivono nel sandbox isolato e sono raggiunti dal localhost (proxy o
# porta pubblicata): il container non espone altro.
set -eu

if [ "${REV_WEB_ENABLE:-1}" = "1" ]; then
  REV_WEB_HOST="${REV_WEB_HOST:-0.0.0.0}" REV_WEB_PORT="${REV_WEB_PORT:-8080}" \
    rev-web &
fi

# house palette (green-on-black) so the terminals match the rest of the toolbox
THEME='{"background":"#0c0e10","foreground":"#d7dde3","cursor":"#45e08c","selectionBackground":"#263138","black":"#14171a","red":"#ff6b6b","green":"#45e08c","yellow":"#e8c07d","blue":"#7aa2f7","magenta":"#c792ea","cyan":"#7dcfff","white":"#d7dde3","brightBlack":"#5b6570","brightRed":"#ff8a8a","brightGreen":"#63f08b","brightYellow":"#f0d39a","brightBlue":"#9ab8ff","brightMagenta":"#dbb0f5","brightCyan":"#a5e3ff","brightWhite":"#eef4f8"}'

case "${REV_MUX:-}" in
  zellij) exec ttyd -W -p 7681 -t fontSize=14 -t "theme=$THEME" \
                   zellij attach --create main ;;
  *)      exec ttyd -W -p 7681 -t fontSize=14 -t "theme=$THEME" bash -l ;;
esac
