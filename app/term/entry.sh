#!/bin/sh
# Terminale CTF (:19022): ttyd -> zellij, a tema con la SPA StegSuite.
set -eu
THEME='{"background":"#0c0e10","foreground":"#d7dde3","cursor":"#45e08c","cursorAccent":"#0c0e10","selectionBackground":"#143325","black":"#14171a","red":"#ff6166","green":"#45e08c","yellow":"#f5c542","blue":"#5fd0f2","magenta":"#c792ea","cyan":"#5fd0f2","white":"#d7dde3","brightBlack":"#66717c","brightRed":"#ffb3b6","brightGreen":"#63f08b","brightYellow":"#f8d77a","brightBlue":"#9ae3f7","brightMagenta":"#dbb0f5","brightCyan":"#a5e3ff","brightWhite":"#f4f7f9"}'
exec ttyd -W -p 7681 -t titleFixed="CTF terminal" -t fontSize=14 \
  -t 'fontFamily=ui-monospace,"JetBrains Mono","Cascadia Code","Fira Code",Menlo,monospace' \
  -t "theme=$THEME" zellij attach --create ctf
