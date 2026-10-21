#!/bin/sh
# Shell nel sandbox rev (docker exec tramite term-proxy, che consente solo exec).
cid=$(docker ps -q --filter label=com.docker.compose.project=ctf \
                  --filter label=com.docker.compose.service=rev 2>/dev/null | head -n 1)
if [ -z "$cid" ]; then
  printf '\033[1;33mrev non e'"'"' avviato.\033[0m  Avvialo con:  ./ctf up rev\n'
  printf 'Poi premi Invio qui (o apri una nuova tab "rev" dal + del terminale).\n'
  read -r _ && exec "$0"
fi
exec docker exec -it -e TERM=xterm-256color "$cid" bash -l
