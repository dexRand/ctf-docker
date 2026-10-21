#!/bin/sh
# Terminale StegSuite (:19022): code-server (VS Code nel browser) su /data/projects.
# Solo localhost (porta pubblicata su BIND_ADDR), quindi niente password.
set -eu
exec code-server --bind-addr 0.0.0.0:8080 --auth none --disable-telemetry \
  --disable-update-check --disable-workspace-trust --app-name StegSuite /data/projects
