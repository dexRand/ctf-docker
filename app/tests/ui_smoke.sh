#!/usr/bin/env bash
# Headless-browser smoke test for the StegSuite SPA (real Chromium in Docker).
#
# Requires the app to be running (`./ctf up stegsuite`); downloads Playwright's
# Chromium on the first run. Uses `--network host`, so it is Linux-only.
set -euo pipefail
cd "$(dirname "$0")/../.."

BASE="${STEGSUITE:-http://127.0.0.1:19014}"
echo "[*] UI smoke test against ${BASE} (Chromium headless in Docker)…"
docker run --rm --network host \
  -v "$PWD/app/tests:/t:ro" \
  -e BASE="$BASE" \
  node:20 sh -c 'cp /t/ui_smoke.mjs /tmp/ && cd /tmp \
    && npm i -s playwright >/dev/null 2>&1 \
    && npx playwright install --with-deps chromium >/dev/null 2>&1 \
    && node ui_smoke.mjs'
