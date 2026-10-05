#!/usr/bin/env bash
# Run the pytest suite against the StegSuite image (its venv has the deps).
# Usage: app/tests/run_unit.sh [pytest args...]
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE="${STEGSUITE_IMAGE:-ctf-stegsuite}"

docker run --rm \
  -v "$PWD/app:/w/app:ro" \
  -w /w \
  -e DATA_DIR=/tmp/stegsuite-test-data \
  "$IMAGE" \
  sh -c '/opt/stegsuite/venv/bin/pip install -q pytest httpx >/dev/null 2>&1 || true;
         exec /opt/stegsuite/venv/bin/python -m pytest app/tests "$@"' sh "$@"