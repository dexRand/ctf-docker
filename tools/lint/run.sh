#!/bin/sh
# Static analysis of the repo, all in containers (docker-first): bugs (ruff),
# security (bandit), dead code (vulture), duplicated code (jscpd).
# Usage: tools/lint/run.sh [--report]   (also: ./ctf lint)
# Exit code != 0 when a gate fails: ruff error, bandit HIGH/MEDIUM with high
# confidence, vulture >= 80 % confidence, or a duplicate of 8+ lines.
set -u
cd "$(dirname "$0")/../.." || exit 1
PY_IMG="python:3.12-slim"
NODE_IMG="node:20-slim"
fail=0

echo "== ruff (bugbear + pyflakes + pylint errors)"
docker run --rm -v "$PWD:/src:ro" -w /src "$PY_IMG" sh -c \
  "pip install -q --root-user-action=ignore ruff==0.8.4 >/dev/null 2>&1 && \
   ruff check --no-cache app/backend app/tests tools" || fail=1

echo "== bandit (security, medium+ severity and confidence)"
docker run --rm -v "$PWD:/src:ro" -w /src "$PY_IMG" sh -c \
  "pip install -q --root-user-action=ignore bandit==1.8.0 >/dev/null 2>&1 && \
   bandit -q -r app/backend tools -x app/backend/migrations,tools/dork/node_modules \
     --severity-level medium --confidence-level medium" || fail=1

echo "== vulture (dead code, >= 80 % confidence)"
docker run --rm -v "$PWD:/src:ro" -w /src "$PY_IMG" sh -c \
  "pip install -q --root-user-action=ignore vulture==2.14 >/dev/null 2>&1 && \
   vulture app/backend tools --min-confidence 80 --exclude migrations" || fail=1

echo "== jscpd (duplicated code: gate 8+ lines; --report lists 5+ lines too)"
min_lines=8; min_tokens=70
[ "${1:-}" = "--report" ] && { min_lines=5; min_tokens=50; }
docker run --rm -v "$PWD:/src:ro" -w /src "$NODE_IMG" sh -c \
  "npx -y jscpd@4.0.5 --silent --min-lines $min_lines --min-tokens $min_tokens \
     --reporters console --exitCode 1 \
     --ignore '**/node_modules/**,**/migrations/**,**/dist/**,**/static/**,**/third_party/**,**/data/**' \
     app/backend app/frontend/src tools 2>&1 | grep -v 'npm notice'" || \
  { [ "$min_lines" = 8 ] && fail=1; }

[ "$fail" = 0 ] && echo "[ok] lint clean" || echo "[x] lint found problems (see above)"
exit "$fail"
