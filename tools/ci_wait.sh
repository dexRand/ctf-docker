#!/usr/bin/env bash
# Wait for the GitHub CI of a commit with no model in the loop (mechanus: L2 is
# long, a script waits for it). Exit 0 when every run is green; otherwise print
# each failed job and the last lines of its log, to hand to the builder.
# Usage: tools/ci_wait.sh [sha=HEAD] [poll_seconds=60] [log_lines=60]
set -euo pipefail
cd "$(dirname "$0")/.."

SHA="$(git rev-parse "${1:-HEAD}")"
POLL="${2:-60}"
LINES="${3:-60}"
REPO="$(git remote get-url origin | sed -E 's#(git@github.com:|https://github.com/)##; s#\.git$##')"
API="https://api.github.com/repos/$REPO"
# token from git's credential helper (needed only for the job logs)
TOKEN="$(printf 'protocol=https\nhost=github.com\n\n' | git credential fill 2>/dev/null | sed -n 's/^password=//p')"
auth=()
[ -n "$TOKEN" ] && auth=(-H "Authorization: Bearer $TOKEN")

get() { curl -sfL -m 30 "${auth[@]}" "$API/$1"; }

echo "[*] CI of ${SHA:0:7} on $REPO (poll ${POLL}s)"
while :; do
  state="$(get "actions/runs?head_sha=$SHA&per_page=20" | python3 -c '
import json, sys
runs = json.load(sys.stdin)["workflow_runs"]
if not runs:
    print("none"); raise SystemExit
if any(r["status"] != "completed" for r in runs):
    print("running"); raise SystemExit
bad = [str(r["id"]) for r in runs if r["conclusion"] not in ("success", "skipped")]
print("failed " + " ".join(bad) if bad else "green")
' || echo "error")"
  case "$state" in
    green) echo "[ok] CI green on ${SHA:0:7}"; exit 0 ;;
    failed*) break ;;
    *) sleep "$POLL" ;;
  esac
done

for run in ${state#failed }; do
  get "actions/runs/$run/jobs" | python3 -c '
import json, sys
for j in json.load(sys.stdin)["jobs"]:
    if j["conclusion"] not in ("success", "skipped"):   # failure, cancelled, timed_out
        steps = [s["name"] for s in j["steps"] if s["conclusion"] not in ("success", "skipped", None)]
        print(j["id"], j["conclusion"], j["name"], "|", ", ".join(steps))
' | while read -r job rest; do
    echo "== [x] $rest"
    # the real error sits before the runner's post-job cleanup
    get "actions/jobs/$job/logs" | cut -c30- | sed '/Post job cleanup/,$d' | tail -n "$LINES" \
      || echo "(log not readable: token missing?)"
  done
done
exit 1
