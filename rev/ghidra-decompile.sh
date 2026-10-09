#!/bin/sh
# Decompile a binary with Ghidra headless (CLI). Prints C to stdout, or to OUTFILE.
#
#   ghidra-decompile BIN [OUTFILE] [SECONDS]
set -eu
bin="${1:?usage: ghidra-decompile BIN [OUTFILE] [SECONDS]}"
out="${2:-}"
secs="${3:-300}"
[ -f "$bin" ] || { echo "not a file: $bin" >&2; exit 1; }

proj="$(mktemp -d)"
tmp="$(mktemp)"
trap 'rm -rf "$proj" "$tmp"' EXIT

# Ghidra prints lots of INFO lines on stdout: silence them and take the C from $tmp.
/opt/ghidra/support/analyzeHeadless "$proj" p \
  -import "$bin" \
  -scriptPath /opt/ghidra_scripts \
  -postScript DecompileAll.java "$tmp" \
  -analysisTimeoutPerFile "$secs" \
  -deleteProject >/dev/null 2>&1 || true

if [ -n "$out" ]; then
  cp "$tmp" "$out"
  chmod 0644 "$out" 2>/dev/null || true
  echo "wrote $out"
else
  cat "$tmp"
fi
