#!/usr/bin/env bash
# Run photo-geolocate inside the StegSuite image (already has exiftool,
# tesseract and Pillow), so nothing is installed on the host.
#
# Usage: ./run.sh PHOTO [geolocate.py args...]
#   ./run.sh photo.jpg
#   ./run.sh photo.jpg --geocode --json out.json
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
image="${STEGSUITE_IMAGE:-ctf-stegsuite}"
photo="${1:?usage: run.sh PHOTO [args...]}"
shift || true

if [ ! -f "$photo" ]; then echo "[!] not a file: $photo" >&2; exit 1; fi
name="$(basename "$photo")"
dir="$(cd "$(dirname "$photo")" && pwd)"

docker run --rm --network host \
  -v "$here:/app:ro" \
  -v "$dir:/work" \
  "$image" \
  /opt/stegsuite/venv/bin/python /app/geolocate.py "/work/$name" "$@"
