#!/usr/bin/env python3
"""Refresh the image digests pinned in compose.yaml and the Dockerfiles.

Every upstream image is written as `name:tag@sha256:…`: the tag says what it
is, the digest says exactly which build. This resolves each tag again (needs
`docker buildx` and network) and rewrites the digest when it moved.

    python3 tools/pin_images.py           # show what would change
    python3 tools/pin_images.py --write   # update the files

After --write: rebuild, `./ctf test -j 3`, then commit.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ["compose.yaml", "app/Dockerfile", "rev/Dockerfile", "zap/Dockerfile"]
PIN_RE = re.compile(r"(?P<ref>[a-z0-9./_-]+:[A-Za-z0-9._-]+)@(?P<digest>sha256:[0-9a-f]{64})")


def resolve(ref: str) -> str | None:
    try:
        out = subprocess.run(["docker", "buildx", "imagetools", "inspect", ref,
                              "--format", "{{.Manifest.Digest}}"],
                             capture_output=True, text=True, timeout=120).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out if out.startswith("sha256:") else None


def main() -> int:
    write = "--write" in sys.argv
    changed = 0
    for rel in FILES:
        path = ROOT / rel
        if not path.exists():
            continue
        text = path.read_text()
        new = text
        for m in PIN_RE.finditer(text):
            current = resolve(m["ref"])
            if current is None:
                print(f"[?] {rel}: cannot resolve {m['ref']}")
            elif current != m["digest"]:
                print(f"[~] {rel}: {m['ref']}  {m['digest'][:19]}… -> {current[:19]}…")
                new = new.replace(m.group(0), f"{m['ref']}@{current}")
                changed += 1
            else:
                print(f"[=] {rel}: {m['ref']}")
        if write and new != text:
            path.write_text(new)
    print(f"{changed} digest(s) {'updated' if write else 'would change'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
