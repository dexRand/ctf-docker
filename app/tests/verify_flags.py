#!/usr/bin/env python3
"""Verify StegSuite's flags against the challenge answers, instance by instance.

Some picoCTF challenges embed a *random* part in the flag, so two writeups of
the same challenge can show different flags (e.g. So Meta `..._43f253bb` vs
`..._dc38ce45`). The only sound check is: for a given artifact, does StegSuite
find the answer that writeup declares *for that artifact*?

This script therefore runs several (artifact, writeup) pairs, including the
same challenge from a *different* repository/instance, and compares the flags
at run time (no hardcoded expectations).

Run against a running StegSuite:
    STEGSUITE=http://localhost:19014 python3 app/tests/verify_flags.py
"""
from __future__ import annotations

import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

from real_challenges import API, DEST, download, get, post, _multipart

B19 = "https://raw.githubusercontent.com/HHousen/PicoCTF-2019/master/Forensics"
B21 = "https://raw.githubusercontent.com/HHousen/PicoCTF-2021/master/Forensics"
K19 = "https://raw.githubusercontent.com/kevinjycui/picoCTF-2019-writeup/master/Forensics"

# (label, artifact url, writeup url that states the answer for THAT artifact)
CASES = [
    # instance A (HHousen)
    ("So Meta A", f"{B19}/So Meta/pico_img.png", f"{B19}/So Meta/README.md"),
    ("Glory A", f"{B19}/Glory of the Garden/garden.jpg", f"{B19}/Glory of the Garden/README.md"),
    ("WLIW A", f"{B19}/What Lies Within/buildings.png", f"{B19}/What Lies Within/README.md"),
    ("extensions A", f"{B19}/extensions/flag.txt", f"{B19}/extensions/README.md"),
    ("information A", f"{B21}/information/cat.jpg", f"{B21}/information/README.md"),
    ("Matryoshka A", f"{B21}/Matryoshka doll/dolls.jpg", f"{B21}/Matryoshka doll/README.md"),
    ("Weird File A", f"{B21}/Weird File/weird.docm", f"{B21}/Weird File/README.md"),
    # instance B (kevinjycui): same challenges, different (randomised) flags
    ("So Meta B", f"{K19}/So Meta/pico_img.png", f"{K19}/So Meta/README.md"),
    ("Glory B", f"{K19}/Glory of the Garden/garden.jpg", f"{K19}/Glory of the Garden/README.md"),
    ("WLIW B", f"{K19}/What Lies Within/buildings.png", f"{K19}/What Lies Within/README.md"),
    ("extensions B", f"{K19}/extensions/flag.txt", f"{K19}/extensions/README.md"),
]

_FLAG = re.compile(r"picoCTF\{[^}\n]{1,200}\}")


def fetch_text(url: str) -> str:
    url = urllib.parse.quote(url, safe=":/")
    req = urllib.request.Request(url, headers={"User-Agent": "stegsuite-dev"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def reference_flags(writeup_url: str) -> set[str]:
    """The flag(s) the writeup declares as the answer (placeholders ignored)."""
    flags = set(_FLAG.findall(fetch_text(writeup_url)))
    return {f for f in flags if not re.fullmatch(r"picoCTF\{[Xx]+\}", f)}


def found_flags(label: str, artifact_url: str) -> set[str]:
    base = Path(urllib.parse.urlparse(artifact_url).path).name
    dest = DEST / f"verify_{label.replace(' ', '_')}_{base}"
    download(artifact_url, dest)
    body, boundary = _multipart(dest, "auto")
    proj = post("/projects", body, f"multipart/form-data; boundary={boundary}")
    post(f"/projects/{proj['id']}/start")
    for _ in range(300):
        status = get(f"/projects/{proj['id']}")["status"]
        if status in ("done", "error", "cancelled"):
            break
        time.sleep(3)
    return {f["value"] for f in get(f"/projects/{proj['id']}/findings") if f["kind"] == "flag"}


def main() -> int:
    print(f"* flag verification (artifact + its writeup) @ {API}")
    ok_all = True
    flags_seen: dict[str, set[str]] = {}
    for label, artifact, writeup in CASES:
        try:
            ref = reference_flags(writeup)
            found = found_flags(label, artifact)
        except Exception as exc:
            print(f"  [ERROR] {label:<14} {exc}")
            ok_all = False
            continue
        ok = bool(ref) and ref.issubset(found)
        ok_all &= ok
        flags_seen[label] = ref
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:<14} "
              f"answer={sorted(ref)} found={sorted(found)}")
    # Show that the two instances really have different flags (per-instance):
    for a, b in [("So Meta A", "So Meta B"), ("Glory A", "Glory B")]:
        if a in flags_seen and b in flags_seen and flags_seen[a] != flags_seen[b]:
            print(f"  (per-instance) {a} != {b}: "
                  f"{sorted(flags_seen[a])} vs {sorted(flags_seen[b])}")
    print(f"* {'ALL CORRECT' if ok_all else 'MISMATCH'}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
