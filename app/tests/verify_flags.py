#!/usr/bin/env python3
"""Verify StegSuite's flags against the challenge answers (independent source).

For every case we download the challenge artifact, run it through StegSuite,
then fetch the reference writeup and compare the flag *it states* with the one
StegSuite found. The expected values are read from the writeup at run time, so
this checks the answers themselves -- not our own constants.

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

# (label, artifact url, writeup url that states the official flag)
CASES = [
    ("So Meta", f"{B19}/So Meta/pico_img.png", f"{B19}/So Meta/README.md"),
    ("information", f"{B21}/information/cat.jpg", f"{B21}/information/README.md"),
    ("Matryoshka doll", f"{B21}/Matryoshka doll/dolls.jpg", f"{B21}/Matryoshka doll/README.md"),
    ("What Lies Within", f"{B19}/What Lies Within/buildings.png", f"{B19}/What Lies Within/README.md"),
    ("Glory of the Garden", f"{B19}/Glory of the Garden/garden.jpg", f"{B19}/Glory of the Garden/README.md"),
    ("extensions", f"{B19}/extensions/flag.txt", f"{B19}/extensions/README.md"),
    ("Weird File", f"{B21}/Weird File/weird.docm", f"{B21}/Weird File/README.md"),
]

_FLAG = re.compile(r"picoCTF\{[^}\n]{1,200}\}")


def fetch_text(url: str) -> str:
    url = urllib.parse.quote(url, safe=":/")
    req = urllib.request.Request(url, headers={"User-Agent": "stegsuite-dev"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def reference_flags(readme_url: str) -> set[str]:
    """The flag(s) the writeup says are the answer."""
    return set(_FLAG.findall(fetch_text(readme_url)))


def found_flags(label: str, artifact_url: str) -> set[str]:
    dest = DEST / f"verify_{label.replace(' ', '_')}_{Path(urllib.parse.urlparse(artifact_url).path).name}"
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
    print(f"* flag verification against writeups @ {API}")
    ok_all = True
    for label, artifact, readme in CASES:
        try:
            ref = reference_flags(readme)
            found = found_flags(label, artifact)
        except Exception as exc:  # network / parsing
            print(f"  [ERROR] {label:<18} {exc}")
            ok_all = False
            continue
        # StegSuite must have found the official answer (and not only fragments)
        ok = bool(ref) and ref.issubset(found)
        ok_all &= ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:<18} "
              f"writeup={sorted(ref)} found={sorted(found)}")
    print(f"* {'ALL CORRECT' if ok_all else 'MISMATCH'}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
