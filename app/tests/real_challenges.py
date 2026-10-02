#!/usr/bin/env python3
"""Real picoCTF challenge test for StegSuite (downloads from GitHub mirrors).

picoctf.net does not resolve from the dev host, so files come from the
HHousen/PicoCTF-* writeup repos on GitHub.

Run against a running StegSuite:
    STEGSUITE=http://localhost:19014 python3 app/tests/real_challenges.py
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

API = os.environ.get("STEGSUITE", "http://localhost:19014") + "/api/v1"
DEST = Path("/tmp/realch")

B19 = "https://raw.githubusercontent.com/HHousen/PicoCTF-2019/master/Forensics"
B21 = "https://raw.githubusercontent.com/HHousen/PicoCTF-2021/master/Forensics"

CASES = [
    ("pico_img.png", f"{B19}/So Meta/pico_img.png", "picoCTF{s0_m3ta_43f253bb}"),
    ("cat.jpg", f"{B21}/information/cat.jpg", "picoCTF{the_m3tadata_1s_modified}"),
    ("dolls.jpg", f"{B21}/Matryoshka doll/dolls.jpg", "picoCTF{336cf6d51c9d9774fd37196c1d7320ff}"),
    ("buildings.png", f"{B19}/What Lies Within/buildings.png", "picoCTF{h1d1ng_1n_th3_b1t5}"),
    ("garden.jpg", f"{B19}/Glory of the Garden/garden.jpg", "picoCTF{more_than_m33ts_the_3y35a97d3bB}"),
    # extension lies: it's a PNG named .txt -> needs type detection for the plan
    ("flag.txt", f"{B19}/extensions/flag.txt", "picoCTF{now_you_know_about_extensions}"),
    # macro-based: base64 inside the vbaProject of a .docm
    ("weird.docm", f"{B21}/Weird File/weird.docm", "picoCTF{m4cr0s_r_d4ng3r0us}"),
]


def download(url: str, dest: Path) -> None:
    if dest.exists() and dest.stat().st_size > 0:
        return
    encoded = urllib.parse.quote(url, safe=":/")
    with urllib.request.urlopen(encoded, timeout=120) as r:
        dest.write_bytes(r.read())


def _multipart(path: Path, mode: str) -> tuple[bytes, str]:
    b = "----stegreal"
    body = (f'--{b}\r\nContent-Disposition: form-data; name="mode"\r\n\r\n{mode}\r\n').encode()
    body += (f'--{b}\r\nContent-Disposition: form-data; name="files"; filename="{path.name}"\r\n'
             f'Content-Type: application/octet-stream\r\n\r\n').encode() + path.read_bytes() + b"\r\n"
    body += f"--{b}--\r\n".encode()
    return body, b


def post(path: str, data: bytes = b"", ctype=None):
    req = urllib.request.Request(API + path, data=data, method="POST")
    if ctype:
        req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read()
    return json.loads(raw) if raw[:1] in (b"{", b"[") else raw.decode()


def get(path: str):
    with urllib.request.urlopen(API + path, timeout=120) as r:
        return json.loads(r.read())


def run_case(name: str, url: str, expect: str) -> bool:
    DEST.mkdir(parents=True, exist_ok=True)
    p = DEST / name
    download(url, p)
    body, b = _multipart(p, "auto")
    proj = post("/projects", body, f"multipart/form-data; boundary={b}")
    post(f"/projects/{proj['id']}/start")
    status = "?"
    for _ in range(300):
        status = get(f"/projects/{proj['id']}")["status"]
        if status in ("done", "error", "cancelled"):
            break
        time.sleep(3)
    flags = [f["value"] for f in get(f"/projects/{proj['id']}/findings") if f["kind"] == "flag"]
    # a flag must never be a fragment of a longer one (e.g. CTF{x} in picoCTF{x})
    fragments = [fl for fl in flags if any(fl != o and fl in o for o in flags)]
    ok = any(expect in fl for fl in flags) and not fragments
    extra = f" fragments={fragments}" if fragments else ""
    print(f"  [{'PASS' if ok else 'FAIL'}] {name:<15} status={status} expect={expect} got={flags[:3]}{extra}")
    return ok


def main() -> int:
    print(f"* real picoCTF challenges against {API}")
    results = [run_case(*c) for c in CASES]
    print(f"* {sum(results)}/{len(results)} passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
