#!/usr/bin/env python3
"""StegSuite CTF regression suite.

Generates deterministic challenge fixtures (one per tool category) and drives
the running API in Auto mode, asserting the expected flag is found.

Run inside the StegSuite container:
    /opt/stegsuite/venv/bin/python /opt/stegsuite/tests/ctf_regression.py
or on the host against a running instance:
    STEGSUITE=http://localhost:19014 python3 app/tests/ctf_regression.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

BASE = os.environ.get("STEGSUITE", "http://127.0.0.1:19014")
API = BASE + "/api/v1"
TMP = Path("/tmp/ctfreg")
TMP.mkdir(parents=True, exist_ok=True)


def sh(cmd: str) -> None:
    subprocess.run(cmd, shell=True, check=True, capture_output=True)


def _multipart(field_files: list[tuple[str, Path]], fields: dict) -> tuple[bytes, str]:
    boundary = "----stegsuite"
    body = b""
    for k, v in fields.items():
        body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
    for _name, path in field_files:
        body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; "
                 f"filename=\"{path.name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
        body += path.read_bytes() + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return body, boundary


def api(path: str, method: str = "GET", data=None, ctype=None):
    req = urllib.request.Request(API + path, data=data, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read()
    return json.loads(raw) if raw and raw[:1] in (b"{", b"[") else raw.decode(errors="replace")


def make_fixtures() -> list[tuple[str, Path, str]]:
    cases: list[tuple[str, Path, str]] = []
    # 1) plaintext -> strings
    p = TMP / "strings.txt"
    p.write_text("benvenuto ITS{strings_flag_1} fine\n")
    cases.append(("strings", p, "ITS{strings_flag_1}"))

    # 2) exif -> exiftool
    p = TMP / "exif.jpg"
    sh(f"convert -size 96x96 xc:navy {p}")
    sh(f"exiftool -overwrite_original -Artist='ITS{{exif_flag_2}}' {p}")
    cases.append(("exif", p, "ITS{exif_flag_2}"))

    # 3) zip appended to a PNG -> binwalk -e + 7z
    sh(f"cd {TMP} && printf 'ITS{{appended_zip_3}}' > f3.txt && rm -f a3.zip && zip -q a3.zip f3.txt")
    p = TMP / "appended.png"
    sh(f"convert -size 64x64 xc:red {p} && cat {TMP}/a3.zip >> {p}")
    cases.append(("binwalk", p, "ITS{appended_zip_3}"))

    # 4) AES-256 ZIP -> fcrackzip/hashcat (secret123 is in passwords.txt)
    sh(f"cd {TMP} && printf 'ITS{{aes_zip_4}}' > f4.txt && rm -f a4.zip && "
       f"7z a -tzip -mem=AES256 -psecret123 a4.zip f4.txt")
    cases.append(("aes-zip", TMP / "a4.zip", "ITS{aes_zip_4}"))

    # 5) steghide JPEG (password ctf)
    p = TMP / "stego.jpg"
    sh(f"cd {TMP} && convert -size 512x512 xc: +noise Random n.png && convert n.png {p} && "
       f"printf 'ITS{{steghide_5}}' > s5.txt && steghide embed -cf {p} -ef s5.txt -p ctf -f")
    cases.append(("steghide", p, "ITS{steghide_5}"))

    # 6) animated GIF with a visible flag -> gif-frames + OCR
    from PIL import Image, ImageDraw
    frames = []
    for text, color in [("intro", "black"), ("ITS{gif_frame_6}", "red"), ("end", "black")]:
        im = Image.new("RGB", (400, 140), "white")
        ImageDraw.Draw(im).text((15, 55), text, fill=color)
        frames.append(im)
    p = TMP / "anim.gif"
    frames[0].save(p, save_all=True, append_images=frames[1:], duration=250, loop=0)
    cases.append(("gif-frames", p, "ITS{gif_frame_6}"))
    return cases


def run_case(name: str, path: Path, expect: str) -> bool:
    body, boundary = _multipart([("files", path)], {"mode": "auto"})
    p = api("/projects", "POST", body, f"multipart/form-data; boundary={boundary}")
    pid = p["id"]
    api(f"/projects/{pid}/start", "POST", b"", "application/json")
    status = "?"
    for _ in range(150):
        status = api(f"/projects/{pid}")["status"]
        if status in ("done", "error", "cancelled"):
            break
        time.sleep(2)
    flags = [f["value"] for f in api(f"/projects/{pid}/findings") if f["kind"] == "flag"]
    ok = any(expect in fl for fl in flags)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name:<10} expected {expect:<22} status={status} flags={flags[:3]}")
    return ok


def main() -> int:
    print(f"* StegSuite CTF regression against {BASE}")
    cases = make_fixtures()
    results = [run_case(n, p, e) for n, p, e in cases]
    passed, total = sum(results), len(results)
    print(f"* {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
