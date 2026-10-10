#!/usr/bin/env python3
"""Invia file locali a StegSuite (API) e stampa flag/password trovate.

    scan.py file.png
    scan.py a.png b.pcapng --mode check
    scan.py file --json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

ROOT = os.environ.get("STEGSUITE", "http://127.0.0.1:19014")
API = ROOT.rstrip("/") + "/api/v1"


def api(path: str, method: str = "GET", data=None, ctype=None):
    req = urllib.request.Request(API + path, data=data, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=300) as r:  # noqa: S310
        raw = r.read()
    return json.loads(raw) if raw[:1] in (b"{", b"[") else raw.decode(errors="replace")


def multipart(paths: list[str], mode: str) -> tuple[bytes, str]:
    boundary = "----ctfscan"
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="mode"\r\n\r\n{mode}\r\n').encode()
    for p in paths:
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="files"; '
                 f'filename="{Path(p).name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
        body += Path(p).read_bytes() + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return body, boundary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ctf scan", description="Analizza file con StegSuite e stampa le flag.")
    ap.add_argument("files", nargs="+", help="uno o più file locali")
    ap.add_argument("--mode", default="auto", choices=["auto", "check"])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    for f in args.files:
        if not Path(f).is_file():
            print(f"[x] file non trovato: {f}", file=sys.stderr)
            return 2
    try:
        api("/projects")  # sanity check: StegSuite raggiungibile?
    except Exception as exc:  # noqa: BLE001
        print(f"[x] StegSuite non raggiungibile su {ROOT}: {exc}", file=sys.stderr)
        print("    avvialo con:  ./ctf up", file=sys.stderr)
        return 2

    body, boundary = multipart(args.files, args.mode)
    pid = api("/projects", "POST", body, f"multipart/form-data; boundary={boundary}")["id"]
    api(f"/projects/{pid}/start", "POST", b"", "application/json")
    status = "?"
    for _ in range(300):
        status = api(f"/projects/{pid}")["status"]
        if status in ("done", "error", "cancelled"):
            break
        time.sleep(2)
    findings = api(f"/projects/{pid}/findings")
    flags = [x["value"] for x in findings if x["kind"] == "flag"]
    pw = [x["value"] for x in findings if x["kind"] == "password"]
    if args.json:
        print(json.dumps({"project": pid, "status": status, "flags": flags,
                          "passwords": pw}, ensure_ascii=False, indent=2))
        return 0
    print(f"progetto {pid} · status {status} · {len(flags)} flag")
    for v in flags:
        print(f"  FLAG  {v}")
    for v in pw:
        print(f"  pass  {v}")
    print(f"  GUI:   {ROOT.rstrip('/')}/#/p/{pid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
