"""Minimal stdlib client for the StegSuite REST API.

Shared by `./ctf scan` (tools/scan.py) and the real-challenge tests, so URL,
API key and upload logic live in one place.

    STEGSUITE=http://127.0.0.1:19014   base URL (default)
    STEGSUITE_API_KEY=...              sent as X-API-Key when set
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
import uuid
from pathlib import Path

ROOT = os.environ.get("STEGSUITE", "http://127.0.0.1:19014").rstrip("/")
API = ROOT + "/api/v1"
API_KEY = os.environ.get("STEGSUITE_API_KEY", "").strip()
FINAL = ("done", "error", "cancelled")


def call(path: str, method: str = "GET", data: bytes | None = None,
         ctype: str | None = None, timeout: int = 300):
    req = urllib.request.Request(API + path, data=data, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    if API_KEY:
        req.add_header("X-API-Key", API_KEY)
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (local service)
        raw = r.read()
    return json.loads(raw) if raw[:1] in (b"{", b"[") else raw.decode(errors="replace")


def multipart(paths: list[Path], fields: dict[str, str]) -> tuple[bytes, str]:
    """multipart/form-data body; a random boundary can't collide with file bytes."""
    boundary = "----stegsuite" + uuid.uuid4().hex
    parts: list[bytes] = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for p in paths:
        name = Path(p).name.replace('"', "_").replace("\r", "_").replace("\n", "_")
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="files"; '
                      f'filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
                     + Path(p).read_bytes() + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def create_project(paths: list[Path], mode: str = "auto") -> str:
    body, ctype = multipart(paths, {"mode": mode})
    return call("/projects", "POST", body, ctype)["id"]


def analyze(paths: list[Path], mode: str = "auto", timeout_s: int = 900,
            poll_s: float = 2.0) -> dict:
    """Upload, start, wait. Returns {project, status, flags, passwords, seconds}."""
    t0 = time.monotonic()
    pid = create_project(paths, mode)
    call(f"/projects/{pid}/start", "POST", b"", "application/json")
    status = "?"
    while time.monotonic() - t0 < timeout_s:
        status = call(f"/projects/{pid}")["status"]
        if status in FINAL:
            break
        time.sleep(poll_s)
    else:
        status = "timeout"
    findings = call(f"/projects/{pid}/findings")
    return {
        "project": pid,
        "status": status,
        "flags": [f["value"] for f in findings if f["kind"] == "flag"],
        "passwords": [f["value"] for f in findings if f["kind"] == "password"],
        "seconds": round(time.monotonic() - t0, 1),
    }
