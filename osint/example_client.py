#!/usr/bin/env python3
"""Client d'esempio per la StegSuite API (solo stdlib) — integrazione OSINT.

La base URL si sceglie con l'ambiente:
    * da un altro container sulla rete `ctfnet`:  http://stegsuite:19014
    * dall'host:                                  http://localhost:19014
Se la StegSuite ha `STEGSUITE_API_KEY`, esporta `STEGSUITE_API_KEY`.

Uso:
    python3 example_client.py health
    python3 example_client.py tools
    python3 example_client.py tool binwalk-extract ./challenge.png
    python3 example_client.py analyze ./a.png ./b.jpg
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

BASE = os.environ.get("STEGSUITE_BASE", "http://localhost:19014").rstrip("/") + "/api/v1"
API_KEY = os.environ.get("STEGSUITE_API_KEY", "")


def _req(path: str, data=None, method: str = "GET", ctype: str | None = None, timeout: int = 120):
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if API_KEY:
        req.add_header("X-API-Key", API_KEY)
    if ctype:
        req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    return json.loads(raw) if raw[:1] in (b"{", b"[") else raw.decode("utf-8", "replace")


def _multipart(files: list[str], fields: dict) -> tuple[bytes, str]:
    b = "----stegclient"
    body = b""
    for k, v in fields.items():
        body += f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    for path in files:
        body += (f'--{b}\r\nContent-Disposition: form-data; name="files"; '
                 f'filename="{os.path.basename(path)}"\r\n'
                 f'Content-Type: application/octet-stream\r\n\r\n').encode()
        body += open(path, "rb").read() + b"\r\n"
    body += f"--{b}--\r\n".encode()
    return body, b


def health():
    return _req("/health")


def tools() -> list[str]:
    return [t["name"] for t in _req("/tools")]


def run_tool(tool: str, path: str):
    """Stateless: esegue un tool su un file e ritorna {tool,status,output,artifacts,job_id}."""
    body, b = _multipart([path], {})
    return _req(f"/tools/{tool}", body, "POST", f"multipart/form-data; boundary={b}")


def analyze(paths: list[str], mode: str = "auto", poll: float = 2.0, timeout: int = 1800):
    """Flusso completo: upload → start → poll → findings."""
    body, b = _multipart(paths, {"mode": mode})
    proj = _req("/projects", body, "POST", f"multipart/form-data; boundary={b}")
    pid = proj["id"]
    _req(f"/projects/{pid}/start", b"", "POST", "application/json")
    st, deadline = "?", time.time() + timeout
    while time.time() < deadline:
        st = _req(f"/projects/{pid}")["status"]
        if st in ("done", "error", "cancelled"):
            break
        time.sleep(poll)
    return {"id": pid, "status": st, "findings": _req(f"/projects/{pid}/findings")}


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "health"
    if cmd == "health":
        print(json.dumps(health()))
    elif cmd == "tools":
        print("\n".join(tools()))
    elif cmd == "tool":
        print(json.dumps(run_tool(sys.argv[2], sys.argv[3]), indent=2)[:2000])
    elif cmd == "analyze":
        res = analyze(sys.argv[2:])
        flags = [f["value"] for f in res["findings"] if f["kind"] == "flag"]
        print(json.dumps({"id": res["id"], "status": res["status"], "flags": flags}, indent=2))
    else:
        print("commands: health | tools | tool <name> <file> | analyze <file...>")
