"""MCP server (Model Context Protocol) so an AI agent can drive the toolbox.

Transport: Streamable HTTP, stateless, JSON responses (no SSE needed), mounted
at `/api/v1/mcp` (same API key as the REST API). Every tool is a thin call to
the REST API on localhost, so the logic stays in one place.

    claude mcp add --transport http ctf http://127.0.0.1:19014/api/v1/mcp
"""
from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable

from .config import API_KEY, MAX_UPLOAD, VERSION

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
LOCAL = os.environ.get("STEGSUITE_SELF_URL", "http://127.0.0.1:19014") + "/api/v1"


# --- REST passthrough ---------------------------------------------------------

def _request(path: str, method: str, data: bytes | None, headers: dict,
             timeout: int) -> tuple[int, str, bytes]:
    """HTTP to our own REST API -> (status, content-type, body). Tests swap this."""
    req = urllib.request.Request(LOCAL + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (localhost)
            return r.status, r.headers.get("content-type") or "", r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("content-type") or "", exc.read()


def _call(path: str, method: str = "GET", body: Any = None, raw: bytes | None = None,
          ctype: str | None = None, timeout: int = 120, binary: bool = False) -> Any:
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if ctype:
        headers["Content-Type"] = ctype
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    status, ct, out = _request(path, method, data, headers, timeout)
    if status >= 400:
        raise ToolError(f"{status}: {out.decode('utf-8', 'replace')[:500]}")
    if binary:
        return out
    return json.loads(out) if "json" in ct else out.decode("utf-8", "replace")


def _multipart(files: list[tuple[str, bytes]], fields: dict[str, str]) -> tuple[bytes, str]:
    b = "----mcp" + uuid.uuid4().hex
    parts = [f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
             for k, v in fields.items() if v != ""]
    for name, content in files:
        safe = name.replace('"', "_").replace("\r", "_").replace("\n", "_")
        parts.append(f'--{b}\r\nContent-Disposition: form-data; name="files"; filename="{safe}"\r\n'
                     f"Content-Type: application/octet-stream\r\n\r\n".encode() + content + b"\r\n")
    parts.append(f"--{b}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={b}"


def _fetch(url: str) -> tuple[str, bytes]:
    """Download a challenge attachment (http/https only, size-capped)."""
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise ToolError("only http(s) URLs")
    req = urllib.request.Request(url, headers={"User-Agent": "ctf-toolbox"})
    with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 (user-requested URL)
        data = r.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise ToolError("file too large")
    name = urllib.parse.unquote(urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]) or "file"
    return name, data


def _files_arg(args: dict) -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    for url in args.get("urls") or []:
        files.append(_fetch(url))
    for f in args.get("files") or []:
        try:
            files.append((f["name"], base64.b64decode(f["content_base64"])))
        except (KeyError, ValueError, TypeError):
            raise ToolError("files: [{name, content_base64}]")
    if not files:
        raise ToolError("give `urls` and/or `files`")
    return files


class ToolError(Exception):
    """Reported to the agent as a tool error (isError), not a protocol error."""


# --- tools --------------------------------------------------------------------

TOOLS: dict[str, tuple[str, dict, Callable[[dict], Any]]] = {}


def tool(name: str, description: str, props: dict | None = None, required: tuple = ()):
    schema = {"type": "object", "properties": props or {}, "required": list(required)}

    def deco(fn):
        TOOLS[name] = (description, schema, fn)
        return fn
    return deco


S = {"type": "string"}
I = {"type": "integer"}
FILES = {
    "urls": {"type": "array", "items": S, "description": "attachment URLs to download"},
    "files": {"type": "array", "description": "inline files",
              "items": {"type": "object", "properties": {"name": S, "content_base64": S},
                        "required": ["name", "content_base64"]}},
}


@tool("list_ctfs", "List CTF events with challenge/solved counters.")
def _list_ctfs(a):
    return _call("/ctfs")


@tool("create_ctf", "Create a CTF event. flag_format: prefix like 'DUCTF{...}' or a regex.",
      {"name": S, "flag_format": S, "url": S, "notes": S}, ("name",))
def _create_ctf(a):
    return _call("/ctfs", "POST", {k: a[k] for k in ("name", "flag_format", "url", "notes") if k in a})


@tool("ctf_scoreboard", "A CTF with every challenge: status, solved, flag, flags found.",
      {"ctf_id": S}, ("ctf_id",))
def _scoreboard(a):
    return _call(f"/ctfs/{a['ctf_id']}")


@tool("add_challenge", "Add a challenge (files from URLs and/or base64) to a CTF; start=true analyzes it.",
      {"ctf_id": S, "name": S, "category": S, "start": {"type": "boolean"}, **FILES}, ("ctf_id",))
def _add_challenge(a):
    body, ctype = _multipart(_files_arg(a), {"name": a.get("name", ""), "category": a.get("category", ""),
                                             "start": "true" if a.get("start", True) else "false"})
    return _call(f"/ctfs/{a['ctf_id']}/challenges", "POST", raw=body, ctype=ctype, timeout=600)


@tool("autosolve", "Analyze every unsolved challenge of a CTF (parallel at a time).",
      {"ctf_id": S, "parallel": I}, ("ctf_id",))
def _autosolve(a):
    return _call(f"/ctfs/{a['ctf_id']}/autosolve", "POST", {"parallel": a.get("parallel", 2)})


@tool("analyze", "Analyze files (URLs and/or base64) as a new project and start it. Returns the project id.",
      {"name": S, "mode": {"type": "string", "enum": ["auto", "check"]}, **FILES})
def _analyze(a):
    body, ctype = _multipart(_files_arg(a), {"name": a.get("name", ""), "mode": a.get("mode", "auto")})
    proj = _call("/projects", "POST", raw=body, ctype=ctype, timeout=600)
    _call(f"/projects/{proj['id']}/start", "POST", {})
    return proj


@tool("project_status", "Status of a project/challenge and its file tree.", {"project_id": S}, ("project_id",))
def _status(a):
    return _call(f"/projects/{a['project_id']}")


@tool("get_flags", "Flags found, each with the chain of files and the tool output that shows it.",
      {"project_id": S}, ("project_id",))
def _flags(a):
    return _call(f"/projects/{a['project_id']}/flags")


@tool("get_report", "Markdown report of a project (lang en|it).",
      {"project_id": S, "lang": {"type": "string", "enum": ["en", "it"]}}, ("project_id",))
def _report(a):
    return _call(f"/projects/{a['project_id']}/report?lang={a.get('lang', 'en')}")


@tool("get_transcript", "Full context of what the analysis did (to continue a challenge by hand).",
      {"project_id": S}, ("project_id",))
def _transcript(a):
    return _call(f"/projects/{a['project_id']}/transcript")


@tool("read_file", "Read a file of the project tree (text, or base64 for binary), up to max_bytes.",
      {"project_id": S, "file_id": I, "max_bytes": I}, ("project_id", "file_id"))
def _read_file(a):
    data = _call(f"/projects/{a['project_id']}/files/{a['file_id']}/content", binary=True)
    data = data[:int(a.get("max_bytes", 65536))]
    try:
        return {"encoding": "utf-8", "content": data.decode("utf-8")}
    except UnicodeDecodeError:
        return {"encoding": "base64", "content": base64.b64encode(data).decode()}


@tool("list_tools", "Analyzers available (name, category, description).")
def _tools(a):
    return _call("/tools")


@tool("run_tools", "Run analyzers on one file of a project, optionally with a password.",
      {"project_id": S, "file_id": I, "tools": {"type": "array", "items": S}, "password": S},
      ("project_id", "file_id", "tools"))
def _run_tools(a):
    body = {"tools": a["tools"], **({"password": a["password"]} if a.get("password") else {})}
    return _call(f"/projects/{a['project_id']}/files/{a['file_id']}/run", "POST", body)


@tool("locked_files", "Files still needing a password.", {"project_id": S}, ("project_id",))
def _locked(a):
    return _call(f"/projects/{a['project_id']}/locked")


@tool("crack", "Crack a locked file with wordlists (names from list_wordlists), rules or a mask.",
      {"project_id": S, "file_id": I, "wordlists": {"type": "array", "items": S},
       "mask": S, "budget_s": I}, ("project_id", "file_id"))
def _crack(a):
    body = {k: a[k] for k in ("file_id", "wordlists", "mask", "budget_s") if k in a}
    return _call(f"/projects/{a['project_id']}/crack", "POST", body)


@tool("list_wordlists", "Wordlists available for cracking (smallest first).")
def _wordlists(a):
    return _call("/wordlists")


@tool("set_challenge", "Edit a challenge: solved, flag, category, name, ctf_id.",
      {"project_id": S, "solved": {"type": "boolean"}, "flag": S, "category": S, "name": S, "ctf_id": S},
      ("project_id",))
def _set(a):
    return _call(f"/projects/{a['project_id']}", "PATCH",
                 {k: v for k, v in a.items() if k != "project_id"})


@tool("toolbox_services", "Other web tools of the toolbox (CyberChef, ZAP, Wireshark, rev sandbox…) and their URLs.")
def _services(a):
    return _call("/services")


# --- JSON-RPC -----------------------------------------------------------------

def _result(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _error(rid, code: int, message: str):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def handle(msg: dict) -> dict | None:
    """One JSON-RPC message -> response (None for notifications)."""
    rid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if rid is None:   # notification (e.g. notifications/initialized)
        return None
    if method == "initialize":
        asked = params.get("protocolVersion")
        return _result(rid, {
            "protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "ctf-toolbox", "version": VERSION},
            "instructions": ("CTF toolbox. Typical flow: create_ctf -> add_challenge (start=true) "
                             "or analyze -> project_status until done -> get_flags. If no flag: "
                             "get_transcript, then run_tools / crack / read_file."),
        })
    if method == "ping":
        return _result(rid, {})
    if method == "tools/list":
        return _result(rid, {"tools": [{"name": n, "description": d, "inputSchema": s}
                                       for n, (d, s, _) in TOOLS.items()]})
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in TOOLS:
            return _error(rid, -32602, f"unknown tool: {name}")
        try:
            out = TOOLS[name][2](args)
            text = out if isinstance(out, str) else json.dumps(out, ensure_ascii=False, default=str, indent=1)
            return _result(rid, {"content": [{"type": "text", "text": text}], "isError": False})
        except (ToolError, OSError, KeyError, ValueError) as exc:
            return _result(rid, {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True})
    return _error(rid, -32601, f"method not found: {method}")
