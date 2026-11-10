"""MCP server (Model Context Protocol) so an AI agent can drive the toolbox.

Transport: Streamable HTTP, stateless, JSON responses (no SSE needed), mounted
at `/api/v1/mcp` (same API key as the REST API). Every tool is a thin call to
the REST API on localhost, so the logic stays in one place.

    claude mcp add --transport http ctf http://127.0.0.1:19014/api/v1/mcp

Results are sized for small local models (16k context): every tool answers in
at most MAX_CHARS characters, long texts are paged (`offset`), and the big
REST payloads (file tree, flag evidence) are summarised unless asked for.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

from .config import API_KEY, DATA_DIR, MAX_UPLOAD, VERSION

log = logging.getLogger(__name__)

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
LOCAL = os.environ.get("STEGSUITE_SELF_URL", "http://127.0.0.1:19014") + "/api/v1"
# ~3k tokens: fits a 16k-context local model with room for the conversation
MAX_CHARS = int(os.environ.get("STEGSUITE_MCP_MAX_CHARS", "12000"))
PAGE_CAP = 200_000
# files an agent on the same machine drops in ./data/inbox (no base64 needed)
INBOX = Path(os.environ.get("STEGSUITE_INBOX", str(DATA_DIR / "inbox")))
ACTIVE = ("created", "queued", "running")
WAIT_CAP = 600


# --- REST passthrough ---------------------------------------------------------

def _request(path: str, method: str, data: bytes | None, headers: dict,
             timeout: int) -> tuple[int, str, bytes]:
    """HTTP to our own REST API -> (status, content-type, body). Tests swap this."""
    req = urllib.request.Request(LOCAL + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - our own REST API on localhost
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
    with urllib.request.urlopen(req, timeout=120) as r:  # nosec B310 - scheme checked above (http/https)
        data = r.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise ToolError("file too large")
    name = urllib.parse.unquote(urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]) or "file"
    return name, data


def _inbox_file(rel: str) -> tuple[str, bytes]:
    """A file from the inbox folder; paths outside it are refused."""
    root = INBOX.resolve()
    path = (root / rel).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ToolError(f"paths: '{rel}' is not a file in the inbox (./data/inbox on the host)")
    if path.stat().st_size > MAX_UPLOAD:
        raise ToolError("file too large")
    return path.name, path.read_bytes()


def _files_arg(args: dict) -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    for rel in args.get("paths") or []:
        files.append(_inbox_file(str(rel)))
    for url in args.get("urls") or []:
        files.append(_fetch(url))
    for f in args.get("files") or []:
        try:
            files.append((f["name"], base64.b64decode(f["content_base64"])))
        except (KeyError, ValueError, TypeError):
            raise ToolError("files: [{name, content_base64}]") from None
    if not files:
        raise ToolError("give `paths` (inbox), `urls` and/or `files`")
    return files


def _page(text: str, offset: int = 0, max_chars: int | None = None) -> str:
    """One window of a long text, with the offset of the next window."""
    size = min(max(int(max_chars or MAX_CHARS), 500), PAGE_CAP)
    offset = max(int(offset or 0), 0)
    chunk = text[offset:offset + size]
    end = offset + len(chunk)
    if offset == 0 and end >= len(text):
        return chunk
    more = f"next offset={end}" if end < len(text) else "end"
    return f"[chars {offset}-{end} of {len(text)}; {more}]\n{chunk}"


def _clip(s: Any, n: int = 300) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + "…"


def _flag_rows(flags: list[dict], limit: int) -> list[dict]:
    """One row per distinct flag value with the shortest proof."""
    rows, seen = [], set()
    for f in flags:
        if f.get("value") in seen:
            continue
        seen.add(f.get("value"))
        ev = f.get("evidence") or {}
        rows.append({"value": f.get("value"), "file": (f.get("file") or {}).get("name"),
                     "file_id": (f.get("file") or {}).get("id"), "how": f.get("how"),
                     "tool": ev.get("tool"), "evidence": _clip(ev.get("lines") or f.get("context"))})
        if len(rows) >= limit:
            break
    return rows


class ToolError(Exception):
    """Reported to the agent as a tool error (isError), not a protocol error."""


# --- tools --------------------------------------------------------------------

TOOLS: dict[str, tuple[str, dict, Callable[[dict], Any]]] = {}
READ_ONLY: set[str] = set()


def tool(name: str, description: str, props: dict | None = None, required: tuple = (),
         read_only: bool = False):
    schema = {"type": "object", "properties": props or {}, "required": list(required)}

    def deco(fn):
        TOOLS[name] = (description, schema, fn)
        if read_only:
            READ_ONLY.add(name)
        return fn
    return deco


S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}
FILES = {
    "paths": {"type": "array", "items": S,
              "description": "files already on this machine: names relative to ./data/inbox"},
    "urls": {"type": "array", "items": S, "description": "attachment URLs to download"},
    "files": {"type": "array", "description": "small inline files (base64)",
              "items": {"type": "object", "properties": {"name": S, "content_base64": S},
                        "required": ["name", "content_base64"]}},
}
WAIT = {"type": "integer", "description": f"seconds to wait for the analysis to end (0-{WAIT_CAP})"}
PAGE = {"offset": {"type": "integer", "description": "start of the window (from 'next offset=')"},
        "max_chars": {"type": "integer", "description": f"window size, default {MAX_CHARS}"}}


def _coerce(schema: dict, args: dict) -> dict:
    """Small models send '12' for 12 and 'true' for true: fix the scalar types."""
    props = schema["properties"]
    missing = [k for k in schema["required"] if args.get(k) in (None, "")]
    if missing:
        raise ToolError(f"missing argument(s): {', '.join(missing)}")
    out = dict(args)
    for k, v in args.items():
        kind = props.get(k, {}).get("type")
        if kind == "integer" and isinstance(v, str):
            try:
                out[k] = int(v.strip())
            except ValueError:
                raise ToolError(f"{k} must be an integer") from None
        elif kind == "boolean" and isinstance(v, str):
            out[k] = v.strip().lower() in ("1", "true", "yes")
        elif kind == "array" and isinstance(v, str):
            out[k] = [v]
    return out


def _wait(pid: str, seconds: int) -> dict:
    """Project detail, polled until it leaves the active states or `seconds` pass."""
    deadline = time.monotonic() + min(max(int(seconds or 0), 0), WAIT_CAP)
    while True:
        proj = _call(f"/projects/{pid}")
        if proj.get("status") not in ACTIVE or time.monotonic() >= deadline:
            return proj
        time.sleep(2)


def _summary(proj: dict, tree_limit: int = 30) -> dict:
    """Project status without the full tree: counts, flags, first files."""
    pid = proj["id"]
    flags = _call(f"/projects/{pid}/flags") if proj.get("status") not in ("created",) else []
    tree = proj.get("tree") or []
    out = {k: proj.get(k) for k in ("id", "name", "status", "mode", "ctf_id", "category",
                                    "solved", "flag", "files")}
    out["flags_found"] = len({f.get("value") for f in flags})
    out["top_flags"] = [r["value"] for r in _flag_rows(flags, 10)]
    out["tree_total"] = len(tree)
    out["tree"] = [{"id": n["id"], "parent_id": n.get("parent_id"), "name": n["name"],
                    "size": n.get("size"), "mime": n.get("mime"), "depth": n.get("depth")}
                   for n in tree[:max(int(tree_limit), 0)]]
    if proj.get("status") in ACTIVE:
        out["hint"] = "still running: call project_status with wait_s=120"
    elif not out["flags_found"]:
        out["hint"] = "no flag: get_transcript (paged), then run_tools / crack / read_file"
    return out


@tool("list_ctfs", "List CTF events with challenge/solved counters.", read_only=True)
def _list_ctfs(a):
    return _call("/ctfs")


@tool("create_ctf", "Create a CTF event. flag_format: prefix like 'DUCTF{...}' or a regex.",
      {"name": S, "flag_format": S, "url": S, "notes": S}, ("name",))
def _create_ctf(a):
    return _call("/ctfs", "POST", {k: a[k] for k in ("name", "flag_format", "url", "notes") if k in a})


@tool("ctf_scoreboard", "A CTF with every challenge: status, solved, flags found (first 5 each).",
      {"ctf_id": S}, ("ctf_id",), read_only=True)
def _scoreboard(a):
    board = _call(f"/ctfs/{a['ctf_id']}")
    for ch in board.get("challenge_list") or []:
        flags = list(dict.fromkeys(ch.get("flags") or []))
        ch["flags"], ch["flags_found"] = flags[:5], len(flags)
    return board


@tool("add_challenge", "Add a challenge to a CTF (files from the inbox, URLs and/or base64); "
      "start=true analyzes it. Follow with project_status(wait_s=...).",
      {"ctf_id": S, "name": S, "category": S, "start": B, **FILES}, ("ctf_id",))
def _add_challenge(a):
    body, ctype = _multipart(_files_arg(a), {"name": a.get("name", ""), "category": a.get("category", ""),
                                             "start": "true" if a.get("start", True) else "false"})
    return _call(f"/ctfs/{a['ctf_id']}/challenges", "POST", raw=body, ctype=ctype, timeout=600)


@tool("autosolve", "Analyze every unsolved challenge of a CTF (parallel at a time).",
      {"ctf_id": S, "parallel": I}, ("ctf_id",))
def _autosolve(a):
    return _call(f"/ctfs/{a['ctf_id']}/autosolve", "POST", {"parallel": a.get("parallel", 2)})


@tool("analyze", "Analyze files as a new project. Easiest call: analyze(paths=['file.png'], "
      "wait_s=300) -> status + flags when it ends. Files: `paths` (in ./data/inbox), `urls` or "
      "base64 `files`.",
      {"name": S, "mode": {"type": "string", "enum": ["auto", "check"]}, "wait_s": WAIT, **FILES})
def _analyze(a):
    body, ctype = _multipart(_files_arg(a), {"name": a.get("name", ""), "mode": a.get("mode", "auto")})
    proj = _call("/projects", "POST", raw=body, ctype=ctype, timeout=600)
    _call(f"/projects/{proj['id']}/start", "POST", {})
    return _summary(_wait(proj["id"], a.get("wait_s", 0)) if a.get("wait_s") else
                    {**proj, "status": "queued"}, tree_limit=5)


@tool("list_projects", "Recent projects/challenges (newest first): id, name, status, files.",
      {"limit": I}, read_only=True)
def _list_projects(a):
    rows = _call("/projects")
    rows = rows.get("projects", rows) if isinstance(rows, dict) else rows
    keys = ("id", "name", "status", "ctf_id", "solved", "flag", "files", "created_at")
    return [{k: p.get(k) for k in keys} for p in rows[:max(int(a.get("limit", 20)), 1)]]


@tool("project_status", "Status of a project: counts, flags found, first files of the tree. "
      "wait_s waits for the end; tree_limit shows more files.",
      {"project_id": S, "wait_s": WAIT, "tree_limit": I}, ("project_id",), read_only=True)
def _status(a):
    return _summary(_wait(a["project_id"], a.get("wait_s", 0)), a.get("tree_limit", 30))


@tool("get_flags", "Flags found (one per value) with file, tool and a short proof. "
      "verbose=true gives the full chain and evidence.",
      {"project_id": S, "limit": I, "verbose": B}, ("project_id",), read_only=True)
def _flags(a):
    flags = _call(f"/projects/{a['project_id']}/flags")
    if a.get("verbose"):
        return flags[:max(int(a.get("limit", 5)), 1)]
    return _flag_rows(flags, max(int(a.get("limit", 20)), 1))


@tool("get_report", "Markdown report of a project (lang en|it), paged with offset/max_chars.",
      {"project_id": S, "lang": {"type": "string", "enum": ["en", "it"]}, **PAGE},
      ("project_id",), read_only=True)
def _report(a):
    text = _call(f"/projects/{a['project_id']}/report?lang={a.get('lang', 'en')}")
    return _page(text if isinstance(text, str) else json.dumps(text), a.get("offset", 0), a.get("max_chars"))


@tool("get_transcript", "Full log of what the analysis did, paged: read the first window, "
      "then call again with the 'next offset'.",
      {"project_id": S, **PAGE}, ("project_id",), read_only=True)
def _transcript(a):
    text = _call(f"/projects/{a['project_id']}/transcript")
    return _page(text if isinstance(text, str) else json.dumps(text), a.get("offset", 0), a.get("max_chars"))


@tool("read_file", "Read a file of the project tree (text, or base64 for binary) from offset, "
      "up to max_bytes (default 8192).",
      {"project_id": S, "file_id": I, "offset": I, "max_bytes": I}, ("project_id", "file_id"), read_only=True)
def _read_file(a):
    data = _call(f"/projects/{a['project_id']}/files/{a['file_id']}/content", binary=True)
    start = max(int(a.get("offset", 0)), 0)
    chunk = data[start:start + min(max(int(a.get("max_bytes", 8192)), 1), PAGE_CAP)]
    out = {"size": len(data), "offset": start, "next_offset": start + len(chunk)
           if start + len(chunk) < len(data) else None}
    try:
        return {**out, "encoding": "utf-8", "content": chunk.decode("utf-8")}
    except UnicodeDecodeError:
        return {**out, "encoding": "base64", "content": base64.b64encode(chunk).decode()}


@tool("list_tools", "Analyzer names by category; give `category` for the descriptions.",
      {"category": S}, read_only=True)
def _tools(a):
    tools = _call("/tools")
    cat = (a.get("category") or "").strip().lower()
    if cat:
        return [{"name": t["name"], "description": t.get("description"),
                 "needs_password": t.get("needs_password")}
                for t in tools if (t.get("category") or "").lower() == cat]
    groups: dict[str, list[str]] = {}
    for t in tools:
        groups.setdefault(t.get("category") or "other", []).append(t["name"])
    return groups


@tool("run_tools", "Run analyzers on one file of a project, optionally with a password.",
      {"project_id": S, "file_id": I, "tools": {"type": "array", "items": S}, "password": S},
      ("project_id", "file_id", "tools"))
def _run_tools(a):
    body = {"tools": a["tools"], **({"password": a["password"]} if a.get("password") else {})}
    return _call(f"/projects/{a['project_id']}/files/{a['file_id']}/run", "POST", body)


@tool("locked_files", "Files still needing a password.", {"project_id": S}, ("project_id",), read_only=True)
def _locked(a):
    return _call(f"/projects/{a['project_id']}/locked")


@tool("crack", "Queue a crack of a locked file with wordlists (names from list_wordlists), rules "
      "or a mask; follow it with crack_jobs.",
      {"project_id": S, "file_id": I, "wordlists": {"type": "array", "items": S},
       "mask": S, "budget_s": I}, ("project_id", "file_id"))
def _crack(a):
    body = {k: a[k] for k in ("file_id", "wordlists", "mask", "budget_s") if k in a}
    return _call(f"/projects/{a['project_id']}/crack", "POST", body)


@tool("crack_jobs", "Crack queue: status of every job (password and wordlist when found).",
      {"project_id": S}, read_only=True)
def _crack_jobs(a):
    return _call("/cracks" + (f"?project_id={a['project_id']}" if a.get("project_id") else ""))


@tool("list_wordlists", "Wordlists available for cracking (smallest first).", read_only=True)
def _wordlists(a):
    return _call("/wordlists")


@tool("list_inbox", "Files in ./data/inbox that analyze/add_challenge accept as `paths`.", read_only=True)
def _inbox(a):
    root = INBOX.resolve()
    if not root.is_dir():
        return {"inbox": str(INBOX), "files": [], "hint": "create ./data/inbox and put files there"}
    files = [{"path": str(p.relative_to(root)), "size": p.stat().st_size}
             for p in sorted(root.rglob("*")) if p.is_file()]
    return {"inbox": str(INBOX), "files": files[:200], "total": len(files)}


@tool("set_challenge", "Edit a challenge: solved, flag, category, name, ctf_id.",
      {"project_id": S, "solved": B, "flag": S, "category": S, "name": S, "ctf_id": S},
      ("project_id",))
def _set(a):
    return _call(f"/projects/{a['project_id']}", "PATCH",
                 {k: v for k, v in a.items() if k != "project_id"})


@tool("toolbox_services", "Other web tools of the toolbox (CyberChef, ZAP, Wireshark, rev sandbox…) "
      "and their URLs.", read_only=True)
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
            "instructions": (
                "CTF toolbox. Simplest: put the file in ./data/inbox, then "
                "analyze(paths=['name'], wait_s=300) -> status + top_flags. "
                "CTF flow: create_ctf -> add_challenge(start=true) -> project_status(wait_s=300) "
                "-> get_flags. If no flag: get_transcript (paged), then run_tools / crack / "
                "read_file. Long texts are paged: call again with the 'next offset'."),
        })
    if method == "ping":
        return _result(rid, {})
    if method == "tools/list":
        return _result(rid, {"tools": [
            {"name": n, "description": d, "inputSchema": s,
             "annotations": {"readOnlyHint": n in READ_ONLY, "openWorldHint": n in ("analyze", "add_challenge")}}
            for n, (d, s, _) in TOOLS.items()]})
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in TOOLS:
            return _error(rid, -32602, f"unknown tool: {name}")
        if not isinstance(args, dict):
            return _error(rid, -32602, "arguments must be an object")
        try:
            out = TOOLS[name][2](_coerce(TOOLS[name][1], args))
            text = out if isinstance(out, str) else json.dumps(out, ensure_ascii=False, default=str)
            cap = max(MAX_CHARS, min(int(args.get("max_chars") or 0), PAGE_CAP))
            if len(text) > cap + 256:      # + the page header
                text = (text[:cap] + f"\n[truncated: {len(text)} chars; narrow the call "
                        "(limit, tree_limit, category) or use a paged tool]")
            return _result(rid, {"content": [{"type": "text", "text": text}], "isError": False})
        except Exception as exc:  # noqa: BLE001 - any failure is reported to the agent, not a 500
            if not isinstance(exc, (ToolError, OSError, KeyError, ValueError, TypeError)):
                log.exception("mcp tool %s failed", name)
            return _result(rid, {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True})
    return _error(rid, -32601, f"method not found: {method}")
