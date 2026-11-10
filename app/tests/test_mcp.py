"""MCP server: JSON-RPC handshake, tool list, tool calls through the REST API."""
import base64
import json
import time

import pytest
from fastapi.testclient import TestClient

from backend import mcp_server


@pytest.fixture(scope="module")
def client():
    from backend.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _route_to_testclient(client, monkeypatch):
    # tools call the REST API over HTTP; in tests, through the TestClient
    def request(path, method, data, headers, timeout):
        r = client.request(method, "/api/v1" + path, content=data, headers=headers)
        return r.status_code, r.headers.get("content-type", ""), r.content
    monkeypatch.setattr(mcp_server, "_request", request)


def rpc(client, method, params=None, rid=1):
    r = client.post("/api/v1/mcp", json={"jsonrpc": "2.0", "id": rid, "method": method,
                                         "params": params or {}})
    assert r.status_code == 200
    return r.json()


def call(client, name, args):
    res = rpc(client, "tools/call", {"name": name, "arguments": args})["result"]
    text = res["content"][0]["text"]
    try:
        return res["isError"], json.loads(text)
    except ValueError:      # plain or paged text ("[chars 0-600 of ...]")
        return res["isError"], text


def test_handshake_and_tool_list(client):
    init = rpc(client, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "t", "version": "0"}})["result"]
    assert init["protocolVersion"] == "2025-06-18" and "tools" in init["capabilities"]
    r = client.post("/api/v1/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert r.status_code == 202
    names = {t["name"] for t in rpc(client, "tools/list")["result"]["tools"]}
    assert {"create_ctf", "add_challenge", "analyze", "get_flags", "crack", "run_tools",
            "toolbox_services"} <= names
    assert client.get("/api/v1/mcp").status_code == 405


def test_agent_flow_ctf_challenge_flag(client):
    err, ctf = call(client, "create_ctf", {"name": "mcp ctf", "flag_format": "MCP{...}"})
    assert not err
    payload = base64.b64encode(b"notes\nMCP{via_the_agent}\n").decode()
    err, proj = call(client, "add_challenge", {"ctf_id": ctf["id"], "name": "c1",
                                               "files": [{"name": "c1.txt", "content_base64": payload}]})
    assert not err
    for _ in range(200):
        _, st = call(client, "project_status", {"project_id": proj["id"]})
        if st["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    _, flags = call(client, "get_flags", {"project_id": proj["id"]})
    assert flags[0]["value"] == "MCP{via_the_agent}"
    _, board = call(client, "ctf_scoreboard", {"ctf_id": ctf["id"]})
    assert board["solved"] == 1
    _, f = call(client, "read_file", {"project_id": proj["id"], "file_id": st["tree"][0]["id"]})
    assert "MCP{via_the_agent}" in f["content"]


def test_errors_are_tool_errors_not_crashes(client):
    err, text = call(client, "project_status", {"project_id": "nope"})
    assert err and "404" in text
    assert "error" in rpc(client, "tools/call", {"name": "nope"})
    assert rpc(client, "bogus/method")["error"]["code"] == -32601


# --- sized for small local models (16k context) ------------------------------

def _flag_project(client, tmp_path, monkeypatch, body=b"notes\nflag{from_the_inbox}\n"):
    monkeypatch.setattr(mcp_server, "INBOX", tmp_path)
    (tmp_path / "chal.txt").write_bytes(body)
    return call(client, "analyze", {"paths": ["chal.txt"], "wait_s": "60"})


def test_inbox_paths_and_wait_return_the_flag(client, tmp_path, monkeypatch):
    err, res = _flag_project(client, tmp_path, monkeypatch)
    assert not err, res
    assert res["status"] == "done" and "flag{from_the_inbox}" in res["top_flags"]
    err, inbox = call(client, "list_inbox", {})
    assert not err and inbox["files"][0]["path"] == "chal.txt"


def test_inbox_refuses_paths_outside(client, tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (tmp_path / "secret.txt").write_text("x")
    monkeypatch.setattr(mcp_server, "INBOX", inbox)
    for bad in ("../secret.txt", "/etc/passwd", "missing.txt"):
        err, text = call(client, "analyze", {"paths": [bad]})
        assert err and "not a file in the inbox" in text


def test_big_answers_are_compact_or_paged(client, tmp_path, monkeypatch):
    _, res = _flag_project(client, tmp_path, monkeypatch)
    pid = res["id"]
    # list_tools: names by category, not 20 KB of descriptions
    err, groups = call(client, "list_tools", {})
    assert not err and isinstance(groups, dict) and all(isinstance(v, list) for v in groups.values())
    monkeypatch.setattr(mcp_server, "MAX_CHARS", 600)
    err, page = call(client, "get_transcript", {"project_id": pid})
    assert not err and page.startswith("[chars 0-600 of ") and "next offset=600" in page
    err, page2 = call(client, "get_transcript", {"project_id": pid, "offset": 600})
    assert not err and page2.startswith("[chars 600-")
    # any answer over the cap is cut with a hint instead of flooding the context
    monkeypatch.setattr(mcp_server, "MAX_CHARS", 100)
    res = rpc(client, "tools/call", {"name": "list_tools", "arguments": {"category": "metadata"}})["result"]
    text = res["content"][0]["text"]
    assert not res["isError"] and "[truncated:" in text and len(text) < 400


def test_flags_are_one_row_per_value_with_short_proof(client, tmp_path, monkeypatch):
    _, res = _flag_project(client, tmp_path, monkeypatch, b"flag{same_one}\n" * 50 + b"flag{other_one}\n")
    _, rows = call(client, "get_flags", {"project_id": res["id"]})
    values = [r["value"] for r in rows]
    assert len(values) == len(set(values)) and {"flag{same_one}", "flag{other_one}"} <= set(values)
    assert all(len(r["evidence"]) <= 301 for r in rows)


def test_small_model_argument_mistakes_are_clear_errors(client):
    err, text = call(client, "project_status", {})
    assert err and "missing argument(s): project_id" in text
    err, text = call(client, "read_file", {"project_id": "nope", "file_id": "abc"})
    assert err and "file_id must be an integer" in text
    r = client.post("/api/v1/mcp", json=[1, 2])
    assert r.status_code == 400
    tools = rpc(client, "tools/list")["result"]["tools"]
    ro = {t["name"] for t in tools if t["annotations"]["readOnlyHint"]}
    assert {"get_flags", "project_status", "list_tools"} <= ro and "crack" not in ro


def test_foreign_browser_origin_is_refused(client):
    body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert client.post("/api/v1/mcp", json=body, headers={"Origin": "http://evil.example"}).status_code == 403
    assert client.post("/api/v1/mcp", json=body, headers={"Origin": "http://localhost:5173"}).status_code == 200
