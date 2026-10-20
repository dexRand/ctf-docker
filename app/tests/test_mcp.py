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
    return res["isError"], (json.loads(text) if text[:1] in "[{" else text)


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
