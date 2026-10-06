"""Every registered analyzer must be reachable and callable through the HTTP API.

The API exposes a generic `POST /api/v1/tools/{tool}`; this suite is the guard
that a tool can never be added to the registry without becoming API-callable
(see docs/API.md). It also checks the catalog is coherent.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

from backend.analyzers import catalog
from backend.analyzers import get as get_tool
from backend.analyzers import REGISTRY

# a 32-byte PNG signature followed by text: enough for libmagic/strings/decode,
# harmless for the rest (they must degrade to skipped/error, never crash the API)
SAMPLE = (b"\x89PNG\r\n\x1a\n" + b"ITS{api_probe_flag_1} " + b"ZmxhZ3s=\n" + b"\x00" * 8)


@pytest.fixture(scope="module")
def client():
    m = importlib.import_module("backend.main")
    with TestClient(m.app) as c:
        yield c


def _catalog_names() -> list[str]:
    return [t["name"] for t in catalog()]


def test_registry_is_not_empty():
    assert len(REGISTRY) >= 37


def test_every_registered_tool_appears_in_the_catalog():
    assert set(_catalog_names()) == set(REGISTRY)


def test_catalog_entries_are_complete_and_unique():
    entries = catalog()
    names = [e["name"] for e in entries]
    assert len(names) == len(set(names)), "duplicate tool name in catalog"
    for e in entries:
        assert e["description"], f"{e['name']} has no description"
        assert e["category"], f"{e['name']} has no category"
        assert isinstance(e["display_order"], int)
        assert isinstance(e["accepts"], list)


def test_catalog_is_sorted_by_display_order():
    orders = [e["display_order"] for e in catalog()]
    assert orders == sorted(orders)


def test_every_tool_is_callable_through_the_api(client):
    """The core promise: any tool in the catalog can be invoked over HTTP."""
    failures: dict[str, object] = {}
    for name in _catalog_names():
        r = client.post(f"/api/v1/tools/{name}",
                        files={"file": (f"{name}-probe.bin", SAMPLE, "application/octet-stream")})
        if r.status_code != 200:
            failures[name] = f"HTTP {r.status_code}"
            continue
        body = r.json()
        if body.get("tool") != name or not body.get("status"):
            failures[name] = f"unexpected body: {body}"
    assert not failures, f"tools not usable via API: {failures}"


def test_unknown_tool_is_a_404(client):
    r = client.post("/api/v1/tools/definitely-not-a-tool",
                    files={"file": ("x.bin", SAMPLE, "application/octet-stream")})
    assert r.status_code == 404


def test_tool_call_reports_its_job_and_artifacts_are_downloadable(client):
    r = client.post("/api/v1/tools/strings",
                    files={"file": ("probe.txt", SAMPLE, "text/plain")})
    assert r.status_code == 200
    body = r.json()
    assert body["tool"] == "strings"
    assert body["job_id"]

    # artifacts of a tool job are downloadable under the same auth rules
    assert client.get(f"/api/v1/tooljobs/{body['job_id']}/files/nope.bin").status_code == 404
    assert client.get(f"/api/v1/tooljobs/{body['job_id']}/files/../../../etc/passwd").status_code == 404

    # the actual extraction needs the `strings` binary (binutils), which is not
    # present in every environment (e.g. a bare pip-only CI); the API contract
    # above still holds, so only assert the payload when the tool really ran.
    if body["status"] != "done":
        pytest.skip("'strings' binary not available in this environment")
    assert "ITS{api_probe_flag_1}" in body["output"]


def test_tool_password_is_accepted_as_a_form_field(client):
    # `steghide` is one of the tools declared needs_password; the endpoint must
    # take the password as a form field, not as a query parameter.
    assert get_tool("steghide").needs_password
    r = client.post("/api/v1/tools/steghide",
                    files={"file": ("probe.jpg", SAMPLE, "image/jpeg")},
                    data={"password": ""})
    assert r.status_code == 200
    assert r.json()["tool"] == "steghide"


def test_tools_catalog_endpoint_matches_the_registry(client):
    served = client.get("/api/v1/tools").json()
    assert [t["name"] for t in served] == _catalog_names()


def test_get_returns_none_for_an_unknown_name():
    assert get_tool("definitely-not-a-tool") is None