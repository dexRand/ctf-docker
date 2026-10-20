"""CTF events: CRUD, challenges, CTF flag format, solved detection, autosolve."""
import io
import time

import pytest
from fastapi.testclient import TestClient

from backend import ctfs


@pytest.fixture(scope="module")
def client():
    from backend.main import app
    with TestClient(app) as c:
        yield c


def _wait(client, url, cond, tries=150):
    for _ in range(tries):
        r = client.get(url).json()
        if cond(r):
            return r
        time.sleep(0.1)
    return r


@pytest.mark.parametrize("fmt,flag,ok", [
    ("DUCTF", b"x DUCTF{abc_1} y", True),
    ("DUCTF{...}", b"DUCTF{abc_1}", True),
    ("FLAG-[0-9a-f]{8}", b"FLAG-deadbeef", True),
    ("DUCTF", b"xDUCTF{glued}", False),
])
def test_format_regex(fmt, flag, ok):
    rx, _ = ctfs.format_regex(fmt)
    assert bool(rx.search(flag)) is ok


def test_invalid_format_is_rejected(client):
    assert client.post("/api/v1/ctfs", json={"name": "x", "flag_format": "a(b"}).status_code == 422
    assert client.post("/api/v1/ctfs", json={"flag_format": "X"}).status_code == 422


def test_ctf_lifecycle_and_solved_detection(client):
    c = client.post("/api/v1/ctfs", json={"name": "Down Under 2026", "flag_format": "DUCTF{...}"}).json()
    cid = c["id"]
    assert cid.startswith("down-under-2026-") and c["challenges"] == 0

    files = {"files": ("note.txt", io.BytesIO(b"hello\nDUCTF{solved_by_format}\n"), "text/plain")}
    p = client.post(f"/api/v1/ctfs/{cid}/challenges",
                    data={"name": "easy", "category": "misc", "start": "true"}, files=files).json()
    assert p["ctf_id"] == cid and p["category"] == "misc"
    done = _wait(client, f"/api/v1/projects/{p['id']}", lambda r: r["status"] in ("done", "error"))
    assert done["status"] == "done"
    assert done["solved"] is True and done["flag"] == "DUCTF{solved_by_format}"

    full = client.get(f"/api/v1/ctfs/{cid}").json()
    assert full["solved"] == 1 and full["challenge_list"][0]["flags"] == ["DUCTF{solved_by_format}"]
    assert [x["id"] for x in client.get(f"/api/v1/projects?ctf_id={cid}").json()] == [p["id"]]

    # a human can correct the answer
    r = client.patch(f"/api/v1/projects/{p['id']}", json={"flag": "DUCTF{fixed}", "category": "forensics"})
    assert r.json()["flag"] == "DUCTF{fixed}" and r.json()["category"] == "forensics"
    assert client.patch(f"/api/v1/projects/{p['id']}", json={"status": "done"}).status_code == 422

    # deleting the CTF keeps its challenges
    assert client.delete(f"/api/v1/ctfs/{cid}").status_code == 200
    assert client.get(f"/api/v1/projects/{p['id']}").json()["ctf_id"] is None


def test_autosolve_runs_unsolved_challenges(client):
    cid = client.post("/api/v1/ctfs", json={"name": "auto", "flag_format": "AUTO"}).json()["id"]
    ids = []
    for i in range(3):
        f = {"files": (f"c{i}.txt", io.BytesIO(f"AUTO{{chall_{i}}}\n".encode()), "text/plain")}
        ids.append(client.post(f"/api/v1/ctfs/{cid}/challenges", data={"name": f"c{i}"}, files=f).json()["id"])
    st = client.post(f"/api/v1/ctfs/{cid}/autosolve", json={"parallel": 2}).json()
    assert st["total"] == 3
    assert client.post(f"/api/v1/ctfs/{cid}/autosolve", json={}).status_code == 409
    final = _wait(client, f"/api/v1/ctfs/{cid}", lambda r: r["solved"] == 3, tries=900)
    assert final["solved"] == 3, (final["autosolve"], [(c["status"], c["solved"], c["flags"])
                                                        for c in final["challenge_list"]])
