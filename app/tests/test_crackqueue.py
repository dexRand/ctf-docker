"""Crack queue: per-file jobs, no duplicates, cancel queued, results applied."""
import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from backend import cracking, crackqueue, storage
from backend.db import engine, init_db
from backend.models import FileNode, Project

PID = "cq-test"


@pytest.fixture(scope="module")
def client():
    from backend.main import app
    init_db()
    (storage.project_dir(PID) / "uploads").mkdir(parents=True, exist_ok=True)
    with Session(engine) as s:
        if not s.get(Project, PID):
            s.add(Project(id=PID, name="cq", status="done"))
            for i, n in ((701, "a.zip"), (702, "b.zip"), (703, "c.zip")):
                (storage.project_dir(PID) / "uploads" / n).write_bytes(b"PK")
                s.add(FileNode(id=i, project_id=PID, name=n, rel_path=f"uploads/{n}"))
            s.commit()
    with TestClient(app) as c:
        yield c


def _wait(cond, tries=100):
    for _ in range(tries):
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_queue_runs_per_file_and_rejects_duplicates(client, monkeypatch):
    gate = threading.Event()

    def fake_crack(path, names, log=None, **kw):
        gate.wait(5)
        pw = "s3cret" if path.name == "a.zip" else None
        return {"password": pw, "kind": "archive", "extracted": [], "wordlist_hit": "10k.txt" if pw else None,
                "wordlists": []}
    monkeypatch.setattr(cracking, "crack_file", fake_crack)

    r1 = client.post(f"/api/v1/projects/{PID}/crack", json={"file_id": 701})
    r2 = client.post(f"/api/v1/projects/{PID}/crack", json={"file_id": 702})
    r3 = client.post(f"/api/v1/projects/{PID}/crack", json={"file_id": 703})
    assert r1.status_code == r2.status_code == r3.status_code == 200
    assert client.post(f"/api/v1/projects/{PID}/crack", json={"file_id": 702}).status_code == 409
    # c.zip is still queued behind the single worker: cancel it
    job3 = r3.json()["job"]
    assert client.delete(f"/api/v1/cracks/{job3}").status_code == 200
    gate.set()
    assert _wait(lambda: all(j["status"] not in ("queued", "running")
                             for j in client.get(f"/api/v1/cracks?project_id={PID}").json()))
    by_file = {j["file_id"]: j for j in client.get(f"/api/v1/cracks?project_id={PID}").json()}
    assert by_file[701]["status"] == "found" and by_file[701]["password"] == "s3cret"
    assert by_file[702]["status"] == "not_found"
    assert by_file[703]["status"] == "cancelled"
    pw = [f for f in client.get(f"/api/v1/projects/{PID}/findings").json() if f["kind"] == "password"]
    assert [p["value"] for p in pw] == ["s3cret"]
    assert client.delete("/api/v1/cracks/999999").status_code == 404


def test_crack_marks_the_project_running_then_restores_it(client, monkeypatch):
    """A crack on a `done` project shows a running job, and the status comes
    back when nothing else is working on it."""
    pid = "cq-status"
    with Session(engine) as s:
        if not s.get(Project, pid):
            (storage.project_dir(pid) / "uploads").mkdir(parents=True, exist_ok=True)
            (storage.project_dir(pid) / "uploads" / "x.zip").write_bytes(b"PK")
            s.add(Project(id=pid, name="cq-status", status="done"))
            s.add(FileNode(project_id=pid, name="x.zip", rel_path="uploads/x.zip"))
            s.commit()
        node = s.exec(select(FileNode).where(FileNode.project_id == pid)).first()

    gate = threading.Event()

    def fake_crack(path, names, log=None, **kw):
        gate.wait(5)
        return {"password": None, "kind": "archive", "extracted": [],
                "wordlist_hit": None, "wordlists": []}
    monkeypatch.setattr(cracking, "crack_file", fake_crack)

    assert client.post(f"/api/v1/projects/{pid}/crack", json={"file_id": node.id}).status_code == 200
    assert _wait(lambda: client.get(f"/api/v1/projects/{pid}").json()["status"] == "running")
    gate.set()
    assert _wait(lambda: client.get(f"/api/v1/projects/{pid}").json()["status"] == "done")


def test_a_batch_of_cracks_restores_the_original_status(client, monkeypatch):
    """Queued jobs must not leave the project stuck on `running`: the status
    saved for the batch is the one from before the first job."""
    pid = "cq-batch"
    with Session(engine) as s:
        if not s.get(Project, pid):
            (storage.project_dir(pid) / "uploads").mkdir(parents=True, exist_ok=True)
            s.add(Project(id=pid, name="cq-batch", status="done"))
            for n in ("one.zip", "two.zip"):
                (storage.project_dir(pid) / "uploads" / n).write_bytes(b"PK")
                s.add(FileNode(project_id=pid, name=n, rel_path=f"uploads/{n}"))
            s.commit()
        nodes = s.exec(select(FileNode).where(FileNode.project_id == pid)).all()

    gate = threading.Event()

    def fake_crack(path, names, log=None, **kw):
        gate.wait(5)
        return {"password": None, "kind": "archive", "extracted": [],
                "wordlist_hit": None, "wordlists": []}
    monkeypatch.setattr(cracking, "crack_file", fake_crack)

    for node in nodes[:2]:
        assert client.post(f"/api/v1/projects/{pid}/crack", json={"file_id": node.id}).status_code == 200
    assert _wait(lambda: client.get(f"/api/v1/projects/{pid}").json()["status"] == "running")
    gate.set()
    assert _wait(lambda: all(j["status"] not in ("queued", "running")
                             for j in client.get(f"/api/v1/cracks?project_id={pid}").json()))
    assert _wait(lambda: client.get(f"/api/v1/projects/{pid}").json()["status"] == "done")


def test_settle_forgets_the_batch_when_an_analysis_owns_the_status(monkeypatch):
    from backend import crackqueue as cq, jobs as analysis
    monkeypatch.setattr(analysis, "is_running", lambda pid: True)
    job = cq.CrackJob(999999, "pid-settle", 1, "x", None, {})
    job.status = "not_found"
    cq._PREV["pid-settle"] = "failed"
    cq._settle(job)
    assert "pid-settle" not in cq._PREV      # no stale status for the next crack
