"""Crack queue: per-file jobs, no duplicates, cancel queued, results applied."""
import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from backend import cracking, storage
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


# ------------------------------------------------ wordlist progress (issue #56)
def test_crack_job_as_dict_exposes_requested_and_tried_wordlists():
    from backend import crackqueue as cq
    job = cq.CrackJob(42, "p", 7, "x.zip", ["a.txt", "b.txt"], {"rules": "best64"})
    d = job.as_dict()
    assert d["wordlists"] == ["a.txt", "b.txt"]
    assert d["opts"] == {"rules": "best64"}
    assert d["tried_wordlists"] == [] and d["current_wordlist"] is None
    assert d["wordlist"] is None            # the winning list is still serialized
    job.tried_wordlists.append("a.txt")
    job.current_wordlist = "b.txt"
    d = job.as_dict()
    assert d["tried_wordlists"] == ["a.txt"] and d["current_wordlist"] == "b.txt"


def _fake_lists(tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("a\n")
    b.write_text("b\n")
    return [a, b]


def test_crack_file_reports_every_wordlist_in_order(tmp_path, monkeypatch):
    """The progress callback fires once per wordlist, in order, with its name."""
    wls = _fake_lists(tmp_path)
    monkeypatch.setattr(cracking.shutil, "which", lambda _name: None)
    monkeypatch.setattr(cracking, "resolve_wordlists", lambda names=None, max_bytes=None: wls)
    seen: list[str] = []
    res = cracking.crack_file(tmp_path / "locked.zip", on_wordlist=seen.append)
    assert seen == ["a.txt", "b.txt"]
    assert res["password"] is None


def test_crack_file_works_without_a_progress_callback(tmp_path, monkeypatch):
    """The auto-crack path calls crack_file without on_wordlist: it must not fail."""
    wls = _fake_lists(tmp_path)
    monkeypatch.setattr(cracking.shutil, "which", lambda _name: None)
    monkeypatch.setattr(cracking, "resolve_wordlists", lambda names=None, max_bytes=None: wls)
    res = cracking.crack_file(tmp_path / "locked.zip")
    assert res["wordlists"] == ["a.txt", "b.txt"]


def test_running_job_tracks_wordlist_progress(client, monkeypatch):
    """_crack maps the callback onto tried_wordlists/current_wordlist and
    publishes it through as_dict, so the SPA can render live progress."""
    pid = "cq-progress"
    with Session(engine) as s:
        if not s.get(Project, pid):
            (storage.project_dir(pid) / "uploads").mkdir(parents=True, exist_ok=True)
            (storage.project_dir(pid) / "uploads" / "w.zip").write_bytes(b"PK")
            s.add(Project(id=pid, name="cq-progress", status="done"))
            s.add(FileNode(project_id=pid, name="w.zip", rel_path="uploads/w.zip"))
            s.commit()
        node = s.exec(select(FileNode).where(FileNode.project_id == pid)).first()

    started, gate = threading.Event(), threading.Event()

    def fake_crack(path, names, log=None, on_wordlist=None, **kw):
        on_wordlist("a.txt")
        started.set()
        gate.wait(5)
        on_wordlist("b.txt")
        return {"password": None, "kind": "archive", "extracted": [],
                "wordlist_hit": None, "wordlists": []}
    monkeypatch.setattr(cracking, "crack_file", fake_crack)

    assert client.post(f"/api/v1/projects/{pid}/crack",
                       json={"file_id": node.id}).status_code == 200
    assert _wait(started.is_set)
    job = client.get(f"/api/v1/cracks?project_id={pid}").json()[0]
    assert job["status"] == "running"
    assert job["current_wordlist"] == "a.txt" and job["tried_wordlists"] == []
    gate.set()
    assert _wait(lambda: client.get(f"/api/v1/cracks?project_id={pid}")
                 .json()[0]["status"] not in ("queued", "running"))
    job = client.get(f"/api/v1/cracks?project_id={pid}").json()[0]
    assert job["tried_wordlists"] == ["a.txt"]   # completed; the last one stays current
    assert job["current_wordlist"] == "b.txt"
    assert job["wordlists"] is None and job["opts"] == {}
