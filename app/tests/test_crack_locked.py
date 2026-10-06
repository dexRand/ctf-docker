"""Locked-file lifecycle: /locked, the crack guard, crack runs and timestamps.

Covers the crack telemetry added to the backend: a cracked file must stop being
reported as locked, cracking an already-cracked file must be rejected, and every
crack attempt is persisted as a single ToolRun with its commands and outcome.
"""
from __future__ import annotations

import datetime as dt
import importlib

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from backend import orchestrator
from backend.db import engine
from backend.models import Finding, ToolRun


@pytest.fixture(scope="module")
def client():
    with TestClient(importlib.import_module("backend.main").app) as c:
        yield c


def _new_project(client, name="locked") -> str:
    r = client.post(
        "/api/v1/projects",
        files=[("files", ("note.bin", b"just some bytes", "application/octet-stream"))],
        data={"mode": "check", "name": name},
    )
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


def _file_id(client, pid: str) -> int:
    return client.get(f"/api/v1/projects/{pid}").json()["tree"][0]["id"]


def _add_locked_run(pid: str, fid: int) -> None:
    with Session(engine) as s:
        s.add(ToolRun(project_id=pid, file_id=fid, tool="7z",
                      status="needs_password", needs_password=True))
        s.commit()


def test_locked_lists_a_file_that_needs_a_password(client):
    pid = _new_project(client)
    fid = _file_id(client, pid)
    _add_locked_run(pid, fid)
    locked = client.get(f"/api/v1/projects/{pid}/locked").json()
    assert [l["file_id"] for l in locked] == [fid]


def test_locked_hides_a_file_that_has_been_cracked(client):
    pid = _new_project(client)
    fid = _file_id(client, pid)
    _add_locked_run(pid, fid)
    with Session(engine) as s:
        s.add(Finding(project_id=pid, file_id=fid, kind="password",
                      value="robot", source="crack:archive", context="10k.txt"))
        s.commit()
    assert client.get(f"/api/v1/projects/{pid}/locked").json() == []


def test_crack_is_rejected_on_an_already_cracked_file(client):
    pid = _new_project(client)
    fid = _file_id(client, pid)
    with Session(engine) as s:
        s.add(Finding(project_id=pid, file_id=fid, kind="password", value="robot"))
        s.commit()
    r = client.post(f"/api/v1/projects/{pid}/crack", json={"file_id": fid})
    assert r.status_code == 409


def test_crack_on_a_still_locked_file_is_accepted(client):
    pid = _new_project(client)
    fid = _file_id(client, pid)
    _add_locked_run(pid, fid)
    r = client.post(f"/api/v1/projects/{pid}/crack", json={"file_id": fid})
    assert r.status_code == 200
    assert r.json()["file_id"] == fid


def test_record_crack_run_keeps_a_single_run_and_updates_it(tmp_path):
    pid = "test-crack-run"
    with Session(engine) as s:
        orchestrator.record_crack_run(
            s, pid, 42, tmp_path,
            {"password": "robot", "wordlist_hit": "10k.txt"}, ["$ hashcat ..."])
        s.commit()
        runs = s.exec(select(ToolRun).where(ToolRun.project_id == pid)).all()
        assert len(runs) == 1
        assert runs[0].tool == "crack"
        assert runs[0].status == "done"
        assert "robot" in runs[0].summary
        assert runs[0].output_path and (tmp_path / runs[0].output_path).is_file()

        # a later failed attempt updates the same row instead of duplicating it
        orchestrator.record_crack_run(s, pid, 42, tmp_path, {"password": None}, [])
        s.commit()
        runs = s.exec(select(ToolRun).where(ToolRun.project_id == pid)).all()
        assert len(runs) == 1
        assert runs[0].status == "skipped"


def test_mark_unlocked_clears_the_needs_password_flag():
    pid = "test-mark-unlocked"
    with Session(engine) as s:
        run = ToolRun(project_id=pid, file_id=9, tool="steghide",
                      status="needs_password", needs_password=True)
        s.add(run)
        s.commit()
        orchestrator.mark_unlocked(s, pid, 9)
        s.commit()
        assert s.get(ToolRun, run.id).needs_password is False


def test_runs_expose_started_and_finished_timestamps(client):
    pid = _new_project(client)
    fid = _file_id(client, pid)
    now = dt.datetime.now(dt.timezone.utc)
    with Session(engine) as s:
        s.add(ToolRun(project_id=pid, file_id=fid, tool="file", status="done",
                      started_at=now, finished_at=now))
        s.commit()
    run = client.get(f"/api/v1/projects/{pid}/runs").json()[0]
    assert run["started_at"] and run["finished_at"]
