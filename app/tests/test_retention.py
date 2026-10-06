"""Optional retention (RETENTION_DAYS): old projects are purged, new kept."""
from __future__ import annotations

import datetime as dt

from sqlmodel import Session

from backend import storage
from backend.config import retention_days
from backend.db import engine, init_db
from backend.models import Project
from backend.retention import purge_old_projects


def _make_project(pid: str, updated: dt.datetime) -> None:
    with Session(engine) as session:
        session.add(Project(id=pid, name=pid, status="done",
                            created_at=updated, updated_at=updated))
        session.commit()
    storage.init_project(pid)
    (storage.project_dir(pid) / "files" / "a.txt").write_text("hi")


def test_retention_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("RETENTION_DAYS", raising=False)
    assert retention_days() == 0
    assert purge_old_projects() == []


def test_purge_removes_old_and_keeps_recent(monkeypatch):
    init_db()
    now = dt.datetime.now(dt.timezone.utc)
    _make_project("ret-old", now - dt.timedelta(days=10))
    _make_project("ret-new", now - dt.timedelta(days=1))
    monkeypatch.setenv("RETENTION_DAYS", "5")

    removed = purge_old_projects(now=now)

    assert "ret-old" in removed
    assert "ret-new" not in removed
    with Session(engine) as session:
        assert session.get(Project, "ret-old") is None
        assert session.get(Project, "ret-new") is not None
    assert not storage.project_dir("ret-old").exists()
    assert storage.project_dir("ret-new").exists()
    storage.delete_project("ret-new")  # keep the shared test DATA_DIR tidy
