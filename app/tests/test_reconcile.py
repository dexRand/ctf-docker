"""Orphaned projects after a restart: solved ones become `done`, others `error`."""
from __future__ import annotations

from sqlmodel import Session

from backend.db import engine, init_db
from backend.models import Finding, Project
from backend.orchestrator import reconcile_orphans


def _mk(pid: str, status: str, with_flag: bool = False) -> None:
    with Session(engine) as s:
        s.add(Project(id=pid, name=pid, status=status))
        if with_flag:
            s.add(Finding(project_id=pid, kind="flag", value="ITS{reconciled}", source="raw"))
        s.commit()


def test_reconcile_marks_a_solved_orphan_as_done():
    init_db()
    _mk("rec-solved", "running", with_flag=True)
    _mk("rec-unsolved", "running", with_flag=False)

    ids = reconcile_orphans()

    assert "rec-solved" in ids and "rec-unsolved" in ids
    with Session(engine) as s:
        assert s.get(Project, "rec-solved").status == "done"
        assert s.get(Project, "rec-unsolved").status == "error"
