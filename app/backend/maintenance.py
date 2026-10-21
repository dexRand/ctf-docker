"""Startup maintenance: orphaned jobs after a restart, legacy duplicate findings."""
from __future__ import annotations

from sqlmodel import Session, select

from .db import engine
from .flagpatterns import _canon_flag, _is_known_prefix
from .models import Event, Finding, Project, ToolRun


def reconcile_orphans() -> list[str]:
    """After a restart there are no in-memory jobs, so any project still marked
    running/queued is orphaned. Mark it as interrupted so the GUI stops spinning.
    """
    with Session(engine) as session:
        projects = session.exec(
            select(Project).where(Project.status.in_(("running", "queued", "paused")))  # type: ignore[attr-defined]
        ).all()
        ids: list[str] = []
        for p in projects:
            # a project that already found a flag counts as solved, not failed:
            # the restart only cut the remaining (often slow) auto-crack short
            solved = session.exec(
                select(Finding).where(Finding.project_id == p.id)
                .where(Finding.kind == "flag")).first()
            if solved:
                p.status = "done"
                session.add(Event(project_id=p.id, level="warn",
                                  message="analysis interrupted by a restart "
                                          "(flag already found)"))
            else:
                p.status = "error"
                session.add(Event(project_id=p.id, level="warn",
                                  message="analysis interrupted by a restart"))
            session.add(p)
            ids.append(p.id)
        runs = session.exec(
            select(ToolRun).where(ToolRun.status.in_(("running", "queued")))  # type: ignore[attr-defined]
        ).all()
        for r in runs:
            r.status = "error"
            session.add(r)
        # a project that ended up in `error` but already holds a flag is really
        # solved (typically an old restart orphan): surface it as `done`
        for p in session.exec(select(Project).where(Project.status == "error")).all():
            flag = session.exec(select(Finding).where(Finding.project_id == p.id)
                                .where(Finding.kind == "flag")).first()
            if flag:
                p.status = "done"
                session.add(Event(project_id=p.id, level="warn",
                                  message="marked done (flag already found)"))
                session.add(p)
                ids.append(p.id)
        session.commit()
        return ids


def dedupe_findings() -> int:
    """Clean stored findings: collapse rot13 twins and whitespace variants of a
    flag, drop fragments of a longer flag, and drop duplicate notes. Older
    projects are cleaned at startup."""
    with Session(engine) as session:
        rows = session.exec(select(Finding)).all()
        by_proj: dict[str, list[Finding]] = {}
        for r in rows:
            by_proj.setdefault(r.project_id, []).append(r)
        removed = 0
        for items in by_proj.values():
            flags = [f for f in items if f.kind == "flag"]
            keep: dict[str, Finding] = {}
            # prefer a known prefix, then fewer spaces, then the shorter value
            flags.sort(key=lambda x: (0 if _is_known_prefix(x.value) else 1,
                                      x.value.count(" "), len(x.value)))
            for f in flags:
                key = _canon_flag(f.value).replace(" ", "")
                if key in keep:
                    session.delete(f)
                    removed += 1
                else:
                    keep[key] = f
            values = {f.value for f in keep.values()}
            for f in list(keep.values()):
                if any(f.value != o and f.value in o for o in values):
                    session.delete(f)
                    removed += 1
            # duplicate notes (same value+source) across auto-crack passes
            seen_notes: set[tuple[str, str]] = set()
            for f in items:
                if f.kind != "note":
                    continue
                key = (f.value, f.source)
                if key in seen_notes:
                    session.delete(f)
                    removed += 1
                else:
                    seen_notes.add(key)
        session.commit()
        return removed
