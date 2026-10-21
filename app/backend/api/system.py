"""System endpoints."""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from .. import services
from ..config import VERSION
from ..db import get_session
from ..models import Finding, Project, ToolRun

router = APIRouter()


@router.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok", "version": VERSION}


@router.get("/api/v1/services")
def toolbox_services(check: bool = True) -> list[dict]:
    """The toolbox's web tools: name, purpose, profile, URL, and whether it is up."""
    return services.catalog(check)


@router.get("/api/v1/stats")
def stats(window: int = 20, session: Session = Depends(get_session)) -> dict:
    """Dashboard numbers for the most recent `window` projects (one call instead
    of findings+runs per project): status/mode counts over all projects, then
    flags, passwords, locked files and the most used tools in the window."""
    projects = session.exec(select(Project).order_by(Project.created_at.desc())).all()
    per_status = Counter(p.status for p in projects)
    per_mode = Counter(p.mode for p in projects)
    recent = [p.id for p in projects[:max(1, window)]]
    flags = Counter(); passwords = Counter(); cracked: dict[str, set] = {}
    for pid, kind, fid in session.exec(select(Finding.project_id, Finding.kind, Finding.file_id)
                                       .where(Finding.project_id.in_(recent))).all():  # type: ignore[attr-defined]
        if kind == "flag":
            flags[pid] += 1
        elif kind == "password":
            passwords[pid] += 1
            cracked.setdefault(pid, set()).add(fid)
    tools = Counter(); runs = 0; locked: dict[str, set] = {}
    for pid, tool, fid, needs in session.exec(select(ToolRun.project_id, ToolRun.tool, ToolRun.file_id,
                                                     ToolRun.needs_password)
                                              .where(ToolRun.project_id.in_(recent))).all():  # type: ignore[attr-defined]
        runs += 1
        tools[tool] += 1
        if needs and fid not in cracked.get(pid, set()):
            locked.setdefault(pid, set()).add(fid)
    by_id = {p.id: p for p in projects}
    per_project = {pid: {"id": pid, "name": by_id[pid].name, "status": by_id[pid].status,
                         "flagsN": flags[pid], "lockedN": len(locked.get(pid, ()))} for pid in recent}
    done = sum(1 for d in per_project.values() if d["status"] == "done")
    solved = sum(1 for d in per_project.values() if d["flagsN"] > 0)
    return {
        "projects": len(projects),
        "flags": sum(flags.values()), "passwords": sum(passwords.values()), "runs": runs,
        "active": per_status["running"] + per_status["queued"],
        "solved": solved, "done": done,
        "blocked": sum(1 for d in per_project.values() if d["lockedN"] > 0),
        "solveRate": round(solved / done * 100) if done else 0,
        "perStatus": dict(per_status), "perMode": dict(per_mode),
        "topTools": tools.most_common(6),
        "perProject": per_project,
    }
