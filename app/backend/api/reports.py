"""Reports for humans and agents: flag routes, markdown report, logs, transcript.

Built server-side (backend/report.py) so the SPA, `./ctf`, scripts and AI
agents all read the same thing.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlmodel import Session

from .. import report
from ..db import get_session

router = APIRouter(tags=["reports"])


def _view(session: Session, pid: str) -> report.ProjectView:
    v = report.ProjectView.load(session, pid)
    if v is None:
        raise HTTPException(404, "project not found")
    return v


@router.get("/api/v1/projects/{pid}/flags")
def project_flags(pid: str, session: Session = Depends(get_session)) -> list[dict]:
    """Every flag with the file chain that led to it and the tool output that shows it."""
    return report.flag_routes(_view(session, pid))


@router.get("/api/v1/projects/{pid}/report")
def project_report(pid: str, format: Literal["md", "json"] = "md",
                   lang: Literal["en", "it"] = "en", session: Session = Depends(get_session)):
    """Human report. `format=md` (Markdown text) or `json` (structured summary)."""
    v = _view(session, pid)
    if format == "json":
        return {
            "project": {"id": v.project.id, "name": v.project.name, "status": v.project.status,
                        "mode": v.project.mode, "files": len(v.nodes), "runs": len(v.runs)},
            "flags": report.flag_routes(v),
            "passwords": [{"value": p.value, "source": p.source, "wordlist": p.context or None,
                           "file_id": p.file_id} for p in v.kind("password")],
            "locked": [{"file_id": fid, "tool": tool} for fid, tool in v.locked.items()],
            "flag_tools": v.flag_tools(),
            "route_tree": v.ascii_route_tree(),
        }
    return PlainTextResponse(report.markdown(v, lang), media_type="text/markdown; charset=utf-8")


@router.get("/api/v1/projects/{pid}/logs", response_class=PlainTextResponse)
def project_logs(pid: str, session: Session = Depends(get_session)) -> str:
    """Event log + every run with its full output (plain text)."""
    return report.full_logs(_view(session, pid))


@router.get("/api/v1/projects/{pid}/transcript", response_class=PlainTextResponse)
def project_transcript(pid: str, session: Session = Depends(get_session)) -> str:
    """Context for an AI agent: findings, flag path, files, runs, event log, then the task."""
    return report.transcript(_view(session, pid))
