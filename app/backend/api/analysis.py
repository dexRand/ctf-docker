"""Analysis control + results (runs, artifacts, findings, events)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, Response
from sqlmodel import Session, select

from .. import orchestrator, storage
from ..db import get_session
from ..models import Artifact, Event, FileNode, Finding, Project, ToolRun

router = APIRouter()


def _run_dict(r: ToolRun, artifacts: list[dict] | None = None) -> dict:
    return {"id": r.id, "file_id": r.file_id, "tool": r.tool, "status": r.status,
            "needs_password": r.needs_password, "exit_code": r.exit_code,
            "summary": r.summary, "output_path": r.output_path,
            "artifacts": artifacts or []}


def _artifact_dict(a: Artifact) -> dict:
    return {"id": a.id, "run_id": a.run_id, "file_id": a.file_id, "name": a.name,
            "size": a.size}


@router.post("/api/v1/projects/{pid}/start")
def start_project(pid: str, session: Session = Depends(get_session)) -> dict:
    p = session.get(Project, pid)
    if not p:
        raise HTTPException(404, "project not found")
    if orchestrator.is_running(pid):
        raise HTTPException(409, "analysis already running")
    p.status = "queued"
    session.add(p)
    session.commit()
    orchestrator.start(pid)
    return {"started": pid}


def _control(pid: str, action: str) -> dict:
    if not orchestrator.control(pid, action):
        raise HTTPException(404, "no running analysis for this project")
    return {action: pid}


@router.post("/api/v1/projects/{pid}/pause")
def pause_project(pid: str) -> dict:
    return _control(pid, "pause")


@router.post("/api/v1/projects/{pid}/resume")
def resume_project(pid: str) -> dict:
    return _control(pid, "resume")


@router.post("/api/v1/projects/{pid}/cancel")
def cancel_project(pid: str) -> dict:
    return _control(pid, "cancel")


@router.get("/api/v1/projects/{pid}/findings")
def project_findings(pid: str, session: Session = Depends(get_session)) -> list[dict]:
    rows = session.exec(select(Finding).where(Finding.project_id == pid).order_by(Finding.id)).all()
    return [{"id": f.id, "file_id": f.file_id, "kind": f.kind, "value": f.value,
             "source": f.source, "context": f.context, "created_at": f.created_at} for f in rows]


@router.get("/api/v1/projects/{pid}/runs")
def project_runs(pid: str, file_id: int | None = None,
                 session: Session = Depends(get_session)) -> list[dict]:
    stmt = select(ToolRun).where(ToolRun.project_id == pid)
    if file_id is not None:
        stmt = stmt.where(ToolRun.file_id == file_id)
    runs = session.exec(stmt.order_by(ToolRun.id)).all()
    arts = session.exec(select(Artifact).where(Artifact.project_id == pid)).all()
    by_run: dict[int, list[dict]] = {}
    for a in arts:
        by_run.setdefault(a.run_id or 0, []).append(_artifact_dict(a))
    return [_run_dict(r, by_run.get(r.id)) for r in runs]


@router.get("/api/v1/projects/{pid}/runs/{rid}/artifacts")
def run_artifacts(pid: str, rid: int, session: Session = Depends(get_session)) -> list[dict]:
    rows = session.exec(select(Artifact).where(Artifact.project_id == pid)
                        .where(Artifact.run_id == rid)).all()
    return [_artifact_dict(a) for a in rows]


@router.get("/api/v1/projects/{pid}/artifacts/{aid}/content")
def artifact_content(pid: str, aid: int, session: Session = Depends(get_session)):
    a = session.get(Artifact, aid)
    if not a or a.project_id != pid:
        raise HTTPException(404, "artifact not found")
    path = storage.project_dir(pid) / a.path
    if not path.is_file():
        raise HTTPException(404, "artifact missing on disk")
    return FileResponse(path, filename=path.name)


@router.get("/api/v1/projects/{pid}/files/{fid}/runs/{rid}")
def run_output(pid: str, fid: int, rid: int, session: Session = Depends(get_session)):
    r = session.get(ToolRun, rid)
    if not r or r.project_id != pid or r.file_id != fid or not r.output_path:
        raise HTTPException(404, "run output not found")
    path = storage.project_dir(pid) / r.output_path
    if not path.is_file():
        raise HTTPException(404, "output missing")
    return Response(path.read_text(errors="replace"), media_type="text/plain; charset=utf-8")


@router.get("/api/v1/projects/{pid}/events")
def project_events(pid: str, session: Session = Depends(get_session)) -> list[dict]:
    rows = session.exec(select(Event).where(Event.project_id == pid).order_by(Event.id)).all()
    return [{"id": e.id, "ts": e.ts, "level": e.level, "message": e.message} for e in rows]
