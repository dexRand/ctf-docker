"""Analysis control + results (runs, artifacts, findings, events)."""
from __future__ import annotations

import threading

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import FileResponse, Response
from sqlmodel import Session, select

from .. import orchestrator, pipeline, storage
from ..analyzers import get as get_tool
from ..db import get_session
from ..models import Artifact, Event, FileNode, Finding, Project, ToolRun

router = APIRouter()


def _run_dict(r: ToolRun, artifacts: list[dict] | None = None) -> dict:
    return {"id": r.id, "file_id": r.file_id, "tool": r.tool, "status": r.status,
            "needs_password": r.needs_password, "exit_code": r.exit_code,
            "summary": r.summary, "output_path": r.output_path,
            "started_at": r.started_at, "finished_at": r.finished_at,
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


_STATUS_AFTER = {"pause": "paused", "resume": "running"}


def _control(pid: str, action: str, session: Session) -> dict:
    if not orchestrator.control(pid, action):
        raise HTTPException(404, "no running analysis for this project")
    p = session.get(Project, pid)
    if p and action in _STATUS_AFTER:  # pause/resume are visible in the project status
        p.status = _STATUS_AFTER[action]
        session.add(p)
        session.commit()
        orchestrator.emit(pid, {"type": "status", "status": p.status})
    return {action: pid}


@router.post("/api/v1/projects/{pid}/pause")
def pause_project(pid: str, session: Session = Depends(get_session)) -> dict:
    return _control(pid, "pause", session)


@router.post("/api/v1/projects/{pid}/resume")
def resume_project(pid: str, session: Session = Depends(get_session)) -> dict:
    return _control(pid, "resume", session)


@router.post("/api/v1/projects/{pid}/cancel")
def cancel_project(pid: str, session: Session = Depends(get_session)) -> dict:
    return _control(pid, "cancel", session)


@router.post("/api/v1/projects/{pid}/files/{fid}/run", status_code=202)
def run_tools(pid: str, fid: int, payload: dict = Body(...),
              session: Session = Depends(get_session)) -> dict:
    """Run one or more analyzers on a file of the project, optionally with a
    password (e.g. steghide/outguess/7z with a password you found). Runs in the
    background; new runs/findings show up in /runs, /findings and on the WS.
    Files it extracts are added to the tree and analyzed."""
    node = session.get(FileNode, fid)
    if not node or node.project_id != pid:
        raise HTTPException(404, "file not found")
    tools = payload.get("tools") or []
    if isinstance(tools, str):
        tools = [tools]
    unknown = [t for t in tools if not get_tool(str(t))]
    if not tools or unknown:
        raise HTTPException(422, f"unknown tool(s): {unknown}" if unknown else "tools: list required")
    password = payload.get("password") or None

    def work() -> None:
        if pipeline.run_tools_on_node(pid, fid, [str(t) for t in tools], password):
            orchestrator.analyze_new(pid)

    threading.Thread(target=work, daemon=True).start()
    return {"started": pid, "file_id": fid, "tools": tools}


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
