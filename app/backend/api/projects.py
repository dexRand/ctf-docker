"""Project lifecycle + files."""
from __future__ import annotations

import mimetypes

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlmodel import Session, select

from .. import storage
from ..config import MAX_UPLOAD
from ..db import get_session
from ..models import Artifact, Event, FileNode, Finding, Project, ToolRun

router = APIRouter()


def _project_dict(p: Project, files: int = 0) -> dict:
    return {"id": p.id, "name": p.name, "status": p.status, "mode": p.mode,
            "created_at": p.created_at, "updated_at": p.updated_at, "files": files}


def _node_dict(n: FileNode) -> dict:
    return {"id": n.id, "parent_id": n.parent_id, "name": n.name, "rel_path": n.rel_path,
            "size": n.size, "mime": n.mime, "sha256": n.sha256, "md5": n.md5,
            "depth": n.depth, "order_index": n.order_index, "origin": n.origin,
            "created_at": n.created_at}


@router.post("/api/v1/projects", status_code=201)
def create_project(
    files: list[UploadFile] = File(...),
    name: str = Form(""),
    mode: str = Form("auto"),
    session: Session = Depends(get_session),
) -> dict:
    if not files:
        raise HTTPException(400, "no files uploaded")
    if mode not in ("auto", "check"):
        mode = "auto"
    total = sum((u.size or 0) for u in files)
    if total > MAX_UPLOAD:
        raise HTTPException(413, f"upload too large ({total} > {MAX_UPLOAD} bytes)")
    pid = storage.new_project_id()
    storage.init_project(pid)
    proj = Project(id=pid, name=name or f"project {pid}", mode=mode, status="created")
    session.add(proj)
    session.add(Event(project_id=pid, message=f"created with {len(files)} file(s)"))
    for i, up in enumerate(files):
        meta = storage.save_upload(pid, up.filename or "file", up.file)
        mime, _ = mimetypes.guess_type(meta["name"])
        session.add(FileNode(project_id=pid, parent_id=None, name=meta["name"],
                             rel_path=f"uploads/{meta['name']}", size=meta["size"],
                             mime=mime, sha256=meta["sha256"], md5=meta["md5"],
                             depth=0, order_index=i, origin="upload"))
    session.commit()
    return _project_dict(proj, files=len(files))


@router.get("/api/v1/projects")
def list_projects(q: str = "", status: str = "", session: Session = Depends(get_session)) -> list[dict]:
    rows = session.exec(select(Project).order_by(Project.created_at.desc())).all()
    out = []
    for p in rows:
        if status and p.status != status:
            continue
        if q and q.lower() not in (p.name or "").lower() and q.lower() not in p.id:
            continue
        count = len(session.exec(select(FileNode).where(FileNode.project_id == p.id)).all())
        out.append(_project_dict(p, files=count))
    return out


@router.get("/api/v1/projects/{pid}")
def get_project(pid: str, session: Session = Depends(get_session)) -> dict:
    p = session.get(Project, pid)
    if not p:
        raise HTTPException(404, "project not found")
    nodes = session.exec(select(FileNode).where(FileNode.project_id == pid)
                         .order_by(FileNode.order_index, FileNode.id)).all()
    return {**_project_dict(p, files=len(nodes)), "tree": [_node_dict(n) for n in nodes]}


@router.delete("/api/v1/projects", status_code=200)
def delete_all_projects(session: Session = Depends(get_session)) -> dict:
    """Remove every project and its files (the whole history)."""
    from .. import orchestrator
    rows = session.exec(select(Project)).all()
    ids = [p.id for p in rows]
    for pid in ids:
        try:
            orchestrator.control(pid, "cancel")
        except Exception:
            pass
        for model in (FileNode, ToolRun, Artifact, Finding, Event):
            for row in session.exec(select(model).where(model.project_id == pid)).all():
                session.delete(row)
        session.delete(session.get(Project, pid))
    session.commit()
    for pid in ids:
        storage.delete_project(pid)
    return {"deleted": len(ids)}


@router.delete("/api/v1/projects/{pid}", status_code=200)
def delete_project(pid: str, session: Session = Depends(get_session)) -> dict:
    p = session.get(Project, pid)
    if not p:
        raise HTTPException(404, "project not found")
    for model in (FileNode, ToolRun, Artifact, Finding, Event):
        for row in session.exec(select(model).where(model.project_id == pid)).all():
            session.delete(row)
    session.delete(p)
    session.commit()
    storage.delete_project(pid)
    return {"deleted": pid}


@router.get("/api/v1/projects/{pid}/files/{fid}/content")
def file_content(pid: str, fid: int, session: Session = Depends(get_session)):
    node = session.get(FileNode, fid)
    if not node or node.project_id != pid:
        raise HTTPException(404, "file not found")
    path = storage.project_dir(pid) / node.rel_path
    if not path.is_file():
        raise HTTPException(404, "file missing on disk")
    return FileResponse(path, filename=node.name,
                        media_type=node.mime or "application/octet-stream")
