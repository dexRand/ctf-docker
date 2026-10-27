"""Project lifecycle + files."""
from __future__ import annotations

import mimetypes

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlmodel import Session, func, select

from .. import storage
from ..config import MAX_UPLOAD
from ..db import delete_project_rows, get_session
from ..models import Ctf, Event, FileNode, Project

router = APIRouter()

# Types the browser may render inline on the app origin. Anything else (HTML,
# SVG, XML, JSON…) is served as a download: a challenge's .html/.svg uploaded
# into a project would otherwise run scripts on localhost:19014 and could call
# the API (same origin). A Content-Security-Policy sandbox is the second layer.
_INLINE_MIME = {"image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp",
                "image/tiff", "image/avif", "application/pdf", "text/plain"}
_FILE_HEADERS = {"X-Content-Type-Options": "nosniff",
                 "Content-Security-Policy": "sandbox"}


def _inline_ok(mime: str) -> bool:
    m = (mime or "").split(";")[0].strip().lower()
    return m in _INLINE_MIME or m.startswith(("audio/", "video/"))


def _project_dict(p: Project, files: int = 0) -> dict:
    return {"id": p.id, "name": p.name, "status": p.status, "mode": p.mode,
            "ctf_id": p.ctf_id, "category": p.category, "solved": p.solved, "flag": p.flag,
            "created_at": p.created_at, "updated_at": p.updated_at, "files": files}


def create_from_uploads(session: Session, files: list[UploadFile], name: str = "",
                        mode: str = "auto", ctf_id: str | None = None,
                        category: str = "") -> dict:
    """Create a project (challenge) from uploaded files; shared by
    POST /projects and POST /ctfs/{cid}/challenges."""
    if not files:
        raise HTTPException(400, "no files uploaded")
    if mode not in ("auto", "check"):
        mode = "auto"
    total = sum((u.size or 0) for u in files)
    if total > MAX_UPLOAD:
        raise HTTPException(413, f"upload too large ({total} > {MAX_UPLOAD} bytes)")
    pid = storage.new_project_id()
    storage.init_project(pid)
    proj = Project(id=pid, name=name or f"project {pid}", mode=mode, status="created",
                   ctf_id=ctf_id, category=category)
    session.add(proj)
    session.add(Event(project_id=pid, message=f"created with {len(files)} file(s)"))
    for i, up in enumerate(files):
        meta = storage.save_upload(pid, up.filename or "file", up.file)
        mime = meta.get("mime") or mimetypes.guess_type(meta["name"])[0]
        session.add(FileNode(project_id=pid, parent_id=None, name=meta["name"],
                             rel_path=f"uploads/{meta['name']}", size=meta["size"],
                             mime=mime, sha256=meta["sha256"], md5=meta["md5"],
                             depth=0, order_index=i, origin="upload"))
    session.commit()
    return _project_dict(proj, files=len(files))


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
    ctf_id: str = Form(""),
    category: str = Form(""),
    session: Session = Depends(get_session),
) -> dict:
    if ctf_id and not session.get(Ctf, ctf_id):
        raise HTTPException(404, "ctf not found")
    return create_from_uploads(session, files, name, mode, ctf_id or None, category)


@router.get("/api/v1/projects")
def list_projects(q: str = "", status: str = "", ctf_id: str = "",
                  session: Session = Depends(get_session)) -> list[dict]:
    stmt = select(Project).order_by(Project.created_at.desc())
    if status:
        stmt = stmt.where(Project.status == status)
    if ctf_id:
        stmt = stmt.where(Project.ctf_id == ctf_id)
    rows = session.exec(stmt).all()
    if q:
        ql = q.lower()
        rows = [p for p in rows if ql in (p.name or "").lower() or ql in p.id]
    counts = dict(session.exec(select(FileNode.project_id, func.count(FileNode.id))
                               .group_by(FileNode.project_id)).all())
    return [_project_dict(p, files=counts.get(p.id, 0)) for p in rows]


_EDITABLE = {"name", "category", "ctf_id", "solved", "flag", "mode"}


@router.patch("/api/v1/projects/{pid}")
def update_project(pid: str, payload: dict = Body(...),
                   session: Session = Depends(get_session)) -> dict:
    """Edit a challenge: name, category, ctf_id (move to a CTF, null = none),
    solved/flag (confirm or correct the answer), mode."""
    p = session.get(Project, pid)
    if not p:
        raise HTTPException(404, "project not found")
    bad = set(payload) - _EDITABLE
    if bad:
        raise HTTPException(422, f"not editable: {sorted(bad)}")
    if payload.get("ctf_id") and not session.get(Ctf, payload["ctf_id"]):
        raise HTTPException(404, "ctf not found")
    if "mode" in payload and payload["mode"] not in ("auto", "check"):
        raise HTTPException(422, "mode must be auto or check")
    for k, v in payload.items():
        setattr(p, k, (bool(v) if k == "solved" else (v or None) if k == "ctf_id" else str(v or "")))
    session.add(p)
    session.commit()
    count = session.exec(select(func.count(FileNode.id)).where(FileNode.project_id == pid)).one()
    return _project_dict(p, files=count)


@router.get("/api/v1/projects/{pid}")
def get_project(pid: str, session: Session = Depends(get_session)) -> dict:
    p = session.get(Project, pid)
    if not p:
        raise HTTPException(404, "project not found")
    nodes = session.exec(select(FileNode).where(FileNode.project_id == pid)
                         .order_by(FileNode.order_index, FileNode.id)).all()
    # mime is filled at upload/extract time; older rows are backfilled once at
    # startup (db.backfill_mime), so this endpoint stays read-only
    return {**_project_dict(p, files=len(nodes)), "tree": [_node_dict(n) for n in nodes]}


@router.delete("/api/v1/projects", status_code=200)
def delete_all_projects(session: Session = Depends(get_session)) -> dict:
    """Remove every project and its files (the whole history)."""
    from .. import orchestrator
    ids = [p.id for p in session.exec(select(Project)).all()]
    for pid in ids:
        orchestrator.stop(pid)
        delete_project_rows(session, pid)
    session.commit()
    for pid in ids:
        storage.delete_project(pid)
    return {"deleted": len(ids)}


@router.delete("/api/v1/projects/{pid}", status_code=200)
def delete_project(pid: str, session: Session = Depends(get_session)) -> dict:
    p = session.get(Project, pid)
    if not p:
        raise HTTPException(404, "project not found")
    from .. import orchestrator
    orchestrator.stop(pid)  # a running job would keep writing into deleted rows
    delete_project_rows(session, pid)
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
    mime = node.mime or storage.sniff_mime(path) or "application/octet-stream"
    if not node.mime:
        node.mime = mime
        session.add(node)
        session.commit()
    # inline only for media the browser cannot script; everything else is a
    # download (a project's HTML/SVG must never run on the app's origin)
    if _inline_ok(mime):
        return FileResponse(path, media_type=mime, headers=_FILE_HEADERS)
    return FileResponse(path, media_type="application/octet-stream",
                        filename=node.name or "download", headers=_FILE_HEADERS)
