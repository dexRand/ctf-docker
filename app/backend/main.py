"""StegSuite backend — FastAPI app (projects, files, tools, terminal).

Phase 1: project lifecycle + uploads + static SPA host.
"""
from __future__ import annotations

import mimetypes
import shutil
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select

from . import storage
from .analyzers import catalog as tool_catalog
from .analyzers import get as get_tool
from .analyzers import run_tool
from .config import API_KEY, TOOLJOBS_DIR, VERSION
from .db import get_session, init_db
from .models import Event, FileNode, Finding, Project, ToolRun

app = FastAPI(
    title="StegSuite",
    version=VERSION,
    description="Self-hosted steganography/forensics workbench.",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

STATIC_DIR = Path(__file__).parent / "static"


@app.on_event("startup")
def _startup() -> None:
    init_db()


# --------------------------------------------------------------------- auth
@app.middleware("http")
async def api_key_guard(request: Request, call_next):
    if API_KEY and request.url.path.startswith("/api") and request.url.path not in ("/api/v1/health",):
        if request.headers.get("x-api-key") != API_KEY:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "invalid or missing X-API-Key"}, status_code=401)
    return await call_next(request)


# ------------------------------------------------------------------ system
@app.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok", "version": VERSION}


def _project_dict(p: Project, files: int = 0) -> dict:
    return {
        "id": p.id, "name": p.name, "status": p.status, "mode": p.mode,
        "created_at": p.created_at, "updated_at": p.updated_at, "files": files,
    }


def _node_dict(n: FileNode) -> dict:
    return {
        "id": n.id, "parent_id": n.parent_id, "name": n.name, "rel_path": n.rel_path,
        "size": n.size, "mime": n.mime, "sha256": n.sha256, "md5": n.md5,
        "depth": n.depth, "order_index": n.order_index, "origin": n.origin,
        "created_at": n.created_at,
    }


# ---------------------------------------------------------------- projects
@app.post("/api/v1/projects", status_code=201)
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
    pid = storage.new_project_id()
    storage.init_project(pid)
    proj = Project(id=pid, name=name or f"project {pid}", mode=mode, status="created")
    session.add(proj)
    session.add(Event(project_id=pid, message=f"created with {len(files)} file(s)"))
    for i, up in enumerate(files):
        meta = storage.save_upload(pid, up.filename or "file", up.file)
        mime, _ = mimetypes.guess_type(meta["name"])
        session.add(FileNode(
            project_id=pid, parent_id=None, name=meta["name"],
            rel_path=f"uploads/{meta['name']}", size=meta["size"],
            mime=mime, sha256=meta["sha256"], md5=meta["md5"],
            depth=0, order_index=i, origin="upload",
        ))
    session.commit()
    return _project_dict(proj, files=len(files))


@app.get("/api/v1/projects")
def list_projects(q: str = "", status: str = "", session: Session = Depends(get_session)) -> list[dict]:
    stmt = select(Project).order_by(Project.created_at.desc())
    rows = session.exec(stmt).all()
    out = []
    for p in rows:
        if status and p.status != status:
            continue
        if q and q.lower() not in (p.name or "").lower() and q.lower() not in p.id:
            continue
        count = len(session.exec(select(FileNode).where(FileNode.project_id == p.id)).all())
        out.append(_project_dict(p, files=count))
    return out


@app.get("/api/v1/projects/{pid}")
def get_project(pid: str, session: Session = Depends(get_session)) -> dict:
    p = session.get(Project, pid)
    if not p:
        raise HTTPException(404, "project not found")
    nodes = session.exec(
        select(FileNode).where(FileNode.project_id == pid).order_by(FileNode.order_index, FileNode.id)
    ).all()
    return {
        **_project_dict(p, files=len(nodes)),
        "tree": [_node_dict(n) for n in nodes],
    }


@app.delete("/api/v1/projects/{pid}", status_code=200)
def delete_project(pid: str, session: Session = Depends(get_session)) -> dict:
    p = session.get(Project, pid)
    if not p:
        raise HTTPException(404, "project not found")
    for model in (FileNode, ToolRun, Finding, Event):
        for row in session.exec(select(model).where(model.project_id == pid)).all():
            session.delete(row)
    session.delete(p)
    session.commit()
    storage.delete_project(pid)
    return {"deleted": pid}


@app.get("/api/v1/projects/{pid}/files/{fid}/content")
def file_content(pid: str, fid: int, session: Session = Depends(get_session)):
    node = session.get(FileNode, fid)
    if not node or node.project_id != pid:
        raise HTTPException(404, "file not found")
    path = storage.project_dir(pid) / node.rel_path
    if not path.is_file():
        raise HTTPException(404, "file missing on disk")
    return FileResponse(path, filename=node.name, media_type=node.mime or "application/octet-stream")


# ---------------------------------------------------------------- tools
@app.get("/api/v1/tools")
def list_tools() -> list[dict]:
    """Catalog of available analyzers (also used by the GUI)."""
    return tool_catalog()


@app.post("/api/v1/tools/{tool}")
def run_single_tool(tool: str, file: UploadFile = File(...), password: str = Form("")) -> dict:
    """Stateless single-tool run on an uploaded file (for external automation)."""
    if not get_tool(tool):
        raise HTTPException(404, f"unknown tool: {tool}")
    job = storage.new_project_id()
    base = TOOLJOBS_DIR / job
    (base / "input").mkdir(parents=True, exist_ok=True)
    name = storage.sanitize_name(file.filename or "file")
    dest = base / "input" / name
    with open(dest, "wb") as out:
        shutil.copyfileobj(file.file, out)
    logs: list[str] = []
    result = run_tool(tool, dest, base, password=password or None, log=logs.append)
    data = result.as_dict()
    data.update({"job_id": job, "tool": tool, "log": logs[-300:]})
    return data


@app.get("/api/v1/tooljobs/{job}/files/{name:path}")
def tool_job_file(job: str, name: str):
    base = (TOOLJOBS_DIR / job).resolve()
    target = (base / name).resolve()
    if target != base and base not in target.parents:
        raise HTTPException(404, "not found")
    if not target.is_file():
        raise HTTPException(404, "not found")
    return FileResponse(target, filename=target.name)


# ---------------------------------------------------------------- static SPA
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="spa")
