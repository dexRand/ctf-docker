"""StegSuite backend — FastAPI app (projects, files, tools, terminal).

Phase 1: project lifecycle + uploads + static SPA host.
"""
from __future__ import annotations

import mimetypes
import shutil
import threading
from pathlib import Path

from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select

from . import cracking, orchestrator, storage
from .analyzers import catalog as tool_catalog
from .analyzers import get as get_tool
from .analyzers import run_tool
from .config import API_KEY, TOOLJOBS_DIR, VERSION
from .db import engine, get_session, init_db
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


# ------------------------------------------------------------ analysis run
@app.post("/api/v1/projects/{pid}/start")
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


@app.post("/api/v1/projects/{pid}/pause")
def pause_project(pid: str) -> dict:
    return _control(pid, "pause")


@app.post("/api/v1/projects/{pid}/resume")
def resume_project(pid: str) -> dict:
    return _control(pid, "resume")


@app.post("/api/v1/projects/{pid}/cancel")
def cancel_project(pid: str) -> dict:
    return _control(pid, "cancel")


@app.get("/api/v1/projects/{pid}/findings")
def project_findings(pid: str, session: Session = Depends(get_session)) -> list[dict]:
    rows = session.exec(select(Finding).where(Finding.project_id == pid).order_by(Finding.id)).all()
    return [{"id": f.id, "file_id": f.file_id, "kind": f.kind, "value": f.value,
             "source": f.source, "created_at": f.created_at} for f in rows]


def _run_dict(r: ToolRun) -> dict:
    return {"id": r.id, "file_id": r.file_id, "tool": r.tool, "status": r.status,
            "needs_password": r.needs_password, "exit_code": r.exit_code,
            "summary": r.summary, "output_path": r.output_path}


@app.get("/api/v1/projects/{pid}/runs")
def project_runs(pid: str, file_id: int | None = None, session: Session = Depends(get_session)) -> list[dict]:
    stmt = select(ToolRun).where(ToolRun.project_id == pid)
    if file_id is not None:
        stmt = stmt.where(ToolRun.file_id == file_id)
    return [_run_dict(r) for r in session.exec(stmt.order_by(ToolRun.id)).all()]


@app.get("/api/v1/projects/{pid}/files/{fid}/runs/{rid}")
def run_output(pid: str, fid: int, rid: int, session: Session = Depends(get_session)):
    r = session.get(ToolRun, rid)
    if not r or r.project_id != pid or r.file_id != fid or not r.output_path:
        raise HTTPException(404, "run output not found")
    path = storage.project_dir(pid) / r.output_path
    if not path.is_file():
        raise HTTPException(404, "output missing")
    return Response(path.read_text(errors="replace"), media_type="text/plain; charset=utf-8")


@app.get("/api/v1/projects/{pid}/events")
def project_events(pid: str, session: Session = Depends(get_session)) -> list[dict]:
    rows = session.exec(select(Event).where(Event.project_id == pid).order_by(Event.id)).all()
    return [{"id": e.id, "ts": e.ts, "level": e.level, "message": e.message} for e in rows]


# ---------------------------------------------------------------- cracking
CRACK_JOBS: dict[str, str] = {}


@app.get("/api/v1/wordlists")
def wordlists() -> list[dict]:
    return cracking.list_wordlists()


@app.get("/api/v1/projects/{pid}/locked")
def locked_files(pid: str, session: Session = Depends(get_session)) -> list[dict]:
    runs = session.exec(select(ToolRun).where(ToolRun.project_id == pid)
                        .where(ToolRun.needs_password == True)).all()  # noqa: E712
    seen: dict[int, str] = {}
    for r in runs:
        seen.setdefault(r.file_id, r.tool)
    out = []
    for fid, tool in seen.items():
        n = session.get(FileNode, fid)
        if n:
            out.append({"file_id": fid, "name": n.name, "kind": tool, "size": n.size})
    return out


def _crack_worker(pid: str, fid: int, names) -> None:
    try:
        with Session(engine) as s:
            node = s.get(FileNode, fid)
            if not node or node.project_id != pid:
                return
            path = storage.project_dir(pid) / node.rel_path
            res = cracking.crack_file(path, names)
            if res["password"]:
                s.add(Finding(project_id=pid, file_id=fid, kind="password",
                              value=res["password"], source=f"crack:{res['kind']}"))
                s.add(Event(project_id=pid, level="info",
                            message=f"password found for {node.name}: {res['password']}"))
                if res["extracted"]:
                    orchestrator.import_children(s, pid, fid, res["extracted"])
                s.commit()
                if res["extracted"]:
                    try:
                        orchestrator.start(pid)
                    except RuntimeError:
                        pass
            else:
                s.add(Event(project_id=pid, level="warn", message=f"password not found for {node.name}"))
                s.commit()
    finally:
        CRACK_JOBS.pop(pid, None)


@app.post("/api/v1/projects/{pid}/crack")
def crack(pid: str, payload: dict = Body(...), session: Session = Depends(get_session)) -> dict:
    fid = payload.get("file_id")
    names = payload.get("wordlists")
    node = session.get(FileNode, fid) if fid is not None else None
    if not node or node.project_id != pid:
        raise HTTPException(404, "file not found")
    if pid in CRACK_JOBS:
        raise HTTPException(409, "cracking already running")
    CRACK_JOBS[pid] = node.name
    threading.Thread(target=_crack_worker, args=(pid, fid, names), daemon=True).start()
    return {"started": pid, "file_id": fid}


@app.get("/api/v1/projects/{pid}/crack/status")
def crack_status(pid: str) -> dict:
    return {"running": pid in CRACK_JOBS, "file": CRACK_JOBS.get(pid)}


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
