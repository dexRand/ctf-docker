"""Cracking: wordlists, locked files, crack jobs."""
from __future__ import annotations

import threading

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlmodel import Session, select

from .. import cracking, orchestrator, storage
from ..bus import bus
from ..db import engine, get_session
from ..models import Event, FileNode, Finding, ToolRun

router = APIRouter()
CRACK_JOBS: dict[str, str] = {}


@router.get("/api/v1/wordlists")
def wordlists() -> list[dict]:
    return cracking.list_wordlists()


@router.get("/api/v1/projects/{pid}/locked")
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
            bus.publish(f"project:{pid}", {"type": "crack", "file_id": fid,
                                           "name": node.name, "status": "running"})
            res = cracking.crack_file(path, names)
            if res["password"]:
                wl_hit = res.get("wordlist_hit") or ""
                bus.publish(f"project:{pid}", {"type": "crack", "file_id": fid,
                                               "status": "found", "password": res["password"],
                                               "wordlist": wl_hit or None})
                s.add(Finding(project_id=pid, file_id=fid, kind="password",
                              value=res["password"], source=f"crack:{res['kind']}",
                              context=wl_hit))
                s.add(Event(project_id=pid, level="info",
                            message=f"password found for {node.name}: {res['password']}"
                                    + (f" via {wl_hit}" if wl_hit else "")))
                if res["extracted"]:
                    orchestrator.import_children(s, pid, fid, res["extracted"])
                s.commit()
                if res["extracted"]:
                    try:
                        orchestrator.start(pid)
                    except RuntimeError:
                        pass
            else:
                bus.publish(f"project:{pid}", {"type": "crack", "file_id": fid, "status": "not_found"})
                s.add(Event(project_id=pid, level="warn", message=f"password not found for {node.name}"))
                s.commit()
    finally:
        CRACK_JOBS.pop(pid, None)


@router.post("/api/v1/projects/{pid}/crack")
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


@router.get("/api/v1/projects/{pid}/crack/status")
def crack_status(pid: str) -> dict:
    return {"running": pid in CRACK_JOBS, "file": CRACK_JOBS.get(pid)}
