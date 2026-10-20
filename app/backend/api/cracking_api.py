"""Cracking: wordlists, locked files, crack jobs."""
from __future__ import annotations

import threading
import traceback

from fastapi import APIRouter, Body, Depends, File, HTTPException, UploadFile
from sqlmodel import Session, select

from .. import crackflow, cracking, orchestrator, storage
from ..bus import bus
from ..db import engine, get_session
from ..models import Event, FileNode, Finding

router = APIRouter()
CRACK_JOBS: dict[str, str] = {}
_CRACK_LOCK = threading.Lock()


@router.get("/api/v1/wordlists")
def wordlists() -> list[dict]:
    return cracking.list_wordlists()


@router.post("/api/v1/wordlists")
def upload_wordlist(file: UploadFile = File(...)) -> dict:
    """Upload a new wordlist; it is stored under /data (persisted)."""
    try:
        return cracking.save_wordlist(file.filename or "wordlist.txt", file.file)
    except ValueError as exc:
        raise HTTPException(413, str(exc))


@router.get("/api/v1/projects/{pid}/locked")
def locked_files(pid: str, session: Session = Depends(get_session)) -> list[dict]:
    locked = crackflow.locked_files(session, pid)
    if not locked:
        return []
    nodes = session.exec(select(FileNode).where(FileNode.id.in_(list(locked)))).all()  # type: ignore[attr-defined]
    by_id = {n.id: n for n in nodes}
    return [{"file_id": fid, "name": by_id[fid].name, "kind": tool, "size": by_id[fid].size}
            for fid, tool in locked.items() if fid in by_id]


def _crack_worker(pid: str, fid: int, names, opts: dict) -> None:
    try:
        with Session(engine) as s:
            node = s.get(FileNode, fid)
            if not node or node.project_id != pid:
                return
            path = storage.project_dir(pid) / node.rel_path
            work = storage.project_dir(pid)
            bus.publish(f"project:{pid}", {"type": "crack", "file_id": fid,
                                           "name": node.name, "status": "running"})
            lines: list[str] = []
            bk = opts.get("bkcrack")
            if bk:
                res = cracking.bkcrack_attack(path, bk.get("name", ""),
                                              bk.get("plaintext", ""), log=lines.append)
            else:
                res = cracking.crack_file(path, names, log=lines.append,
                                          **{k: v for k, v in opts.items() if k != "bkcrack"})
            if crackflow.apply_crack_result(s, pid, node, work, res, lines):
                orchestrator.analyze_new(pid)
    except Exception as exc:  # the UI waits for a final crack event: always send one
        bus.publish(f"project:{pid}", {"type": "crack", "file_id": fid, "status": "error",
                                       "error": f"{type(exc).__name__}: {exc}"[:300]})
        with Session(engine) as s:
            s.add(Event(project_id=pid, level="error",
                        message="crack failed: " + traceback.format_exc()[-800:]))
            s.commit()
    finally:
        with _CRACK_LOCK:
            CRACK_JOBS.pop(pid, None)


@router.post("/api/v1/projects/{pid}/crack")
def crack(pid: str, payload: dict = Body(...), session: Session = Depends(get_session)) -> dict:
    fid = payload.get("file_id")
    names = payload.get("wordlists")
    node = session.get(FileNode, fid) if fid is not None else None
    if not node or node.project_id != pid:
        raise HTTPException(404, "file not found")
    already = session.exec(select(Finding).where(Finding.project_id == pid)
                           .where(Finding.file_id == fid)
                           .where(Finding.kind == "password")).first()
    if already:
        raise HTTPException(409, "file already cracked")
    opts: dict = {}
    if "rules" in payload:
        opts["rules"] = payload.get("rules")
    if payload.get("mask"):
        opts["mask"] = str(payload["mask"])
    if payload.get("budget_s") is not None:
        try:
            opts["budget_s"] = int(payload["budget_s"])
        except (TypeError, ValueError):
            raise HTTPException(422, "budget_s must be an integer (seconds)")
    bk = payload.get("bkcrack")
    if isinstance(bk, dict):
        opts["bkcrack"] = {"name": bk.get("name", ""), "plaintext": bk.get("plaintext", "")}
    with _CRACK_LOCK:
        if pid in CRACK_JOBS:
            raise HTTPException(409, "cracking already running")
        CRACK_JOBS[pid] = node.name
    threading.Thread(target=_crack_worker, args=(pid, fid, names, opts), daemon=True).start()
    return {"started": pid, "file_id": fid}


@router.get("/api/v1/projects/{pid}/crack/status")
def crack_status(pid: str) -> dict:
    return {"running": pid in CRACK_JOBS, "file": CRACK_JOBS.get(pid)}
