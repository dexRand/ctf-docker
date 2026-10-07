"""Cracking: wordlists, locked files, crack jobs."""
from __future__ import annotations

import threading

from fastapi import APIRouter, Body, Depends, File, HTTPException, UploadFile
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


@router.post("/api/v1/wordlists")
def upload_wordlist(file: UploadFile = File(...)) -> dict:
    """Upload a new wordlist; it is stored under /data (persisted)."""
    try:
        return cracking.save_wordlist(file.filename or "wordlist.txt", file.file)
    except ValueError as exc:
        raise HTTPException(413, str(exc))


@router.get("/api/v1/projects/{pid}/locked")
def locked_files(pid: str, session: Session = Depends(get_session)) -> list[dict]:
    cracked = {f.file_id for f in session.exec(
        select(Finding).where(Finding.project_id == pid)
        .where(Finding.kind == "password")).all()}
    runs = session.exec(select(ToolRun).where(ToolRun.project_id == pid)
                        .where(ToolRun.needs_password == True)).all()  # noqa: E712
    seen: dict[int, str] = {}
    for r in runs:
        if r.file_id in cracked:
            continue
        seen.setdefault(r.file_id, r.tool)
    out = []
    for fid, tool in seen.items():
        n = session.get(FileNode, fid)
        if n:
            out.append({"file_id": fid, "name": n.name, "kind": tool, "size": n.size})
    return out


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
            orchestrator.record_crack_run(s, pid, fid, work, res, lines)
            if res["password"]:
                wl_hit = res.get("wordlist_hit") or ""
                bus.publish(f"project:{pid}", {"type": "crack", "file_id": fid,
                                               "status": "found", "password": res["password"],
                                               "wordlist": wl_hit or None})
                s.add(Finding(project_id=pid, file_id=fid, kind="password",
                              value=res["password"], source=f"crack:{res['kind']}",
                              context=wl_hit))
                orchestrator.mark_unlocked(s, pid, fid)
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
    already = session.exec(select(Finding).where(Finding.project_id == pid)
                           .where(Finding.file_id == fid)
                           .where(Finding.kind == "password")).first()
    if already:
        raise HTTPException(409, "file already cracked")
    if pid in CRACK_JOBS:
        raise HTTPException(409, "cracking already running")
    opts: dict = {}
    if "rules" in payload:
        opts["rules"] = payload.get("rules")
    if payload.get("mask"):
        opts["mask"] = str(payload["mask"])
    if payload.get("budget_s") is not None:
        opts["budget_s"] = int(payload["budget_s"])
    bk = payload.get("bkcrack")
    if isinstance(bk, dict):
        opts["bkcrack"] = {"name": bk.get("name", ""), "plaintext": bk.get("plaintext", "")}
    CRACK_JOBS[pid] = node.name
    threading.Thread(target=_crack_worker, args=(pid, fid, names, opts), daemon=True).start()
    return {"started": pid, "file_id": fid}


@router.get("/api/v1/projects/{pid}/crack/status")
def crack_status(pid: str) -> dict:
    return {"running": pid in CRACK_JOBS, "file": CRACK_JOBS.get(pid)}
