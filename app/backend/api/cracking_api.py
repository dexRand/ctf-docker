"""Cracking: wordlists, locked files, crack jobs."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, File, HTTPException, UploadFile
from sqlmodel import Session, select

from .. import crackflow, cracking, crackqueue
from ..db import get_session
from ..models import FileNode, Finding

router = APIRouter()


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
    try:
        job = crackqueue.submit(pid, fid, node.name, names, opts)
    except crackqueue.AlreadyQueued as exc:
        raise HTTPException(409, str(exc))
    return {"started": pid, "file_id": fid, "job": job.id, "queued_before": crackqueue.position(job)}


@router.get("/api/v1/projects/{pid}/crack/status")
def crack_status(pid: str) -> dict:
    """Crack jobs of the project (queued/running first)."""
    js = crackqueue.jobs(pid)
    active = [j for j in js if j.status in ("queued", "running")]
    return {"running": bool(active), "file": active[0].name if active else None,
            "jobs": [j.as_dict() for j in js]}


@router.get("/api/v1/cracks")
def list_cracks(project_id: str = "") -> list[dict]:
    """Every crack job (newest first): status, password and wordlist when found."""
    return [j.as_dict() for j in crackqueue.jobs(project_id or None)]


@router.delete("/api/v1/cracks/{job_id}")
def cancel_crack(job_id: int) -> dict:
    """Cancel a queued crack (a running one can't be interrupted)."""
    if not crackqueue.get(job_id):
        raise HTTPException(404, "crack job not found")
    if not crackqueue.cancel(job_id):
        raise HTTPException(409, "only queued jobs can be cancelled")
    return {"cancelled": job_id}
