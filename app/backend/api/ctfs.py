"""CTF events: a CTF holds its challenges (projects) and their flag format."""
from __future__ import annotations

import re

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, UploadFile
from sqlmodel import Session, func, select

from .. import ctfs, storage
from ..db import get_session
from ..models import Ctf, FileNode, Finding, Project
from .projects import _project_dict, create_from_uploads

router = APIRouter(tags=["ctfs"])

_FIELDS = ("name", "flag_format", "url", "notes")


def _ctf_id(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:32] or "ctf"
    return f"{slug}-{storage.new_project_id()[-6:]}"


def _get(session: Session, cid: str) -> Ctf:
    c = session.get(Ctf, cid)
    if not c:
        raise HTTPException(404, "ctf not found")
    return c


def _ctf_dict(c: Ctf, session: Session) -> dict:
    total = session.exec(select(func.count(Project.id)).where(Project.ctf_id == c.id)).one()
    solved = session.exec(select(func.count(Project.id)).where(Project.ctf_id == c.id)
                          .where(Project.solved == True)).one()  # noqa: E712
    run = ctfs.AUTOSOLVES.get(c.id)
    return {"id": c.id, "name": c.name, "flag_format": c.flag_format, "url": c.url,
            "notes": c.notes, "created_at": c.created_at,
            "challenges": total, "solved": solved,
            "autosolve": run.status() if run else None}


def _check(payload: dict) -> dict:
    data = {k: str(payload[k] or "") for k in _FIELDS if k in payload}
    if "flag_format" in data and not ctfs.valid_format(data["flag_format"]):
        raise HTTPException(422, "flag_format: not a prefix (DUCTF{...}) nor a valid regex")
    return data


@router.get("/api/v1/ctfs")
def list_ctfs(session: Session = Depends(get_session)) -> list[dict]:
    return [_ctf_dict(c, session) for c in session.exec(select(Ctf).order_by(Ctf.created_at.desc()))]


@router.post("/api/v1/ctfs", status_code=201)
def create_ctf(payload: dict = Body(...), session: Session = Depends(get_session)) -> dict:
    """New CTF: {name, flag_format?: "DUCTF{...}" or a regex, url?, notes?}."""
    data = _check(payload)
    if not data.get("name"):
        raise HTTPException(422, "name required")
    c = Ctf(id=_ctf_id(data["name"]), **data)
    session.add(c)
    session.commit()
    return _ctf_dict(c, session)


@router.get("/api/v1/ctfs/{cid}")
def get_ctf(cid: str, session: Session = Depends(get_session)) -> dict:
    """The CTF with its challenges (status, solved, flags found so far)."""
    c = _get(session, cid)
    projects = session.exec(select(Project).where(Project.ctf_id == cid)
                            .order_by(Project.created_at)).all()
    pids = [p.id for p in projects]
    counts = dict(session.exec(select(FileNode.project_id, func.count(FileNode.id))
                               .where(FileNode.project_id.in_(pids))  # type: ignore[attr-defined]
                               .group_by(FileNode.project_id)).all()) if pids else {}
    flags: dict[str, list[str]] = {}
    for f in session.exec(select(Finding).where(Finding.project_id.in_(pids))  # type: ignore[attr-defined]
                          .where(Finding.kind == "flag")).all() if pids else []:
        flags.setdefault(f.project_id, []).append(f.value)
    out = _ctf_dict(c, session)
    out["challenge_list"] = [{**_project_dict(p, counts.get(p.id, 0)), "flags": flags.get(p.id, [])}
                             for p in projects]
    return out


@router.patch("/api/v1/ctfs/{cid}")
def update_ctf(cid: str, payload: dict = Body(...), session: Session = Depends(get_session)) -> dict:
    c = _get(session, cid)
    for k, v in _check(payload).items():
        setattr(c, k, v)
    session.add(c)
    session.commit()
    return _ctf_dict(c, session)


@router.delete("/api/v1/ctfs/{cid}")
def delete_ctf(cid: str, session: Session = Depends(get_session)) -> dict:
    """Delete the CTF; its challenges are kept (detached, ctf_id = null)."""
    c = _get(session, cid)
    ctfs.stop_autosolve(cid)
    for p in session.exec(select(Project).where(Project.ctf_id == cid)).all():
        p.ctf_id = None
        session.add(p)
    session.delete(c)
    session.commit()
    return {"deleted": cid}


@router.post("/api/v1/ctfs/{cid}/challenges", status_code=201)
def add_challenge(cid: str, files: list[UploadFile] = File(...), name: str = Form(""),
                  category: str = Form(""), mode: str = Form("auto"),
                  start: bool = Form(False), session: Session = Depends(get_session)) -> dict:
    """Upload a challenge into the CTF (`start=true` analyzes it right away)."""
    _get(session, cid)
    proj = create_from_uploads(session, files, name, mode, cid, category)
    if start:
        from .. import orchestrator
        orchestrator.start(proj["id"])
    return proj


@router.post("/api/v1/ctfs/{cid}/autosolve", status_code=202)
def autosolve(cid: str, payload: dict = Body(default={}),
              session: Session = Depends(get_session)) -> dict:
    """Analyze every unsolved challenge, `parallel` at a time (default 2).
    A flag in the CTF format marks a challenge solved."""
    _get(session, cid)
    try:
        run = ctfs.start_autosolve(cid, int(payload.get("parallel", 2)),
                                   bool(payload.get("include_solved", False)))
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    except (TypeError, ValueError):
        raise HTTPException(422, "parallel must be an integer")
    return run.status()


@router.get("/api/v1/ctfs/{cid}/autosolve")
def autosolve_status(cid: str, session: Session = Depends(get_session)) -> dict:
    _get(session, cid)
    run = ctfs.AUTOSOLVES.get(cid)
    if not run:
        raise HTTPException(404, "no autosolve for this ctf")
    return run.status()


@router.delete("/api/v1/ctfs/{cid}/autosolve")
def autosolve_stop(cid: str) -> dict:
    """Stop queueing challenges (the ones already running finish)."""
    if not ctfs.stop_autosolve(cid):
        raise HTTPException(404, "no autosolve for this ctf")
    return {"stopped": cid}
