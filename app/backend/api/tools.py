"""Analyzer catalog + stateless single-tool API (for external projects)."""
from __future__ import annotations

import shutil

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse

from .. import storage
from ..analyzers import catalog as tool_catalog
from ..analyzers import get as get_tool
from ..analyzers import run_tool
from ..config import TOOLJOBS_DIR

router = APIRouter()


@router.get("/api/v1/tools")
def list_tools() -> list[dict]:
    """Catalog of available analyzers (name, category, description, flags)."""
    return tool_catalog()


@router.post("/api/v1/tools/{tool}")
def run_single_tool(tool: str, file: UploadFile = File(...), password: str = Form("")) -> dict:
    """Run one tool on an uploaded file (stateless). Output + downloadable artifacts."""
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


@router.get("/api/v1/tooljobs/{job}/files/{name:path}")
def tool_job_file(job: str, name: str):
    base = (TOOLJOBS_DIR / job).resolve()
    target = (base / name).resolve()
    if target != base and base not in target.parents:
        raise HTTPException(404, "not found")
    if not target.is_file():
        raise HTTPException(404, "not found")
    return FileResponse(target, filename=target.name)
