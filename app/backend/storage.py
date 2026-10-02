"""Filesystem layout for projects.

/data/projects/<id>/
    uploads/     original uploaded files
    files/       every analysed file (originals + extracted), by node id
    work/        tool outputs, one dir per file node
"""
from __future__ import annotations

import hashlib
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from .config import PROJECTS_DIR


def new_project_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


def sanitize_name(name: str) -> str:
    name = (name or "file").replace("\\", "/").split("/")[-1].strip()
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name or "file"


def project_dir(pid: str) -> Path:
    return PROJECTS_DIR / pid


def init_project(pid: str) -> None:
    for sub in ("uploads", "files", "work"):
        (project_dir(pid) / sub).mkdir(parents=True, exist_ok=True)


def delete_project(pid: str) -> None:
    shutil.rmtree(project_dir(pid), ignore_errors=True)


def _hashes(path: Path) -> tuple[str, str, int]:
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            size += len(chunk)
            md5.update(chunk)
            sha.update(chunk)
    return sha.hexdigest(), md5.hexdigest(), size


def save_upload(pid: str, filename: str, src: BinaryIO) -> dict:
    """Save an uploaded stream into uploads/ and return file metadata."""
    name = sanitize_name(filename)
    dest = project_dir(pid) / "uploads" / name
    n = 1
    while dest.exists():
        dest = project_dir(pid) / "uploads" / f"{Path(name).stem}_{n}{Path(name).suffix}"
        n += 1
    with open(dest, "wb") as out:
        shutil.copyfileobj(src, out)
    sha, md5, size = _hashes(dest)
    return {"name": dest.name, "path": dest, "sha256": sha, "md5": md5, "size": size}


def file_node_path(pid: str, node_id: int, name: str) -> Path:
    """Where an analysed file node is stored (files/<id>__<name>)."""
    return project_dir(pid) / "files" / f"{node_id}__{sanitize_name(name)}"


def hashes_of(path: Path) -> tuple[str, str, int]:
    return _hashes(path)
