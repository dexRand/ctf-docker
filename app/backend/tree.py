"""File tree of a project: store extracted files as child nodes."""
from __future__ import annotations

import shutil
from pathlib import Path

from sqlmodel import Session, func, select

from . import storage
from .models import FileNode


def _next_order(session: Session, pid: str) -> int:
    """Next discovery index, read from the DB: the job thread and a manual crack
    (another session) both add nodes, so a cached counter would hand out duplicates."""
    last = session.exec(select(func.max(FileNode.order_index))
                        .where(FileNode.project_id == pid)).one()
    return (last if last is not None else -1) + 1


def _store_extracted(session: Session, pid: str, parent: FileNode, src: Path,
                     tool: str | None = None) -> FileNode:
    name = storage.sanitize_name(src.name)
    # the same bytes extracted twice (a zip found again under another name, an
    # archive carved by two tools) are the same node: analysing them again only
    # repeats the same tools and multiplies their children
    sha, md5, size = storage.hashes_of(src)
    same = session.exec(select(FileNode).where(FileNode.project_id == pid)
                        .where(FileNode.sha256 == sha)).first()
    if same:
        src.unlink(missing_ok=True)
        return same
    order = _next_order(session, pid)
    rel = f"files/{order:04d}__{name}"
    n = 1
    while (storage.project_dir(pid) / rel).exists():  # never overwrite another node
        rel = f"files/{order:04d}-{n}__{name}"
        n += 1
    dest = storage.project_dir(pid) / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(src), str(dest))
    except (OSError, shutil.Error):
        shutil.copy2(src, dest)
    origin = f"extracted:{tool}:{parent.id}" if tool else f"extracted:{parent.id}"
    node = FileNode(project_id=pid, parent_id=parent.id, name=name, rel_path=rel,
                    size=size, mime=storage.sniff_mime(dest), sha256=sha, md5=md5,
                    depth=parent.depth + 1, order_index=order, origin=origin)
    session.add(node)
    session.flush()
    return node



def import_children(session: Session, pid: str, parent_id: int, paths: list[str],
                    tool: str = "crack") -> list[int]:
    """Store files recovered by cracking as children of an existing node."""
    parent = session.get(FileNode, parent_id)
    if not parent:
        return []
    ids: list[int] = []
    for src in paths:
        ids.append(_store_extracted(session, pid, parent, Path(src), tool=tool).id)
    session.flush()
    return ids
