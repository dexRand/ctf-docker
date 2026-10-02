"""Recursive, ordered analysis orchestrator.

For each file node, in discovery order: run the applicable analyzers, store
their output, hunt flags, create child nodes for extracted files and recurse
until the tree is exhausted (or the depth limit is reached).
"""
from __future__ import annotations

import datetime as dt
import re
import shutil
import threading
import uuid
from pathlib import Path

from sqlmodel import Session, select

from . import storage
from .analyzers import get as get_tool
from .bus import bus
from .analyzers.base import ToolContext
from .config import PROJECTS_DIR
from .db import engine
from .models import Artifact, Event, FileNode, Finding, Project, ToolRun

FLAG_PATTERNS = [
    r"ITS\{[^}\n]{1,200}\}", r"flag\{[^}\n]{1,200}\}", r"FLAG\{[^}\n]{1,200}\}",
    r"CTF\{[^}\n]{1,200}\}", r"ctf\{[^}\n]{1,200}\}", r"HTB\{[^}\n]{1,200}\}",
    r"picoCTF\{[^}\n]{1,200}\}", r"[0-9A-Za-z_]{2,32}\{[ -~]{1,200}\}",
]
_FLAG_RE = [re.compile(p.encode(), re.IGNORECASE) for p in FLAG_PATTERNS]

# ordered analysis plan (order matters: metadata -> text -> steg -> extract)
DEFAULT_PLAN = [
    "file", "exiftool", "identify", "ffprobe", "pdfinfo",
    "strings", "hexyl", "xxd", "pdftotext", "pdfid", "binwalk-scan",
    "ocr",
    "zsteg", "steghide", "outguess", "jsteg", "openstego",
    "bit-planes", "channel-remap", "gif-frames",
    "morse", "dtmf", "spectrogram", "waveform",
    "7z", "binwalk-extract", "foremost", "pngcheck",
]
HEAVY_EXTRACT = {"binwalk-extract", "foremost"}
ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".tgz")


class Job:
    def __init__(self, project_id: str) -> None:
        self.project_id = project_id
        self.cancelled = False
        self.paused = False
        self.gate = threading.Event()
        self.gate.set()
        self.thread: threading.Thread | None = None
        self.processed = 0

    def wait(self) -> None:
        self.gate.wait()

    def pause(self) -> None:
        self.paused = True
        self.gate.clear()

    def resume(self) -> None:
        self.paused = False
        self.gate.set()

    def cancel(self) -> None:
        self.cancelled = True
        self.gate.set()


JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _event(session: Session, pid: str, message: str, level: str = "info") -> None:
    session.add(Event(project_id=pid, message=message, level=level))
    bus.publish(f"project:{pid}", {"type": "event", "level": level, "message": message})


def _emit(pid: str, event: dict) -> None:
    bus.publish(f"project:{pid}", event)


def _hunt(session: Session, project_id: str, file_id: int | None, text: str, source: str) -> None:
    if not text:
        return
    data = text.encode("latin-1", "replace")
    existing = {f.value for f in session.exec(select(Finding).where(Finding.project_id == project_id)).all()}
    for pat in _FLAG_RE:
        for m in pat.findall(data):
            value = m.decode("latin-1", "replace")
            if not all(32 <= ord(c) <= 126 for c in value):
                continue
            if value in existing:
                continue
            existing.add(value)
            session.add(Finding(project_id=project_id, file_id=file_id, kind="flag", value=value, source=source))


def _plan_for(name: str, mime: str | None, is_text: bool) -> list[str]:
    plan = []
    for tool in DEFAULT_PLAN:
        a = get_tool(tool)
        if not a or not a.matches(mime, name):
            continue
        if tool in HEAVY_EXTRACT and is_text and not name.lower().endswith(ARCHIVE_EXT):
            continue
        plan.append(tool)
    return plan


def _store_extracted(session: Session, pid: str, parent: FileNode, src: Path, order: int) -> FileNode:
    name = storage.sanitize_name(src.name)
    rel = f"files/{order:04d}__{name}"
    dest = storage.project_dir(pid) / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(src), str(dest))
    except (OSError, shutil.Error):
        shutil.copy2(src, dest)
    sha, md5, size = storage.hashes_of(dest)
    node = FileNode(project_id=pid, parent_id=parent.id, name=name, rel_path=rel,
                    size=size, mime=None, sha256=sha, md5=md5, depth=parent.depth + 1,
                    order_index=order, origin=f"extracted:{parent.id}")
    session.add(node)
    session.flush()
    return node


def _run(pid: str, job: Job) -> None:
    work = storage.project_dir(pid)
    with Session(engine) as session:
        proj = session.get(Project, pid)
        if not proj:
            return
        proj.status = "running"
        proj.updated_at = _now()
        session.add(proj)
        _event(session, pid, "analysis started")
        session.commit()
        _emit(pid, {"type": "status", "status": "running"})

        nodes = session.exec(select(FileNode).where(FileNode.project_id == pid)
                             .order_by(FileNode.order_index, FileNode.id)).all()
        queue: list[FileNode] = list(nodes)
        order = max((n.order_index for n in nodes), default=-1) + 1
        processed: set[str] = set()
        depth_limit = 3

        while queue:
            if job.cancelled:
                break
            job.wait()
            if job.cancelled:
                break
            node = queue.pop(0)
            if node.depth >= depth_limit or (node.sha256 and node.sha256 in processed):
                continue
            if node.sha256:
                processed.add(node.sha256)

            _emit(pid, {"type": "file", "file_id": node.id, "name": node.name,
                        "depth": node.depth, "size": node.size})
            abs_path = work / node.rel_path
            if not abs_path.is_file():
                continue
            out_dir = work / "work" / str(node.id)
            out_dir.mkdir(parents=True, exist_ok=True)

            def record(tool_name: str, result) -> None:
                rel_out = None
                if result.output:
                    op = out_dir / f"{tool_name}.out"
                    op.write_text(result.output, errors="replace")
                    rel_out = str(op.relative_to(work))
                run = ToolRun(project_id=pid, file_id=node.id, tool=tool_name,
                              status=result.status, needs_password=result.needs_password,
                              exit_code=result.exit_code, summary=result.summary[:500],
                              output_path=rel_out, started_at=_now(), finished_at=_now())
                session.add(run)
                session.flush()
                for art in result.artifacts:
                    p = Path(str(art.get("path", "")))
                    try:
                        rel_art = str(p.relative_to(work))
                    except ValueError:
                        rel_art = str(art.get("name", ""))
                    session.add(Artifact(project_id=pid, run_id=run.id, file_id=node.id,
                                         name=str(art.get("name", p.name)),
                                         path=rel_art, size=int(art.get("size", 0))))
                if result.output:
                    _hunt(session, pid, node.id, result.output, f"{tool_name}:{node.name}")
                if result.needs_password:
                    session.add(Finding(project_id=pid, file_id=node.id, kind="note",
                                        value=f"password required: {node.name}", source=tool_name))
                _emit(pid, {"type": "tool", "file_id": node.id, "name": node.name, "tool": tool_name,
                            "status": result.status, "needs_password": result.needs_password,
                            "summary": result.summary, "extracted": len(result.extracted)})

            # detect type first, then build the plan (text files skip heavy carving)
            ftype = ""
            file_analyzer = get_tool("file")
            if file_analyzer:
                r0 = file_analyzer.run(ToolContext(input=abs_path, workdir=out_dir, log=lambda _m: None))
                ftype = r0.output
                record("file", r0)
            is_text = any(k in ftype.lower() for k in ("text", "ascii", "unicode"))

            for tool_name in [t for t in _plan_for(node.name, node.mime, is_text) if t != "file"]:
                if job.cancelled:
                    break
                job.wait()
                analyzer = get_tool(tool_name)
                result = analyzer.run(ToolContext(input=abs_path, workdir=out_dir, log=lambda _m: None))
                record(tool_name, result)
                for src in result.extracted:
                    child = _store_extracted(session, pid, node, Path(src), order)
                    order += 1
                    queue.append(child)

            job.processed += 1
            proj.updated_at = _now()
            session.add(proj)
            session.commit()
            _emit(pid, {"type": "progress", "processed": job.processed})

        proj = session.get(Project, pid) or proj
        proj.status = "cancelled" if job.cancelled else "done"
        proj.updated_at = _now()
        session.add(proj)
        _event(session, pid, f"analysis {proj.status}", "warn" if job.cancelled else "info")
        session.commit()
        _emit(pid, {"type": "status", "status": proj.status})
    with _JOBS_LOCK:
        JOBS.pop(pid, None)


def import_children(session: Session, pid: str, parent_id: int, paths: list[str]) -> list[int]:
    """Store files recovered by cracking as children of an existing node."""
    parent = session.get(FileNode, parent_id)
    if not parent:
        return []
    last = session.exec(select(FileNode).where(FileNode.project_id == pid)
                        .order_by(FileNode.order_index.desc())).first()
    order = (last.order_index if last else -1) + 1
    ids: list[int] = []
    for src in paths:
        child = _store_extracted(session, pid, parent, Path(src), order)
        order += 1
        ids.append(child.id)
    session.flush()
    return ids


def start(pid: str) -> Job:
    with _JOBS_LOCK:
        if pid in JOBS:
            raise RuntimeError("already running")
        job = Job(pid)
        JOBS[pid] = job
    t = threading.Thread(target=_run, args=(pid, job), daemon=True)
    job.thread = t
    t.start()
    return job


def control(pid: str, action: str) -> bool:
    with _JOBS_LOCK:
        job = JOBS.get(pid)
    if not job:
        return False
    if action == "pause":
        job.pause()
    elif action == "resume":
        job.resume()
    elif action == "cancel":
        job.cancel()
    else:
        return False
    return True


def is_running(pid: str) -> bool:
    with _JOBS_LOCK:
        return pid in JOBS
