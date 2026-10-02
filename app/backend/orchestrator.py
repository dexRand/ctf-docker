"""Recursive, ordered analysis orchestrator.

For each file node, in discovery order: run the applicable analyzers, store
their output, hunt flags, create child nodes for extracted files and recurse
until the tree is exhausted (or the depth limit is reached).
"""
from __future__ import annotations

import base64
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

STRICT_PATTERNS = [
    r"ITS\{[^}\n]{1,200}\}", r"flag\{[^}\n]{1,200}\}", r"FLAG\{[^}\n]{1,200}\}",
    r"CTF\{[^}\n]{1,200}\}", r"ctf\{[^}\n]{1,200}\}", r"HTB\{[^}\n]{1,200}\}",
    r"picoCTF\{[^}\n]{1,200}\}",
]
GENERIC_PATTERNS = [r"[0-9A-Za-z_]{2,32}\{[A-Za-z0-9_\-!?.,:;@#$%^&*+=/ ]{1,120}\}"]
_STRICT_RE = [re.compile(p.encode(), re.IGNORECASE) for p in STRICT_PATTERNS]
_GENERIC_RE = [re.compile(p.encode(), re.IGNORECASE) for p in GENERIC_PATTERNS]
# sources where the generic "<word>{...}" pattern is skipped (noisy OCR / raw bytes)
VISION_SOURCES = ("ocr", "bit-planes", "channel-remap", "image-enhance",
                  "gif-frames", "spectrogram", "waveform", "raw")


def _ok_flag(value: str) -> bool:
    if value.count("{") != 1 or value.count("}") != 1:
        return False
    if any(c in value for c in "|\n\r\t"):
        return False
    body = value[value.find("{") + 1:value.rfind("}")]
    if not body or len(body) > 200:
        return False
    return sum(ch.isalnum() for ch in body) >= 3
# OCR often reads '{' as f/F/l/L/[/( and ']'/'}' as ] or ). This fuzzy pattern
# rescues flags found by OCR/vision tools and normalises them back.
_FUZZY_RE = re.compile(
    rb"(picoCTF|ITS|FLAG|flag|HTB|ctf|CTF)[\{\[\(fFlL]([ -~]{1,180}?)[\}\]\)]", re.IGNORECASE)

# ordered analysis plan (order matters: metadata -> text -> steg -> extract)
DEFAULT_PLAN = [
    "file", "exiftool", "identify", "ffprobe", "pdfinfo",
    "strings", "hexyl", "xxd", "pdftotext", "pdfid", "binwalk-scan",
    "decode", "morse-text",
    "ocr",
    "zsteg", "png-chunks", "steghide", "outguess", "jsteg", "openstego",
    "bit-planes", "channel-remap", "image-enhance", "gif-frames",
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


def _printable(b: bytes) -> bool:
    if not b:
        return False
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not t:
        return False
    good = sum(1 for c in t if 32 <= ord(c) < 127 or c in "\n\r\t")
    return good / len(t) >= 0.85


def _views(data: bytes) -> list[bytes]:
    """Byte views to hunt in: raw, plus UTF-16 LE/BE when the data is null-heavy."""
    views = [data]
    if data and data.count(0) > len(data) // 4:
        # UTF-16 without the usual decode (keeps a trailing odd byte, e.g. "}")
        views.append(data[0::2])
        views.append(data[1::2])
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                views.append(data.decode(enc, "ignore").encode("latin-1", "replace"))
            except Exception:
                pass
    return views


def _hunt(session: Session, project_id: str, file_id: int | None, text: str,
          source: str, depth: int = 0) -> None:
    if not text:
        return
    data = text.encode("latin-1", "replace")
    views = _views(data)
    existing = {f.value for f in session.exec(select(Finding).where(Finding.project_id == project_id)).all()}
    is_vision = source.split(":", 1)[0] in VISION_SOURCES
    pats = list(_STRICT_RE) + ([] if is_vision else list(_GENERIC_RE))

    def add(value: str, src: str) -> None:
        if value in existing or not _ok_flag(value):
            return
        existing.add(value)
        session.add(Finding(project_id=project_id, file_id=file_id, kind="flag", value=value, source=src))

    for view in views:
        for pat in pats:
            for m in pat.findall(view):
                add(m.decode("latin-1", "replace"), source)
        for m in _FUZZY_RE.finditer(view):
            add((m.group(1) + b"{" + m.group(2) + b"}").decode("latin-1", "replace"), f"fuzzy:{source}")
    if depth >= 2:
        return
    # inline encodings in tool outputs (e.g. base64 in EXIF metadata)
    decoders: list[tuple[str, object]] = [
        ("b64", lambda t: base64.b64decode(t + b"=" * ((4 - len(t) % 4) % 4), validate=False)),
        ("hex", lambda t: bytes.fromhex(t.decode())),
    ]
    for name, fn in decoders:
        pat = rb"[A-Za-z0-9+/]{16,}={0,2}" if name == "b64" else rb"(?:[0-9a-fA-F]{2}){8,}"
        for view in views:
            for m in re.finditer(pat, view):
                try:
                    dec = fn(m.group(0))
                except Exception:
                    continue
                if b"{" in dec and _printable(dec):
                    _hunt(session, project_id, file_id, dec.decode("latin-1", "replace"),
                          f"{name}:{source}", depth + 1)


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
        pending: list[FileNode] = list(nodes)
        order = max((n.order_index for n in nodes), default=-1) + 1
        processed: set[str] = set()
        depth_limit = 6  # nested archives (Matryoshka doll) can be several levels deep

        def analyze(node: FileNode) -> None:
            nonlocal order
            if node.depth >= depth_limit or (node.sha256 and node.sha256 in processed):
                return
            if node.sha256:
                processed.add(node.sha256)

            _emit(pid, {"type": "file", "file_id": node.id, "name": node.name,
                        "depth": node.depth, "size": node.size})
            abs_path = work / node.rel_path
            if not abs_path.is_file():
                return
            out_dir = work / "work" / str(node.id)
            out_dir.mkdir(parents=True, exist_ok=True)

            # hunt the raw file content too (catches UTF-16 flags, inline encodings…)
            try:
                raw = abs_path.read_bytes()[:5_000_000]
                _hunt(session, pid, node.id, raw.decode("latin-1", "replace"), f"raw:{node.name}")
            except OSError:
                pass

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
                    pending.append(child)

            job.processed += 1
            proj.updated_at = _now()
            session.add(proj)
            session.commit()
            _emit(pid, {"type": "progress", "processed": job.processed})

        rounds = 0
        while True:
            while pending:
                if job.cancelled:
                    break
                job.wait()
                if job.cancelled:
                    break
                analyze(pending.pop(0))
            if job.cancelled or proj.mode != "auto" or rounds >= 3:
                break
            new_nodes = _auto_crack(session, pid, work, job)
            if not new_nodes:
                break
            pending.extend(new_nodes)
            rounds += 1

        proj = session.get(Project, pid) or proj
        proj.status = "cancelled" if job.cancelled else "done"
        proj.updated_at = _now()
        session.add(proj)
        _event(session, pid, f"analysis {proj.status}", "warn" if job.cancelled else "info")
        session.commit()
        _emit(pid, {"type": "status", "status": proj.status})
    with _JOBS_LOCK:
        JOBS.pop(pid, None)


def _auto_crack(session: Session, pid: str, work: Path, job: Job) -> list[FileNode]:
    """Auto mode: try every wordlist on the locked files; return unlocked nodes."""
    from . import cracking
    already = {f.file_id for f in session.exec(
        select(Finding).where(Finding.project_id == pid).where(Finding.kind == "password")).all()}
    runs = session.exec(select(ToolRun).where(ToolRun.project_id == pid)
                        .where(ToolRun.needs_password == True)).all()  # noqa: E712
    fids: list[int] = []
    for r in runs:
        if r.file_id not in already and r.file_id not in fids:
            fids.append(r.file_id)

    new_nodes: list[FileNode] = []
    for fid in fids:
        if job.cancelled:
            break
        node = session.get(FileNode, fid)
        if not node:
            continue
        _emit(pid, {"type": "crack", "file_id": fid, "name": node.name, "status": "running"})
        res = cracking.crack_file(work / node.rel_path, None)
        if res["password"]:
            session.add(Finding(project_id=pid, file_id=fid, kind="password",
                                value=res["password"], source=f"crack:{res['kind']}"))
            session.add(Event(project_id=pid, level="info",
                              message=f"password found for {node.name}: {res['password']}"))
            _emit(pid, {"type": "crack", "file_id": fid, "status": "found",
                        "password": res["password"]})
            if res["extracted"]:
                ids = import_children(session, pid, fid, res["extracted"])
                session.flush()
                for i in ids:
                    nn = session.get(FileNode, i)
                    if nn:
                        new_nodes.append(nn)
            session.commit()
        else:
            _emit(pid, {"type": "crack", "file_id": fid, "status": "not_found"})
            session.add(Event(project_id=pid, level="warn", message=f"password not found for {node.name}"))
            session.commit()
    return new_nodes


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
