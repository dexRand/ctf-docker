"""The analysis job: walk the file tree in discovery order and run analyzers.

For each file node: run the applicable analyzers, store their output, hunt
flags, create child nodes for extracted files and recurse until the tree is
exhausted (or the depth limit is reached); in auto mode, crack locked files
with the small wordlists and analyze what they unlock.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import datetime as dt
import traceback
from pathlib import Path

from sqlmodel import Session, select

from . import storage
from .analyzers import get as get_tool
from .analyzers.base import ToolContext, ToolResult
from .config import MAX_DEPTH
from .crackflow import _auto_crack
from .ctfs import update_solved
from .db import engine
from .events import emit as _emit, event as _event, now as _now
from .flaghunt import _hunt
from .models import Artifact, FileNode, Finding, Project, ToolRun
from .planner import _HEAVY_SEM, _HEAVY_TOOLS, _detect_ext, _plan_for
from .tree import _store_extracted

if TYPE_CHECKING:  # jobs imports this module: type-only import
    from .jobs import Job


def run_analyzer(tool_name: str, path: Path, out_dir: Path,
                 password: str | None = None) -> tuple[ToolResult, list[str]]:
    """Run one analyzer on a file; never raises (errors become an error result).
    Heavy tools share a global semaphore so CPU-bound runs don't pile up."""
    analyzer = get_tool(tool_name)
    logs: list[str] = []
    if analyzer is None:
        return ToolResult(tool_name, status="error", summary="unknown tool"), logs
    tctx = ToolContext(input=path, workdir=out_dir, password=password, log=logs.append)
    try:
        if tool_name in _HEAVY_TOOLS:
            with _HEAVY_SEM:
                return analyzer.run(tctx), logs
        return analyzer.run(tctx), logs
    except Exception as exc:  # one broken analyzer must not kill the job
        return ToolResult(tool_name, status="error",
                          summary=f"{type(exc).__name__}: {exc}"[:500],
                          output=traceback.format_exc()[-8000:]), logs


def record_run(session: Session, pid: str, node: FileNode, tool_name: str,
               result: ToolResult, logs: list[str] | None = None,
               started: "dt.datetime | None" = None) -> ToolRun:
    """Persist one analyzer run: output file, ToolRun, artifacts, flag hunt,
    'password required' note, live event. Commits (short SQLite writes)."""
    work = storage.project_dir(pid)
    out_dir = work / "work" / str(node.id)
    out_dir.mkdir(parents=True, exist_ok=True)
    content = result.output or ""
    if logs:
        content = "# commands:\n# " + "\n# ".join(logs) + "\n\n" + content
    rel_out = None
    if content:
        op = out_dir / f"{tool_name}.out"
        op.write_text(content, errors="replace")
        rel_out = str(op.relative_to(work))
    run = ToolRun(project_id=pid, file_id=node.id, tool=tool_name,
                  status=result.status, needs_password=result.needs_password,
                  exit_code=result.exit_code, summary=result.summary[:500],
                  output_path=rel_out, started_at=started or _now(), finished_at=_now())
    session.add(run)
    session.flush()
    # files moved into the tree as children must not stay as artifacts
    # too (their old path would no longer exist)
    moved = {str(x) for x in result.extracted}
    for art in result.artifacts:
        if str(art.get("path", "")) in moved:
            continue
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
        note_val = f"password required: {node.name}"
        exists = session.exec(select(Finding).where(Finding.project_id == pid)
                              .where(Finding.kind == "note")
                              .where(Finding.value == note_val)).first()
        if not exists:
            session.add(Finding(project_id=pid, file_id=node.id, kind="note",
                                value=note_val, source=tool_name))
    _emit(pid, {"type": "tool", "file_id": node.id, "name": node.name, "tool": tool_name,
                "status": result.status, "needs_password": result.needs_password,
                "summary": result.summary, "extracted": len(result.extracted)})
    # persist now: keep the SQLite write transaction short so a long
    # tool run never blocks other requests ("database is locked")
    session.commit()
    return run


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
        if job.only_new:
            seen = set(session.exec(select(ToolRun.file_id).where(ToolRun.project_id == pid)).all())
            nodes = [n for n in nodes if n.id not in seen]
        pending: list[FileNode] = list(nodes)
        processed: set[str] = set()
        depth_limit = MAX_DEPTH  # nested archives (Matryoshka doll) can be several levels deep

        def analyze(node: FileNode) -> None:
            if node.depth >= depth_limit or (node.sha256 and node.sha256 in processed):
                return
            if node.sha256:
                processed.add(node.sha256)

            _emit(pid, {"type": "file", "file_id": node.id, "name": node.name,
                        "depth": node.depth, "size": node.size,
                        "total": job.processed + 1 + len(pending)})
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

            # detect type first, then build the plan (text files skip heavy carving)
            ftype = ""
            if get_tool("file"):
                t0 = _now()
                r0, file_logs = run_analyzer("file", abs_path, out_dir)
                ftype = r0.output
                record_run(session, pid, node, "file", r0, file_logs, t0)
            is_text = any(k in ftype.lower() for k in ("text", "ascii", "unicode"))
            # if the name lies (PNG called .txt…), use the detected type for the plan
            detected = _detect_ext(ftype)
            plan_name = node.name
            if detected and not node.name.lower().endswith(detected):
                plan_name = node.name + detected
            plan = _plan_for(plan_name, node.mime, is_text)

            for tool_name in [t for t in plan if t != "file"]:
                if job.cancelled:
                    break
                job.wait()
                t0 = _now()
                result, logs = run_analyzer(tool_name, abs_path, out_dir)
                record_run(session, pid, node, tool_name, result, logs, t0)
                for src in result.extracted:
                    child = _store_extracted(session, pid, node, Path(src), tool=tool_name)
                    pending.append(child)
                if result.consumed:
                    break

            job.processed += 1
            proj.updated_at = _now()
            session.add(proj)
            session.commit()
            _emit(pid, {"type": "progress", "processed": job.processed,
                        "total": job.processed + len(pending)})

        rounds = 0
        try:
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
        except Exception:  # never leave a project spinning in "running"
            session.rollback()  # the failing statement may have poisoned the session
            _event(session, pid, "analysis failed: " + traceback.format_exc()[-800:], "error")
            proj = session.get(Project, pid) or proj
            proj.status = "error"
            proj.updated_at = _now()
            session.add(proj)
            session.commit()
            _emit(pid, {"type": "status", "status": "error"})
            return

        update_solved(session, pid)
        proj = session.get(Project, pid) or proj
        proj.status = "cancelled" if job.cancelled else "done"
        proj.updated_at = _now()
        session.add(proj)
        _event(session, pid, f"analysis {proj.status}", "warn" if job.cancelled else "info")
        session.commit()
        _emit(pid, {"type": "status", "status": proj.status})


def run_tools_on_node(pid: str, file_id: int, tools: list[str],
                      password: str | None = None) -> list[int]:
    """Run the given analyzers on one file now (outside a job), record them and
    store what they extract; returns the ids of the new child nodes."""
    work = storage.project_dir(pid)
    children: list[int] = []
    with Session(engine) as session:
        node = session.get(FileNode, file_id)
        if not node or node.project_id != pid:
            return children
        abs_path = work / node.rel_path
        out_dir = work / "work" / str(node.id)
        out_dir.mkdir(parents=True, exist_ok=True)
        for tool_name in tools:
            t0 = _now()
            result, logs = run_analyzer(tool_name, abs_path, out_dir, password=password)
            record_run(session, pid, node, tool_name, result, logs, t0)
            for src in result.extracted:
                children.append(_store_extracted(session, pid, node, Path(src), tool=tool_name).id)
            update_solved(session, pid)
            session.commit()
    return children
