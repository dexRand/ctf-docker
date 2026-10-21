"""Cracking inside the analysis flow: record crack runs, auto-crack locked files."""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import TYPE_CHECKING

from sqlmodel import Session, select

from .events import emit as _emit, event as _event, now as _now
from .models import Event, FileNode, Finding, ToolRun
from .planner import origin_tool, STEG_DECODERS
from .tree import import_children

if TYPE_CHECKING:  # jobs imports this module: type-only import
    from .jobs import Job


def mark_unlocked(session: Session, pid: str, file_id: int) -> None:
    """After a successful crack, a file no longer needs a password.

    Clears ``needs_password`` on every run that asked for one, so the file
    stops being reported as locked/locked while keeping the failed run history.
    """
    for r in session.exec(select(ToolRun).where(ToolRun.project_id == pid)
                          .where(ToolRun.file_id == file_id)
                          .where(ToolRun.needs_password == True)).all():  # noqa: E712
        r.needs_password = False


def record_crack_run(session: Session, pid: str, file_id: int, work: Path,
                     res: dict, lines: list[str]) -> None:
    """Persist a ToolRun for a crack attempt.

    Cracking used to leave only a Finding/Event, so the crack step had no run,
    no command log and did not appear in the runs list / graph. This stores the
    executed commands and the outcome like any other analyzer run.
    """
    out_dir = work / "work" / str(file_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    body = ""
    if lines:
        body += "# commands:\n# " + "\n# ".join(lines) + "\n\n"
    if res.get("password"):
        hit = res.get("wordlist_hit") or ""
        body += "password: " + res["password"] + (f"  (via {hit})" if hit else "")
        summary = "password: " + res["password"] + (f" (via {hit})" if hit else "")
        status, code = "done", 0
    else:
        body += "password not found"
        summary, status, code = "password not found", "skipped", 1
    op = out_dir / "crack.out"
    op.write_text(body, errors="replace")
    # one crack run per file: update it across auto-crack rounds / manual retries
    run = session.exec(select(ToolRun).where(ToolRun.project_id == pid)
                       .where(ToolRun.file_id == file_id)
                       .where(ToolRun.tool == "crack")).first()
    if run is None:
        run = ToolRun(project_id=pid, file_id=file_id, tool="crack")
        session.add(run)
    run.status = status
    run.exit_code = code
    run.summary = summary[:500]
    run.output_path = str(op.relative_to(work))
    run.needs_password = False
    run.finished_at = _now()
    if run.started_at is None:
        run.started_at = _now()


def locked_files(session: Session, pid: str) -> dict[int, str]:
    """{file_id: tool that asked for a password} for files not cracked yet."""
    cracked = set(session.exec(select(Finding.file_id).where(Finding.project_id == pid)
                               .where(Finding.kind == "password")).all())
    runs = session.exec(select(ToolRun).where(ToolRun.project_id == pid)
                        .where(ToolRun.needs_password == True)  # noqa: E712
                        .order_by(ToolRun.id)).all()
    out: dict[int, str] = {}
    for r in runs:
        if r.file_id in cracked:
            continue
        if r.tool in ("steghide", "outguess"):
            node = session.get(FileNode, r.file_id)
            # steghide/outguess can't tell "no payload" from "wrong passphrase":
            # on a node a stego decoder produced the lock is a false positive.
            if node and origin_tool(node.origin) in STEG_DECODERS:
                continue
        out.setdefault(r.file_id, r.tool)
    return out


def apply_crack_result(session: Session, pid: str, node: FileNode, work: Path,
                       res: dict, lines: list[str]) -> list[int]:
    """Persist a crack outcome (run, password finding, event, live message) and
    import the files it unlocked. Returns the new child node ids. Commits."""
    fid = node.id
    record_crack_run(session, pid, fid, work, res, lines)
    ids: list[int] = []
    if res["password"]:
        wl_hit = res.get("wordlist_hit") or ""
        session.add(Finding(project_id=pid, file_id=fid, kind="password",
                            value=res["password"], source=f"crack:{res['kind']}",
                            context=wl_hit))
        mark_unlocked(session, pid, fid)
        session.add(Event(project_id=pid, level="info",
                          message=f"password found for {node.name}: {res['password']}"
                                  + (f" via {wl_hit}" if wl_hit else "")))
        _emit(pid, {"type": "crack", "file_id": fid, "status": "found",
                    "password": res["password"], "wordlist": wl_hit or None})
        if res["extracted"]:
            ids = import_children(session, pid, fid, res["extracted"])
    else:
        _emit(pid, {"type": "crack", "file_id": fid, "status": "not_found"})
        session.add(Event(project_id=pid, level="warn", message=f"password not found for {node.name}"))
    session.commit()
    return ids


# metadata fields that CTF authors use to leave a password around
_HINT_KEYS = re.compile(r"(?i)title|comment|author|artist|description|subject|keyword|copyright|"
                        r"caption|creator|note|password|passwd|hint|label|headline|rights|instruction")
_EXIF_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9 /_-]{1,40}?)\s*:\s(.+)$")
_CHUNK_LINE = re.compile(r"^(?:tEXt|iTXt|zTXt): (.+)$")


def context_wordlist(session: Session, pid: str, work: Path) -> Path | None:
    """Password candidates from the challenge itself: descriptive metadata
    fields (exiftool) and PNG text chunks of every file of the project, whole
    values and their words. Written to work/crack-context.txt (tried first)."""
    cands: list[str] = []
    runs = session.exec(select(ToolRun).where(ToolRun.project_id == pid)
                        .where(ToolRun.tool.in_(("exiftool", "png-chunks")))).all()  # type: ignore[attr-defined]
    for r in runs:
        if not r.output_path:
            continue
        try:
            text = (work / r.output_path).read_text("utf-8", "replace")
        except OSError:
            continue
        for line in text.splitlines():
            m = _EXIF_LINE.match(line.strip()) if r.tool == "exiftool" else _CHUNK_LINE.match(line.strip())
            if not m:
                continue
            if r.tool == "exiftool":
                if not _HINT_KEYS.search(m.group(1)):
                    continue
                value = m.group(2).strip()
            else:
                value = re.split(r"[\x00=]", m.group(1), maxsplit=1)[-1].strip()
            if 3 <= len(value) <= 200:
                cands += [value] + [w for w in re.split(r"[\s,;]+", value) if 3 <= len(w) <= 64]
    cands = list(dict.fromkeys(cands))[:2000]
    if not cands:
        return None
    path = work / "crack-context.txt"
    path.write_text("\n".join(cands) + "\n")
    return path


def _auto_crack(session: Session, pid: str, work: Path, job: Job) -> list[FileNode]:
    """Auto mode: try the *small* wordlists on the locked files; return unlocked
    nodes. Bounded by ``AUTO_CRACK_MAX_MB`` (per list) and ``AUTO_CRACK_BUDGET_S``
    (per project) so a false "locked" (e.g. a JPEG with no steghide payload)
    cannot stall the analysis for hours."""
    from . import cracking
    fids = list(locked_files(session, pid))
    if not fids:
        return []

    names = [p.name for p in cracking.resolve_wordlists(max_bytes=cracking.AUTO_CRACK_MAX_BYTES)]
    deadline = (time.time() + cracking.AUTO_CRACK_BUDGET_S) if cracking.AUTO_CRACK_BUDGET_S > 0 else None
    _event(session, pid, f"auto-crack: {len(names)} wordlists (≤ "
                         f"{cracking.AUTO_CRACK_MAX_BYTES // (1024 * 1024)} MB)"
                         + (f", budget {cracking.AUTO_CRACK_BUDGET_S}s" if deadline else ""))
    session.commit()

    new_nodes: list[FileNode] = []
    for fid in fids:
        if job.cancelled:
            break
        if deadline and time.time() > deadline:
            _event(session, pid, "auto-crack time budget reached", "warn")
            session.commit()
            break
        node = session.get(FileNode, fid)
        if not node:
            continue
        _emit(pid, {"type": "crack", "file_id": fid, "name": node.name, "status": "running"})
        lines: list[str] = []
        budget = max(1, int(deadline - time.time())) if deadline else None
        res = cracking.crack_file(work / node.rel_path, names, log=lines.append, budget_s=budget,
                                  extra_wordlists=[c for c in [context_wordlist(session, pid, work)] if c])
        for i in apply_crack_result(session, pid, node, work, res, lines):
            nn = session.get(FileNode, i)
            if nn:
                new_nodes.append(nn)
    return new_nodes
