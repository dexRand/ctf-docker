"""CTF events: flag format, solved detection and the autosolver queue.

A CTF groups challenges (projects). Its `flag_format` drives the flag hunt of
every challenge in it, and a flag matching that format marks the challenge
solved. `autosolve` analyzes every unsolved challenge, a few at a time.
"""
from __future__ import annotations

import re
import threading
import time
from functools import lru_cache

from sqlmodel import Session, select

from .db import engine
from .models import Ctf, Finding, Project

_PREFIX_RE = re.compile(r"([A-Za-z0-9_\-]{1,40})(?:\{(?:\.\.\.|…|\*|)\})?")


@lru_cache(maxsize=64)
def format_regex(fmt: str) -> tuple[re.Pattern | None, bool]:
    """(compiled bytes regex, is_prefix) for a CTF flag format.

    `DUCTF`, `DUCTF{...}`, `DUCTF{}` -> prefix mode: `DUCTF{<1-200 chars>}`.
    Anything else is a regular expression (e.g. `FLAG-[0-9a-f]{8}`).
    An invalid regex gives (None, False): callers validate on input.
    """
    fmt = (fmt or "").strip()
    if not fmt:
        return None, False
    m = _PREFIX_RE.fullmatch(fmt)
    if m:
        pat = r"(?<![0-9A-Za-z_])" + re.escape(m.group(1)) + r"\{[^}\n]{1,200}\}"
        return re.compile(pat.encode()), True
    try:
        return re.compile(fmt.encode()), False
    except re.error:
        return None, False


def valid_format(fmt: str) -> bool:
    return not fmt.strip() or format_regex(fmt)[0] is not None


def project_format(session: Session, pid: str) -> str:
    """Flag format of the CTF a project belongs to ('' when none)."""
    proj = session.get(Project, pid)
    if not proj or not proj.ctf_id:
        return ""
    ctf = session.get(Ctf, proj.ctf_id)
    return ctf.flag_format if ctf else ""


def update_solved(session: Session, pid: str) -> bool:
    """Mark the challenge solved when a found flag matches its CTF format.
    Never un-solves (a human may have confirmed it). Returns `solved`."""
    proj = session.get(Project, pid)
    if not proj:
        return False
    if proj.solved:
        return True
    rx, _ = format_regex(project_format(session, pid))
    if rx is None:
        return False
    for f in session.exec(select(Finding).where(Finding.project_id == pid)
                          .where(Finding.kind == "flag").order_by(Finding.id)).all():
        if rx.fullmatch(f.value.encode("latin-1", "replace")):
            proj.solved, proj.flag = True, f.value
            session.add(proj)
            return True
    return False


# --- autosolver ---------------------------------------------------------------

class Autosolve:
    """Background run over a CTF's unsolved challenges, `parallel` at a time."""

    def __init__(self, ctf_id: str, pids: list[str], parallel: int) -> None:
        self.ctf_id = ctf_id
        self.queue = list(pids)
        self.total = len(pids)
        self.parallel = max(1, parallel)
        self.running: set[str] = set()
        self.done: list[str] = []
        self.cancelled = False
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def status(self) -> dict:
        return {"ctf_id": self.ctf_id, "total": self.total, "queued": len(self.queue),
                "running": sorted(self.running), "finished": len(self.done),
                "active": self.thread.is_alive(), "cancelled": self.cancelled}

    def _loop(self) -> None:
        from . import orchestrator
        while (self.queue or self.running) and not self.cancelled:
            for pid in [p for p in self.running if not orchestrator.is_running(p)]:
                self.running.discard(pid)
                self.done.append(pid)
            while self.queue and len(self.running) < self.parallel:
                pid = self.queue.pop(0)
                if orchestrator.is_running(pid):   # started by hand meanwhile
                    self.running.add(pid)
                    continue
                with Session(engine) as s:
                    p = s.get(Project, pid)
                    if not p or p.solved:
                        continue
                    p.status = "queued"
                    s.add(p)
                    s.commit()
                try:
                    orchestrator.start(pid)
                    self.running.add(pid)
                except RuntimeError:
                    self.running.add(pid)
            time.sleep(1)


AUTOSOLVES: dict[str, Autosolve] = {}
_LOCK = threading.Lock()


def start_autosolve(ctf_id: str, parallel: int = 2, include_solved: bool = False) -> Autosolve:
    with Session(engine) as s:
        q = select(Project.id).where(Project.ctf_id == ctf_id).order_by(Project.created_at)
        if not include_solved:
            q = q.where(Project.solved == False)  # noqa: E712
        pids = list(s.exec(q).all())
    with _LOCK:
        cur = AUTOSOLVES.get(ctf_id)
        if cur and cur.thread.is_alive():
            raise RuntimeError("autosolve already running")
        run = AUTOSOLVES[ctf_id] = Autosolve(ctf_id, pids, parallel)
    run.thread.start()
    return run


def stop_autosolve(ctf_id: str) -> bool:
    with _LOCK:
        run = AUTOSOLVES.get(ctf_id)
    if not run:
        return False
    run.cancelled = True
    return True
