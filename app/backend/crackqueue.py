"""Crack queue: manual crack requests run here, CRACK_WORKERS at a time.

One job per file (several files of a project can be queued); a file that is
already queued or running can't be queued twice. Queued jobs can be cancelled.
Every state change is published on the project's bus, so the GUI follows it.
"""
from __future__ import annotations

import itertools
import os
import queue
import threading
import time
import traceback
from dataclasses import dataclass, field

from sqlmodel import Session

from . import crackflow, cracking, storage
from .bus import bus
from .db import engine
from .models import Event, FileNode

CRACK_WORKERS = max(1, int(os.environ.get("CRACK_WORKERS", "1") or 1))
_KEEP = 200        # finished jobs kept for GET /cracks


@dataclass
class CrackJob:
    id: int
    project_id: str
    file_id: int
    name: str
    wordlists: list[str] | None
    opts: dict
    status: str = "queued"           # queued|running|found|not_found|error|cancelled
    password: str | None = None
    wordlist: str | None = None
    error: str | None = None
    queued_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("id", "project_id", "file_id", "name", "status",
                                              "password", "wordlist", "error", "queued_at",
                                              "started_at", "finished_at")}


_JOBS: dict[int, CrackJob] = {}
_LOCK = threading.Lock()
_QUEUE: "queue.Queue[CrackJob]" = queue.Queue()
_IDS = itertools.count(1)
_started = False


class AlreadyQueued(RuntimeError):
    pass


def submit(project_id: str, file_id: int, name: str, wordlists, opts: dict) -> CrackJob:
    global _started
    with _LOCK:
        for j in _JOBS.values():
            if j.project_id == project_id and j.file_id == file_id and j.status in ("queued", "running"):
                raise AlreadyQueued("this file is already queued or being cracked")
        job = CrackJob(next(_IDS), project_id, file_id, name, wordlists, opts)
        _JOBS[job.id] = job
        _prune()
        if not _started:
            for i in range(CRACK_WORKERS):
                threading.Thread(target=_worker, name=f"crack-{i}", daemon=True).start()
            _started = True
    _QUEUE.put(job)
    _publish(job)
    return job


def jobs(project_id: str | None = None) -> list[CrackJob]:
    with _LOCK:
        out = [j for j in _JOBS.values() if project_id is None or j.project_id == project_id]
    return sorted(out, key=lambda j: j.id, reverse=True)


def get(job_id: int) -> CrackJob | None:
    return _JOBS.get(job_id)


def cancel(job_id: int) -> bool:
    """Cancel a queued job (a running crack can't be interrupted)."""
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job or job.status != "queued":
            return False
        job.status = "cancelled"
        job.finished_at = time.time()
    _publish(job)
    return True


def position(job: CrackJob) -> int:
    with _LOCK:
        return sum(1 for j in _JOBS.values() if j.status == "queued" and j.id < job.id)


def _prune() -> None:
    done = [j for j in _JOBS.values() if j.status not in ("queued", "running")]
    for j in sorted(done, key=lambda j: j.id)[:-_KEEP]:
        _JOBS.pop(j.id, None)


def _publish(job: CrackJob) -> None:
    status = {"found": "found", "not_found": "not_found"}.get(job.status, job.status)
    bus.publish(f"project:{job.project_id}", {"type": "crack", "file_id": job.file_id,
                                              "name": job.name, "status": status,
                                              "job": job.id, "password": job.password,
                                              "wordlist": job.wordlist, "error": job.error})


def _worker() -> None:
    while True:
        job = _QUEUE.get()
        with _LOCK:
            if job.status != "queued":       # cancelled while waiting
                continue
            job.status, job.started_at = "running", time.time()
        _publish(job)
        try:
            _run(job)
        except Exception as exc:  # the GUI waits for a final event: always send one
            job.status, job.error = "error", f"{type(exc).__name__}: {exc}"[:300]
            with Session(engine) as s:
                s.add(Event(project_id=job.project_id, level="error",
                            message="crack failed: " + traceback.format_exc()[-800:]))
                s.commit()
        job.finished_at = time.time()
        _publish(job)


def _run(job: CrackJob) -> None:
    from . import orchestrator
    with Session(engine) as s:
        node = s.get(FileNode, job.file_id)
        if not node or node.project_id != job.project_id:
            job.status, job.error = "error", "file not found"
            return
        work = storage.project_dir(job.project_id)
        path = work / node.rel_path
        lines: list[str] = []
        bk = job.opts.get("bkcrack")
        if bk:
            res = cracking.bkcrack_attack(path, bk.get("name", ""), bk.get("plaintext", ""),
                                          log=lines.append)
        else:
            ctx_wl = crackflow.context_wordlist(s, job.project_id, work)
            res = cracking.crack_file(path, job.wordlists, log=lines.append,
                                      extra_wordlists=[ctx_wl] if ctx_wl else None,
                                      **{k: v for k, v in job.opts.items() if k != "bkcrack"})
        job.status = "found" if res["password"] else "not_found"
        job.password, job.wordlist = res["password"], res.get("wordlist_hit")
        if crackflow.apply_crack_result(s, job.project_id, node, work, res, lines):
            orchestrator.analyze_new(job.project_id)
