"""Background analysis jobs: one thread per running project."""
from __future__ import annotations

import threading

from .pipeline import _run


class Job:
    def __init__(self, project_id: str) -> None:
        self.project_id = project_id
        self.cancelled = False
        self.paused = False
        self.gate = threading.Event()
        self.gate.set()
        self.thread: threading.Thread | None = None
        self.processed = 0
        self.only_new = False   # analyze only nodes that have no tool runs yet
        self.requeue = False    # new files arrived meanwhile: run again when done

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


def start(pid: str, only_new: bool = False) -> Job:
    with _JOBS_LOCK:
        if pid in JOBS:
            raise RuntimeError("already running")
        job = Job(pid)
        job.only_new = only_new
        JOBS[pid] = job
    t = threading.Thread(target=_job_main, args=(pid, job), daemon=True)
    job.thread = t
    t.start()
    return job


def _job_main(pid: str, job: Job) -> None:
    """Thread entry: whatever happens in `_run`, the job is unregistered."""
    try:
        _run(pid, job)
    finally:
        with _JOBS_LOCK:
            if JOBS.get(pid) is job:
                JOBS.pop(pid)
    if job.requeue and not job.cancelled:
        analyze_new(pid)


def analyze_new(pid: str) -> None:
    """Analyze files added after the last run (e.g. by a crack). If a job is
    running, it picks them up in a follow-up pass once it finishes."""
    with _JOBS_LOCK:
        job = JOBS.get(pid)
        if job:
            job.requeue = True
            return
    try:
        start(pid, only_new=True)
    except RuntimeError:  # started by someone else in between: let it requeue
        analyze_new(pid)


def stop(pid: str, wait_s: float = 15.0) -> None:
    """Cancel a running job and wait for its thread (before deleting a project)."""
    with _JOBS_LOCK:
        job = JOBS.get(pid)
    if not job:
        return
    job.cancel()
    if job.thread and job.thread is not threading.current_thread():
        job.thread.join(wait_s)


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
