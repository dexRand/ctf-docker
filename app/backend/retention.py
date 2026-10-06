"""Optional retention: delete projects untouched for ``RETENTION_DAYS`` days.

Disabled by default (``RETENTION_DAYS=0``). Runs at startup; a project's
``updated_at`` timestamp drives the cutoff. Both the database rows and the
project's files on disk are removed.
"""
from __future__ import annotations

import datetime as dt

from sqlmodel import Session, select

from . import storage
from .config import retention_days
from .db import delete_project_rows, engine
from .models import Project


def _as_utc(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def purge_old_projects(now: dt.datetime | None = None) -> list[str]:
    """Delete projects older than the configured retention; return their ids."""
    days = retention_days()
    if days <= 0:
        return []
    now = _as_utc(now or dt.datetime.now(dt.timezone.utc))
    cutoff = now - dt.timedelta(days=days)
    removed: list[str] = []
    with Session(engine) as session:
        for project in session.exec(select(Project)).all():
            if project.updated_at is not None and _as_utc(project.updated_at) < cutoff:
                delete_project_rows(session, project.id)
                removed.append(project.id)
        session.commit()
    for pid in removed:
        storage.delete_project(pid)
    return removed
