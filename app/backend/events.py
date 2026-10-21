"""Project events: persisted log lines + live messages on the bus."""
from __future__ import annotations

import datetime as dt

from sqlmodel import Session

from .bus import bus
from .models import Event


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)



def event(session: Session, pid: str, message: str, level: str = "info") -> None:
    session.add(Event(project_id=pid, message=message, level=level))
    bus.publish(f"project:{pid}", {"type": "event", "level": level, "message": message})


def emit(pid: str, event: dict) -> None:
    bus.publish(f"project:{pid}", event)
