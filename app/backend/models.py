"""Database models (SQLite)."""
from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlmodel import Field, SQLModel


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Project(SQLModel, table=True):
    id: str = Field(primary_key=True)
    name: str = ""
    status: str = "created"      # created|queued|running|paused|done|error|cancelled
    mode: str = "auto"           # auto|check
    settings_json: str = "{}"
    created_at: dt.datetime = Field(default_factory=_now)
    updated_at: dt.datetime = Field(default_factory=_now)


class FileNode(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: str = Field(index=True)
    parent_id: Optional[int] = Field(default=None, index=True)
    rel_path: str = ""           # path on disk inside the project's files/ dir
    name: str = ""
    size: int = 0
    mime: Optional[str] = None
    sha256: str = ""
    md5: str = ""
    depth: int = 0
    order_index: int = 0
    origin: str = "upload"       # upload | extracted:<tool>
    created_at: dt.datetime = Field(default_factory=_now)


class ToolRun(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: str = Field(index=True)
    file_id: int = Field(index=True)
    tool: str = ""
    status: str = "queued"       # queued|running|done|error|skipped
    needs_password: bool = False
    exit_code: Optional[int] = None
    summary: str = ""
    output_path: Optional[str] = None
    started_at: Optional[dt.datetime] = None
    finished_at: Optional[dt.datetime] = None


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: str = Field(index=True)
    file_id: Optional[int] = None
    kind: str = "note"           # flag|password|note
    value: str = ""
    source: str = ""
    created_at: dt.datetime = Field(default_factory=_now)


class Event(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: str = Field(index=True)
    ts: dt.datetime = Field(default_factory=_now)
    level: str = "info"
    message: str = ""
