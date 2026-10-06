"""SQLite engine + session helpers."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import event, inspect
from sqlmodel import Session, create_engine, select

from .config import DATA_DIR, DB_PATH

DATA_DIR.mkdir(parents=True, exist_ok=True)
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record) -> None:
    """WAL + a busy timeout so a long analysis never returns 'database is locked'."""
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA busy_timeout=30000")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.close()


MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def _alembic_config():
    """Alembic config pointing at the app's migrations + database."""
    from alembic.config import Config as AlembicConfig

    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{DB_PATH}")
    return cfg


def _legacy_revision(inspector) -> str | None:
    """Revision a pre-Alembic database corresponds to.

    Databases created by the old ``create_all`` + ``_migrate`` have no
    ``alembic_version``; we stamp them at the matching revision so Alembic only
    applies what is still missing. ``None`` = fresh database (upgrade creates all).
    """
    if "finding" not in set(inspector.get_table_names()):
        return None
    cols = {c["name"] for c in inspector.get_columns("finding")}
    return "0002" if "context" in cols else "0001"


def init_db() -> None:
    """Create or upgrade the schema through Alembic migrations."""
    from alembic import command

    cfg = _alembic_config()
    insp = inspect(engine)
    if "alembic_version" not in set(insp.get_table_names()):
        rev = _legacy_revision(insp)
        if rev:
            command.stamp(cfg, rev)
    command.upgrade(cfg, "head")


def delete_project_rows(session: Session, pid: str) -> None:
    """Delete a project and all its rows (filesystem is the caller's job)."""
    from .models import Artifact, Event, FileNode, Finding, Project, ToolRun

    for model in (FileNode, ToolRun, Artifact, Finding, Event):
        for row in session.exec(select(model).where(model.project_id == pid)).all():
            session.delete(row)
    project = session.get(Project, pid)
    if project:
        session.delete(project)


def get_session():
    with Session(engine) as session:
        yield session
