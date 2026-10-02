"""SQLite engine + session helpers."""
from __future__ import annotations

from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

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


def init_db() -> None:
    SQLModel.metadata.create_all(engine)
    _migrate()


def _migrate() -> None:
    """Lightweight, additive migrations for SQLite (create_all won't alter)."""
    with engine.begin() as conn:
        cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(finding)").fetchall()}
        if "context" not in cols:
            conn.exec_driver_sql("ALTER TABLE finding ADD COLUMN context VARCHAR DEFAULT ''")


def get_session():
    with Session(engine) as session:
        yield session
