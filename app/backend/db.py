"""SQLite engine + session helpers."""
from __future__ import annotations

from sqlmodel import Session, SQLModel, create_engine

from .config import DATA_DIR, DB_PATH

DATA_DIR.mkdir(parents=True, exist_ok=True)
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
)


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
