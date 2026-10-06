"""Schema migrations (Alembic): legacy detection + fresh database creation."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect

from backend.db import _legacy_revision, engine, init_db

EXPECTED = {"project", "filenode", "toolrun", "artifact", "finding", "event",
            "alembic_version"}


def test_fresh_database_gets_the_full_schema():
    init_db()
    tables = set(inspect(engine).get_table_names())
    assert EXPECTED <= tables
    cols = {c["name"] for c in inspect(engine).get_columns("finding")}
    assert "context" in cols


def test_legacy_database_without_context_is_stamped_at_0001(tmp_path: Path):
    e = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with e.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE finding (id INTEGER PRIMARY KEY, value VARCHAR)")
    assert _legacy_revision(inspect(e)) == "0001"


def test_legacy_database_with_context_is_stamped_at_0002(tmp_path: Path):
    e = create_engine(f"sqlite:///{tmp_path / 'legacy2.db'}")
    with e.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE finding (id INTEGER PRIMARY KEY, context VARCHAR DEFAULT '')")
    assert _legacy_revision(inspect(e)) == "0002"


def test_empty_database_is_fresh(tmp_path: Path):
    e = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    assert _legacy_revision(inspect(e)) is None
