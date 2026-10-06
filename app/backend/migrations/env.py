"""Alembic environment — used programmatically by ``backend.db.init_db``.

The database URL comes from the app config (``DATA_DIR/stegsuite.db``) unless the
caller set ``sqlalchemy.url`` explicitly (autogenerate / tests).
"""
from __future__ import annotations

import sys
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel

# make ``backend`` importable regardless of the working directory
APP_DIR = Path(__file__).resolve().parents[2]
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from backend import models  # noqa: E402,F401  (registers the tables)
from backend.config import DB_PATH  # noqa: E402

config = context.config
if config.config_file_name:
    from logging.config import fileConfig

    fileConfig(config.config_file_name)

if not config.get_main_option("sqlalchemy.url"):
    config.set_main_option("sqlalchemy.url", f"sqlite:///{DB_PATH}")

target_metadata = SQLModel.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # SQLite needs batch mode for ALTER
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
