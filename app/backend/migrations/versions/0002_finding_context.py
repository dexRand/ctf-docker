"""add finding.context

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-06 19:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = '0002'
down_revision: Union[str, None] = '0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ``server_default`` gives existing rows a value; SQLite requires a default
    # for a NOT NULL column added to a populated table.
    op.add_column(
        "finding",
        sa.Column("context", sqlmodel.sql.sqltypes.AutoString(),
                  nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("finding", "context")
