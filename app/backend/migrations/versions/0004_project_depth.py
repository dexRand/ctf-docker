"""Analysis depth tier: project.depth

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-27 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = '0004'
down_revision: Union[str, None] = '0003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_STR = sqlmodel.sql.sqltypes.AutoString


def upgrade() -> None:
    # normal/deep/full: existing projects keep the fast default
    with op.batch_alter_table("project") as b:
        b.add_column(sa.Column("depth", _STR(), nullable=False, server_default="normal"))


def downgrade() -> None:
    with op.batch_alter_table("project") as b:
        b.drop_column("depth")
