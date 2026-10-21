"""CTF events: ctf table, project.ctf_id/category/solved/flag

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-20 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = '0003'
down_revision: Union[str, None] = '0002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_STR = sqlmodel.sql.sqltypes.AutoString


def upgrade() -> None:
    op.create_table(
        "ctf",
        sa.Column("id", _STR(), nullable=False),
        sa.Column("name", _STR(), nullable=False, server_default=""),
        sa.Column("flag_format", _STR(), nullable=False, server_default=""),
        sa.Column("url", _STR(), nullable=False, server_default=""),
        sa.Column("notes", _STR(), nullable=False, server_default=""),
        sa.Column("created_at", sqlmodel.sql.sqltypes.UTCDateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    # existing projects become challenges without a CTF
    with op.batch_alter_table("project") as b:
        b.add_column(sa.Column("ctf_id", _STR(), nullable=True))
        b.add_column(sa.Column("category", _STR(), nullable=False, server_default=""))
        b.add_column(sa.Column("solved", sa.Boolean(), nullable=False, server_default=sa.false()))
        b.add_column(sa.Column("flag", _STR(), nullable=False, server_default=""))
        b.create_index("ix_project_ctf_id", ["ctf_id"])


def downgrade() -> None:
    with op.batch_alter_table("project") as b:
        b.drop_index("ix_project_ctf_id")
        for col in ("flag", "solved", "category", "ctf_id"):
            b.drop_column(col)
    op.drop_table("ctf")
