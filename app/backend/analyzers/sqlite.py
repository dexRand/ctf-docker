"""SQLite databases: dump the readable text of every table.

Browser profiles, mobile apps and "app data" challenges keep the interesting
strings (URLs, form values, cookies, chat messages) in SQLite. The file is
opened read-only/immutable so a half-copied DB never blocks the analysis.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

_SQLITE_MAGIC = b"SQLite format 3\x00"
_TEXT = re.compile(r"^[ -~\t\r\n]{2,}$")
_MAX_ROWS = 500
_MAX_VALUE = 2000
_MAX_OUTPUT = 200_000


def dump_sqlite(path: Path) -> str:
    """Text dump of every table: `table: value | value …` (newest rows first
    when the table has an id). Empty string when it is not a readable DB."""
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=5)
    except sqlite3.Error:
        return ""
    try:
        tables = [r[0] for r in con.execute(
            "select name from sqlite_master where type='table' and name not like 'sqlite_%'")]
        lines: list[str] = []
        for table in tables:
            quoted = table.replace('"', '""')      # a table name can contain `"`
            try:
                cols = [r[1] for r in con.execute(f'pragma table_info("{quoted}")')]
                if not cols:
                    continue
                rows = con.execute(f'select * from "{quoted}" limit {_MAX_ROWS}').fetchall()
            except sqlite3.Error:
                continue                            # skip this table, not the database
            values: list[str] = []
            for row in rows:
                for value in row:
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8")
                        except UnicodeDecodeError:
                            continue
                    if isinstance(value, str) and _TEXT.match(value):
                        values.append(value[:_MAX_VALUE])
            if values:
                lines.append(f"== {table} ==")
                lines.extend(dict.fromkeys(values))
            if sum(len(x) for x in lines) > _MAX_OUTPUT:
                break
        return "\n".join(lines)[:_MAX_OUTPUT]
    except sqlite3.Error:
        return ""
    finally:
        con.close()


class SqliteAnalyzer(Analyzer):
    name = "sqlite"
    category = "extract"
    description = "Dump the text of a SQLite database (browser history, cookies, app data)."
    accepts = (".sqlite", ".sqlite3", ".db", ".bak", ".sqlite2")
    display_order = 234

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            with ctx.input.open("rb") as fh:
                magic = fh.read(16)
            if magic != _SQLITE_MAGIC:
                return ToolResult(self.name, status="skipped", summary="not a SQLite database")
        except OSError:
            return ToolResult(self.name, status="skipped", summary="unreadable")
        text = dump_sqlite(ctx.input)
        if not text.strip():
            return ToolResult(self.name, status="skipped", summary="no readable text")
        return ToolResult(self.name, status="done", summary=f"{text.count('== ')} table(s)",
                          output=text)


register(SqliteAnalyzer())
