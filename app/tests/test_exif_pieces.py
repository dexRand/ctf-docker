"""exiftool: a flag split across descriptive metadata fields (TJCTF 2022 fake-geoguessr)."""
from __future__ import annotations

from types import SimpleNamespace

from backend.analyzers import get
from backend.analyzers.base import ToolResult


def test_flag_rebuilt_from_copyright_and_comment(monkeypatch):
    exif = get("exiftool")
    out = ("Copyright                       : tjctf{thats_a_\n"
           "Exposure Time                   : 1/520\n"
           "Exposure Mode                   : Auto\n"
           "Comment                         : lot_of_metadata}\n")
    base = type(exif).__mro__[1]
    monkeypatch.setattr(base, "run", lambda self, ctx: ToolResult("exiftool", status="done",
                                                                   output=out))
    r = exif.run(SimpleNamespace())
    assert "tjctf{thats_a_lot_of_metadata}" in r.output
