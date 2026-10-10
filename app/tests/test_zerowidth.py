"""Unit tests for the zero-width / whitespace stego decoder (no external tools)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from backend.analyzers.base import ToolContext
from backend.analyzers.zerowidth import ZeroWidthAnalyzer


def _run(data: bytes):
    d = Path(tempfile.mkdtemp(prefix="zw-"))
    p = d / "note.txt"
    p.write_bytes(data)
    return ZeroWidthAnalyzer().run(ToolContext(input=p, workdir=d / "w"))


def _bitstring(text: str) -> list[int]:
    return [(ord(c) >> i) & 1 for c in text for i in range(7, -1, -1)]


def test_zero_width_flag() -> None:
    hidden = "ITS{zero_width_flag}"
    zw = "".join("\u200b" if b == 0 else "\u200d" for b in _bitstring(hidden))
    res = _run(("looks like a normal file\n" + zw + "\n").encode("utf-8"))
    assert res.status == "done"
    assert hidden in res.output


def test_trailing_whitespace_flag() -> None:
    hidden = "ITS{ws_flag}"
    bits = _bitstring(hidden)
    lines = ["code" + "".join(" " if b == 0 else "\t" for b in bits[i:i + 4])
             for i in range(0, len(bits), 4)]
    res = _run("\n".join(lines).encode("utf-8"))
    assert hidden in res.output


def test_plain_text_is_skipped() -> None:
    res = _run(b"just a normal file with nothing hidden\n")
    assert res.status == "skipped"
