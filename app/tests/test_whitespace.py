"""Unit tests for the Whitespace esolang interpreter (no external tools)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from backend.analyzers.base import ToolContext
from backend.analyzers.whitespace import WhitespaceAnalyzer, looks_like_whitespace, run

S, T, L = " ", "\t", "\n"


def _push(n: int) -> str:
    bits = bin(abs(n))[2:]
    return S + S + (S if n >= 0 else T) + "".join(S if b == "0" else T for b in bits) + L


def _outchar() -> str:
    return T + L + S + S


def _program(text: str) -> str:
    return "".join(_push(ord(c)) + _outchar() for c in text) + L + L + L


def _run(data: bytes):
    d = Path(tempfile.mkdtemp(prefix="ws-"))
    p = d / "prog.txt"
    p.write_bytes(data)
    return WhitespaceAnalyzer().run(ToolContext(input=p, workdir=d / "w"))


def test_whitespace_prints_flag() -> None:
    assert run(_program("ITS{ws_esolang}")) == "ITS{ws_esolang}"


def test_looks_like_whitespace() -> None:
    assert looks_like_whitespace(_program("hi").encode("utf-8"))
    assert not looks_like_whitespace(b"hello world, not whitespace")
    assert not looks_like_whitespace(b"   ")


def test_analyzer_runs_whitespace_program() -> None:
    res = _run(_program("ITS{ws_analyzer}").encode("utf-8"))
    assert res.status == "done"
    assert "ITS{ws_analyzer}" in res.output


def test_analyzer_skips_plain_text() -> None:
    assert _run(b"just some text\n").status == "skipped"


def test_arithmetic_and_loop() -> None:
    # push 'A'(65), push 'B'(66), add -> 131? no: 65+1 then outchar -> 'B'
    prog = _push(65) + _push(1) + T + S + S + S + _outchar() + L + L + L  # add = T S S S
    assert run(prog) == "B"
