"""Unit tests for the letter-case (binary/Bacon) stego decoder (no tools)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from backend.analyzers.base import ToolContext
from backend.analyzers.casebits import CaseBitsAnalyzer


def _run(data: bytes):
    d = Path(tempfile.mkdtemp(prefix="cb-"))
    p = d / "text.txt"
    p.write_bytes(data)
    return CaseBitsAnalyzer().run(ToolContext(input=p, workdir=d / "w"))


def _case_text(bits: list[int]) -> bytes:
    return "".join("A" if b else "a" for b in bits).encode()


def test_case_bits_8bit_ascii() -> None:
    hidden = "ITS{case_bits_flag}"
    bits = [int(b) for c in hidden for b in f"{ord(c):08b}"]
    res = _run(_case_text(bits))
    assert res.status == "done"
    assert hidden in res.output


def test_bacon_5bit() -> None:
    msg = "HELLOWORLD"
    bits = [int(b) for c in msg for b in f"{ord(c) - 65:05b}"]
    res = _run(_case_text(bits))
    assert msg in res.output


def test_too_few_letters_skips() -> None:
    assert _run(b"HeLLo WoRld").status == "skipped"
