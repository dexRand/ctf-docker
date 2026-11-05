"""winreg: Windows registry hives (signature gating + activity-key extraction).

The sample hive in `tests/data/NTUSER.DAT` comes from regipy's test suite
(MIT licence): https://github.com/mkorman90/regipy/tree/master/regipy_tests/data
(`NTUSER.DAT.xz`, decompressed). It is a small real hive with RecentDocs,
UserAssist, RunMRU, TypedPaths and Environment.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from backend.analyzers.base import ToolContext
from backend.analyzers.winreg import WinregAnalyzer

HIVE = Path(__file__).parent / "data" / "NTUSER.DAT"


def test_gating_skips_a_file_that_is_not_a_hive(tmp_path):
    p = tmp_path / "note.dat"
    p.write_bytes(b"hello world")
    r = WinregAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and "not a registry hive" in r.summary


def test_gating_skips_a_corrupt_hive(tmp_path):
    p = tmp_path / "broken"
    p.write_bytes(b"regf" + b"\x00" * 8192)
    r = WinregAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped"


def test_gating_is_fast_on_an_ordinary_file(tmp_path):
    import time
    p = tmp_path / "big.bin"
    p.write_bytes(b"\x00" * (8 << 20))
    t0 = time.monotonic()
    r = WinregAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped"
    assert time.monotonic() - t0 < 0.2          # only 4 bytes are read


def test_binary_values_show_the_text_they_contain():
    from backend.analyzers.winreg import _binary_text
    # RecentDocs name "clp-1.JPG" encoded as UTF-16LE
    assert _binary_text("63006c0070002d0031002e004a005000470000") == "clp-1.JPG"


def test_a_real_hive_gives_the_activity_keys(tmp_path):
    pytest.importorskip("regipy")
    r = WinregAnalyzer().run(ToolContext(input=HIVE, workdir=tmp_path / "w"))
    assert r.status == "done", r.summary
    out = r.output or ""
    assert "== interesting keys ==" in out
    for key in ("RecentDocs", "UserAssist", "Environment"):
        assert key in out, key
    # UserAssist value names are stored in ROT13: they must come out readable
    assert "UEME_CTLSESSION" in out
    # REG_BINARY is hex in regipy: the UTF-16LE filename must be decoded
    assert "clp-1.JPG" in out
    assert "keys," in r.summary and "value(s)" in r.summary
