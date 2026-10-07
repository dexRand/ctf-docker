"""OpenStego: the `-p` flag must be omitted when no password is known.

An empty `-p ""` makes OpenStego print its help and never extract (the bug this
guards against).
"""
from __future__ import annotations

from pathlib import Path

from backend.analyzers.steg import _openstego_cmd


def test_openstego_cmd_omits_an_empty_password():
    cmd = _openstego_cmd(Path("/a.png"), Path("/o"), "")
    assert "-p" not in cmd
    assert cmd == ["openstego", "extract", "-sf", "/a.png", "-xf", "/o"]


def test_openstego_cmd_includes_the_password_when_set():
    cmd = _openstego_cmd(Path("/a.png"), Path("/o"), "secret")
    assert cmd[-2:] == ["-p", "secret"]
