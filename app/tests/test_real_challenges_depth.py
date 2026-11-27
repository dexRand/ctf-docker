"""Verification harness: the --depth flag reaches the analysis request.

Deep/full cases must be verifiable with `--gaps -k <name>` instead of silently
running at the default `normal` tier.
"""
from __future__ import annotations

import pytest

import real_challenges as rc


def test_run_defaults_to_normal_depth(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(rc, "DEST", tmp_path)
    monkeypatch.setattr(rc, "download", lambda url, dest: dest.write_bytes(b"x"))

    def fake_analyze(paths, mode, **kw):
        seen["depth"] = kw.get("depth")
        return {"project": "p", "status": "done", "flags": [], "passwords": [], "seconds": 0}

    monkeypatch.setattr(rc.ss, "analyze", fake_analyze)
    rc.run("case", [("f.bin", "http://x")], "flag{x}")
    assert seen["depth"] == "normal"


def test_run_threads_explicit_depth(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(rc, "DEST", tmp_path)
    monkeypatch.setattr(rc, "download", lambda url, dest: dest.write_bytes(b"x"))

    def fake_analyze(paths, mode, **kw):
        seen["depth"] = kw.get("depth")
        return {"project": "p", "status": "done", "flags": [], "passwords": [], "seconds": 0}

    monkeypatch.setattr(rc.ss, "analyze", fake_analyze)
    rc.run("case", [("f.bin", "http://x")], "flag{x}", depth="full")
    assert seen["depth"] == "full"


def test_main_passes_depth_to_every_case(monkeypatch):
    monkeypatch.setattr(rc, "all_cases", lambda *a, **k: [("case", [("f", "u")], "flag{x}")])
    seen = {}

    def fake_run(label, files, expect, depth="normal"):
        seen["depth"] = depth
        return {"label": label, "ok": True, "expect": expect, "seconds": 0}

    monkeypatch.setattr(rc, "run", fake_run)
    assert rc.main(["--depth", "deep"]) == 0
    assert seen["depth"] == "deep"


def test_depth_choices_are_normal_deep_full(capsys):
    with pytest.raises(SystemExit) as exc:
        rc.main(["--help"])
    assert exc.value.code == 0
    assert "--depth {normal,deep,full}" in capsys.readouterr().out
