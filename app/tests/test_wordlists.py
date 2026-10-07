"""User-uploaded wordlists (persisted under DATA_DIR/wordlists)."""
from __future__ import annotations

import io

import pytest

from backend import cracking


def _isolate(tmp_path, monkeypatch):
    d = tmp_path / "wordlists"
    monkeypatch.setattr(cracking, "USER_WORDLIST_DIR", d)
    monkeypatch.setattr(cracking, "WORDLIST_DIRS", [d])
    return d


def test_save_wordlist_sanitises_and_counts(tmp_path, monkeypatch):
    d = _isolate(tmp_path, monkeypatch)
    info = cracking.save_wordlist("../my list.txt", io.BytesIO(b"a\nb\nc\n"))
    assert info["name"].endswith(".txt")
    assert "/" not in info["name"] and ".." not in info["name"]
    assert info["size"] == 6 and info["lines"] == 3
    assert (d / info["name"]).is_file()
    assert info["name"] in [w["name"] for w in cracking.list_wordlists()]


def test_save_wordlist_does_not_overwrite(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    a = cracking.save_wordlist("x.txt", io.BytesIO(b"one\n"))
    b = cracking.save_wordlist("x.txt", io.BytesIO(b"two\n"))
    assert a["name"] != b["name"]


def test_save_wordlist_rejects_oversized_and_cleans_up(tmp_path, monkeypatch):
    d = _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(cracking, "MAX_WORDLIST_BYTES", 4)
    with pytest.raises(ValueError):
        cracking.save_wordlist("big.txt", io.BytesIO(b"1234567890"))
    assert not list(d.iterdir())


def test_resolve_wordlists_respects_max_bytes(tmp_path, monkeypatch):
    d = tmp_path / "wl"
    d.mkdir()
    (d / "small.txt").write_text("a\nb\n")
    (d / "big.txt").write_text("x" * 5000)
    monkeypatch.setattr(cracking, "WORDLIST_DIRS", [d])
    assert [p.name for p in cracking.resolve_wordlists(max_bytes=100)] == ["small.txt"]
    assert {p.name for p in cracking.resolve_wordlists()} == {"small.txt", "big.txt"}
