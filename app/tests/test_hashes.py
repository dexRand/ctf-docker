"""hashes: bare hashes in a text file, identified and put through hashcat."""
from __future__ import annotations

import hashlib
import subprocess

from backend.analyzers import hashes
from backend.analyzers.base import ToolContext
from backend.analyzers.hashes import HashesAnalyzer, find_hashes

MD5_PASSWORD = hashlib.md5(b"password", usedforsecurity=False).hexdigest()
SHA1 = hashlib.sha1(b"password", usedforsecurity=False).hexdigest()
SHA256 = hashlib.sha256(b"password").hexdigest()
BCRYPT = "$2b$12$" + "a" * 22 + "b" * 31
MD5CRYPT = "$1$abcdefgh$" + "c" * 22
SHA512CRYPT = "$6$saltsalt$" + "d" * 86
DUMP = ("Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
        "31d6cfe0d16ae931b73c59d7e0c089c0:::")

RANDOM_HEX = "\n".join(
    hashlib.sha256(f"seed-{i}".encode()).hexdigest()[:32] for i in range(10_000))


def test_every_supported_type_is_recognised():
    text = (f"md5 {MD5_PASSWORD}\nsha1 {SHA1}\nsha256 {SHA256}\n"
            f"bcrypt {BCRYPT}\nmd5crypt {MD5CRYPT}\nsha512crypt {SHA512CRYPT}\n"
            f"dump {DUMP}\n")
    kinds = [kind for _display, kind, _modes in find_hashes(text)]
    assert "md5/ntlm" in kinds
    assert "sha1" in kinds
    assert "sha256" in kinds
    assert "bcrypt" in kinds
    assert "md5crypt" in kinds and "sha512crypt" in kinds
    assert "ntlm (dump)" in kinds


def test_the_same_hash_twice_is_listed_once():
    items = find_hashes(f"{MD5_PASSWORD}\n{MD5_PASSWORD}\n")
    assert len(items) == 1


def test_degenerate_hex_runs_are_not_hashes():
    # ASCII art/shading made of one repeated hex digit is not a hash
    assert find_hashes("f" * 32) == []
    assert find_hashes("a" * 64) == []
    assert find_hashes(MD5_PASSWORD) != []       # a real hash still passes


def test_a_very_long_colon_free_line_does_not_hang():
    # psimage can emit a 140 KB single-line token: the secretsdump regex must
    # not rescan the line from every character (O(n^2) -> hang)
    text = "A" * 300_000 + "\n" + DUMP + "\n"
    found = find_hashes(text)
    assert [kind for _d, kind, _m in found] == ["ntlm (dump)"]


def test_a_dump_line_after_a_short_token_still_matches():
    assert [kind for _d, kind, _m in find_hashes(f"note {DUMP}\n")] == ["ntlm (dump)"]


def test_at_most_fifty_candidates_are_kept():
    items = find_hashes(RANDOM_HEX)
    assert len(items) == 50


def test_a_long_hex_string_is_not_a_hash():
    # 64 hex characters are SHA256, never a 32/40-character prefix of it
    assert [kind for _d, kind, _m in find_hashes(SHA256)] == ["sha256"]
    # a 128-character hex run is not a hash of any supported type
    assert find_hashes("a" * 128) == []
    # ... and a 64-char hash does not leak a 32-char MD5 from its prefix
    assert len(find_hashes(SHA256)) == 1


def test_text_without_hashes_is_skipped(tmp_path):
    p = tmp_path / "note.txt"
    p.write_text("nothing to see here, just a note with words.\n")
    r = HashesAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped"


def test_a_secretsdump_line_is_cracked_on_its_nt_hash(monkeypatch, tmp_path):
    p = tmp_path / "dump.txt"
    p.write_text(DUMP + "\n")
    calls = []

    def fake_run(cmd, timeout=300, **_kw):
        calls.append(list(cmd))
        if "--show" in cmd:
            nt = DUMP.split(":")[3]
            return subprocess.CompletedProcess(cmd, 0, f"{nt}:Password123!\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(hashes.cracking, "resolve_wordlists", lambda **kw: [p])
    monkeypatch.setattr(hashes, "which", lambda name: "/usr/bin/hashcat")
    ctx = ToolContext(input=p, workdir=tmp_path / "w")
    monkeypatch.setattr(ctx, "run", fake_run)
    r = HashesAnalyzer().run(ctx)
    assert r.status == "done"
    assert DUMP in r.output and "Password123!" in r.output
    assert any("-m" in c and "1000" in c for c in calls)


def test_md5_password_is_cracked(monkeypatch, tmp_path):
    p = tmp_path / "hash.txt"
    p.write_text(f"md5: {MD5_PASSWORD}\n")

    def fake_run(cmd, timeout=300, **_kw):
        if "--show" in cmd:
            return subprocess.CompletedProcess(cmd, 0, f"{MD5_PASSWORD}:password\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(hashes.cracking, "resolve_wordlists", lambda **kw: [p])
    monkeypatch.setattr(hashes, "which", lambda name: "/usr/bin/hashcat")
    ctx = ToolContext(input=p, workdir=tmp_path / "w")
    monkeypatch.setattr(ctx, "run", fake_run)
    r = HashesAnalyzer().run(ctx)
    assert r.status == "done"
    line = [ln for ln in r.output.splitlines() if MD5_PASSWORD in ln][0]
    assert line.endswith("password")


def test_no_hashcat_still_lists_the_hash_as_not_found(monkeypatch, tmp_path):
    p = tmp_path / "hash.txt"
    p.write_text(f"{SHA1}\n")
    monkeypatch.setattr(hashes, "which", lambda name: None)
    r = HashesAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "done" and "non trovata" in r.output


def test_the_total_budget_stops_the_runs(monkeypatch, tmp_path):
    p = tmp_path / "many.txt"
    p.write_text("\n".join([MD5_PASSWORD, SHA1]) + "\n")
    runs = []

    def fake_run(cmd, timeout=300, **_kw):
        runs.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    clock = iter([0.0, 0.0] + [10_000.0] * 100)
    monkeypatch.setattr(hashes, "_clock", lambda: next(clock))
    monkeypatch.setattr(hashes.cracking, "resolve_wordlists", lambda **kw: [p])
    monkeypatch.setattr(hashes, "which", lambda name: "/usr/bin/hashcat")
    ctx = ToolContext(input=p, workdir=tmp_path / "w")
    monkeypatch.setattr(ctx, "run", fake_run)
    r = HashesAnalyzer().run(ctx)
    assert r.status == "done"
    # deadline (60 s) is spent by the first hashcat call: the later modes never run
    assert len([c for c in runs if "--show" not in c]) == 1
    assert r.output.count("non trovata") == 2
