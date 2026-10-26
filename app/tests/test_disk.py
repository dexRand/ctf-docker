"""Disk-image analyzer: fls line parsing and file prioritisation (no tool needed)."""
from __future__ import annotations

from backend.analyzers.disk import _FLS_RE, _score


def _parse(lines):
    out = []
    for line in lines:
        m = _FLS_RE.match(line.strip())
        if m and m.group(1) == "r":
            out.append((int(m.group(3)), m.group(4).strip()))
    return out


def test_fls_regular_files_and_paths():
    files = _parse([
        "d/d 11:\t/lost+found",
        "r/r 12:\t/flag.txt",
        "r/r * 13:\t/root/flag.txt",     # deleted entry
        "r/r 14:\t/etc/passwd",
    ])
    assert (12, "/flag.txt") in files
    assert (13, "/root/flag.txt") in files        # deleted file is still recoverable
    assert all(p != "/lost+found" for _i, p in files)


def test_flag_names_are_prioritised():
    assert _score("/root/flag.txt") > _score("/etc/passwd")
    assert _score("/root/root.txt") > _score("/var/log/messages")
