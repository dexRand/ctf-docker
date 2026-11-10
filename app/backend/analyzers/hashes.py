"""Bare hashes in text files: identify them and try the small wordlists.

Reversing/forensics challenges often hand over a file with a naked hash (a
config dump, a `secretsdump.py` output, a bcrypt row). The hash is recognised
by shape, the right hashcat mode is chosen and the small wordlists are tried
under **one** 60 s deadline for the whole file — a text with 50 hashes must not
turn into 50 full cracking sessions (issue #16).
"""
from __future__ import annotations

import re
import time
from pathlib import Path

from .. import cracking
from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register
from .util import TEXT_EXT, load_text

MAX_HASHES = 50
_BUDGET = 60                       # seconds of hashcat, for the whole file
_clock = time.monotonic            # monkeypatched by the budget test

# hashcat modes
MODE_MD5, MODE_NTLM, MODE_SHA1, MODE_SHA256 = 0, 1000, 100, 1400
MODE_BCRYPT, MODE_MD5CRYPT, MODE_SHA256CRYPT, MODE_SHA512CRYPT = 3200, 500, 7400, 1800
_MODE_ORDER = (MODE_MD5, MODE_NTLM, MODE_SHA1, MODE_SHA256,
               MODE_BCRYPT, MODE_MD5CRYPT, MODE_SHA256CRYPT, MODE_SHA512CRYPT)

# one regex per shape; the hex one tries 64 first so a SHA256 is never cut down
# to a 32/40-character "hash" and a 128-char run is not a hash at all
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}"
                  r"|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
_BCRYPT = re.compile(r"\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}")
_CRYPT = re.compile(r"\$(?:1|5|6)\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{22,86}")
# anchored at the start of a token and length-capped: without them a long
# colon-free run (a 141 KB `psimage` line) makes `[^\s:]+` rescan the rest of
# the line from every character (O(n²), the analysis hangs instead of skipping)
_DUMP = re.compile(r"(?<![^\s:])([^\s:]{1,64}):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::")
_MIN_DISTINCT = 6                  # a hash is high entropy: "ffff..." is ASCII art


def _hex_item(value: str) -> tuple[str, tuple[int, ...]] | None:
    if len(set(value)) < _MIN_DISTINCT:
        return None                # a run of one digit/letter, not a hash
    if len(value) == 32:                       # MD5 or NTLM: try both modes
        return "md5/ntlm", (MODE_MD5, MODE_NTLM)
    if len(value) == 40:
        return "sha1", (MODE_SHA1,)
    if len(value) == 64:
        return "sha256", (MODE_SHA256,)
    return None


def find_hashes(text: str, limit: int = MAX_HASHES) -> list[tuple[str, str, tuple[int, ...]]]:
    """(printed value, kind, hashcat modes) for up to `limit` distinct hashes."""
    found: list[tuple[str, str, tuple[int, ...]]] = []
    seen: set[str] = set()
    spent: list[tuple[int, int]] = []           # spans already claimed by a dump

    def add(value: str, kind: str, modes: tuple[int, ...]) -> None:
        if value in seen or len(found) >= limit:
            return
        seen.add(value)
        found.append((value, kind, modes))

    for m in _DUMP.finditer(text):              # user:rid:lm:nt::: (secretsdump)
        add(m.group(0), "ntlm (dump)", (MODE_NTLM,))
        spent.append(m.span())
    for m in _CRYPT.finditer(text):
        value = m.group(0)
        kind = {1: "md5crypt", 5: "sha256crypt", 6: "sha512crypt"}[int(value[1])]
        mode = {1: MODE_MD5CRYPT, 5: MODE_SHA256CRYPT, 6: MODE_SHA512CRYPT}[int(value[1])]
        add(value, kind, (mode,))
        spent.append(m.span())
    for m in _BCRYPT.finditer(text):
        add(m.group(0), "bcrypt", (MODE_BCRYPT,))
        spent.append(m.span())
    for m in _HEX.finditer(text):
        if any(a <= m.start() < b for a, b in spent):
            continue                            # part of a secretsdump line
        item = _hex_item(m.group(0))
        if item:
            kind, modes = item
            add(m.group(0), kind, modes)
        if len(found) >= limit:
            break
    return found


def _value_of(display: str, kind: str) -> str:
    """The part hashcat must crack: the NT hash of a secretsdump line."""
    if kind == "ntlm (dump)":
        return display.split(":")[3]
    return display


def _modes_groups(items):
    groups: dict[int, list[tuple[int, str]]] = {}
    for index, (display, kind, modes) in enumerate(items):
        value = _value_of(display, kind)
        for mode in modes:
            groups.setdefault(mode, []).append((index, value))
    return groups


def _combined_wordlist(wordlists, outdir: Path) -> Path | None:
    """One file with every small list: one hashcat start per mode instead of one
    per list (the startup dominates on 100 KB lists)."""
    dest = outdir / "wordlists.txt"
    total = 0
    with open(dest, "wb") as out:
        for wl in wordlists:
            try:
                with open(wl, "rb") as fh:
                    data = fh.read((8 << 20) + 1)
            except OSError:
                continue
            if total + len(data) > 8 << 20:
                break
            out.write(data if data.endswith(b"\n") else data + b"\n")
            total += len(data)
    return dest if total else None


def _show_found(show: str, members: list[tuple[int, str]]) -> dict[int, str]:
    """`hash:password` lines -> {item index: password} (exact hash only)."""
    by_value: dict[str, list[int]] = {}
    for index, value in members:
        by_value.setdefault(value.lower(), []).append(index)
    out: dict[int, str] = {}
    for line in (show or "").splitlines():
        value, sep, password = line.partition(":")
        if not sep or not password:
            continue
        for index in by_value.get(value.strip().lower(), []):
            out.setdefault(index, password)
    return out


class HashesAnalyzer(Analyzer):
    name = "hashes"
    category = "crypto"
    description = "Find bare hashes in a text file (MD5/NTLM, SHA1/256, bcrypt, crypt, secretsdump) and crack them."
    accepts = TEXT_EXT
    display_order = 132

    def run(self, ctx: ToolContext) -> ToolResult:
        text, err = load_text(self.name, ctx.input)
        if err:
            return err
        items = find_hashes(text)
        if not items:
            return ToolResult(self.name, status="skipped", summary="no hash found")
        outdir = ctx.sub(self.name)
        solved = self._crack(ctx, items, outdir)
        lines = [f"{display}  {kind}  {solved.get(i, 'non trovata')}"
                 for i, (display, kind, _modes) in enumerate(items)]
        artifacts = [{"name": p.name, "path": str(p), "size": p.stat().st_size}
                     for p in sorted(outdir.glob("mode*.txt"))]
        return ToolResult(self.name, status="done",
                          summary=f"{len(items)} hash(es), {len(solved)} cracked",
                          output="\n".join(lines)[:200_000], artifacts=artifacts)

    @staticmethod
    def _crack(ctx: ToolContext, items, outdir: Path) -> dict[int, str]:
        """One hashcat run per (mode, wordlist), all hashes of the mode inside;
        a single deadline covers every mode and wordlist."""
        solved: dict[int, str] = {}
        if not which("hashcat"):
            return solved
        wordlists = [p for p in cracking.resolve_wordlists(
            max_bytes=cracking.AUTO_CRACK_MAX_BYTES) if p.is_file()]
        if not wordlists:
            return solved
        wordlists.sort(key=lambda p: p.stat().st_size)
        combined = _combined_wordlist(wordlists, outdir)
        if combined is None:
            return solved
        deadline = _clock() + _BUDGET
        groups = _modes_groups(items)
        for mode in _MODE_ORDER:
            members = [(i, v) for i, v in groups.get(mode, []) if i not in solved]
            if not members:
                continue
            left = int(deadline - _clock())
            if left <= 0:
                return solved
            hashfile = outdir / f"mode{mode}.txt"
            hashfile.write_text("\n".join(v for _i, v in members) + "\n")
            pot = outdir / f"mode{mode}.pot"
            ctx.run(cracking.hashcat_args(mode, str(hashfile), wordlist=str(combined),
                                          potfile=str(pot), runtime=left),
                    timeout=left + 60)
            show = ctx.run(["hashcat", "-m", str(mode), str(hashfile),
                            "--potfile-path", str(pot), "--show", "--quiet"],
                           timeout=60)
            solved.update(_show_found(show.stdout or "", members))
            if len(solved) == len(items):
                return solved
        return solved


register(HashesAnalyzer())
