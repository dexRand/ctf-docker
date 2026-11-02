"""macOS .DS_Store: the names of the files a folder held, even deleted ones.

Finder keeps one record per file (name in UTF-16BE + a 4-char code + a type).
`Iloc` records carry the icon position, i.e. the order the files were shown in:
a flag split across several (often base64) file names is rebuilt in that order
(TJCTF 2025 "footprint").
"""
from __future__ import annotations

import base64
import binascii
import re
import struct

from ..flagpatterns import FLAG_PREFIXES
from .base import Analyzer, ToolContext, ToolResult
from .registry import register

MAGIC = b"\x00\x00\x00\x01Bud1"
_PREFIX = re.compile(r"(?i)(" + "|".join(re.escape(p) for p in FLAG_PREFIXES) + r")\{")
_MAX = 8 << 20                    # a .DS_Store is a few KB; never read more
# uint32 name length (chars), the UTF-16BE name, then the record code
_RECORD = re.compile(rb"\x00\x00\x00([\x01-\x7f])((?:\x00[\x20-\x7e]|[\x01-\xff][\x00-\xff])+?)"
                     rb"([A-Za-z]{4})(blob|bool|long|shor|type|ustr|comp|dutc)")


def records(data: bytes) -> list[tuple[str, str, bytes]]:
    """(file name, record code, raw data after the type) for each record."""
    out = []
    for m in _RECORD.finditer(data):
        n, raw = m.group(1)[0], m.group(2)
        if len(raw) != 2 * n:
            continue
        try:
            name = raw.decode("utf-16-be")
        except UnicodeDecodeError:
            continue
        out.append((name, m.group(3).decode(), data[m.end():m.end() + 64]))
    return out


def icon_order(recs: list[tuple[str, str, bytes]]) -> list[str]:
    """File names sorted by icon position (Iloc: y then x); the rest after."""
    pos: dict[str, tuple[int, int]] = {}
    for name, code, rest in recs:
        if code == "Iloc" and len(rest) >= 12 and name not in pos:
            _blen, x, y = struct.unpack(">III", rest[:12])
            pos[name] = (y, x)
    names = list(dict.fromkeys(n for n, _c, _r in recs if n.strip() and n not in (".", "@")))
    return sorted((n for n in names if n in pos), key=lambda n: pos[n]) \
        + [n for n in names if n not in pos]


def _b64(name: str) -> str | None:
    if len(name) < 4 or not re.fullmatch(r"[A-Za-z0-9_\-+/=]+", name):
        return None
    try:
        raw = base64.urlsafe_b64decode(name.replace("+", "-").replace("/", "_")
                                       + "=" * (-len(name) % 4))
    except (binascii.Error, ValueError):
        return None
    if not raw or sum(32 <= b < 127 for b in raw) < 0.9 * len(raw):
        return None                      # random ids (base64 of 16 bytes) are not text
    return raw.decode("ascii", "replace")


def rebuild_flag(pieces: list[str]) -> str | None:
    """Start at the piece holding `prefix{`, then take the other pieces in
    order (wrapping around) until one closes the brace."""
    for i, piece in enumerate(pieces):
        m = _PREFIX.search(piece)
        if not m:
            continue
        flag = piece[m.start():]
        for nxt in pieces[i + 1:] + pieces[:i]:
            if "}" in flag:
                break
            flag += nxt
        if "}" in flag:
            return flag[:flag.index("}") + 1]
    return None


class DsStoreAnalyzer(Analyzer):
    name = "ds-store"
    category = "forensics"
    description = "macOS .DS_Store: file names (deleted files too) in icon order, base64 names decoded."
    accepts = ("ds_store", "application/x-apple-ds-store")
    display_order = 166

    def run(self, ctx: ToolContext) -> ToolResult:
        with open(ctx.input, "rb") as fh:
            data = fh.read(_MAX)
        if not data.startswith(MAGIC):
            return ToolResult(self.name, status="skipped", summary="not a .DS_Store (no Bud1)")
        names = icon_order(records(data))
        if not names:
            return ToolResult(self.name, status="skipped", summary="no file records")
        decoded = [(n, _b64(n)) for n in names]
        lines = [f"{n}" + (f"  -> {d!r}" if d else "") for n, d in decoded]
        pieces = [d.strip() for _n, d in decoded if d and d.strip()]
        out = "\n".join(lines)
        if pieces:
            out += "\n\n[base64 names joined in icon order]\n" + "".join(pieces)
            flag = rebuild_flag(pieces)
            if flag:
                out += "\n[flag rebuilt from the name pieces]\n" + flag
        joined = bool(pieces)
        return ToolResult(self.name, status="done",
                          summary=f"{len(names)} file name(s)"
                                  + (f", {sum(1 for _n, d in decoded if d)} base64" if joined else ""),
                          output=out)


register(DsStoreAnalyzer())
