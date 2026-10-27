"""Flag bits hidden in the LSB of the raw file bytes.

Classic "Investigative Reversing" scheme: a binary reads the flag, offsets each
character by a constant, and writes its 8 bits into the LSB of consecutive file
bytes starting at some offset, least-significant bit first. Offset, bit order and
constant are unknown.

The LSB plane is packed into characters for every bit offset and bit order, then
the search is done on the **differences between consecutive characters**: they do
not depend on the (unknown) additive constant, so one scan covers all 32 shifts
and the constant is recovered from the first character.
"""
from __future__ import annotations

from ..flagpatterns import FLAG_PREFIXES
from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import IMG_EXT

# every known prefix, both cases (the bit stream is case-sensitive)
_PREFIXES = [p + "{" for p in FLAG_PREFIXES] + [p.upper() + "{" for p in FLAG_PREFIXES]
_MAX_BYTES = 8_000_000
_MAX_HITS = 8               # occurrences tried per signature and stream


def _signatures() -> dict[bytes, list[tuple[str, bytes]]]:
    """Group prefixes by their shift-invariant difference signature."""
    groups: dict[bytes, list[tuple[str, bytes]]] = {}
    for pre in _PREFIXES:
        pb = pre.encode()
        sig = bytes((pb[i + 1] - pb[i]) & 0xFF for i in range(len(pb) - 1))
        groups.setdefault(sig, []).append((pre, pb))
    return groups


_SIGS: dict[bytes, list[tuple[str, bytes]]] = {}


def _decode(vals, start: int, shift: int, cap: int = 400) -> str:
    """Apply the character shift from `start` and read until the closing brace."""
    import numpy as np
    seg = vals[start:start + cap]
    if not seg.size:
        return ""
    chars = ((seg.astype(np.uint16) + shift) & 0xFF).astype(np.uint8)
    out: list[str] = []
    for v in chars.tolist():
        ch = chr(v)
        out.append(ch)
        if ch == "}":
            break
    return "".join(out)


def find_lsb_flags(raw: bytes) -> list[str]:
    import numpy as np

    if not _SIGS:
        _SIGS.update(_signatures())
    bits = (np.frombuffer(raw, dtype=np.uint8) & 1).astype(np.uint8)
    if bits.size < 8 * 16:
        return []
    weights = np.array([128, 64, 32, 16, 8, 4, 2, 1], dtype=np.uint16)
    found: list[str] = []
    seen: set[str] = set()
    for offset in range(8):                       # the flag may start mid-byte
        n = (bits.size - offset) // 8
        if n < 16:
            continue
        rows = bits[offset:offset + n * 8].reshape(n, 8)
        for lsb_first in (True, False):
            view = rows[:, ::-1] if lsb_first else rows
            vals = (view * weights).sum(axis=1).astype(np.uint8)
            deltas = (vals[1:] - vals[:-1]).tobytes()   # uint8: wraps mod 256
            for sig, prefixes in _SIGS.items():
                pos, hits = deltas.find(sig), 0
                while pos != -1 and hits < _MAX_HITS:
                    hits += 1
                    for pre, pb in prefixes:
                        shift = (pb[0] - int(vals[pos])) & 0xFF
                        text = _decode(vals, pos, shift)
                        if not text.startswith(pre) or "}" not in text:
                            continue
                        body = text[len(pre):-1]
                        # short prefixes (CTF{) have a weak signature: a few
                        # random hits per megabyte. A real body is printable.
                        if not body or not body.isprintable() or text in seen:
                            continue
                        seen.add(text)
                        found.append(text)
                    pos = deltas.find(sig, pos + 1)
    return found


class LsbBitsAnalyzer(Analyzer):
    name = "lsb-bits"
    category = "steg"
    description = "Flag bits in the LSB of the raw file bytes (unknown offset, bit order, shift)."
    accepts = IMG_EXT
    display_order = 339

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            raw = ctx.input.read_bytes()[:_MAX_BYTES]
        except OSError as exc:
            return ToolResult(self.name, status="skipped", summary=f"cannot read: {exc}")
        flags = find_lsb_flags(raw)
        if not flags:
            return ToolResult(self.name, status="skipped", summary="no LSB-encoded flag bits")
        return ToolResult(self.name, status="done",
                          summary=f"{len(flags)} flag(s) in raw-byte LSB",
                          output="\n".join(flags))


register(LsbBitsAnalyzer())
