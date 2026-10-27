"""Flag bits hidden in the LSB of the raw file bytes.

Classic "Investigative Reversing" scheme: a binary reads the flag, offsets each
character by a constant, and writes its 8 bits into the LSB of consecutive file
bytes starting at some offset, least-significant bit first. Offset, bit order and
constant are unknown, so instead of brute-forcing every start position we search
the LSB bit string for the bit encoding of a known flag prefix under each
candidate order/shift, then decode forward from there.
"""
from __future__ import annotations

from ..flagpatterns import FLAG_PREFIXES
from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import IMG_EXT, bits_to_ints

# every known prefix, both cases (the bit search is case-sensitive)
_PREFIXES = [p + "{" for p in FLAG_PREFIXES] + [p.upper() + "{" for p in FLAG_PREFIXES]
_MAX_BYTES = 8_000_000


def _char_bits(v: int, lsb_first: bool) -> str:
    v &= 0xFF
    order = range(8) if lsb_first else range(7, -1, -1)
    return "".join("1" if (v >> i) & 1 else "0" for i in order)


def _decode(bits, start: int, lsb_first: bool, shift: int, cap: int = 400) -> str:
    """Decode up to `cap` chars from bit `start` (numpy: millions of bits)."""
    seg = bits[start:start + 8 * cap]
    n = len(seg) // 8
    if not n:
        return ""
    rows = seg[:n * 8].reshape(n, 8)
    if lsb_first:
        rows = rows[:, ::-1]                  # bit 0 first in each character
    out: list[str] = []
    for v in bits_to_ints(rows.reshape(-1).copy(), 8):
        ch = chr((v + shift) & 0xFF)
        out.append(ch)
        if ch == "}":
            break
    return "".join(out)


def find_lsb_flags(raw: bytes) -> list[str]:
    import numpy as np
    bits = np.frombuffer(raw, dtype=np.uint8) & 1      # the LSB plane, as 0/1
    as_text = (bits + 48).tobytes()                    # b"0101..." for the search
    found: list[str] = []
    seen: set[str] = set()
    for lsb_first in (True, False):
        for shift in range(32):
            for pre in _PREFIXES:
                enc = "".join(_char_bits((ord(c) - shift) & 0xFF, lsb_first) for c in pre)
                start = as_text.find(enc.encode())
                if start == -1:
                    continue
                text = _decode(bits, start, lsb_first, shift)
                if text.startswith(pre) and "}" in text and text not in seen:
                    seen.add(text)
                    found.append(text)
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
