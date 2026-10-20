"""Zero-width and trailing-whitespace steganography.

Two classic "invisible text" tricks we did not cover:
- zero-width characters (U+200B ZWSP / U+200C ZWNJ / U+200D ZWJ / U+FEFF …) used
  as the two symbols of a binary stream hidden inside otherwise normal text;
- trailing spaces/tabs at the end of each line (space = 0, tab = 1).

Both decode to bytes, which we emit so the flag hunt scans them.
"""
from __future__ import annotations

from collections import Counter

from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import TEXT_EXT, bits_to_bytes, is_printable

_ZW = ("\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u00ad", "\u180e")
_MAX_OUT = 50_000


class ZeroWidthAnalyzer(Analyzer):
    name = "zero-width"
    category = "steg"
    description = "Decode zero-width (ZWSP/ZWNJ/ZWJ) and trailing-whitespace stego."
    accepts = TEXT_EXT + ("text/",)
    display_order = 128

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            data = ctx.input.read_bytes()
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        text = data.decode("utf-8", "replace")
        out: list[str] = []

        seq = [c for c in text if c in _ZW]
        if len(seq) >= 16:
            # the two most frequent symbols are the bits; a 3rd char is usually a
            # separator (ignored). Try both 0/1 assignments and 8/7-bit widths.
            order = [c for c, _ in Counter(seq).most_common(3)]
            if len(order) >= 2:
                decodes: list[str] = []
                for zero, one in ((order[0], order[1]), (order[1], order[0])):
                    bits = [0 if c == zero else 1 for c in seq if c in (zero, one)]
                    for width in (8, 7):
                        dec = bits_to_bytes(bits, width).decode("latin-1", "replace")
                        if is_printable(dec.encode("latin-1")) and dec not in decodes:
                            decodes.append(dec)
                for dec in decodes:
                    out.append(f"[zero-width {len(seq)} chars] " + dec[:_MAX_OUT])

        tw: list[int] = []
        for line in text.split("\n"):
            for ch in line[len(line.rstrip(" \t")):]:
                tw.append(0 if ch == " " else 1)
        if len(tw) >= 16:
            dec = bits_to_bytes(tw)
            if is_printable(dec):
                out.append(f"[trailing-whitespace {len(tw)} bits] "
                           + dec.decode("latin-1", "replace")[:_MAX_OUT])

        if not out:
            return ToolResult(self.name, status="skipped", summary="no zero-width/whitespace stego")
        return ToolResult(self.name, status="done", summary=f"{len(out)} decode(s)",
                          output="\n".join(out)[:_MAX_OUT + 10_000])


register(ZeroWidthAnalyzer())
