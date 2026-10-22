"""Zero-width and trailing-whitespace steganography.

Two classic "invisible text" tricks we did not cover:
- zero-width characters (U+200B ZWSP / U+200C ZWNJ / U+200D ZWJ / U+FEFF …) used
  as the two symbols of a binary stream hidden inside otherwise normal text;
- trailing spaces/tabs at the end of each line (space = 0, tab = 1).

Both decode to bytes, which we emit so the flag hunt scans them.
"""
from __future__ import annotations

import re
from collections import Counter

from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import TEXT_EXT, bits_to_bytes, is_printable

_ZW = ("\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u00ad", "\u180e")
_ZW_RE = re.compile("[" + "".join(_ZW) + "]")
_TRAIL_RE = re.compile(r"[ \t]+(?=\r?\n|$)")
_MAX_OUT = 50_000


def _decode_two_symbols(seq: list[str]) -> list[str]:
    """The two most frequent symbols are the bits (a 3rd one is usually a
    separator, ignored). Both 0/1 assignments, 8- and 7-bit; printable only."""
    order = [c for c, _ in Counter(seq).most_common(3)]
    if len(order) < 2:
        return []
    decodes: list[str] = []
    for zero, one in ((order[0], order[1]), (order[1], order[0])):
        bits = [0 if c == zero else 1 for c in seq if c in (zero, one)]
        for width in (8, 7):
            dec = bits_to_bytes(bits, width).decode("latin-1", "replace")
            if is_printable(dec.encode("latin-1")) and dec not in decodes:
                decodes.append(dec[:_MAX_OUT])
    return decodes


class ZeroWidthAnalyzer(Analyzer):
    name = "zero-width"
    category = "steg"
    description = "Decode zero-width (ZWSP/ZWNJ/ZWJ), two-symbol whitespace and trailing-whitespace stego."
    accepts = TEXT_EXT + ("text/",)
    display_order = 128

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            data = ctx.input.read_bytes()
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        text = data.decode("utf-8", "replace")
        out: list[str] = []

        seq = _ZW_RE.findall(text)
        if len(seq) >= 16:
            out += [f"[zero-width {len(seq)} chars] " + d for d in _decode_two_symbols(seq)]

        # a whole text written with two symbols only (e.g. em-space / space,
        # picoCTF "WhitePages"): the symbols are the bits. Count at C speed and
        # build the list only when the condition holds (logs are 20 MB).
        counts = Counter(text.replace("\r", "").replace("\n", ""))
        body_len = sum(counts.values())
        top = counts.most_common(3)
        if body_len >= 64 and len(top) >= 2 and top[0][1] + top[1][1] >= 0.98 * body_len:
            body = [c for c in text if c not in "\r\n"]
            pair = f"U+{ord(top[0][0]):04X}/U+{ord(top[1][0]):04X}"
            out += [f"[two-symbol {pair} {len(body)} chars] " + d
                    for d in _decode_two_symbols(body)]

        tw: list[int] = [0 if ch == " " else 1
                         for match in _TRAIL_RE.findall(text) for ch in match]
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
