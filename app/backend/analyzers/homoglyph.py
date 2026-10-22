"""Unicode homoglyph stego.

Two things:
- *de-homoglyph*: text where Latin letters are swapped with look-alikes (Cyrillic
  "а/е/о", Greek "α/ο/ρ" …) — we map them back to Latin so the real flag becomes
  readable and findable;
- *bit stream*: Latin vs confusable letters can encode the bits of a message.
"""
from __future__ import annotations

import re

from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import TEXT_EXT, bits_to_bytes, is_printable


_CONFUSABLES = {
    # Cyrillic → Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "м": "m", "т": "t", "н": "h", "к": "k", "в": "b", "ԁ": "d",
    "А": "A", "В": "B", "Е": "E", "І": "I", "Ј": "J", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S",
    # Greek → Latin
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ϲ": "c", "А": "A",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "Λ": "L", "Θ": "O",
}
_MIN_HITS = 6
_TRANS = str.maketrans(_CONFUSABLES)
_HIT_RE = re.compile("[" + "".join(re.escape(c) for c in _CONFUSABLES) + "]")
# keep only letters (ASCII + confusables), then map: confusable -> 1, ASCII -> 0
_BIT_KEEP_RE = re.compile("[^A-Za-z" + "".join(re.escape(c) for c in _CONFUSABLES) + "]")
_BIT_TRANS = str.maketrans({**{k: "1" for k in _CONFUSABLES},
                            **{chr(c): "0" for c in range(65, 91)},
                            **{chr(c): "0" for c in range(97, 123)}})


class HomoglyphAnalyzer(Analyzer):
    name = "homoglyph"
    category = "steg"
    description = "De-homoglyph (Cyrillic/Greek look-alikes) and decode Latin/non-Latin bits."
    accepts = TEXT_EXT + ("text/",)
    display_order = 131

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            data = ctx.input.read_bytes()
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        text = data.decode("utf-8", "replace")
        hits = _HIT_RE.findall(text)
        if len(hits) < _MIN_HITS:
            return ToolResult(self.name, status="skipped", summary="no homoglyphs")

        cleaned = text.translate(_TRANS)
        results = [f"[de-homoglyph {len(hits)} chars] " + cleaned[:4000]]

        # bits: ASCII Latin letter = 0, confusable (look-alike) letter = 1
        compact = _BIT_KEEP_RE.sub("", text).translate(_BIT_TRANS)
        try:
            import numpy as np
            bits = np.frombuffer(compact.encode("ascii", "ignore"), dtype=np.uint8) - 48
        except Exception:
            bits = [1 if c == "1" else 0 for c in compact]
        if len(bits) >= 64:
            for inv in (False, True):
                b2 = (1 - bits) if inv else bits
                dec = bits_to_bytes(b2)
                if is_printable(dec) and dec.strip():
                    results.append(f"[homoglyph bits{' (inv)' if inv else ''}] "
                                   + dec.decode("latin-1", "replace")[:4000])
        return ToolResult(self.name, status="done", summary=f"{len(hits)} homoglyph(s)",
                          output="\n".join(results)[:60_000])


register(HomoglyphAnalyzer())
