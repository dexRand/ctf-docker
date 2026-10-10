"""Unicode homoglyph stego.

Two things:
- *de-homoglyph*: text where Latin letters are swapped with look-alikes (Cyrillic
  "а/е/о", Greek "α/ο/ρ" …) — we map them back to Latin so the real flag becomes
  readable and findable;
- *bit stream*: Latin vs confusable letters can encode the bits of a message.
"""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

TEXT_EXT = (".txt", ".md", ".html", ".htm", ".js", ".py", ".c", ".csv", ".log",
            ".xml", ".yaml", ".yml", ".srt", ".vtt")

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


def _bytes_from_bits(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - len(bits) % 8, 8):
        val = 0
        for b in bits[i:i + 8]:
            val = (val << 1) | b
        out.append(val & 0xFF)
    return bytes(out)


def _printable(blob: bytes) -> bool:
    if not blob:
        return False
    good = sum(1 for c in blob if 32 <= c < 127 or c in (9, 10, 13))
    return good / len(blob) >= 0.90


class HomoglyphAnalyzer(Analyzer):
    name = "homoglyph"
    category = "stego"
    description = "De-homoglyph (Cyrillic/Greek look-alikes) and decode Latin/non-Latin bits."
    accepts = TEXT_EXT + ("text/",)
    display_order = 131

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            data = ctx.input.read_bytes()
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        text = data.decode("utf-8", "replace")
        hits = [c for c in text if c in _CONFUSABLES]
        if len(hits) < _MIN_HITS:
            return ToolResult(self.name, status="skipped", summary="no homoglyphs")

        cleaned = "".join(_CONFUSABLES.get(c, c) for c in text)
        results = [f"[de-homoglyph {len(hits)} chars] " + cleaned[:4000]]

        # bits: ASCII Latin letter = 0, confusable (look-alike) letter = 1
        bits: list[int] = []
        for c in text:
            if c in _CONFUSABLES:
                bits.append(1)
            elif c.isascii() and c.isalpha():
                bits.append(0)
        if len(bits) >= 64:
            for inv in (False, True):
                b2 = [1 - b for b in bits] if inv else bits
                dec = _bytes_from_bits(b2)
                if _printable(dec) and dec.strip():
                    results.append(f"[homoglyph bits{' (inv)' if inv else ''}] "
                                   + dec.decode("latin-1", "replace")[:4000])
        return ToolResult(self.name, status="done", summary=f"{len(hits)} homoglyph(s)",
                          output="\n".join(results)[:60_000])


register(HomoglyphAnalyzer())
