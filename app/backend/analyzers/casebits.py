"""Case-based stego: the message is encoded in the letter case (upper/lower).

Two common variants:
- binary: uppercase/lowercase letters are the bits of an 8-bit stream;
- Bacon's cipher: 5-bit groups (A=0 … Z=25).

We extract the case sequence of every letter and decode both ways.
"""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

TEXT_EXT = (".txt", ".md", ".html", ".htm", ".js", ".py", ".c", ".csv", ".log",
            ".xml", ".yaml", ".yml", ".srt", ".vtt")
_BACON = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_MIN_LETTERS = 32


def _bytes_from_bits(bits: list[int], width: int = 8) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - len(bits) % width, width):
        val = 0
        for b in bits[i:i + width]:
            val = (val << 1) | b
        out.append(val & 0xFF)
    return bytes(out)


def _printable(blob: bytes) -> bool:
    if not blob:
        return False
    good = sum(1 for c in blob if 32 <= c < 127 or c in (9, 10, 13))
    return good / len(blob) >= 0.90


def _bacon(bits: list[int]) -> str:
    out = []
    for i in range(0, len(bits) - len(bits) % 5, 5):
        val = 0
        for b in bits[i:i + 5]:
            val = (val << 1) | b
        out.append(_BACON[val] if val < 26 else "?")
    return "".join(out)


class CaseBitsAnalyzer(Analyzer):
    name = "case-bits"
    category = "stego"
    description = "Decode data hidden in the letter case (upper/lower bits, Bacon)."
    accepts = TEXT_EXT + ("text/",)
    display_order = 130

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            data = ctx.input.read_bytes()
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        text = data.decode("utf-8", "replace")
        letters = [c for c in text if c.isalpha() and (c.isupper() or c.islower())]
        if len(letters) < _MIN_LETTERS:
            return ToolResult(self.name, status="skipped", summary="too few letters")
        results: list[str] = []
        for tag, bits in (("upper=1", [1 if c.isupper() else 0 for c in letters]),
                          ("lower=1", [0 if c.isupper() else 1 for c in letters])):
            raw = _bytes_from_bits(bits)
            if _printable(raw):
                dec = raw.decode("latin-1", "replace")
                if dec.strip():
                    results.append(f"[case {tag} / 8-bit] {dec[:4000]}")
            bacon = _bacon(bits)
            if len(bacon) >= 8:
                results.append(f"[case {tag} / Bacon 5-bit] {bacon[:4000]}")
        if not results:
            return ToolResult(self.name, status="skipped", summary="nothing printable")
        return ToolResult(self.name, status="done", summary=f"{len(results)} decode(s)",
                          output="\n".join(results)[:60_000])


register(CaseBitsAnalyzer())
