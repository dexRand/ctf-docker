"""Case-based stego: the message is encoded in the letter case (upper/lower).

Two common variants:
- binary: uppercase/lowercase letters are the bits of an 8-bit stream;
- Bacon's cipher: 5-bit groups (A=0 … Z=25).

We extract the case sequence of every letter and decode both ways.
"""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import TEXT_EXT, bits_to_bytes, bits_to_ints, is_printable

_BACON = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_MIN_LETTERS = 32


def _bacon(bits: list[int]) -> str:
    return "".join(_BACON[v] if v < 26 else "?" for v in bits_to_ints(bits, 5))


class CaseBitsAnalyzer(Analyzer):
    name = "case-bits"
    category = "steg"
    description = "Decode data hidden in the letter case (upper/lower bits, Bacon)."
    accepts = TEXT_EXT + ("text/",)
    display_order = 130

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            data = ctx.input.read_bytes()
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        text = data.decode("utf-8", "replace")
        # a 20 MB log has millions of letters: extract them as UTF-8 bytes and
        # keep the case as a numpy bool array (the per-char loop was ~15s)
        try:
            import numpy as np
            arr = np.frombuffer(text.encode("utf-8", "ignore"), dtype=np.uint8)
            letters = arr[((arr >= 65) & (arr <= 90)) | ((arr >= 97) & (arr <= 122))]
            if letters.size < _MIN_LETTERS:
                return ToolResult(self.name, status="skipped", summary="too few letters")
            upper = letters < 97
            pairs = (("upper=1", upper), ("lower=1", ~upper))
        except Exception:
            letters_l = [c for c in text if c.isalpha() and (c.isupper() or c.islower())]
            if len(letters_l) < _MIN_LETTERS:
                return ToolResult(self.name, status="skipped", summary="too few letters")
            pairs = (("upper=1", [1 if c.isupper() else 0 for c in letters_l]),
                     ("lower=1", [0 if c.isupper() else 1 for c in letters_l]))
        results: list[str] = []
        for tag, bits in pairs:
            raw = bits_to_bytes(bits)
            if is_printable(raw):
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
