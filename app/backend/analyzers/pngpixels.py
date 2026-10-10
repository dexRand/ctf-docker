"""Low-bit-depth / palette PNG stego.

When an image uses very few distinct pixel values (1-bit B/W, a small grayscale
range, or a tiny palette), the pixel values themselves — not just their LSBs — can
carry a bit stream. We map the values to bits and decode; for palette images we
also try the raw index bytes.
"""
from __future__ import annotations

from collections import Counter

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

_MAX_PIXELS = 5_000_000
_MAX_VALUES = 16


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


class PngPixelsAnalyzer(Analyzer):
    name = "png-pixels"
    category = "stego"
    description = "Decode data hidden in low-bit-depth / palette PNG pixel values."
    accepts = (".png", "image/png")
    display_order = 274

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            from PIL import Image
        except Exception:  # noqa: BLE001
            return ToolResult(self.name, status="skipped", summary="Pillow not installed")
        try:
            im = Image.open(ctx.input)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(self.name, status="error", summary=f"cannot open: {exc}")
        if im.width * im.height > _MAX_PIXELS or im.mode not in ("1", "L", "P", "I;16"):
            return ToolResult(self.name, status="skipped", summary=f"mode {im.mode} not low-bit-depth")
        px = list(im.getdata())
        counts = Counter(px)
        if not (2 <= len(counts) <= _MAX_VALUES):
            return ToolResult(self.name, status="skipped", summary=f"{len(counts)} distinct value(s)")

        results: list[str] = []
        order = [v for v, _ in counts.most_common()]
        for zero, one in ((order[0], order[1]), (order[1], order[0])):
            bits = [0 if p == zero else 1 for p in px if p in (zero, one)]
            dec = _bytes_from_bits(bits)
            if _printable(dec) and dec.strip():
                results.append(f"[pixel-values msb] {dec.decode('latin-1', 'replace')[:4000]}")
                break
        if im.mode == "P":   # palette indices as raw bytes
            raw = bytes(int(p) & 0xFF for p in px)
            if _printable(raw) and raw.strip():
                results.append(f"[palette-index bytes] {raw.decode('latin-1', 'replace')[:4000]}")
        if not results:
            return ToolResult(self.name, status="skipped", summary="no printable decode")
        return ToolResult(self.name, status="done", summary=f"{len(results)} decode(s)",
                          output="\n".join(results)[:60_000])


register(PngPixelsAnalyzer())
