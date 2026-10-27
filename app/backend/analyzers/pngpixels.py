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
from .util import bits_to_bytes, is_printable

_MAX_PIXELS = 5_000_000
_MAX_VALUES = 16


class PngPixelsAnalyzer(Analyzer):
    name = "png-pixels"
    category = "steg"
    description = "Decode data hidden in low-bit-depth / palette PNG pixel values."
    accepts = (".png", "image/png")
    display_order = 333

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
            dec = bits_to_bytes(bits)
            if is_printable(dec) and dec.strip():
                results.append(f"[pixel-values msb] {dec.decode('latin-1', 'replace')[:4000]}")
                break
        if im.mode == "P":   # palette indices as raw bytes
            raw = bytes(int(p) & 0xFF for p in px)
            if is_printable(raw) and raw.strip():
                results.append(f"[palette-index bytes] {raw.decode('latin-1', 'replace')[:4000]}")
        if not results:
            return ToolResult(self.name, status="skipped", summary="no printable decode")
        return ToolResult(self.name, status="done", summary=f"{len(results)} decode(s)",
                          output="\n".join(results)[:60_000])


register(PngPixelsAnalyzer())
