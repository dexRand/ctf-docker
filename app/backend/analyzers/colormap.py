"""Few-colour images: AperiSolve-style "colour map" reveal.

When a picture has only a handful of distinct colours, the structure hidden in
them (a QR painted with two near-identical colours, a gradient-encoded message,
a palette whose indices matter) disappears visually. This maps every distinct
colour to a clearly different one — and to its **index** as grey — so the
pipeline's OCR/QR/stego tools see the structure again.
"""
from __future__ import annotations

import colorsys

from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import IMG_EXT, load_image

MAX_PIXELS = 4_000_000      # heavy per-pixel work only on challenge-sized images
MAX_COLOURS = 64            # more than this is a photo, not a palette
MIN_SIDE = 16


class ColorMapAnalyzer(Analyzer):
    name = "color-map"
    category = "steg"
    description = "Few-colour image: map each distinct colour to a distinct one and to its index (grey)."
    accepts = IMG_EXT
    display_order = 357

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            import numpy as np
            from PIL import Image
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"PIL/numpy missing: {exc}")
        img, err = load_image(self.name, ctx.input, "RGB")
        if err:
            return err
        w, h = img.size
        if w * h > MAX_PIXELS or min(w, h) < MIN_SIDE:
            return ToolResult(self.name, status="skipped", summary="image too big/small")
        colours = img.getcolors(maxcolors=MAX_COLOURS + 1)
        if colours is None:
            return ToolResult(self.name, status="skipped",
                              summary=f"more than {MAX_COLOURS} colours")
        if len(colours) < 2:
            return ToolResult(self.name, status="skipped", summary="single colour")
        # stable order: by luminance, so the index images are reproducible
        palette = sorted((c for _, c in colours),
                         key=lambda c: c[0] * 299 + c[1] * 587 + c[2] * 114)
        arr = np.asarray(img)
        packed = ((arr[:, :, 0].astype(np.int32) << 16)
                  | (arr[:, :, 1].astype(np.int32) << 8) | arr[:, :, 2])
        keys = np.array([(c[0] << 16) | (c[1] << 8) | c[2] for c in palette], dtype=np.int32)
        # searchsorted needs numerically sorted keys: look up there, then map the
        # position back to the luminance order of `palette`
        order = np.argsort(keys)
        pos = np.clip(np.searchsorted(keys[order], packed), 0, len(keys) - 1)
        idx = order[pos].astype(np.uint8)
        outdir = ctx.sub(self.name)
        n = len(palette)
        produced = []
        # 1) index as grey: reveals the structure of a palette-index stego
        grey = (idx.astype(np.float32) * (255.0 / max(1, n - 1))).astype(np.uint8)
        gpath = outdir / f"{ctx.input.stem}_index-grey.png"
        Image.fromarray(grey).save(gpath)
        produced.append(gpath)
        # 2) a distinct, deterministic colour per index (hue wheel)
        lut = np.zeros((n, 3), np.uint8)
        for i in range(n):
            r, g, b = colorsys.hsv_to_rgb(i / max(1, n), 1.0, 1.0)
            lut[i] = (int(r * 255), int(g * 255), int(b * 255))
        cpath = outdir / f"{ctx.input.stem}_color-map.png"
        Image.fromarray(lut[idx]).save(cpath)
        produced.append(cpath)
        # NB: the variants are *artifacts*, not children: the index image still
        # has ≤64 colours, so handing it back to the pipeline would run this same
        # analyzer on it again and double the tree at every depth.
        text = [f"{n} colours: " + ", ".join("#%02x%02x%02x" % c for c in palette[:40])]
        for path in produced:
            text.append(f"== {path.stem} ==")
            found = self._ocr(path)
            if found:
                text.append(found[:4000])
            qr = self._zbar(path)
            if qr:
                text.append("QR: " + qr[:1000])
        return ToolResult(self.name, status="done",
                          summary=f"{n} colours mapped",
                          output="\n".join(text)[:200_000],
                          artifacts=[{"name": p.name, "path": str(p),
                                      "size": p.stat().st_size} for p in produced])

    @staticmethod
    def _ocr(path) -> str:
        """OCR a variant (plus the usual OCR-confusion variants)."""
        try:
            from .vision import _confusable_variants, ocr_image
            text = ocr_image(path, timeout=60, thorough=False, max_dim=1600)
            variants = _confusable_variants(text)
            return (text + "\n" + variants).strip() if variants else text
        except Exception:
            return ""

    @staticmethod
    def _zbar(path) -> str:
        """A QR painted with near-identical colours decodes once they are split."""
        try:
            from .base import run_cmd, which
            if not which("zbarimg"):
                return ""
            proc = run_cmd(["zbarimg", "--quiet", "--raw", str(path)], timeout=60)
            return (proc.stdout or "").strip()
        except Exception:
            return ""


register(ColorMapAnalyzer())
