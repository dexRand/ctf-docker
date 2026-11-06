"""Low-contrast (semi-transparent) overlays: high-pass + amplify + OCR.

A flag drawn at 2-5% opacity is invisible in the picture and in a plain OCR
pass, but stands out once the image is compared with its blurred copy. The
enhanced images are kept as artifacts (one look in the GUI is usually enough)
and OCR is attempted on the whole picture and, for large photos, on four
overlapping quadrants — the text keeps its size, so downscaling is not allowed.
"""
from __future__ import annotations

import re

from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import IMG_EXT, load_image

MAX_PIXELS = 16_000_000       # a 16 MPix high-pass is still ~0.5 s
OCR_MAX = 1600                # whole-image OCR pass
_QUAD_OVERLAP = 160
_DEADLINE_S = 45

# a token that looks like a flag: "prefix{body}"
_TOKEN = re.compile(r"[A-Za-z0-9_]{2,24}\{[ -~]{2,180}\}")


def _high_pass(img, k: int = 22):
    """The picture minus its blurred copy, amplified around mid-grey."""
    import numpy as np
    from PIL import ImageFilter
    bg = img.filter(ImageFilter.GaussianBlur(3))
    d = np.asarray(img).astype(np.int16) - np.asarray(bg).astype(np.int16)
    return np.clip(128 + d * k, 0, 255).astype(np.uint8)


class FaintAnalyzer(Analyzer):
    name = "faint"
    category = "steg"
    description = "Semi-transparent overlay: high-pass enhancement + OCR (whole image and quadrants)."
    accepts = IMG_EXT
    display_order = 358

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            from PIL import Image
            from .vision import ocr_image
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"PIL/numpy missing: {exc}")
        img, err = load_image(self.name, ctx.input, "L")
        if err:
            return err
        w, h = img.size
        if w * h > MAX_PIXELS:
            return ToolResult(self.name, status="skipped", summary=f"image too big ({w}x{h})")
        outdir = ctx.sub(self.name)
        outdir.mkdir(parents=True, exist_ok=True)
        hp = _high_pass(img)
        full = outdir / f"{ctx.input.stem}_faint.png"
        Image.fromarray(hp).save(full)
        texts: list[str] = []
        # 1) the whole picture, downscaled: cheap, catches big overlays
        small = Image.fromarray(hp)
        if max(small.size) > OCR_MAX:
            r = OCR_MAX / max(small.size)
            small = small.resize((int(small.width * r), int(small.height * r)), Image.LANCZOS)
        p = outdir / f"{ctx.input.stem}_faint_ocr.png"
        small.save(p)
        for _ in range(2):          # sparse and block mode: one may hit, the other miss
            text = ocr_image(p, timeout=20, thorough=False, max_dim=OCR_MAX)
            if text:
                texts.append(text)
        # NB: no OCR of the quadrants at full resolution. A 3648x2432 photo
        # costs ~100 s there and tesseract still does not read a 30-px overlay;
        # the artifact is what makes it visible (a human reads it in a second).
        interesting = [t for t in texts if _TOKEN.search(t)]
        lines = [f"high-pass k=22, {w}x{h}"]
        if interesting:
            lines.append("== tokens ==")
            lines += interesting[:4]
        unknown = [t for t in texts if t not in interesting]
        if unknown:
            lines.append("== ocr ==")
            lines += [t[:1500] for t in unknown[:3]]
        return ToolResult(self.name, status="done",
                          summary=f"enhanced ({'flag-like token' if interesting else 'no token'})",
                          output="\n".join(lines)[:200_000],
                          artifacts=[{"name": full.name, "path": str(full),
                                      "size": full.stat().st_size}])

    @staticmethod
    def _quadrants(w: int, h: int) -> dict[str, tuple[int, int, int, int]]:
        mx, my = w // 2, h // 2
        o = _QUAD_OVERLAP
        return {"tl": (0, 0, min(w, mx + o), min(h, my + o)),
                "tr": (max(0, mx - o), 0, w, min(h, my + o)),
                "bl": (0, max(0, my - o), min(w, mx + o), h),
                "br": (max(0, mx - o), max(0, my - o), w, h)}


register(FaintAnalyzer())
