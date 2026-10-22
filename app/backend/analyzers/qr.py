"""QR / barcode decoder (zbarimg)."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, out_of, which
from .registry import register
from .util import IMG_EXT


def _deblurred(path: Path, outdir: Path):
    """Deblurred copies of an image: upscale, strong unsharp mask, adaptive
    threshold. A smeared QR (ImaginaryCTF "blurry") decodes only after this."""
    try:
        from PIL import Image, ImageFilter
        import numpy as np
    except Exception:
        return
    try:
        im = Image.open(path).convert("L")
    except Exception:
        return
    # a blurred QR is small; upscaling a multi-megapixel photo 4x costs minutes
    if max(im.size) > 500:
        f = 500 / max(im.size)
        im = im.resize((max(1, round(im.width * f)), max(1, round(im.height * f))),
                       Image.LANCZOS)
    for sc in (3, 4):
        up = im.resize((im.width * sc, im.height * sc), Image.LANCZOS)
        for rad, pct in ((6, 500), (8, 600)):
            sh = up.filter(ImageFilter.UnsharpMask(radius=rad, percent=pct, threshold=0))
            arr = np.asarray(sh, dtype=np.float32)
            local = np.asarray(sh.filter(ImageFilter.GaussianBlur(15)), dtype=np.float32)
            bw = np.where(arr < local - 6, 0, 255).astype("uint8")
            out = outdir / f"qr_{sc}_{rad}.png"
            Image.fromarray(bw).save(out)
            yield out



class QrAnalyzer(Analyzer):
    name = "qr"
    category = "extract"
    description = "Decode QR codes and barcodes (zbarimg)."
    accepts = IMG_EXT
    display_order = 245

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("zbarimg"):
            return ToolResult(self.name, status="skipped", summary="zbarimg not installed")
        proc = ctx.run(["zbarimg", "--quiet", "--raw", str(ctx.input)], timeout=120)
        out = out_of(proc)
        if not out.strip():
            tmpdir = Path(tempfile.mkdtemp(prefix="stegsuite-qr-"))
            try:
                for img in _deblurred(ctx.input, tmpdir):
                    proc = ctx.run(["zbarimg", "--quiet", "--raw", str(img)], timeout=60)
                    out = out_of(proc)
                    if out.strip():
                        break
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)
        if not out.strip():
            # zbarimg exits 4 when no symbol is found: informational, not an error
            return ToolResult(self.name, status="skipped", summary="no QR/barcode",
                              output=out[-1000:], exit_code=proc.returncode)
        n = len(out.splitlines())
        return ToolResult(self.name, status="done", summary=f"{n} code(s) decoded",
                          output=out, exit_code=proc.returncode)


register(QrAnalyzer())
