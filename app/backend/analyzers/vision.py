"""Vision analyzers: OCR (tesseract) to read visible text/flags."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

IMG_EXT = (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".tif", ".webp", ".ppm")
_KNOWN_FLAG = re.compile(r"(?i)(picoCTF|ITS|flag|CTF|HTB)\{[^}\n]{2,}\}")


def _tess(img, psm: int, timeout: int) -> str:
    tmp = Path("/tmp") / f"ocr_{os.getpid()}_{abs(hash(img.tobytes())) % 100000}_{psm}.png"
    try:
        img.save(tmp)
        r = subprocess.run(["tesseract", str(tmp), "stdout", "--psm", str(psm)],
                           capture_output=True, text=True, errors="replace", timeout=timeout)
        return (r.stdout or "").strip()
    except Exception:
        return ""
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def ocr_image(path: Path, timeout: int = 90) -> str:
    """Run tesseract on a file and return recognized text ('' if unavailable).

    Small images are upscaled first (OCR on tiny text is otherwise poor). When
    the plain grayscale pass finds no brace-delimited token (a flag), each RGB
    channel is tried too: a flag drawn in a colour close to the background
    (e.g. light blue on sky) is invisible in grayscale but stands out in one
    channel.
    """
    if not shutil.which("tesseract"):
        return ""
    try:
        from PIL import Image
        base = Image.open(path)
        base.load()  # decode now so a truncated image degrades to "" instead of raising later
    except Exception:
        return ""
    texts: list[str] = []
    gray = base.convert("L")
    w, h = gray.size
    if max(w, h) < 1000:
        f = max(2, (1000 // max(w, h)) + 1)
        gray = gray.resize((w * f, h * f), Image.LANCZOS)
    for psm in (6, 7):
        t = _tess(gray, psm, timeout)
        if t and t not in texts:
            texts.append(t)
    if not any(_KNOWN_FLAG.search(t) for t in texts):
        # a flag drawn in a colour close to the background is invisible in
        # grayscale but stands out in one channel; OCR each channel on the top
        # and bottom bands, where such flags are usually placed
        rgb = base.convert("RGB")
        W, H = rgb.size
        band = max(64, H // 5) if H >= 100 else H
        bands = [(0, band)] if H < 100 else [(0, band), (H - band, H)]
        for ch in ("R", "G", "B"):
            full = rgb.getchannel(ch)
            for (t, b) in bands:
                c = full.crop((0, t, W, b))
                if max(c.size) < 2000:
                    c = c.resize((c.width * 2, c.height * 2), Image.LANCZOS)
                txt = _tess(c, 6, timeout)
                if txt and txt not in texts:
                    texts.append(txt)
    return "\n".join(texts)


class OcrAnalyzer(Analyzer):
    name = "ocr"
    category = "vision"
    description = "OCR the visible text of an image (tesseract) — catches visible flags."
    accepts = IMG_EXT
    display_order = 365

    def run(self, ctx: ToolContext) -> ToolResult:
        if not shutil.which("tesseract"):
            return ToolResult(self.name, status="skipped", summary="tesseract not installed")
        text = ocr_image(ctx.input)
        return ToolResult(self.name, status="done", summary=f"{len(text)} char OCR",
                          output=text)


register(OcrAnalyzer())
