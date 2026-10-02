"""Vision analyzers: OCR (tesseract) to read visible text/flags."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

IMG_EXT = (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".tif", ".webp", ".ppm")


def ocr_image(path: Path, timeout: int = 90) -> str:
    """Run tesseract on a file and return recognized text ('' if unavailable).

    Small images are upscaled first: OCR on tiny text (e.g. GIF frames) is very
    inaccurate otherwise.
    """
    if not shutil.which("tesseract"):
        return ""
    src = path
    tmp: Path | None = None
    try:
        from PIL import Image
        im = Image.open(path).convert("L")
        w, h = im.size
        if max(w, h) < 1000:
            f = max(2, (1000 // max(w, h)) + 1)
            im = im.resize((w * f, h * f), Image.LANCZOS)
            tmp = Path("/tmp") / f"ocr_{os.getpid()}_{abs(hash(str(path))) % 100000}.png"
            im.save(tmp)
            src = tmp
    except Exception:
        pass
    try:
        r = subprocess.run(["tesseract", str(src), "stdout"],
                           capture_output=True, text=True, errors="replace", timeout=timeout)
        return (r.stdout or "").strip()
    except Exception:
        return ""
    finally:
        if tmp:
            try:
                tmp.unlink()
            except OSError:
                pass


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
