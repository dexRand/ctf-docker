"""Vision analyzers: OCR (tesseract) to read visible text/flags."""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, run_cmd
from ..config import OCR_EXTRA_LANGS, OCR_LANGS, OCR_MAX_DIM
from .registry import register
from .util import IMG_EXT

_KNOWN_FLAG = re.compile(r"(?i)(picoCTF|ITS|flag|CTF|HTB)\{[^}\n]{2,}\}")

# OCR confuses 0 with O and 1 with l/I. Inside a flag body (never the prefix)
# fix the obvious cases: O/I surrounded by lowercase, l next to a digit.
_CONFUSE = {"O": "0", "I": "1", "@": "0"}
_FLAG_TOKEN = re.compile(r"(?i)(picoCTF|ITS|flag|CTF|HTB|SEKAI|DUCTF|tjctf|ictf|lactf|uiuctf)\{([^}]{2,180})\}")


def _confusable_variants(text: str) -> str:
    """The same OCR text with the classic 0/O and 1/l/i misreadings corrected in
    every flag-like token, so the flag hunt can match the real flag."""
    extra: list[str] = []
    for m in _FLAG_TOKEN.finditer(text):
        body = re.sub(r"\s+", "", m.group(2))   # OCR may wrap the flag on two lines
        fixed: list[str] = []
        for i, ch in enumerate(body):
            prev = body[i - 1] if i else ""
            nxt = body[i + 1] if i + 1 < len(body) else ""
            if ch in _CONFUSE and (prev.islower() or nxt.islower()):
                fixed.append(_CONFUSE[ch])
            elif ch == "l" and (prev.isdigit() or nxt.isdigit()):
                fixed.append("1")
            else:
                fixed.append(ch)
        v = "".join(fixed)
        if v != body:
            extra.append(f"{m.group(1)}{{{v}}}")
        # a leet-style body (several digits) may have read 1 as i ("qu1t3")
        if sum(c.isdigit() for c in body) >= 2 and "i" in v:
            leet = v.replace("i", "1")
            if leet != v:
                extra.append(f"{m.group(1)}{{{leet}}}")
    return "\n".join(dict.fromkeys(extra))


def _denoised_text(base, timeout: int) -> str:
    """Median-filter + hard threshold: dense coloured noise (c0rrupt) survives a
    plain grayscale pass, but the solid text is the only thick dark stroke."""
    from PIL import Image, ImageFilter
    g = base.convert("L").filter(ImageFilter.MedianFilter(5))
    bw = g.point(lambda v: 0 if v < 90 else 255)
    if max(bw.size) < 2000:
        f = max(2, 2000 // max(bw.size))
        bw = bw.resize((bw.width * f, bw.height * f), Image.LANCZOS)
    return _tess(bw, 6, timeout)


def _tess_cmd(tmp, psm: int, langs: str) -> list:
    cmd = ["tesseract", str(tmp), "stdout", "--psm", str(psm)]
    if langs and langs != "eng":
        cmd += ["-l", langs]
    return cmd


def _combined_langs(base: str, extra: str) -> str:
    """Language spec for the fallback pass ('' when no extra language is set)."""
    return f"{base}+{extra}" if extra else ""


def _tess(img, psm: int, timeout: int, langs: str | None = None) -> str:
    lang = OCR_LANGS if langs is None else langs
    fd, name = tempfile.mkstemp(prefix="stegsuite-ocr-", suffix=".png")  # unique per call/thread
    os.close(fd)
    tmp = Path(name)
    try:
        img.save(tmp)
        r = run_cmd(_tess_cmd(tmp, psm, lang), timeout=timeout)
        if r.returncode != 0 and lang != "eng":
            # e.g. the extra language pack is not installed in this environment
            r = run_cmd(_tess_cmd(tmp, psm, "eng"), timeout=timeout)
        return (r.stdout or "").strip()
    except Exception:
        return ""
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def ocr_image(path: Path, timeout: int = 90, thorough: bool = True) -> str:
    """Run tesseract on a file and return recognized text ('' if unavailable).

    Small images are upscaled first (OCR on tiny text is otherwise poor). When
    the plain grayscale pass finds no brace-delimited token (a flag), each RGB
    channel is tried too: a flag drawn in a colour close to the background
    (e.g. light blue on sky) is invisible in grayscale but stands out in one
    channel.

    ``thorough=False`` skips those extra channel/band passes (and the fallback
    language): used for the dozens of *derived* images (bit planes, enhancement
    variants) where a flag, if present, is large text — this keeps the analysis
    from running hundreds of tesseract calls.
    """
    if not shutil.which("tesseract"):
        return ""
    try:
        from PIL import Image
        base = Image.open(path)
        base.load()  # decode now so a truncated image degrades to "" instead of raising later
    except Exception:
        return ""
    # downscale huge images: tesseract on multi-MP photos is very slow and the
    # flags in them are large text anyway
    if OCR_MAX_DIM:
        w0, h0 = base.size
        if max(w0, h0) > OCR_MAX_DIM:
            f = OCR_MAX_DIM / max(w0, h0)
            base = base.resize((max(1, round(w0 * f)), max(1, round(h0 * f))), Image.LANCZOS)
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
    if thorough and not any(_KNOWN_FLAG.search(t) for t in texts):
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
    if thorough and not any(_KNOWN_FLAG.search(t) for t in texts):
        # dense coloured noise: a median filter keeps the thick text strokes
        dn = _denoised_text(base, timeout)
        if dn and dn not in texts:
            texts.append(dn)
    if thorough and not any(_KNOWN_FLAG.search(t) for t in texts):
        # handwritten flags are often rotated ("Congrats!" on ictf): straighten
        # the red channel (blue ink on white is dark there) and retry
        red = base.convert("RGB").getchannel("R")
        for ang in (-30, -25, -20, 20, 25, 30):
            rot = red.rotate(ang, expand=True, fillcolor=255)
            t = _tess(rot, 6, timeout)
            if t and t not in texts:
                texts.append(t)
            if _KNOWN_FLAG.search(t or ""):
                break
    if thorough and OCR_EXTRA_LANGS and not any(_KNOWN_FLAG.search(t) for t in texts):
        # no flag in English: one more pass with the extra language(s) (e.g. ita)
        extra = _combined_langs(OCR_LANGS, OCR_EXTRA_LANGS)
        for psm in (6, 7):
            t = _tess(gray, psm, timeout, extra)
            if t and t not in texts:
                texts.append(t)
    joined = "\n".join(texts)
    variants = _confusable_variants(joined)
    return joined + (("\n== OCR normalized ==\n" + variants) if variants else "")


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
