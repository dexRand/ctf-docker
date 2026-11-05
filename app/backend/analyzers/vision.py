"""Vision analyzers: OCR (tesseract) to read visible text/flags."""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path

from ..flagpatterns import FLAG_PREFIXES
from .base import Analyzer, ToolContext, ToolResult, run_cmd
from ..config import OCR_EXTRA_LANGS, OCR_LANGS, OCR_MAX_DIM
from .registry import register
from .util import IMG_EXT

_PREFIX_ALT = "|".join(re.escape(p) for p in FLAG_PREFIXES)
_KNOWN_FLAG = re.compile(r"(?i)(" + _PREFIX_ALT + r")\{[^}\n]{2,}\}")

# OCR confuses 0 with O and 1 with l/I. Inside a flag body (never the prefix)
# fix the obvious cases: O/I surrounded by lowercase, l next to a digit.
_CONFUSE = {"O": "0", "I": "1", "@": "0"}
# any `prefix{body}` token, not just the known CTF prefixes: the variants must
# keep the real prefix (`utflag{...}`, not the inner `flag{...}`)
_FLAG_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_]{1,15})\{([^}]{2,180})\}")


_LINE_START = re.compile(r"(?i)^(" + _PREFIX_ALT + r")\s*[{}(\[]\s*([A-Za-z0-9_\-!?@.]*)$")
_LINE_BODY = re.compile(r"^[A-Za-z0-9_\-!?@.]{1,40}[})\]]?$")


def _multiline_flags(text: str) -> str:
    """A flag drawn over several lines ("FLAG{" / "n0th1ng" / "_much}") comes
    out of OCR one line at a time, and the opening brace is often misread
    ("FLAG}", "FLAG("): join a `prefix` + brace line with the following
    body-like lines up to the one that closes it (WaniCTF 2023 whats_happening)."""
    lines = [ln.strip() for ln in text.splitlines()]
    out: list[str] = []
    for i, ln in enumerate(lines):
        m = _LINE_START.match(ln)
        if not m:
            continue
        body = m.group(2)
        for nxt in lines[i + 1:i + 6]:
            nxt = nxt.replace(" ", "")
            if not _LINE_BODY.match(nxt):
                break
            if nxt[-1] in "})]":
                out.append(f"{m.group(1)}{{{body}{nxt[:-1]}}}")
                break
            body += nxt
    return "\n".join(dict.fromkeys(out))


def _confusable_variants(text: str) -> str:
    """The same OCR text with the classic 0/O and 1/l/i misreadings corrected in
    every flag-like token, so the flag hunt can match the real flag."""
    extra: list[str] = []
    for m in _FLAG_TOKEN.finditer(text):
        body = re.sub(r"\s+", "", m.group(2))   # OCR may wrap the flag on two lines
        # OCR also splits a prefix ("ut  flag{...}"): the real flag carries it
        pre = text[max(0, m.start() - 16):m.start()]
        # only a wide gap is an OCR split ("ut  flag{"); "see flag{" is prose
        glued = re.search(r"([A-Za-z][A-Za-z0-9_]{0,3})\s{2,}$", pre)
        prefixes = [m.group(1)]
        if glued:
            prefixes.append(glued.group(1) + m.group(1))
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
            extra += [f"{pre}{{{v}}}" for pre in prefixes]
        # a leet body written with letters (OCR un-leeted it): "lOtS Of TAR5"
        # is "l0t5_0f_TAR5". Spaces were underscores in the picture, and O/S
        # next to the digits are 0/5. Only for bodies that already have digits.
        raw_body = m.group(2).strip()
        if any(c.isdigit() for c in raw_body) and ("O" in raw_body or "S" in raw_body):
            unleet = raw_body if "_" in raw_body else raw_body.replace(" ", "_")
            unleet = unleet.replace("O", "0").replace("S", "5")
            unleet = re.sub(r"\s+", "", unleet)
            if unleet != raw_body:
                extra += [f"{pre}{{{unleet}}}" for pre in prefixes]
        # a leet-style body (several digits) may have read 1 as i or as a
        # lowercase l ("qu1t3", "s1mple" -> "s lmple"): one position at a time,
        # replacing every l would turn "slmple" into "s1mp1e"
        if sum(c.isdigit() for c in v) >= 1:
            for i, ch in enumerate(v):
                if ch in "il":
                    fixed_l = v[:i] + "1" + v[i + 1:]
                    extra += [f"{pre}{{{fixed_l}}}" for pre in prefixes]
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


def flatten_alpha(im):
    """Composite a transparent image on white, as a viewer shows it. Dropping
    the alpha channel instead (convert("L")) reveals the colour stored under
    the transparent pixels, which can hide the text (BuckeyeCTF 2023 replace-me:
    a gray+alpha PNG read as noise)."""
    from PIL import Image
    if im.mode in ("RGBA", "LA", "PA") or (im.mode == "P" and "transparency" in im.info):
        rgba = im.convert("RGBA")
        bg = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        return Image.alpha_composite(bg, rgba).convert("RGB")
    return im


def ocr_image(path: Path, timeout: int = 90, thorough: bool = True,
              max_dim: int | None = None) -> str:
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
    base = flatten_alpha(base)
    # downscale huge images: tesseract on multi-MP photos is very slow and the
    # flags in them are large text anyway
    limit = max_dim or OCR_MAX_DIM
    if limit:
        w0, h0 = base.size
        if max(w0, h0) > limit:
            f = limit / max(w0, h0)
            base = base.resize((max(1, round(w0 * f)), max(1, round(h0 * f))), Image.LANCZOS)
    texts: list[str] = []
    gray = base.convert("L")
    w, h = gray.size
    try:
        from PIL import ImageOps, ImageStat
        if ImageStat.Stat(gray).mean[0] < 96:
            # light text on a dark background: tesseract wants dark on light, and
            # at the original size (an upscale blurred the "_" under a "g" away,
            # TJCTF 2025 packet-palette)
            t = _tess(ImageOps.invert(gray), 6, timeout)
            if t:
                texts.append(t)
    except Exception:
        pass
    if max_dim is None and max(w, h) < 1000:
        # tiny images get upscaled for OCR; an explicit max_dim is a hard cap
        f = max(2, (1000 // max(w, h)) + 1)
        gray = gray.resize((w * f, h * f), Image.LANCZOS)
    for psm in (6, 7):
        t = _tess(gray, psm, timeout)
        if t and t not in texts:
            texts.append(t)
    if not any(_KNOWN_FLAG.search(t) for t in texts):
        # automatic page segmentation: text in a small graphic with other shapes
        # around it (icons, charger images) is only found as its own block
        t = _tess(gray, 3, timeout)
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
    if thorough and not any(_KNOWN_FLAG.search(t) for t in texts) and sum(len(t) for t in texts) >= 20:
        # handwritten flags are often rotated ("Congrats!" on ictf): straighten
        # the red channel (blue ink on white is dark there) and retry
        red = base.convert("RGB").getchannel("R")
        # the rotated text is large: a 1000 px copy is still readable and makes
        # six tesseract passes affordable on a multi-megapixel photo
        if max(red.size) > 1000:
            f = 1000 / max(red.size)
            red = red.resize((max(1, round(red.width * f)), max(1, round(red.height * f))),
                             Image.LANCZOS)
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
    lines_joined = _multiline_flags(joined)
    if lines_joined:
        joined += "\n== OCR lines joined ==\n" + lines_joined
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
