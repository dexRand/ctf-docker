"""Unit tests for homoglyph and low-bit-depth PNG stego (no external tools)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from backend.analyzers.base import ToolContext
from backend.analyzers.homoglyph import HomoglyphAnalyzer
from backend.analyzers.pngpixels import PngPixelsAnalyzer


def _run(analyzer, data: bytes, name: str = "f.txt"):
    d = Path(tempfile.mkdtemp(prefix="st-"))
    p = d / name
    p.write_bytes(data)
    return analyzer.run(ToolContext(input=p, workdir=d / "w"))


def test_dehomoglyph_recovers_flag() -> None:
    # Cyrillic look-alikes: І Т Ѕ о о р
    text = "hello ІТЅ{hоmоglурh} world"
    res = _run(HomoglyphAnalyzer(), text.encode("utf-8"))
    assert res.status == "done"
    assert "ITS{homoglyph}" in res.output


def test_homoglyph_skips_plain_text() -> None:
    assert _run(HomoglyphAnalyzer(), b"plain ascii text here").status == "skipped"


def test_png_low_bits_decodes() -> None:
    from PIL import Image

    hidden = "ITS{png_pixels}"
    bits = [int(b) for c in hidden for b in f"{ord(c):08b}"]
    im = Image.new("1", (len(bits), 1))
    im.putdata([255 if b else 0 for b in bits])
    d = Path(tempfile.mkdtemp(prefix="png-"))
    p = d / "bits.png"
    im.save(p)
    res = PngPixelsAnalyzer().run(ToolContext(input=p, workdir=d / "w"))
    assert res.status == "done"
    assert hidden in res.output


def test_png_random_skips() -> None:
    from PIL import Image

    im = Image.new("RGB", (20, 20), (12, 34, 56))
    d = Path(tempfile.mkdtemp(prefix="png2-"))
    p = d / "plain.png"
    im.save(p)
    assert PngPixelsAnalyzer().run(ToolContext(input=p, workdir=d / "w")).status == "skipped"
