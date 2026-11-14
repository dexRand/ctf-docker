"""image-enhance: whiteness/blackness views for neutral ink on a busy background.

Covers the TJCTF 2024 "purified" (out.qoi) class: hand written white text over
saturated colour bands. The grayscale variants lose the ink, so two extra views
are produced: ``whiteness`` = 255 - min(R,G,B) and ``blackness`` = max(R,G,B),
both stretched by 255/160. They only appear when the content really looks like a
saturated palette with neutral (white/black) ink: noise, gray ramps, text-free
rainbows, flat tints and 16-bit gray images must not add a single OCR call.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import numpy as np
import pytest
from PIL import Image, ImageDraw, ImageFont

from backend.analyzers import vision
from backend.analyzers.base import ToolContext
from backend.analyzers.image import ImageEnhanceAnalyzer

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
BANDS = [(255, 0, 0), (255, 128, 0), (255, 255, 0), (0, 255, 0),
         (0, 255, 255), (0, 0, 255), (128, 0, 255), (255, 0, 255)]
SIZE = (1000, 240)          # 64 px monospace: tesseract reads the `_` at this size
FONT_SIZE = 64
INK = (255, 255, 255)
# the five variants that always exist: autocontrast/equalize/invert/highlights/shadows
BASE_VIEWS = 5


def _rainbow(text: str | None = None, ink: tuple[int, int, int] = INK,
             size: tuple[int, int] = SIZE) -> Image.Image:
    w, h = size
    img = Image.new("RGB", size)
    px = img.load()
    for x in range(w):
        colour = BANDS[min(len(BANDS) - 1, x * len(BANDS) // w)]
        for y in range(h):
            px[x, y] = colour
    if text:
        font = ImageFont.truetype(FONT, FONT_SIZE)
        d = ImageDraw.Draw(img)
        box = d.textbbox((0, 0), text, font=font)
        d.text(((w - (box[2] - box[0])) // 2 - box[0],
                (h - (box[3] - box[1])) // 2 - box[1]), text, font=font, fill=ink)
    return img


def _run(tmp_path: Path, img: Image.Image, monkeypatch, name: str = "img.png"):
    p = tmp_path / name
    img.save(p)
    calls: list[str] = []

    def fake_ocr(path, **_kw):
        calls.append(Path(path).name)
        return ""

    monkeypatch.setattr(vision, "ocr_image", fake_ocr)
    res = ImageEnhanceAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "work"))
    names = [Path(a["name"]).name for a in res.artifacts]
    return res, names, calls


def test_white_ink_adds_only_the_whiteness_view(tmp_path, monkeypatch):
    res, names, calls = _run(tmp_path, _rainbow("flag{white_on_rainbow}"), monkeypatch)
    assert res.status == "done", res.summary
    assert any(n.endswith("_whiteness.png") for n in names), names
    assert not any(n.endswith("_blackness.png") for n in names), names
    assert len(calls) == BASE_VIEWS + 1, calls      # exactly one OCR for the new view


def test_black_ink_adds_only_the_blackness_view(tmp_path, monkeypatch):
    res, names, calls = _run(tmp_path, _rainbow("flag{black_on_rainbow}", ink=(0, 0, 0)),
                             monkeypatch)
    assert res.status == "done", res.summary
    assert any(n.endswith("_blackness.png") for n in names), names
    assert not any(n.endswith("_whiteness.png") for n in names), names
    assert len(calls) == BASE_VIEWS + 1, calls


def test_palette_png_is_supported(tmp_path, monkeypatch):
    img = _rainbow("flag{palette}").convert("P", palette=Image.Palette.ADAPTIVE, colors=16)
    res, names, calls = _run(tmp_path, img, monkeypatch, "palette.png")
    assert res.status == "done", res.summary
    assert any(n.endswith("_whiteness.png") for n in names), names
    assert len(calls) == BASE_VIEWS + 1, calls


def _noise() -> Image.Image:
    rng = np.random.default_rng(0)
    return Image.fromarray(rng.integers(0, 256, (128, 128, 3), dtype=np.uint8))


def _gray_ramp() -> Image.Image:
    ramp = np.tile(np.arange(256, dtype=np.uint8), (128, 1))
    return Image.fromarray(np.dstack([ramp, ramp, ramp]))


def _gray16() -> Image.Image:
    ramp = (np.arange(128 * 128, dtype=np.uint32) % 65536).astype(np.uint16)
    return Image.fromarray(ramp.reshape(128, 128))


def _solid() -> Image.Image:
    return Image.new("RGB", (256, 128), (30, 144, 255))


@pytest.mark.parametrize("maker", [_noise, _gray_ramp, _gray16, _solid,
                                   lambda: _rainbow()],   # last: rainbow, no text
                         ids=["noise", "gray-ramp", "gray-16bit", "solid-tint", "no-text"])
def test_unrelated_content_keeps_the_ocr_count(tmp_path, monkeypatch, maker):
    res, names, calls = _run(tmp_path, maker(), monkeypatch)
    assert res.status == "done", res.summary
    assert not any(n.endswith(("_whiteness.png", "_blackness.png")) for n in names), names
    assert len(calls) == BASE_VIEWS, calls            # zero extra OCR


@pytest.mark.skipif(shutil.which("tesseract") is None, reason="tesseract not installed")
def test_tesseract_reads_white_ink_on_rainbow(tmp_path):
    p = tmp_path / "white_ink.png"
    _rainbow("flag{white_on_rainbow}").save(p)
    res = ImageEnhanceAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "work"))
    assert res.status == "done", res.summary
    lines = [ln for ln in res.output.splitlines() if ln.startswith("whiteness:")]
    assert lines, res.output
    assert "flag{white_on_rainbow}" in lines[0], res.output
