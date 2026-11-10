"""color-map: few-colour images mapped to distinct colours + index grey (AperiSolve style)."""
from __future__ import annotations

import numpy as np
from PIL import Image

from backend.analyzers.base import ToolContext
from backend.analyzers.colormap import ColorMapAnalyzer


def _patchwork(path, colours=4, size=(32, 32)):
    arr = np.zeros((*size, 3), np.uint8)
    for i, c in enumerate([(0, 0, 0), (255, 255, 255), (10, 10, 10), (200, 30, 30)][:colours]):
        arr[i * (size[1] // colours):(i + 1) * (size[1] // colours), :] = c
    Image.fromarray(arr).save(path)
    return path


def test_few_colours_are_mapped_as_artifacts(tmp_path):
    p = _patchwork(tmp_path / "palette.png", colours=4)
    r = ColorMapAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "done", r.summary
    assert "4 colours mapped" in r.summary
    # artifacts, not children: the index image would be colour-mapped again
    assert not r.extracted
    assert len(r.artifacts) == 2
    grey = next(a for a in r.artifacts if a["name"].endswith("index-grey.png"))
    with Image.open(grey["path"]) as im:
        assert im.size == (32, 32)
        assert len(im.getcolors(64) or []) == 4   # four distinct grey levels


def test_a_photo_is_skipped_fast(tmp_path):
    rng = np.random.default_rng(7)
    arr = rng.integers(0, 256, (64, 64, 3), dtype=np.uint8)
    p = tmp_path / "photo.png"
    Image.fromarray(arr).save(p)
    r = ColorMapAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and "more than" in r.summary


def test_a_single_colour_image_is_skipped(tmp_path):
    p = tmp_path / "flat.png"
    Image.new("RGB", (32, 32), (7, 7, 7)).save(p)
    r = ColorMapAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and "single colour" in r.summary


def test_the_two_colour_case_of_a_qr(tmp_path):
    p = tmp_path / "qr.png"
    im = Image.new("RGB", (29, 29), (255, 255, 255))
    for i in range(29):
        im.putpixel((i, i), (0, 0, 0))
    im.save(p)
    r = ColorMapAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "done" and "2 colours mapped" in r.summary


def test_index_follows_the_luminance_order_for_any_palette(tmp_path):
    # blue < red < green by luminance, but not by RGB value: searchsorted on the
    # luminance-sorted keys used to give green the index of red
    arr = np.zeros((48, 48, 3), np.uint8)
    arr[:16] = (0, 0, 255)
    arr[16:32] = (255, 0, 0)
    arr[32:] = (0, 255, 0)
    p = tmp_path / "rgb.png"
    Image.fromarray(arr).save(p)
    r = ColorMapAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    grey = next(a for a in r.artifacts if a["name"].endswith("index-grey.png"))
    g = np.asarray(Image.open(grey["path"]))
    assert g[0, 0] < g[20, 0] < g[40, 0]          # 0, 1, 2 scaled
