"""faint: high-pass enhancement for semi-transparent overlays."""
from __future__ import annotations

import numpy as np
from PIL import Image

from backend.analyzers.base import ToolContext
from backend.analyzers.faint import FaintAnalyzer


def _with_faint_overlay(path, size=(400, 300)):
    arr = np.full((size[1], size[0]), 120, np.uint8)
    # un'overlay al ~2%: 3 livelli sopra lo sfondo
    arr[120:180, 80:320] = 124
    Image.fromarray(arr).convert("RGB").save(path)
    return path


def test_overlay_is_enhanced_into_an_artifact(tmp_path):
    p = _with_faint_overlay(tmp_path / "faint.png")
    r = FaintAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "done", r.summary
    assert "high-pass" in (r.output or "")
    assert len(r.artifacts) == 1
    with Image.open(r.artifacts[0]["path"]) as im:
        assert im.size == (400, 300)
        # l'overlay deve risultare molto più contrastato dell'originale
        assert im.convert("L").getextrema()[1] - im.convert("L").getextrema()[0] > 40


def test_huge_image_is_skipped(tmp_path):
    p = tmp_path / "huge.png"
    Image.new("RGB", (5000, 4000)).save(p)      # 20 MPix
    r = FaintAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and "too big" in r.summary


def test_non_image_is_skipped(tmp_path):
    p = tmp_path / "x.png"
    p.write_bytes(b"not an image")
    r = FaintAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped"
