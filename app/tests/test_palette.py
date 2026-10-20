"""channel-remap repaints palette images by index (same colour, different index)."""
import numpy as np
from PIL import Image

from backend.analyzers.base import ToolContext
from backend.analyzers.image import ChannelRemapAnalyzer


def test_identical_palette_colours_are_separated(tmp_path, monkeypatch):
    import backend.analyzers.vision as vision
    monkeypatch.setattr(vision, "ocr_image", lambda *a, **k: "")
    idx = np.zeros((20, 30), dtype=np.uint8)
    idx[5:15, 10:20] = 1                       # a hidden square in index 1 ...
    im = Image.fromarray(idx, "P")
    im.putpalette([40, 49, 53] * 2 + [0, 0, 0] * 254)   # ... with the same colour as index 0
    p = tmp_path / "pal.png"
    im.save(p)
    ChannelRemapAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    mask = np.asarray(Image.open(tmp_path / "w" / "channel-remap" / "pal_palette-mask.png"))
    assert mask[0, 0] == 255 and mask[10, 15] == 0
