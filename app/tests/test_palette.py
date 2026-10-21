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


def _wrap_in_pixels(payload: bytes, fmt: str, tmp_path):
    """An RGB image whose raw pixel bytes are `payload` (padded)."""
    import io
    payload += b"\x00" * (-len(payload) % 3)
    n = len(payload) // 3
    img = Image.frombytes("RGB", (n, 1), payload)
    buf = io.BytesIO()
    img.save(buf, fmt)
    return buf.getvalue()


def test_pixel_bytes_follows_an_image_chain(tmp_path):
    from backend.analyzers.image import PixelBytesAnalyzer
    inner = Image.new("RGB", (16, 16), (200, 10, 10))
    import io
    b = io.BytesIO()
    inner.save(b, "PNG")
    level1 = _wrap_in_pixels(b.getvalue(), "BMP", tmp_path)      # BMP whose pixels are a PNG
    level0 = _wrap_in_pixels(level1, "PNG", tmp_path)            # PNG whose pixels are that BMP
    p = tmp_path / "outer.png"
    p.write_bytes(level0)
    res = PixelBytesAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.status == "done" and "BMP -> PNG" in res.summary
    final = Image.open(res.extracted[0])
    assert final.size == (16, 16) and final.getpixel((0, 0)) == (200, 10, 10)


def test_pixel_bytes_skips_ordinary_images(tmp_path):
    from backend.analyzers.image import PixelBytesAnalyzer
    p = tmp_path / "plain.png"
    Image.new("RGB", (32, 32), (1, 2, 3)).save(p)
    assert PixelBytesAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w")).status == "skipped"
