"""pixel-bytes: a whole file drawn as gray pixels (R=G=B, one byte per pixel).

Covers the ic24 "elf in front of a sunset" class: an ELF (or another strong
magic) is written as gray pixels over the first rows of a colour photo, so the
raw pixel bytes start with ``\\x7f\\x7f\\x7fELF...`` (not a magic) and look like
noise. One channel is read back and the payload ends at the first non-gray
pixel. A top-down BMP (negative height) must survive ``image-repair`` untouched.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from backend.analyzers.base import ToolContext
from backend.analyzers.image import PixelBytesAnalyzer
from backend.analyzers.repair import ImageRepairAnalyzer

# 64 bytes: four full rows of a 16-px-wide image, and the first 64 pixels of a
# 32-px-wide one. `\x7fELF` is a strong 4-byte signature.
PAYLOAD = b"\x7fELF\x02\x01\x01\x00" + bytes(range(56))

PHOTO = (180, 40, 90)           # decidedly non-gray background


def _draw(payload: bytes, size: tuple[int, int] = (32, 8), mode: str = "RGB") -> Image.Image:
    """A colour photo whose first pixels are `payload` drawn in gray."""
    bands = len(mode)
    arr = np.zeros((size[1], size[0], bands), dtype=np.uint8)
    arr[:, :, 0], arr[:, :, 1], arr[:, :, 2] = PHOTO
    if bands == 4:
        arr[:, :, 3] = 255
    flat = arr.reshape(-1, bands)
    assert len(payload) < len(flat), "payload must leave a non-gray pixel"
    for i, b in enumerate(payload):
        flat[i, :3] = b                 # R=G=B=b: one payload byte per pixel
    return Image.fromarray(arr, mode)


def _pixels(tmp_path: Path, img: Image.Image, name: str):
    p = tmp_path / name
    img.save(p)
    return PixelBytesAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "work"))


@pytest.mark.parametrize("mode,suffix", [("RGB", ".png"), ("RGBA", ".png"), ("RGB", ".bmp")])
def test_gray_rows_with_elf_are_extracted(tmp_path, mode, suffix) -> None:
    res = _pixels(tmp_path, _draw(PAYLOAD, mode=mode), f"photo{suffix}")
    assert res.status == "done", res.summary
    assert res.extracted, res.summary
    out = Path(res.extracted[0])
    assert out.suffix == ".elf"
    assert out.read_bytes() == PAYLOAD


def test_rows_hidden_by_height_are_found_after_repair(tmp_path) -> None:
    p = tmp_path / "hidden.bmp"
    _draw(PAYLOAD, size=(16, 6)).save(p)
    data = bytearray(p.read_bytes())
    data[22:26] = (1).to_bytes(4, "little")        # only the first row is declared
    p.write_bytes(data)

    repaired = ImageRepairAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "r"))
    assert repaired.status == "done" and repaired.extracted, repaired.summary
    fixed = Path(repaired.extracted[0])

    res = PixelBytesAnalyzer().run(ToolContext(input=fixed, workdir=tmp_path / "w"))
    assert res.status == "done", res.summary
    assert res.extracted and Path(res.extracted[0]).read_bytes() == PAYLOAD


@pytest.mark.parametrize("head", [b"BM", b"MZ", b"\x1f\x8b\x08"])
def test_weak_or_excluded_magics_are_skipped(tmp_path, head) -> None:
    payload = head + b"\x00" * (64 - len(head))
    res = _pixels(tmp_path, _draw(payload), "photo.png")
    assert res.status == "skipped", res.summary
    assert not res.extracted


def test_coloured_pixels_spelling_elf_are_skipped(tmp_path) -> None:
    # the first pixels encode "\x7fELF" in the red channel only: not gray
    img = _draw(b"\x00" * 64, size=(32, 8))
    arr = np.asarray(img).copy()
    flat = arr.reshape(-1, 3)
    for i, b in enumerate(b"\x7fELF"):
        flat[i] = (b, 40, 90)
    p = tmp_path / "coloured.png"
    Image.fromarray(arr, "RGB").save(p)
    res = PixelBytesAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.status == "skipped", res.summary
    assert not res.extracted


def test_valid_top_down_bmp_is_not_repaired(tmp_path) -> None:
    p = tmp_path / "topdown.bmp"
    _draw(PAYLOAD, size=(16, 6)).save(p)
    data = bytearray(p.read_bytes())
    data[22:26] = (-6).to_bytes(4, "little", signed=True)   # top-down, valid
    p.write_bytes(data)

    res = ImageRepairAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.status == "done", res.summary
    assert not res.extracted, res.output
    fixed = p.read_bytes()
    assert fixed[22:26] == data[22:26]             # the sign is preserved
