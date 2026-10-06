"""The OCR helper must degrade gracefully: a broken/truncated image is common in
CTF work (e.g. the output of an imperfect PNG repair) and must never raise,
otherwise it would take down the whole analysis job."""
import struct
import zlib
from pathlib import Path

from backend.analyzers.vision import ocr_image


def _chunk(typ: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + typ + data
            + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))


def _truncated_png() -> bytes:
    # valid signature + IHDR, but no IDAT/IEND: PIL opens it, decode fails
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr)


def test_truncated_png_returns_empty_string(tmp_path: Path):
    p = tmp_path / "broken.png"
    p.write_bytes(_truncated_png())
    assert ocr_image(p) == ""


def test_missing_file_returns_empty_string(tmp_path: Path):
    assert ocr_image(tmp_path / "nope.png") == ""
