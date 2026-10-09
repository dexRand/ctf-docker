"""Unit tests for JPEG/BMP header repair (no external tools required)."""
from __future__ import annotations

import struct

from backend.analyzers.repair import carve_embedded, repair_bmp, repair_jpeg


def make_bmp(width: int, height: int, bpp: int = 24) -> bytearray:
    """A minimal valid 54-byte-header BMP (BITMAPINFOHEADER, no compression)."""
    row = ((width * bpp + 31) >> 5) * 4
    pixels = b"\x00" * (row * height)
    size = 54 + len(pixels)
    hdr = b"BM" + struct.pack("<IHHI", size, 0, 0, 54)
    info = struct.pack("<IiiHHIIiiII", 40, width, height, 1, bpp,
                       0, len(pixels), 2835, 2835, 0, 0)
    return bytearray(hdr + info + pixels)


def test_valid_bmp_stays_unchanged() -> None:
    data = make_bmp(1134, 300)
    log: list[str] = []
    fixed = repair_bmp(bytes(data), log)
    assert fixed is not None
    assert fixed == bytes(data)
    assert log == []


def test_bmp_height_less_than_data_is_recomputed() -> None:
    # emulate the "cut-off" trick: header height 1 but real data is taller
    data = make_bmp(1134, 300)
    data[22:26] = (1).to_bytes(4, "little")
    log: list[str] = []
    fixed = repair_bmp(bytes(data), log)
    assert fixed is not None
    assert struct.unpack_from("<I", fixed, 22)[0] == 300
    assert any("height" in l for l in log)


def test_bmp_corrupt_offset_and_dib_rebuilt_tunn3l() -> None:
    # the real tunn3l v1s10n pattern: pixel data for 850 rows, declared height
    # 306, and both offset (0x0A) and DIB size (0x0E) fields read 0xD0BA, so the
    # file is not even a recognisable BMP
    data = make_bmp(1134, 850)
    data[22:26] = (306).to_bytes(4, "little")
    data[10:14] = (0xD0BA).to_bytes(4, "little")
    data[14:18] = (0xD0BA).to_bytes(4, "little")
    log: list[str] = []
    fixed = repair_bmp(bytes(data), log)
    assert fixed is not None
    assert struct.unpack_from("<I", fixed, 10)[0] == 54
    assert struct.unpack_from("<I", fixed, 14)[0] == 40
    # pixel rows available: (filesize - 54) // rowbytes(=3404 for 24bpp@1134)
    assert struct.unpack_from("<I", fixed, 22)[0] == 850
    assert any("non-standard" in l for l in log)
    assert any("850" in l for l in log)


def test_bmp_corrupt_ext_keeps_pixels() -> None:
    data = make_bmp(64, 16, bpp=8)
    data[10:14] = (0xFFFF).to_bytes(4, "little")
    log: list[str] = []
    fixed = repair_bmp(bytes(data), log)
    assert fixed is not None
    assert struct.unpack_from("<I", fixed, 22)[0] == 16


def test_repair_bmp_rejects_non_bmp() -> None:
    assert repair_bmp(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, []) is None


def test_jpeg_missing_eoi_is_appended() -> None:
    data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 40
    log: list[str] = []
    fixed = repair_jpeg(data, log)
    assert fixed is not None
    assert fixed.endswith(b"\xff\xd9")
    assert any("EOI" in l for l in log)


def test_valid_jpeg_stays_unchanged() -> None:
    data = b"\xff\xd8" + b"\x00" * 40 + b"\xff\xd9"
    assert repair_jpeg(data, []) == data


def test_carve_embedded_gif_after_junk_prefix() -> None:
    # picoCTF/Olimpiadi "corrupted file": 8 junk bytes before a valid GIF
    gif = b"GIF89a" + b"\x00" * 64
    log: list[str] = []
    sliced, ext = carve_embedded(b"GHIF_O_G" + gif, log)
    assert ext == ".gif"
    assert sliced == gif
    assert any("offset 8" in l for l in log)


def test_carve_leaves_valid_images_alone() -> None:
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    data, ext = carve_embedded(png, [])
    assert ext == "" and data == png


def test_carve_finds_nothing_in_random_data() -> None:
    data, ext = carve_embedded(b"\x00\x01\x02" + b"random bytes" * 10, [])
    assert ext == "" and data == b"\x00\x01\x02" + b"random bytes" * 10