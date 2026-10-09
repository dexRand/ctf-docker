"""Unit tests for the PNG repair (signature / chunk type / CRC) — synthetic file."""
from __future__ import annotations

import io

from PIL import Image

from backend.analyzers.png import PNG_SIG, repair_png


def _make_png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (16, 12), (200, 30, 30)).save(buf, format="PNG")
    return buf.getvalue()


def test_valid_png_is_left_unchanged() -> None:
    data = _make_png()
    fixed, log = repair_png(data)
    assert fixed == data
    assert log == []


def test_repair_restores_signature_and_ihdr_type() -> None:
    data = bytearray(_make_png())
    # corrupt the 8-byte signature
    data[1:4] = b"\x65\x4e\x34"
    data[6:8] = b"\xb0\xaa"
    # corrupt the first chunk type ("IHDR" -> 'C"DR'), as in picoCTF "c0rrupt"
    assert bytes(data[12:16]) == b"IHDR"
    data[12:16] = b'C"DR'

    fixed, log = repair_png(bytes(data))
    assert fixed[:8] == PNG_SIG
    im = Image.open(io.BytesIO(fixed))
    im.load()
    assert im.size == (16, 12)


def test_repair_fixes_corrupted_crc() -> None:
    data = bytearray(_make_png())
    pos = data.find(b"IDAT")
    assert pos != -1
    length = int.from_bytes(data[pos - 4:pos], "big")
    crc_pos = pos + 4 + length          # first byte of the IDAT CRC
    data[crc_pos] ^= 0xFF

    fixed, _log = repair_png(bytes(data))
    im = Image.open(io.BytesIO(fixed))
    im.load()
    assert im.size == (16, 12)
