"""png-repair: IDAT whose zlib wrapper/adler is broken but the deflate is fine."""
from __future__ import annotations

import io
import struct
import zlib

import pytest
from PIL import Image

from backend.analyzers.png import PNG_SIG, rebuild_bad_zlib_png


def _png(size=(32, 24)) -> bytes:
    buf = io.BytesIO()
    im = Image.new("RGB", size)
    for x in range(size[0]):
        for y in range(size[1]):
            im.putpixel((x, y), (x * 5 % 256, y * 7 % 256, (x + y) % 256))
    im.save(buf, "PNG")
    return buf.getvalue()


def _break_adler(raw: bytes) -> bytes:
    """Corrompe l'adler32 (ultimi 4 byte dell'IDAT) e il CRC del chunk."""
    out = bytearray(raw)
    pos = 8
    while pos + 8 <= len(out):
        ln = struct.unpack(">I", out[pos:pos + 4])[0]
        ctype = out[pos + 4:pos + 8]
        if ctype == b"IDAT":
            end = pos + 8 + ln
            out[end - 1] ^= 0xFF                      # adler32
            crc = zlib.crc32(bytes(out[pos + 4:end])) & 0xFFFFFFFF
            out[end:end + 4] = struct.pack(">I", crc)
            break
        pos += 12 + ln
    return bytes(out)


def test_healthy_png_is_left_alone():
    raw = _png()
    assert rebuild_bad_zlib_png(raw)[0] is None


def test_broken_adler_is_rebuilt_and_decodes():
    broken = _break_adler(_png())
    with pytest.raises(Exception):
        Image.open(io.BytesIO(broken)).load()
    fixed, log = rebuild_bad_zlib_png(broken)
    assert fixed and fixed.startswith(PNG_SIG)
    assert any("ricostruito" in line for line in log)
    with Image.open(io.BytesIO(fixed)) as im:
        im.load()
        assert im.size == (32, 24)


def test_an_unrelated_file_is_not_a_png():
    assert rebuild_bad_zlib_png(b"hello world")[0] is None
