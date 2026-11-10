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


def test_palette_png_keeps_plte_after_rebuild():
    buf = io.BytesIO()
    im = Image.new("P", (16, 16))
    im.putpalette([0, 0, 0, 255, 0, 0] + [0] * (254 * 3))
    for x in range(16):
        im.putpixel((x, x), 1)
    im.save(buf, "PNG")
    fixed, _log = rebuild_bad_zlib_png(_break_adler(buf.getvalue()))
    assert fixed is not None and b"PLTE" in fixed
    out = Image.open(io.BytesIO(fixed))
    out.load()
    assert out.mode == "P" and out.getpixel((3, 3)) == 1


def test_huge_dimensions_are_refused_before_decompressing():
    ihdr = struct.pack(">IIBBBBB", 50_000, 50_000, 8, 2, 0, 0, 0)
    chunk = lambda t, d: (struct.pack(">I", len(d)) + t + d                    # noqa: E731
                          + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF))
    bomb = zlib.compress(b"\x00" * 1_000_000)[:-4] + b"\x00\x00\x00\x00"     # broken adler
    png = PNG_SIG + chunk(b"IHDR", ihdr) + chunk(b"IDAT", bomb) + chunk(b"IEND", b"")
    fixed, log = rebuild_bad_zlib_png(png)
    assert fixed is None and any("troppo grande" in ln for ln in log)
