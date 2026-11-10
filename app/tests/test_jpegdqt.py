"""jpeg-dqt: rebuild wiped quantization tables (TJCTF 2025 "quant")."""
from __future__ import annotations

import io
import struct

from PIL import Image

from backend.analyzers.base import ToolContext
from backend.analyzers.jpegdqt import JpegDqtAnalyzer, invalid_tables, rebuild

LUMA = (16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
        14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
        18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
        49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99)
CHROMA = (17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99,
          24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99, 99,
          99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
          99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99)


def _jpeg(size=(64, 48)) -> bytes:
    buf = io.BytesIO()
    im = Image.new("RGB", size)
    for x in range(size[0]):
        for y in range(size[1]):
            im.putpixel((x, y), (x * 4 % 256, y * 5 % 256, (x + y) % 256))
    im.save(buf, "JPEG", quality=90)
    return buf.getvalue()


def _wipe_tables(raw: bytes) -> bytes:
    """Zero the DQT payloads, leaving one value (like the challenge does)."""
    out = bytearray(raw)
    pos = 2
    while pos + 4 <= len(out):
        if out[pos] != 0xFF:
            pos += 1
            continue
        marker = out[pos + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        length = struct.unpack_from(">H", out, pos + 2)[0]
        if marker == 0xDB:
            start = pos + 5                       # keep the table id byte
            out[start:pos + 2 + length] = b"\x00" * (len(out[start:pos + 2 + length]) - 1) + b"\x01"
        if marker == 0xDA:
            break
        pos += 2 + length
    return bytes(out)


def test_gating_skips_a_healthy_jpeg(tmp_path):
    p = tmp_path / "good.jpg"
    p.write_bytes(_jpeg())
    r = JpegDqtAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and "fine" in r.summary


def test_gating_skips_a_non_jpeg(tmp_path):
    p = tmp_path / "photo.jpg"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    assert invalid_tables(p.read_bytes()) is False
    r = JpegDqtAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped"


def test_wiped_tables_are_rebuilt_and_the_picture_decodes(tmp_path):
    wiped = _wipe_tables(_jpeg())
    assert invalid_tables(wiped) is True
    p = tmp_path / "quant.jpg"
    p.write_bytes(wiped)
    r = JpegDqtAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "done", r.summary
    assert "all-ones" in r.summary or "annex-k" in r.summary
    assert r.extracted, "the decoded picture must become a child for OCR"
    with Image.open(r.extracted[0]) as im:
        assert im.size == (64, 48)


def test_rebuild_replaces_every_table():
    wiped = _wipe_tables(_jpeg())
    fixed = rebuild(wiped, 0)
    assert invalid_tables(fixed) is False
    assert len(fixed) == len(wiped)
    with Image.open(io.BytesIO(fixed)) as im:
        assert im.size == (64, 48)


def test_standard_tables_are_used_for_the_second_component():
    wiped = _wipe_tables(_jpeg())
    fixed = rebuild(wiped, 1)
    assert LUMA[:8] in [tuple(fixed[i:i + 8]) for i in range(len(fixed) - 8)]
    assert CHROMA[:8] in [tuple(fixed[i:i + 8]) for i in range(len(fixed) - 8)]


def test_sixteen_bit_tables_are_parsed_and_rebuilt():
    from backend.analyzers.jpegdqt import _dqt_spans, invalid_tables, rebuild
    table = (1,) * 63 + (0,)                                  # one zero: wiped
    body = bytes([0x10]) + b"".join(v.to_bytes(2, "big") for v in table)   # Pq=1, Tq=0
    seg = b"\xff\xdb" + (2 + len(body)).to_bytes(2, "big") + body
    raw = b"\xff\xd8" + seg + b"\xff\xda\x00\x02" + b"\x00" * 8 + b"\xff\xd9"
    spans = _dqt_spans(raw)
    assert spans and spans[0][1] - spans[0][0] == 128 and spans[0][3] == 2
    assert invalid_tables(raw)
    fixed = rebuild(raw, 0)
    assert not invalid_tables(fixed) and len(fixed) == len(raw)
