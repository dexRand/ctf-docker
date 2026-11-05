"""JPEG with zeroed quantization tables: rebuild them and decode the picture.

TJCTF 2025 "quant": the two DQT segments are all zero, so every decoder refuses
the file. The picture was written without quantizing ("the lion doesn't
quantize"), so replacing the tables with all ones — then with the standard
Annex K tables as a second attempt — makes it decode.
"""
from __future__ import annotations

import struct

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

_MAX_INPUT = 64 << 20

# ITU T.81 Annex K, natural order
_LUMA = (16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
         14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
         18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
         49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99)
_CHROMA = (17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99,
           24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99, 99,
           99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
           99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99)
_VARIANTS = (("all-ones", (1,) * 64, (1,) * 64),
             ("annex-k", _LUMA, _CHROMA))


def _dqt_spans(raw: bytes) -> list[tuple[int, int, int]]:
    """(payload start, payload end, table id) for every DQT segment before SOS."""
    spans: list[tuple[int, int, int]] = []
    pos = 2
    while pos + 4 <= len(raw):
        if raw[pos] != 0xFF:
            pos += 1
            continue
        marker = raw[pos + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        length = struct.unpack_from(">H", raw, pos + 2)[0]
        if length < 2:
            break
        end = pos + 2 + length
        if marker == 0xDB:
            body = pos + 4
            while body < end:                       # a DQT can hold several tables
                table_id = raw[body] & 0x0F
                spans.append((body + 1, min(body + 65, end), table_id))
                body += 65
        elif marker == 0xDA:                        # start of scan: entropy data follows
            break
        pos = end
    return spans


def invalid_tables(raw: bytes) -> bool:
    """True when a DQT holds a zero: the spec allows 1..255, so the file is broken.

    The challenge zeroes the tables but usually leaves one value behind, so
    "all zeros" is too strict — any zero means the quantizers were wiped.
    """
    if raw[:2] != b"\xff\xd8":
        return False
    spans = _dqt_spans(raw)
    return any(0 in raw[a:b] for a, b, _ in spans)


def rebuild(raw: bytes, variant: int) -> bytes:
    """A copy of the JPEG with the zero tables replaced by `variant`'s tables."""
    _name, luma, chroma = _VARIANTS[variant]
    out = bytearray(raw)
    for start, end, table_id in _dqt_spans(raw):
        table = luma if table_id == 0 else chroma
        out[start:end] = bytes(table[: end - start])
    return bytes(out)


class JpegDqtAnalyzer(Analyzer):
    name = "jpeg-dqt"
    category = "repair"
    description = "JPEG with zeroed quantization tables: rebuild the tables so it decodes."
    accepts = (".jpg", ".jpeg", "image/jpeg")
    display_order = 239

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            if ctx.input.stat().st_size > _MAX_INPUT:
                return ToolResult(self.name, status="skipped", summary="image too big")
            with open(ctx.input, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            return ToolResult(self.name, status="skipped", summary=f"cannot read: {exc}")
        if not invalid_tables(raw):
            return ToolResult(self.name, status="skipped", summary="quantization tables are fine")
        try:
            from PIL import Image
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"PIL missing: {exc}")
        outdir = ctx.sub(self.name)
        outdir.mkdir(parents=True, exist_ok=True)
        for i, (name, _luma, _chroma) in enumerate(_VARIANTS):
            fixed = outdir / f"{ctx.input.stem}.{name}.jpg"
            fixed.write_bytes(rebuild(raw, i))
            try:
                with Image.open(fixed) as im:
                    im.load()
                    colors = im.convert("RGB").getcolors(maxcolors=1 << 16)
                    if colors is not None and len(colors) < 2:
                        continue               # a blank frame: wrong tables
                    png = outdir / f"{ctx.input.stem}.{name}.png"
                    im.convert("RGB").save(png)
            except Exception as exc:
                ctx.log(f"{name}: {type(exc).__name__}: {exc}")
                continue
            return ToolResult(self.name, status="done",
                              summary=f"tables rebuilt ({name}), {im.width}x{im.height}",
                              output=f"quantization tables rebuilt with {name}\n"
                                     f"size: {im.width}x{im.height}",
                              extracted=[str(png)],
                              artifacts=[{"name": png.name, "path": str(png),
                                          "size": png.stat().st_size},
                                         {"name": fixed.name, "path": str(fixed),
                                          "size": fixed.stat().st_size}])
        return ToolResult(self.name, status="skipped",
                          summary="zero tables, but no variant decodes")


register(JpegDqtAnalyzer())
