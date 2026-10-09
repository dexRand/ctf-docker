"""Image repair: corrupt JPEG/BMP headers (analogous to `png-repair`).

BMP: rebuild a standard BITMAPINFOHEADER when the pixel-data offset or DIB
size field is implausible, and recompute a height that is too small for the
actual pixel data (e.g. the picoCTF "tunn3l v1s10n" class of challenges).

JPEG: best-effort fix of a missing End-Of-Image marker (truncated file).
"""
from __future__ import annotations

import struct

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

_DIB_SIZES = {12, 40, 52, 56, 64, 108, 124}
_BMP_SIG = b"BM"
_JPEG_SIG = b"\xff\xd8"
_JPEG_EOI = b"\xff\xd9"


def _rowbytes(width: int, bpp: int) -> int:
    return ((width * bpp + 31) >> 5) * 4


def repair_bmp(data: bytes, log: list[str]) -> bytes | None:
    """Repair a BMP header. Returns the fixed bytes, or None if it is not a BMP."""
    if len(data) < 26 or not data.startswith(_BMP_SIG):
        return None

    def u32(o: int) -> int:
        return struct.unpack_from("<I", data, o)[0]

    file_size = u32(2)
    offset = u32(10)
    dib = u32(14)
    width = u32(18)
    height = u32(22)
    bpp = struct.unpack_from("<H", data, 28)[0]

    standard = (54 <= offset <= file_size) and dib in _DIB_SIZES
    row = _rowbytes(width, bpp) if standard and width > 0 and bpp > 0 else 0
    if not standard or row <= 0:
        log.append("non-standard header: rebuilding DIB/offset (40/54)")
        offset, dib = 54, 40
        row = _rowbytes(width, bpp)
    if row <= 0:
        return None
    available = max(0, file_size - offset)
    fitted = available // row
    if fitted <= 0:
        return None
    if fitted != height:
        log.append(f"height {height} -> {fitted} ({available} bytes, {row} B/row)")
        height = fitted

    out = bytearray(data)
    out[10:14] = offset.to_bytes(4, "little")
    out[14:18] = dib.to_bytes(4, "little")
    out[22:26] = (height & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out)


def repair_jpeg(data: bytes, log: list[str]) -> bytes | None:
    """Repair a truncated JPEG by appending the missing EOI marker.

    Returns the (possibly unchanged) bytes when the input is a JPEG, or None
    when it is not a JPEG at all.
    """
    if len(data) < 4 or not data.startswith(_JPEG_SIG):
        return None
    if data.endswith(_JPEG_EOI):
        return data
    log.append("missing EOI marker (FFD9): appended")
    return data + _JPEG_EOI


_IMG_MAGICS = (b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"BM", b"\xff\xd8")
_EMBED_MAGICS = ((b"GIF89a", ".gif"), (b"GIF87a", ".gif"),
                 (b"\x89PNG\r\n\x1a\n", ".png"), (b"\xff\xd8\xff", ".jpg"))


def carve_embedded(data: bytes, log: list[str], max_off: int = 64) -> tuple[bytes, str]:
    """If an image magic appears just after some leading garbage, slice from it.

    Covers the "corrupted file" trick: a valid GIF/PNG/JPEG preceded by a short
    junk prefix, so the file no longer starts with its magic.
    """
    if data.startswith(_IMG_MAGICS):
        return data, ""
    best: tuple[int, bytes, str] | None = None
    for magic, ext in _EMBED_MAGICS:
        i = data.find(magic, 1, max_off + len(magic))
        if i > 0 and (best is None or i < best[0]):
            best = (i, data[i:], ext)
    if best is None:
        return data, ""
    off, sliced, ext = best
    log.append(f"{ext} data found at offset {off}: sliced off {off} byte(s)")
    return sliced, ext


class ImageRepairAnalyzer(Analyzer):
    name = "image-repair"
    category = "extract"
    description = "Repair corrupted JPEG/BMP/PNG/GIF images (header, height, EOI, junk prefix)."
    # accepts everything: a corrupted image may have a wrong/absent extension
    # and `file` may not recognise it. We gate internally on signatures.
    accepts = ()
    display_order = 237

    def run(self, ctx: ToolContext) -> ToolResult:
        data = ctx.input.read_bytes()
        if not data:
            return ToolResult(self.name, status="skipped", summary="empty file")
        log: list[str] = []
        fixed: bytes | None = None
        ext = ""
        bmp = repair_bmp(data, log)
        if bmp is not None:
            fixed, ext = bmp, ".bmp"
        else:
            jpg = repair_jpeg(data, log)
            if jpg is not None:
                fixed, ext = jpg, ".jpg"
            else:
                carved, cext = carve_embedded(data, log)
                if cext:
                    fixed, ext = carved, cext
        if fixed is None:
            return ToolResult(self.name, status="skipped",
                              summary="not a repairable JPEG/BMP/PNG/GIF")
        if fixed == data:
            return ToolResult(self.name, status="done", summary="image already valid",
                              output="\n".join(log))
        out = ctx.sub(self.name) / (ctx.input.name + ".fixed" + ext)
        out.write_bytes(fixed)
        return ToolResult(self.name, status="done", output="\n".join(log),
                          summary="image repaired",
                          extracted=[str(out)],
                          artifacts=[{"name": out.name, "path": str(out),
                                      "size": out.stat().st_size}])


register(ImageRepairAnalyzer())