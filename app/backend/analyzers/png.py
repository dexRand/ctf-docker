"""PNG analyzers: chunk/text dump + repair of corrupted files."""
from __future__ import annotations

import math
import os
import shutil
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

TEXT_CHUNKS = {"tEXt", "iTXt", "zTXt", "eXIf"}
KNOWN = {"IHDR", "IDAT", "IEND", "PLTE"}
PNG_SIG = b"\x89PNG\r\n\x1a\n"

# chunk types we accept while re-synchronising after a corrupted length/type
_CHUNK_TYPES = {b"IHDR", b"IDAT", b"IEND", b"PLTE", b"pHYs", b"sRGB", b"tEXt", b"iTXt",
                b"zTXt", b"gAMA", b"bKGD", b"cHRM", b"eXIf", b"tIME", b"iCCP", b"sBIT",
                b"hIST", b"sPLT", b"tRNS", b"acTL", b"fcTL", b"fdAT", b"cICP", b"mDCv",
                b"cLLi"}


class PngChunksAnalyzer(Analyzer):
    name = "png-chunks"
    category = "steg"
    description = "Dump PNG chunks and the text of tEXt/iTXt/zTXt/eXIf (hidden metadata)."
    accepts = (".png",)
    display_order = 335

    def run(self, ctx: ToolContext) -> ToolResult:
        data = ctx.input.read_bytes()
        if data[:8] != PNG_SIG:
            return ToolResult(self.name, status="skipped", summary="not a PNG")
        pos = 8
        lines: list[str] = []
        while pos + 8 <= len(data):
            try:
                length = struct.unpack(">I", data[pos:pos + 4])[0]
            except struct.error:
                break
            ctype = data[pos + 4:pos + 8].decode("latin-1", "replace")
            cdata = data[pos + 8:pos + 8 + length]
            pos += 12 + length
            if ctype in TEXT_CHUNKS:
                if ctype == "zTXt":
                    # keyword \0 method byte, then zlib data (a bad chunk may lack the NUL)
                    key, _, rest = cdata.partition(b"\x00")
                    try:
                        text = (key.decode("latin-1") + " = "
                                + zlib.decompress(rest[1:]).decode("utf-8", "replace"))
                    except Exception:
                        text = cdata.decode("utf-8", "replace")
                else:
                    text = cdata.decode("utf-8", "replace")
                lines.append(f"{ctype}: {text}")
            elif ctype not in KNOWN:
                lines.append(f"{ctype} ({length} bytes)")
            if ctype == "IEND":
                trailing = len(data) - pos
                if trailing:
                    lines.append(f"trailing after IEND: {trailing} bytes "
                                 f"(starts {data[pos:pos + 8].hex()})")
                break
        return ToolResult(self.name, status="done", output="\n".join(lines),
                          summary=f"{len(lines)} chunk")


def _next_chunk_type(buf: bytearray, start: int) -> int | None:
    """Offset of the next plausible known chunk type at/after `start`."""
    for p in range(start, len(buf) - 4):
        if bytes(buf[p:p + 4]) in _CHUNK_TYPES and p >= 4:
            ln = int.from_bytes(buf[p - 4:p], "big")
            if ln <= len(buf) - p:
                return p
    return None


def repair_png(data: bytes) -> tuple[bytes, list[str]]:
    """Best-effort PNG repair: signature, corrupted chunk types/lengths, CRCs."""
    out = bytearray(data)
    if len(out) < 16:
        return bytes(out), ["file too small"]
    out[0:8] = PNG_SIG
    log: list[str] = []
    o, end = 8, len(out)
    while o + 8 <= end:
        length = int.from_bytes(out[o:o + 4], "big")
        ctype = bytes(out[o + 4:o + 8])
        if o == 8 or bytes(out[o + 2:o + 4]) == b"DR":
            # first chunk / IHDR whose type bytes were corrupted
            ctype, length = b"IHDR", 13
            out[o:o + 4] = (13).to_bytes(4, "big")
            out[o + 4:o + 8] = b"IHDR"
        elif not ctype.isalpha():
            np_ = _next_chunk_type(out, o + 8)
            guess = bytes(out[np_:np_ + 4]) if np_ is not None else b"IDAT"
            log.append(f"chunk type {ctype!r} -> {guess!r}")
            ctype = guess
            out[o + 4:o + 8] = ctype
        if ctype == b"IEND":
            length = 0
            out[o:o + 4] = (0).to_bytes(4, "big")
        dstart, dend = o + 8, o + 8 + length
        if (length == 0 and ctype != b"IEND") or length > end - dstart - 4:
            np_ = _next_chunk_type(out, dstart + 1)
            if np_ is None:
                log.append(f"{ctype.decode('latin-1')} bad length, stop")
                break
            length = (np_ - 4) - dstart - 4
            out[o:o + 4] = length.to_bytes(4, "big")
            dend = dstart + length
            log.append(f"{ctype.decode('latin-1')} length -> {length}")
        crc = zlib.crc32(bytes(out[o + 4:dend])) & 0xffffffff
        out[dend:dend + 4] = crc.to_bytes(4, "big")
        name = bytes(out[o + 4:o + 8])
        o = dend + 4
        if name == b"IEND":
            break
    return bytes(out), log


class PngRepairAnalyzer(Analyzer):
    name = "png-repair"
    category = "extract"
    description = "Repair a corrupted PNG (signature, chunk types/lengths, CRCs)."
    # accepts everything: a corrupted PNG may have a wrong/absent extension and
    # `file` may not recognise it. We gate internally by looking for PNG chunks.
    accepts = ()
    display_order = 236

    def run(self, ctx: ToolContext) -> ToolResult:
        data = ctx.input.read_bytes()
        looks_png = (data[:8] == PNG_SIG
                     or b"IHDR" in data[:64]
                     or b"IDAT" in data[:8192]
                     or bytes(data[12:16]) == b'C"DR')
        if not looks_png:
            return ToolResult(self.name, status="skipped", summary="not a PNG")
        fixed, log = repair_png(data)
        if fixed[:8] != PNG_SIG:
            return ToolResult(self.name, status="skipped", summary="not repairable")
        if fixed == data:
            return ToolResult(self.name, status="done", summary="PNG already valid",
                              output="\n".join(log))
        out = ctx.sub(self.name) / (ctx.input.name + ".fixed.png")
        out.write_bytes(fixed)
        return ToolResult(self.name, status="done", output="\n".join(log),
                          summary="PNG repaired" + (f" ({len(log)} fix)" if log else ""),
                          extracted=[str(out)],
                          artifacts=[{"name": out.name, "path": str(out),
                                      "size": out.stat().st_size}])


register(PngChunksAnalyzer())
register(PngRepairAnalyzer())


_IDAT_MAX = 256 << 20        # a decoded IDAT above this is a bomb, not a picture


def _chunk(ctype: bytes, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload)) + ctype + payload
            + struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF))


def _idat_bytes(data: bytes) -> bytes:
    pos, out = 8, bytearray()
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        if ctype == b"IDAT":
            out += data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if ctype == b"IEND":
            break
    return bytes(out)


def _zstd_limited(blob: bytes, limit: int, tmpdir: Path) -> bytes | None:
    """zstd -d with a hard output cap (a decompression bomb must not fill RAM)."""
    if not shutil.which("zstd"):
        return None
    tmpdir.mkdir(parents=True, exist_ok=True)
    tmp = tmpdir / "idat.bin"
    tmp.write_bytes(blob)
    try:
        proc = subprocess.Popen(["zstd", "-d", "-c", "-q", str(tmp)],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            return proc.stdout.read(limit + 1) or None
        finally:
            proc.kill()
            proc.wait(timeout=10)
    except OSError:
        return None
    finally:
        tmp.unlink(missing_ok=True)


def rebuild_idat_png(data: bytes, log: list[str], tmpdir: Path) -> bytes | None:
    """Rebuild a PNG whose IDAT is zstd/raw deflate instead of zlib.

    The IHDR can lie about the size (miniscule: 3x32 for an 800x800 image), so
    the width/height are inferred from the decompressed scanlines."""
    idat = _idat_bytes(data)
    if not idat:
        return None
    try:
        zlib.decompressobj().decompress(idat, 64)
        return None                              # a normal zlib IDAT
    except zlib.error:
        pass
    raw, how = _zstd_limited(idat, _IDAT_MAX, tmpdir), "zstd"
    if not raw:
        try:
            raw = zlib.decompressobj(-15).decompress(idat, _IDAT_MAX + 1)
            how = "raw deflate"
        except zlib.error:
            raw = None
    if not raw:
        log.append("IDAT: not zlib/zstd/deflate")
        return None
    if len(raw) > _IDAT_MAX:
        log.append(f"IDAT: decompresses over {_IDAT_MAX >> 20} MiB")
        return None
    for ch, ctype in ((3, 2), (4, 6), (1, 0)):
        w = math.isqrt(max(1, len(raw) // ch))
        while w > 1 and len(raw) % (w * ch + 1):
            w -= 1
        if w <= 1 or len(raw) % (w * ch + 1):
            continue
        h = len(raw) // (w * ch + 1)
        if h < 2 or h > w * 4:
            continue
        log.append(f"IDAT: {len(raw)} B ({how}) -> PNG {w}x{h} ({ch} channels)")
        ihdr = struct.pack(">IIBBBBB", w, h, 8, ctype, 0, 0, 0)
        return (PNG_SIG + _chunk(b"IHDR", ihdr)
                + _chunk(b"IDAT", zlib.compress(raw, 6)) + _chunk(b"IEND", b""))
    log.append(f"IDAT: decompressed {len(raw)} B, size unknown")
    return None


class PngIdatAnalyzer(Analyzer):
    """PNG whose IDAT is not zlib (e.g. zstd): TJCTF 2023 "miniscule".

    A normal PNG compresses IDAT with zlib. When that fails, try zstd / raw
    deflate, rebuild a valid PNG from the decompressed scanlines (inferring the
    real size) and hand it to the pipeline so OCR/vision can read it.
    """
    name = "png-idat"
    category = "steg"
    description = "PNG with a non-zlib IDAT (zstd / raw deflate): rebuild a valid PNG."
    accepts = (".png",)
    display_order = 334

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            data = ctx.input.read_bytes()
        except OSError:
            return ToolResult(self.name, status="skipped", summary="unreadable")
        if data[:8] != PNG_SIG:
            return ToolResult(self.name, status="skipped", summary="not a PNG")
        log: list[str] = []
        png = rebuild_idat_png(data, log, ctx.sub(self.name))
        if not png:
            return ToolResult(self.name, status="skipped", summary="IDAT is zlib or unknown",
                              output="\n".join(log))
        out = ctx.sub(self.name) / (ctx.input.stem + ".idat.png")
        out.write_bytes(png)
        try:                                   # normalise so OCR reads it reliably
            from PIL import Image
            img = Image.open(out)
            img.load()
            img.save(out)
        except Exception:
            pass
        return ToolResult(self.name, status="done",
                          summary=log[-1] if log else "IDAT rebuilt",
                          output="\n".join(log),
                          extracted=[str(out)],
                          artifacts=[{"name": out.name, "path": str(out),
                                      "size": out.stat().st_size}])


register(PngIdatAnalyzer())
