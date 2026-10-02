"""PNG analyzers: chunk/text dump + repair of corrupted files."""
from __future__ import annotations

import struct
import zlib

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
                    body = cdata.split(b"\x00", 1)[1]
                    try:
                        text = zlib.decompress(body).decode("utf-8", "replace")
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
            return ToolResult(self.name, status="skipped", summary="non è un PNG")
        fixed, log = repair_png(data)
        if fixed[:8] != PNG_SIG:
            return ToolResult(self.name, status="skipped", summary="non riparabile")
        if fixed == data:
            return ToolResult(self.name, status="done", summary="PNG già valido",
                              output="\n".join(log))
        out = ctx.sub(self.name) / (ctx.input.name + ".fixed.png")
        out.write_bytes(fixed)
        return ToolResult(self.name, status="done", output="\n".join(log),
                          summary="PNG riparato" + (f" ({len(log)} fix)" if log else ""),
                          extracted=[str(out)],
                          artifacts=[{"name": out.name, "path": str(out),
                                      "size": out.stat().st_size}])


register(PngChunksAnalyzer())
register(PngRepairAnalyzer())
