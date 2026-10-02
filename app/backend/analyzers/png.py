"""PNG structure analyzer: dump non-standard chunks (tEXt/iTXt/zTXt/eXIf) text."""
from __future__ import annotations

import struct

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

TEXT_CHUNKS = {"tEXt", "iTXt", "zTXt", "eXIf"}
KNOWN = {"IHDR", "IDAT", "IEND", "PLTE"}


class PngChunksAnalyzer(Analyzer):
    name = "png-chunks"
    category = "steg"
    description = "Dump PNG chunks and the text of tEXt/iTXt/zTXt/eXIf (hidden metadata)."
    accepts = (".png",)
    display_order = 335

    def run(self, ctx: ToolContext) -> ToolResult:
        data = ctx.input.read_bytes()
        if data[:8] != b"\x89PNG\r\n\x1a\n":
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
                        import zlib
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


register(PngChunksAnalyzer())
