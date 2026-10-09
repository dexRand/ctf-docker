"""LSB bit-plane carving.

zsteg can extract the raw bit stream for a given spec; a hidden archive/image is
often that stream with a short junk prefix (e.g. a zip right after 3 bytes). Try
a few common specs and carve any embedded file magic found in the stream.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register

# bit 1/2 of the low channels, both bit orders, plus one deeper plane
_SPECS = ["b1,bgr,lsb,xy", "b1,rgba,lsb,xy", "b2,bgr,lsb,xy", "b2,rgba,lsb,xy",
          "b1,bgr,msb,xy", "b2,bgr,msb,xy", "b3,rgba,lsb,xy"]
_MAGICS = [(b"PK\x03\x04", ".zip"), (b"\x89PNG\r\n\x1a\n", ".png"), (b"%PDF", ".pdf"),
           (b"GIF89a", ".gif"), (b"GIF87a", ".gif"), (b"\xff\xd8\xff", ".jpg"),
           (b"\x1f\x8b\x08", ".gz"), (b"BZh", ".bz2"), (b"\xfd7zXZ", ".xz")]
_MIN = 64


class LsbCarveAnalyzer(Analyzer):
    name = "lsb-carve"
    category = "steg"
    description = "Carve a hidden file (zip/png/pdf…) out of the LSB bit planes of a PNG/BMP."
    accepts = (".png", ".bmp")
    display_order = 336

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("zsteg"):
            return ToolResult(self.name, status="skipped", summary="zsteg not installed")
        outdir = ctx.sub(self.name)
        produced: list[Path] = []
        seen: set[tuple] = set()
        for spec in _SPECS:
            try:
                proc = subprocess.run(["zsteg", "-e", spec, str(ctx.input)],
                                      capture_output=True, timeout=120,
                                      stdin=subprocess.DEVNULL)
            except (OSError, subprocess.TimeoutExpired):
                continue
            data = proc.stdout or b""
            if len(data) < _MIN:
                continue
            for magic, ext in _MAGICS:
                i = data.find(magic)
                if i == -1:
                    continue
                carved = data[i:]
                if len(carved) < _MIN:
                    break
                key = (ext, len(carved))
                if key in seen:
                    break
                seen.add(key)
                fn = outdir / f"{ctx.input.stem}__{spec.replace(',', '-')}{ext}"
                fn.write_bytes(carved)
                produced.append(fn)
                break
        if not produced:
            return ToolResult(self.name, status="done", summary="no embedded file in the LSB")
        return ToolResult(
            self.name, status="done", summary=f"{len(produced)} carved file(s)",
            extracted=[str(f) for f in produced],
            artifacts=[{"name": f.name, "path": str(f), "size": f.stat().st_size} for f in produced],
        )


register(LsbCarveAnalyzer())
