"""QR / barcode decoder (zbarimg)."""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult, out_of, which
from .registry import register

IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp",
           ".pbm", ".pgm", ".ppm")


class QrAnalyzer(Analyzer):
    name = "qr"
    category = "extract"
    description = "Decode QR codes and barcodes (zbarimg)."
    accepts = IMG_EXT
    display_order = 245

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("zbarimg"):
            return ToolResult(self.name, status="skipped", summary="zbarimg not installed")
        proc = ctx.run(["zbarimg", "--quiet", "--raw", str(ctx.input)], timeout=120)
        out = out_of(proc)
        if not out.strip():
            # zbarimg exits 4 when no symbol is found: informational, not an error
            return ToolResult(self.name, status="skipped", summary="nessun QR/barcode",
                              output=out[-1000:], exit_code=proc.returncode)
        n = len(out.splitlines())
        return ToolResult(self.name, status="done", summary=f"{n} codice/i decodificato/i",
                          output=out, exit_code=proc.returncode)


register(QrAnalyzer())
