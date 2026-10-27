"""PDF analyzers: embedded images and encryption.

`pdftotext` only sees the text layer. CTF PDFs often draw the flag inside an
image (UTCTF 2024 "contract": the flag is one of nine embedded pictures, covered
by the page layout), or lock the whole document, which the auto-crack can open
with `pdfcrack` only if something says the file is encrypted.
"""
from __future__ import annotations

from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register

_MAX_IMAGES = 20
_SMALL = 1000          # px on the long side: a logo/QR/flag graphic, not a page


class PdfAnalyzer(Analyzer):
    """Report an encrypted PDF so the pipeline auto-cracks it."""
    name = "pdf"
    category = "extract"
    description = "PDF guard: an encrypted document is reported as locked for the auto-crack."
    accepts = (".pdf",)
    display_order = 114

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            size = ctx.input.stat().st_size
            with open(ctx.input, "rb") as fh:
                head = fh.read(1 << 20)
                encrypted = b"/Encrypt" in head
                if not encrypted and size > len(head):
                    fh.seek(max(len(head), size - 65536))
                    encrypted = b"/Encrypt" in fh.read()
        except OSError as exc:
            return ToolResult(self.name, status="skipped", summary=f"cannot read: {exc}")
        if not encrypted:
            return ToolResult(self.name, status="skipped", summary="not encrypted")
        return ToolResult(self.name, status="skipped", summary="encrypted PDF (/Encrypt)",
                          needs_password=True)


def _small_image(path: Path) -> bool:
    try:
        from PIL import Image
        with Image.open(path) as im:
            return max(im.size) <= _SMALL
    except Exception:
        return False


class PdfImagesAnalyzer(Analyzer):
    """Every image inside the PDF, hidden or covered ones included."""
    name = "pdf-images"
    category = "extract"
    description = "Images embedded in a PDF (pdfimages -all) for OCR and image stego."
    accepts = (".pdf",)
    display_order = 242

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("pdfimages"):
            return ToolResult(self.name, status="skipped", summary="pdfimages not installed")
        outdir = ctx.sub(self.name)
        outdir.mkdir(parents=True, exist_ok=True)
        proc = ctx.run(["pdfimages", "-all", str(ctx.input), str(outdir / "img")], timeout=180)
        imgs = sorted(p for p in outdir.iterdir() if p.is_file() and p.name.startswith("img"))
        if not imgs:
            return ToolResult(self.name, status="skipped",
                              summary=f"no embedded images ({proc.returncode})")
        keep = imgs[:_MAX_IMAGES]
        # A PDF that already has a text layer needs no OCR of the page-sized
        # background images (each one cost ~200 s of OCR + bit planes on the
        # UTCTF "contract"); the flag, when it is a picture, is a small one.
        txt = ctx.run(["pdftotext", str(ctx.input), "-"], timeout=60).stdout or ""
        if len(txt.strip()) >= 200:
            small = [p for p in keep if _small_image(p)]
            if small:
                keep = small
        return ToolResult(self.name, status="done",
                          summary=f"{len(keep)} embedded image(s)"
                                  + (f" of {len(imgs)}" if len(imgs) > len(keep) else ""),
                          output="\n".join(f"{p.name}  {p.stat().st_size} B" for p in keep),
                          extracted=[str(p) for p in keep],
                          artifacts=[{"name": p.name, "path": str(p),
                                      "size": p.stat().st_size} for p in keep])


register(PdfAnalyzer())
register(PdfImagesAnalyzer())
