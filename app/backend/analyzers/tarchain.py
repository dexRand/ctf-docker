"""Chains of nested tar archives ("like1000": 1000.tar -> 999.tar -> ... -> flag.png).

The pipeline stops at `MAX_DEPTH` (6) and unpacks to disk, so a thousand layers
never reach the bottom. This walks the chain **in memory** (bounded) and hands
over the innermost files; for a picture it also runs a binarized 2x OCR pass,
because the flag is usually drawn tiny at the bottom of the stack.
"""
from __future__ import annotations

import io
import tarfile
import time

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

_MAX_LAYERS = 5000
_MAX_INPUT = 64 << 20            # a single archive of the chain
_DEADLINE = 60                   # seconds: each layer replaces the previous one


def is_tar(blob: bytes) -> bool:
    return len(blob) >= 262 and blob[257:262] == b"ustar"


def _inner_tar(blob: bytes) -> bytes | None:
    """The single `.tar` member of an archive, or None when this is the bottom."""
    try:
        with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            tars = [m for m in members if m.name.lower().endswith((".tar", ".tar.gz", ".tgz"))]
            if len(tars) != 1:
                return None
            fh = tf.extractfile(tars[0])
            return fh.read() if fh else None
    except (tarfile.TarError, OSError, EOFError):
        return None


def _bottom_files(blob: bytes) -> list[tuple[str, bytes]]:
    """Files of the last archive of the chain."""
    try:
        with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
            out: list[tuple[str, bytes]] = []
            for m in tf.getmembers():
                if not m.isfile() or m.size > (16 << 20):
                    continue
                fh = tf.extractfile(m)
                if fh:
                    out.append((m.name, fh.read()))
            return out[:20]
    except (tarfile.TarError, OSError, EOFError):
        return []


class TarChainAnalyzer(Analyzer):
    name = "tar-chain"
    category = "extract"
    description = "Nested tar chains (1000.tar → 999.tar → …): walk in memory, keep the innermost files."
    accepts = (".tar", "application/x-tar")
    display_order = 217

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            if ctx.input.stat().st_size > _MAX_INPUT:
                return ToolResult(self.name, status="skipped", summary="archive too big")
            blob = ctx.input.read_bytes()
        except OSError as exc:
            return ToolResult(self.name, status="skipped", summary=f"cannot read: {exc}")
        if not is_tar(blob):
            return ToolResult(self.name, status="skipped", summary="not a tar")
        if _inner_tar(blob) is None:
            return ToolResult(self.name, status="skipped", summary="no nested tar chain")
        started = time.monotonic()
        layers = 0
        while layers < _MAX_LAYERS:
            if time.monotonic() - started > _DEADLINE:
                break
            inner = _inner_tar(blob)
            if inner is None or len(inner) > _MAX_INPUT:
                break
            blob = inner           # only one layer is held in memory at a time
            layers += 1
        files = _bottom_files(blob)
        if not files:
            return ToolResult(self.name, status="skipped",
                              summary=f"{layers} layer(s), no readable file at the bottom")
        outdir = ctx.sub(self.name)
        outdir.mkdir(parents=True, exist_ok=True)
        produced: list = []
        for name, data in files:
            clean = name.rsplit("/", 1)[-1] or f"layer{layers}.bin"
            dest = outdir / f"{layers}__{clean}"
            dest.write_bytes(data)
            produced.append(dest)
        text = [f"layers: {layers}", "innermost files: " + ", ".join(p.name for p in produced)]
        # the flag is often drawn tiny in the last picture: OCR a sharpened 2x copy
        for dest in produced:
            if dest.suffix.lower() not in (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff"):
                continue
            try:
                from PIL import Image
                from .vision import _confusable_variants, ocr_image
                with Image.open(dest) as im:
                    gray = im.convert("L")
                    if max(gray.size) > 4000:
                        continue
                    big = gray.resize((gray.width * 2, gray.height * 2), Image.LANCZOS)
                    sharp = outdir / (dest.stem + ".ocr.png")
                    big.point(lambda v: 0 if v < 128 else 255).save(sharp)
                found = ocr_image(sharp, timeout=120, thorough=False)
                variants = _confusable_variants(found)
                if found or variants:
                    text.append("== OCR (2x binarized) ==\n" + found[:4000])
                if variants:
                    text.append("== OCR normalized ==\n" + variants[:4000])
            except Exception as exc:            # OCR is best effort
                ctx.log(f"ocr skipped: {type(exc).__name__}: {exc}")
        return ToolResult(self.name, status="done",
                          summary=f"{layers} nested layer(s), {len(produced)} file(s) at the bottom",
                          output="\n".join(text),
                          extracted=[str(p) for p in produced],
                          artifacts=[{"name": p.name, "path": str(p),
                                      "size": p.stat().st_size} for p in produced])


register(TarChainAnalyzer())
