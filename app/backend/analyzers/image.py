"""Image steg analyzers that need Python (bit planes, channel remap)."""
from __future__ import annotations

from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

IMG_EXT = (".png", ".bmp", ".jpg", ".jpeg", ".gif", ".tiff", ".webp")
MAX_PIXELS = 12_000_000


class BitPlanesAnalyzer(Analyzer):
    name = "bit-planes"
    category = "steg"
    description = "Visualise each bit plane per channel (LSB stego detection)."
    accepts = IMG_EXT
    display_order = 350

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            import numpy as np
            from PIL import Image
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"PIL/numpy missing: {exc}")
        try:
            img = Image.open(ctx.input).convert("RGBA")
        except Exception as exc:
            return ToolResult(self.name, status="error", summary=f"cannot open image: {exc}")
        w, h = img.size
        if w * h > MAX_PIXELS:
            return ToolResult(self.name, status="skipped", summary=f"image too big ({w}x{h})")
        arr = np.asarray(img)
        outdir = ctx.sub(self.name)
        files: list[Path] = []
        for ci, ch in enumerate("RGBA"):
            for bit in range(8):
                plane = (((arr[:, :, ci] >> bit) & 1) * 255).astype("uint8")
                fn = outdir / f"{ctx.input.stem}_{ch}{bit}.png"
                Image.fromarray(plane, mode="L").save(fn)
                files.append(fn)
        return ToolResult(
            self.name, status="done", summary=f"{len(files)} bit-plane",
            artifacts=[{"name": str(f.relative_to(ctx.workdir)), "path": str(f), "size": f.stat().st_size} for f in files],
        )


class ChannelRemapAnalyzer(Analyzer):
    name = "channel-remap"
    category = "steg"
    description = "Random channel/palette remaps to reveal hidden colours."
    accepts = IMG_EXT
    display_order = 355

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            import numpy as np
            from PIL import Image
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"PIL/numpy missing: {exc}")
        try:
            img = Image.open(ctx.input).convert("RGB")
        except Exception as exc:
            return ToolResult(self.name, status="error", summary=f"cannot open image: {exc}")
        if img.size[0] * img.size[1] > MAX_PIXELS:
            return ToolResult(self.name, status="skipped", summary="image too big")
        arr = np.asarray(img)
        rng = np.random.default_rng(1234)
        outdir = ctx.sub(self.name)
        files: list[Path] = []
        for i in range(8):
            perm = rng.permutation(3)
            remapped = arr[:, :, perm]
            fn = outdir / f"{ctx.input.stem}_remap{i}.png"
            Image.fromarray(remapped).save(fn)
            files.append(fn)
        return ToolResult(
            self.name, status="done", summary=f"{len(files)} remap",
            artifacts=[{"name": str(f.relative_to(ctx.workdir)), "path": str(f), "size": f.stat().st_size} for f in files],
        )


register(BitPlanesAnalyzer())
register(ChannelRemapAnalyzer())
