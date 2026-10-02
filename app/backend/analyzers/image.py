"""Image steg analyzers that need Python (bit planes, channel remap)."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

IMG_EXT = (".png", ".bmp", ".jpg", ".jpeg", ".gif", ".tiff", ".webp")
MAX_PIXELS = 4_000_000  # larger images: skip the heavy plane generation


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
        # OCR only the LSB planes (bit 0/1): a flag drawn in the LSB is captured
        # without OCR-ing all 32 planes (slow on big images).
        lines: list[str] = []
        try:
            from .vision import ocr_image
            for f in files:
                m = re.search(r"_([RGBA])(\d)\.png$", f.name)
                if not m or int(m.group(2)) > 1:
                    continue
                t = ocr_image(f)
                if t:
                    lines.append(f"{f.name}: {t}")
        except Exception:
            pass
        return ToolResult(
            self.name, status="done", summary=f"{len(files)} bit-plane",
            output="\n".join(lines),
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


class ImageEnhanceAnalyzer(Analyzer):
    name = "image-enhance"
    category = "vision"
    description = ("Levels/auto-contrast/equalize/highlights variants + OCR "
                   "(text hidden in the brightest pixels).")
    accepts = IMG_EXT
    display_order = 356

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            import numpy as np
            from PIL import Image, ImageOps
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"PIL/numpy missing: {exc}")
        try:
            img = Image.open(ctx.input).convert("RGB")
        except Exception as exc:
            return ToolResult(self.name, status="error", summary=f"cannot open image: {exc}")
        if img.size[0] * img.size[1] > MAX_PIXELS:
            return ToolResult(self.name, status="skipped", summary="image too big")
        arr = np.asarray(img).astype("int16")
        variants = {
            "autocontrast": ImageOps.autocontrast(img),
            "equalize": ImageOps.equalize(img),
            "invert": ImageOps.invert(img),
            "highlights": Image.fromarray(np.clip((arr - 200) * 255 // 55, 0, 255).astype("uint8")),
            "shadows": Image.fromarray(np.clip(arr * 255 // 64, 0, 255).astype("uint8")),
        }
        outdir = ctx.sub(self.name)
        files = []
        texts = []
        try:
            from .vision import ocr_image
        except Exception:
            ocr_image = lambda _p: ""
        for name, v in variants.items():
            fn = outdir / f"{ctx.input.stem}_{name}.png"
            v.save(fn)
            files.append(fn)
            t = ocr_image(fn)
            if t:
                texts.append(f"{name}: {t}")
        return ToolResult(
            self.name, status="done", summary=f"{len(files)} varianti", output="\n".join(texts),
            artifacts=[{"name": str(f.relative_to(ctx.workdir)), "path": str(f), "size": f.stat().st_size} for f in files],
        )


register(BitPlanesAnalyzer())
register(ChannelRemapAnalyzer())
register(ImageEnhanceAnalyzer())
