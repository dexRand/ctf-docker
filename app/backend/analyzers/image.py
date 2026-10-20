"""Image steg analyzers that need Python (bit planes, channel remap)."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import IMG_EXT

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
        # OCR only the LSB (bit 0) of R/G/B: a flag drawn in the LSB is captured
        # with a light OCR pass, without scanning all 32 planes (slow).
        lines: list[str] = []
        try:
            from .vision import ocr_image
            for f in files:
                m = re.search(r"_([RGBA])(\d)\.png$", f.name)
                if not m or m.group(1) not in "RGB" or int(m.group(2)) != 0:
                    continue
                t = ocr_image(f, thorough=False)
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
    description = "Channel remaps + palette-index repaint (+OCR) to reveal hidden colours."
    accepts = IMG_EXT
    display_order = 355

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            import numpy as np
            from PIL import Image
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"PIL/numpy missing: {exc}")
        try:
            src = Image.open(ctx.input)
            src.load()
            img = src.convert("RGB")
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
        texts: list[str] = []
        if src.mode == "P":
            texts += self._palette_variants(src, ctx.input.stem, outdir, files)
        return ToolResult(
            self.name, status="done", summary=f"{len(files)} remap",
            output="\n".join(texts),
            artifacts=[{"name": str(f.relative_to(ctx.workdir)), "path": str(f), "size": f.stat().st_size} for f in files],
        )

    @staticmethod
    def _palette_variants(src, stem: str, outdir: Path, files: list[Path]) -> list[str]:
        """Palette images can hide a picture in entries with (almost) the same
        colour (TJCTF "pals"): repaint by palette *index*, then OCR."""
        import numpy as np
        from PIL import Image
        idx = np.asarray(src)
        counts = np.bincount(idx.reshape(-1), minlength=256)
        bg = int(counts.argmax())
        n = len(counts)
        # one clearly different colour per index (hues spread by the golden ratio)
        hues = [Image.new("HSV", (1, 1), (int(i * 0.618034 * 255) % 256, 255, 255)).convert("RGB").getpixel((0, 0))
                for i in range(n)]
        lut = np.array(hues, dtype=np.uint8)
        lut[bg] = (255, 255, 255)
        variants = {"palette-index": lut[idx],
                    "palette-mask": np.where(idx == bg, 255, 0).astype(np.uint8)}
        texts = []
        try:
            from .vision import ocr_image
        except Exception:
            def ocr_image(_p, **_kw) -> str:
                return ""
        for name, arr in variants.items():
            fn = outdir / f"{stem}_{name}.png"
            Image.fromarray(arr).save(fn)
            files.append(fn)
            t = ocr_image(fn, thorough=False)
            if t:
                texts.append(f"{name}: {t}")
        return texts


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
            def ocr_image(_p, **_kw) -> str:
                return ""
        for name, v in variants.items():
            fn = outdir / f"{ctx.input.stem}_{name}.png"
            v.save(fn)
            files.append(fn)
            t = ocr_image(fn, thorough=False)
            if t:
                texts.append(f"{name}: {t}")
        return ToolResult(
            self.name, status="done", summary=f"{len(files)} variant(s)", output="\n".join(texts),
            artifacts=[{"name": str(f.relative_to(ctx.workdir)), "path": str(f), "size": f.stat().st_size} for f in files],
        )


register(BitPlanesAnalyzer())
register(ChannelRemapAnalyzer())
register(ImageEnhanceAnalyzer())
