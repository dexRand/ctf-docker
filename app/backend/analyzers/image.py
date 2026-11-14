"""Image steg analyzers that need Python (bit planes, channel remap)."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import IMG_EXT, magic_ext, load_image
from ..magic import MAGICS

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
        img, err = load_image(self.name, ctx.input, "RGBA")
        if err:
            return err
        w, h = img.size
        if w * h > MAX_PIXELS:
            return ToolResult(self.name, status="skipped", summary=f"image too big ({w}x{h})")
        arr = np.asarray(img)
        outdir = ctx.sub(self.name)
        files: list[Path] = []
        for ci, ch in enumerate("RGBA"):
            for bit in range(8):
                plane = (((arr[:, :, ci] >> bit) & 1)).astype(bool)
                fn = outdir / f"{ctx.input.stem}_{ch}{bit}.png"
                Image.fromarray(plane).save(fn)     # 1-bit PNG: 8x smaller/faster
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
                t = ocr_image(f, thorough=False, max_dim=800)
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
        src, err = load_image(self.name, ctx.input)     # palette kept for the P-mode variants
        if err:
            return err
        img = src.convert("RGB")
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
        img, err = load_image(self.name, ctx.input, "RGB")
        if err:
            return err
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


_PIL_EXT = {"PNG": ".png", "JPEG": ".jpg", "GIF": ".gif", "BMP": ".bmp", "TIFF": ".tif",
            "WEBP": ".webp", "SGI": ".sgi", "TGA": ".tga", "QOI": ".qoi", "PPM": ".ppm",
            "ICO": ".ico", "DDS": ".dds", "PCX": ".pcx"}
_MAX_CHAIN = 32


def _pixel_bytes(img) -> bytes:
    return img.tobytes()


_GRAY_PROBE = 64            # pixels of row 0 checked before reading the payload
_GRAY_MAX = 4 << 20          # bytes of one channel kept (bounded by MAX_PIXELS)
_GRAY_SKIP_EXT = {".bmp", ".exe", ".gz"}   # short/misleading signatures


def _gray_run(raw: bytes, channels: int, limit: int) -> bytes:
    """One channel of the gray pixels at the start of `raw` (R=G=B), stopping at
    the first non-gray pixel or after `limit` bytes."""
    out = bytearray()
    for i in range(0, len(raw), channels):
        px = raw[i:i + channels]
        if len(px) < channels or px[0] != px[1] or px[1] != px[2]:
            break
        out.append(px[0])
        if len(out) >= limit:
            break
    return bytes(out)


def _gray_payload(raw: bytes, channels: int) -> tuple[bytes, str]:
    """A whole file drawn as gray pixels (one byte per pixel) at the start of
    `raw`, as (bytes, extension), else (b"", ""). Only a strong (>=4 byte)
    magic counts: short ones ("BM", "MZ", gzip) match a gray gradient by chance."""
    if channels < 3:
        return b"", ""
    head = _gray_run(raw[:channels * _GRAY_PROBE], channels, _GRAY_PROBE)
    ext = next((e for sig, e in MAGICS
                if len(sig) >= 4 and e not in _GRAY_SKIP_EXT and head.startswith(sig)), "")
    if not ext:
        return b"", ""
    return _gray_run(raw, channels, _GRAY_MAX), ext


def _as_image(raw: bytes):
    """The image Pillow finds in `raw` (fully decoded, not tiny), else None."""
    import io
    from PIL import Image
    try:
        im = Image.open(io.BytesIO(raw))
        im.load()
    except Exception:
        return None
    return im if im.size[0] * im.size[1] >= 16 else None


class PixelBytesAnalyzer(Analyzer):
    """The raw pixel bytes can be a whole file (TJCTF "purified": QOI -> PNG ->
    SGI -> TGA -> WEBP -> TIFF -> BMP -> PNG, each the pixels of the previous).
    The chain is followed here (deeper than the tree's MAX_DEPTH); the last image,
    or a non-image file found by its signature, becomes a child."""
    name = "pixel-bytes"
    category = "steg"
    description = "Raw pixel bytes that are a file of their own (an image chain, a zip…), followed to the end."
    accepts = IMG_EXT
    display_order = 338

    def run(self, ctx: ToolContext) -> ToolResult:
        img, err = load_image(self.name, ctx.input)
        if err:
            return err
        chain = [img.format or "?"]
        last_img, last_raw, file_ext = None, None, ""
        gray = False
        cur = img
        for _ in range(_MAX_CHAIN):
            if cur.size[0] * cur.size[1] > MAX_PIXELS:
                break
            raw = _pixel_bytes(cur)
            nxt = _as_image(raw)
            if nxt is None:
                file_ext = magic_ext(raw)          # pixels that are a zip/pdf/…
                if file_ext:
                    last_raw = raw
                elif cur.mode in ("RGB", "RGBA"):
                    gray_raw, gray_ext = _gray_payload(raw, len(cur.mode))
                    if gray_ext:
                        last_raw, file_ext, gray = gray_raw, gray_ext, True
                break
            chain.append(nxt.format or "?")
            last_img, last_raw, cur = nxt, raw, nxt
        if last_raw is None:
            return ToolResult(self.name, status="skipped", summary="pixels are not a file")
        outdir = ctx.sub(self.name)
        ext = file_ext or _PIL_EXT.get(last_img.format or "", ".bin")
        fn = outdir / f"{ctx.input.stem}_pixels_{len(chain) - 1}{ext}"
        if not file_ext and ext not in (".png", ".jpg", ".gif", ".bmp"):
            fn = fn.with_suffix(".png")            # exotic format: hand over a PNG
            last_img.save(fn)
        else:
            fn.write_bytes(last_raw)
        summary = (f"gray pixels -> {file_ext}" if gray else
                   f"pixels -> {' -> '.join(chain[1:])}" + (f" -> {file_ext}" if file_ext else ""))
        return ToolResult(self.name, status="done",
                          summary=summary,
                          output="chain: " + " -> ".join(chain) + (f" -> {file_ext} file" if file_ext else ""),
                          extracted=[str(fn)],
                          artifacts=[{"name": fn.name, "path": str(fn), "size": fn.stat().st_size}])


register(BitPlanesAnalyzer())
register(PixelBytesAnalyzer())
register(ChannelRemapAnalyzer())
register(ImageEnhanceAnalyzer())
