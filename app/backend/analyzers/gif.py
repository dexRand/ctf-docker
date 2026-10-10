"""Animated GIF analysis: frames, frame-diff, and frame-delay decoding (vision)."""
from __future__ import annotations

from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

MAX_FRAMES = 500
MAX_NODES = 40  # frames returned as children (full pipeline); others stay artifacts


def _try_decode_bits(values: list[int]) -> list[str]:
    """If the delays take 2 distinct values, try reading them as bits -> ASCII."""
    uniq = sorted(set(values))
    if len(uniq) != 2:
        return []
    lo, hi = uniq
    out = []
    for swap in (False, True):
        bits = []
        for v in values:
            b = 1 if v == hi else 0
            bits.append(1 - b if swap else b)
        text = ""
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for b in bits[i:i + 8]:
                byte = (byte << 1) | b
            text += chr(byte) if 32 <= byte <= 126 else "."
        if any(c.isalnum() for c in text):
            out.append(f"swap={swap}: {text}")
    return out


class GifFramesAnalyzer(Analyzer):
    name = "gif-frames"
    category = "vision"
    description = ("Split an animated GIF into frames, highlight the frames that change "
                   "the most and try to decode a flag hidden in the frame delays.")
    accepts = (".gif",)
    display_order = 360

    def run(self, ctx: ToolContext) -> ToolResult:
        outdir = ctx.sub(self.name)
        try:
            from PIL import Image, ImageSequence
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"PIL missing: {exc}")

        frames: list[Path] = []
        durations: list[int] = []
        try:
            im = Image.open(ctx.input)
            for i, fr in enumerate(ImageSequence.Iterator(im)):
                if i >= MAX_FRAMES:
                    break
                durations.append(int(fr.info.get("duration", 0) or 0))
                fn = outdir / f"frame_{i:04d}.png"
                fr.convert("RGBA").save(fn)
                frames.append(fn)
        except Exception as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read gif: {exc}")
        if not frames:
            return ToolResult(self.name, status="done", summary="no frames")

        # frame-difference scores
        diffs: list[tuple[float, int]] = []
        try:
            import numpy as np
            from PIL import Image
            prev = None
            for i, f in enumerate(frames):
                arr = np.asarray(Image.open(f).convert("RGB")).astype("int16")
                if prev is not None and arr.shape == prev.shape:
                    d = np.abs(arr - prev)
                    score = float(d.mean())
                    diffs.append((score, i))
                    if score > 0.5:
                        dimg = Image.fromarray(np.clip(d.sum(axis=2), 0, 255).astype("uint8"))
                        dimg.save(outdir / f"diff_{i:04d}.png")
                prev = arr
        except Exception:
            pass

        # OCR each frame so a flag shown in a frame is captured automatically
        lines_ocr: list[tuple[int, str]] = []
        try:
            from .vision import ocr_image
            for i, f in enumerate(frames):
                text = ocr_image(f)
                if text:
                    lines_ocr.append((i, text))
        except Exception:
            pass

        lines = [f"frames: {len(frames)}", f"durations(ms): {durations}"]
        for i, text in lines_ocr:
            lines.append(f"ocr frame {i:04d}: {text}")
        dec = _try_decode_bits(durations)
        if dec:
            lines.append("delay-bit decode:")
            lines += [f"  {d}" for d in dec]
        top = [i for _, i in sorted(diffs, reverse=True)[:5]]
        if top:
            lines.append(f"most-changed frames: {top}")
        lines += [f"diff frame {i:04d} = {s:.2f}" for s, i in sorted(diffs, reverse=True)[:20]]

        artifacts = [{"name": str(f.relative_to(ctx.workdir)), "path": str(f),
                      "size": f.stat().st_size} for f in sorted(outdir.glob("*.png"))]
        # analyse every frame as a normal child (bit-planes, zsteg, channel-remap,
        # image-enhance, OCR): a flag can be drawn or hidden in a single frame.
        # Above MAX_NODES, sample evenly plus the most-changed frames.
        if len(frames) <= MAX_NODES:
            exported = list(frames)
        else:
            step = len(frames) / MAX_NODES
            keep = sorted({int(i * step) for i in range(MAX_NODES)}
                          | {i for _, i in sorted(diffs, reverse=True)[:10]})
            exported = [frames[i] for i in keep if 0 <= i < len(frames)]
        return ToolResult(self.name, status="done",
                          summary=f"{len(frames)} frame, {len(exported)} analysed",
                          output="\n".join(lines), artifacts=artifacts,
                          extracted=[str(f) for f in exported])


register(GifFramesAnalyzer())
