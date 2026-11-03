"""Animated GIF analysis: frames, frame-diff, and frame-delay decoding (vision)."""
from __future__ import annotations

import hashlib
from pathlib import Path

import base64
import binascii
import re

from .base import Analyzer, ToolContext, ToolResult, run_cmd, which
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


_B64_ONLY = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def strip_strides(n: int, w: int, h: int, max_k: int = 40) -> list[int]:
    """Strides k for which stacking every k-th frame-strip gives a roughly
    square picture (a QR cut into horizontal strips, one per frame)."""
    if n < 4 or h * 4 > w:
        return []
    out = []
    for k in range(1, min(n, max_k) + 1):
        rows = (n // k) * h
        if 0.6 * w <= rows <= 1.6 * w:
            out.append(k)
    return out


def stacked_qr(frames: list[Path], outdir: Path) -> list[str]:
    """Rebuild QR codes cut into strips across GIF frames (DUCTF 2021 "how to
    pronounce GIF": frames j, j+10, j+20 ... form one code) and decode them.
    Base64-only texts are also joined in order (a flag split over two codes)."""
    if not which("zbarimg") or not frames:
        return []
    from PIL import Image
    imgs = [Image.open(f).convert("L") for f in frames]
    w, h = imgs[0].size
    if any(im.size != (w, h) for im in imgs):
        return []
    lines: list[str] = []
    for k in strip_strides(len(imgs), w, h):
        texts: list[str] = []
        for j in range(k):
            group = imgs[j::k]
            text = ""
            # the strip edges are often anti-aliased (a light line between
            # strips breaks the QR grid): drop the edge rows and binarize
            for top, bottom in ((0, 0), (0, 1), (1, 0), (1, 1)):
                sh = h - top - bottom
                canvas = Image.new("L", (w, sh * len(group)), 255)
                for r, im in enumerate(group):
                    canvas.paste(im.crop((0, top, w, h - bottom)), (0, r * sh))
                if (top, bottom) != (0, 0):
                    canvas = canvas.point(lambda v: 255 if v > 127 else 0)
                path = outdir / f"stacked_k{k}_{j:02d}.png"
                canvas.save(path)
                proc = run_cmd(["zbarimg", "--quiet", "--raw", str(path)], timeout=30)
                text = (proc.stdout or "").strip()
                if text:
                    break
            if text:
                texts.append(text)
                lines.append(f"stacked QR (every {k}th frame from {j}): {text[:500]}")
        if not texts:
            continue
        joined = "".join(t for t in texts if _B64_ONLY.match(t) and len(t) >= 4)
        if joined:
            try:
                dec = base64.b64decode(joined + "=" * (-len(joined) % 4))
                lines.append(f"base64 QR texts joined (every {k}th frame): "
                             + dec.decode("utf-8", "replace"))
            except (binascii.Error, ValueError):
                pass
        break                          # the stride that decodes is the right one
    return lines


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

        # Frames analysed as children get the full pipeline (OCR included), so
        # here only the frames that are NOT exported are OCR'd (quick pass):
        # every frame is read once, none twice. Identical frames are exported
        # once (the tree dedupes by hash anyway; this avoids the work upfront).
        exported = self._pick_exported(frames, diffs)
        # frames that stack into readable QR codes are strips of a bigger
        # picture: OCR or a full pipeline on each 20-px strip finds nothing and
        # cost minutes (DUCTF 2021 gif: 120 strips). They stay artifacts.
        stacked = stacked_qr(frames, outdir)
        if stacked:
            exported = []
        lines_ocr: list[tuple[int, str]] = []
        exported_set = set(exported)
        rest = [] if stacked else [i for i, f in enumerate(frames) if f not in exported_set]
        if rest:
            from .vision import ocr_image
            for i in rest:
                text = ocr_image(frames[i], thorough=False)
                if text:
                    lines_ocr.append((i, text))

        lines = [f"frames: {len(frames)}", f"durations(ms): {durations}"]
        lines += stacked
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
        return ToolResult(self.name, status="done",
                          summary=f"{len(frames)} frame, {len(exported)} analysed",
                          output="\n".join(lines), artifacts=artifacts,
                          extracted=[str(f) for f in exported])


    @staticmethod
    def _pick_exported(frames: list[Path], diffs: list[tuple[float, int]]) -> list[Path]:
        """Frames analysed as normal children (bit-planes, zsteg, channel-remap,
        image-enhance, OCR): a flag can be drawn or hidden in a single frame.
        Distinct frames only; above MAX_NODES, an even sample plus the
        most-changed frames."""
        seen: set[str] = set()
        distinct: list[int] = []
        for i, f in enumerate(frames):
            h = hashlib.sha1(f.read_bytes()).hexdigest()
            if h not in seen:
                seen.add(h)
                distinct.append(i)
        if len(distinct) > MAX_NODES:
            step = len(distinct) / MAX_NODES
            keep = {distinct[int(k * step)] for k in range(MAX_NODES)}
            keep |= {i for _, i in sorted(diffs, reverse=True)[:10]}
            distinct = sorted(keep)
        return [frames[i] for i in distinct]


register(GifFramesAnalyzer())
