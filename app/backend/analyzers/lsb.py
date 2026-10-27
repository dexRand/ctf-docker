"""LSB bit-plane carving.

zsteg can extract the raw bit stream for a given spec; a hidden archive/image is
often that stream with a short junk prefix (e.g. a zip right after 3 bytes). Try
a few common specs and carve any embedded file magic found in the stream.
"""
from __future__ import annotations

from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, run_cmd, which
from .util import magic_ext, printable_ratio
from .registry import register

# bit 1/2 of the low channels, both bit orders, plus one deeper plane
_SPECS = ["b1,bgr,lsb,xy", "b1,rgba,lsb,xy", "b2,bgr,lsb,xy", "b2,rgba,lsb,xy",
          "b1,bgr,msb,xy", "b2,bgr,msb,xy", "b3,rgba,lsb,xy"]
_MAGICS = [(b"PK\x03\x04", ".zip"), (b"\x89PNG\r\n\x1a\n", ".png"), (b"%PDF", ".pdf"),
           (b"GIF89a", ".gif"), (b"GIF87a", ".gif"), (b"\xff\xd8\xff", ".jpg"),
           (b"\x1f\x8b\x08", ".gz"), (b"BZh", ".bz2"), (b"\xfd7zXZ", ".xz")]
_MIN = 64
_MAX_NUMPY_PIXELS = 40_000_000   # above this (or for palette/gray images) zsteg does it
_CHAN = {"r": 0, "g": 1, "b": 2, "a": 3}


def lsb_stream(arr, spec: str) -> bytes:
    """The bit stream `zsteg -e <spec>` extracts, computed with numpy in one go.

    Same semantics as zsteg (checked byte for byte in tests): pixels in xy order,
    channels in spec order, the low `n` bits of each channel high bit first;
    `lsb` packs each 8 bits MSB-first, `msb` packs them LSB-first."""
    import numpy as np
    nbits, chans, order, _xy = spec.split(",")
    n = int(nbits[1:])
    a = arr[:, :, [_CHAN[c] for c in chans]]
    planes = [(a >> b) & 1 for b in range(n - 1, -1, -1)]
    bits = np.stack(planes, axis=-1).reshape(-1)
    bits = bits[: len(bits) - len(bits) % 8]
    return np.packbits(bits, bitorder="big" if order == "lsb" else "little").tobytes()


def _rgba_head(path: Path, max_pixels: int = _MAX_NUMPY_PIXELS):
    """RGBA array of an RGB/RGBA image; for a huge image only its first rows
    (hidden data starts at the beginning of the stream). None otherwise."""
    try:
        from PIL import Image
        import numpy as np
        Image.MAX_IMAGE_PIXELS = None               # big challenge images are legitimate
        with Image.open(path) as im:
            if im.mode not in ("RGB", "RGBA"):
                return None
            rows = max(1, min(im.height, max_pixels // max(1, im.width)))
            head = im.crop((0, 0, im.width, rows)) if rows < im.height else im
            return np.asarray(head.convert("RGBA"))
    except Exception:
        return None


def _streams(path: Path, arr=None):
    """(spec, stream) for every spec: numpy for RGB/RGBA images, zsteg otherwise."""
    arr = _rgba_head(path) if arr is None else arr
    for spec in _SPECS:
        if arr is not None:
            yield spec, lsb_stream(arr, spec)
            continue
        proc = run_cmd(["zsteg", "-e", spec, path], timeout=120, binary=True)
        if proc.returncode not in (124, 127):
            yield spec, proc.stdout or b""


class LsbCarveAnalyzer(Analyzer):
    name = "lsb-carve"
    category = "steg"
    description = "Carve a hidden file (zip/png/pdf…) out of the LSB bit planes of a PNG/BMP."
    accepts = (".png", ".bmp")
    display_order = 336

    def run(self, ctx: ToolContext) -> ToolResult:
        # RGB/RGBA images are decoded with numpy, so zsteg is only needed for the
        # other modes (palette/gray): don't skip the whole analyzer without it.
        arr = _rgba_head(ctx.input)
        if arr is None and not which("zsteg"):
            return ToolResult(self.name, status="skipped", summary="zsteg not installed")
        outdir = ctx.sub(self.name)
        produced: list[Path] = []
        seen: set[tuple] = set()
        for spec, data in _streams(ctx.input, arr):
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


class StepicAnalyzer(Analyzer):
    """stepic (Python stego library): every 3 pixels hide one byte — the LSBs of
    the first 8 of their 9 RGB values, MSB first; the 9th LSB is 1 on the last
    byte (picoCTF 2025 "flags are stepic", a 150 MP PNG). Only the beginning of
    the image is read."""
    name = "stepic"
    category = "steg"
    description = "Decode stepic LSB stego (3 pixels per byte, end marker)."
    accepts = (".png", ".bmp")
    display_order = 337
    MAX_BYTES = 1_000_000

    def run(self, ctx: ToolContext) -> ToolResult:
        import numpy as np
        arr = _rgba_head(ctx.input, max_pixels=3 * self.MAX_BYTES)
        if arr is None:
            return ToolResult(self.name, status="skipped", summary="not an RGB image")
        rgb = arr[:, :, :3].reshape(-1, 3)
        n = len(rgb) // 3
        if n == 0:
            return ToolResult(self.name, status="skipped", summary="image too small")
        groups = (rgb[: n * 3].reshape(n, 9) & 1).astype(np.uint8)
        ends = np.flatnonzero(groups[:, 8])
        if not len(ends):
            return ToolResult(self.name, status="skipped", summary="no stepic end marker")
        data = np.packbits(groups[: ends[0] + 1, :8], axis=1).reshape(-1).tobytes()
        if len(data) < 4 or (printable_ratio(data) < 0.9 and not magic_ext(data)):
            return ToolResult(self.name, status="skipped", summary="no stepic payload")
        out = ctx.sub(self.name) / f"{ctx.input.stem}.stepic{magic_ext(data) or '.txt'}"
        out.write_bytes(data)
        text = data.decode("latin-1") if printable_ratio(data) >= 0.9 else ""
        return ToolResult(self.name, status="done", summary=f"{len(data)} byte(s) decoded",
                          output=text[:200_000],
                          extracted=[str(out)] if magic_ext(data) else [],
                          artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])


register(StepicAnalyzer())


_MSB_PREFIXES = (b"picoCTF{", b"flag{", b"FLAG{", b"ITS{", b"CTF{", b"HTB{")


def msb_stream(arr, chans: str, bitorder: str) -> bytes:
    """The bit 7 (MSB) of the given channels, packed into bytes."""
    import numpy as np
    a = arr[:, :, [_CHAN[c] for c in chans]]
    bits = ((a >> 7) & 1).reshape(-1)
    bits = bits[: len(bits) - len(bits) % 8]
    return np.packbits(bits, bitorder=bitorder).tobytes()


def find_msb_flag(arr) -> list[str]:
    """Flag bytes hidden in the most significant bit of the pixel channels.

    Tries the common channel orders (RGB/BGR/RGBA/BGRA) and both bit orders,
    then looks for a known flag prefix and cuts it at the closing brace.
    """
    found: list[str] = []
    for chans in ("rgb", "bgr", "rgba", "bgra"):
        for order in ("big", "little"):
            data = msb_stream(arr, chans, order)
            for pre in _MSB_PREFIXES:
                i = data.find(pre)
                if i == -1:
                    continue
                j = data.find(b"}", i)
                if j == -1 or j - i > 200:
                    continue
                value = data[i:j + 1].decode("latin-1", "replace")
                if value not in found:
                    found.append(value)
    return found


class MsbBitsAnalyzer(Analyzer):
    name = "msb-bits"
    category = "steg"
    description = "Flag bits in the most significant bit (MSB plane) of the image pixels."
    accepts = (".png", ".bmp", ".gif", ".tif", ".tiff")
    display_order = 340
    MAX_PIXELS = 40_000_000

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            import numpy as np
            from PIL import Image
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"PIL/numpy missing: {exc}")
        try:
            im = Image.open(ctx.input).convert("RGBA")
            im.load()
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"cannot open image: {exc}")
        if im.width * im.height > self.MAX_PIXELS:
            return ToolResult(self.name, status="skipped", summary="image too big")
        flags = find_msb_flag(np.asarray(im))
        if not flags:
            return ToolResult(self.name, status="skipped", summary="no MSB-encoded flag")
        return ToolResult(self.name, status="done", summary=f"{len(flags)} MSB flag(s)",
                          output="\n".join(flags))


register(MsbBitsAnalyzer())

