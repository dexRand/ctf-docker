"""SSTV (Slow-Scan Television) decoder for audio challenges (m00nwalk-style).

An SSTV transmission encodes an image as an FM audio signal: brightness maps to
a tone between 1500 Hz (black) and 2300 Hz (white); a 9 ms 1200 Hz *sync* pulse
marks each line. This module demodulates the audio (band-pass + Hilbert
instantaneous frequency), finds the sync pulses, identifies the mode from their
spacing, and reconstructs the picture, which is then OCR'd for a flag.

Currently supported: **Scottie S1** and **Scottie S2** (RGB, sync mid-line).
The mode table makes adding Robot 36 / Martin M1 straightforward.

No external decoder (qsstv) or heavy dependency is needed: only numpy, which is
already a backend dependency.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:  # optional: a missing numpy must only disable SSTV, not the whole registry
    import numpy as np
except ImportError:  # pragma: no cover
    np = None

from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register
from .util import AV_EXT


SYNC_HZ = 1200.0
BLACK_HZ = 1500.0
WHITE_HZ = 2300.0
SPAN = WHITE_HZ - BLACK_HZ


@dataclass(frozen=True)
class Mode:
    name: str
    vis: int
    width: int
    height: int
    # separator / sync / porch durations (ms)
    sep_ms: float
    sync_ms: float
    porch_ms: float
    scan_ms: float
    channels: tuple  # channel order in the line, e.g. ("G", "B", "R")

    @property
    def period_ms(self) -> float:
        return self.sep_ms + self.scan_ms + self.sep_ms + self.scan_ms \
            + self.sync_ms + self.porch_ms + self.scan_ms

    @property
    def sync_offset_ms(self) -> float:
        """Distance from the line start to the mid-line sync pulse start."""
        return self.sep_ms + self.scan_ms + self.sep_ms + self.scan_ms

    def channel_offset_ms(self, idx: int) -> float:
        if idx == 0:  # Green
            return self.sep_ms
        if idx == 1:  # Blue
            return self.sep_ms + self.scan_ms + self.sep_ms
        # Red: after the mid-line sync + porch
        return self.sync_offset_ms + self.sync_ms + self.porch_ms


MODES = {
    "ScottieS1": Mode("ScottieS1", 60, 320, 256, 1.5, 9.0, 1.5, 138.240, ("G", "B", "R")),
    "ScottieS2": Mode("ScottieS2", 56, 160, 256, 1.5, 9.0, 1.5, 88.064, ("G", "B", "R")),
}


# ---------------------------------------------------------------------------
# signal processing
# ---------------------------------------------------------------------------

def _is_pcm16_wav(path: Path) -> bool:
    import wave
    try:
        with wave.open(str(path), "rb") as w:
            return w.getsampwidth() == 2
    except Exception:
        return False


def _read_wav(path: Path) -> tuple[np.ndarray, int]:
    """Read a mono PCM WAV as float in [-1, 1] (raises on failure)."""
    import wave

    with wave.open(str(path), "rb") as w:
        fs = w.getframerate()
        sw = w.getsampwidth()
        nch = w.getnchannels()
        raw = w.readframes(w.getnframes())
    if sw != 2:
        raise ValueError(f"unsupported sample width {sw * 8} bit")
    data = np.frombuffer(raw, dtype="<i2").astype(np.float64)
    if nch > 1:
        data = data[:(len(data) // nch) * nch].reshape(-1, nch).mean(axis=1)
    return data / 32768.0, fs


def _bandpass(x: np.ndarray, fs: int, lo: float = 1000.0, hi: float = 2600.0) -> np.ndarray:
    n = len(x)
    spec = np.fft.rfft(x)
    freqs = np.fft.rfftfreq(n, 1.0 / fs)
    spec *= ((freqs >= lo) & (freqs <= hi))
    return np.fft.irfft(spec, n=n)


def _hilbert(x: np.ndarray) -> np.ndarray:
    n = len(x)
    spec = np.fft.fft(x)
    h = np.zeros(n)
    h[0] = 1.0
    if n % 2 == 0:
        h[n // 2] = 1.0
        h[1:n // 2] = 2.0
    else:
        h[1:(n + 1) // 2] = 2.0
    return np.fft.ifft(spec * h)


def _boxcar(x: np.ndarray, k: int) -> np.ndarray:
    """Centred moving average (prefix sums — O(n), unlike a k-wide median)."""
    if k <= 1:
        return x
    n = len(x)
    cs = np.concatenate([[0.0], np.cumsum(x)])
    half = k // 2
    i = np.arange(n)
    a = np.clip(i - half, 0, n)
    b = np.clip(i - half + k, 0, n)
    return (cs[b] - cs[a]) / np.maximum(1, b - a)


def demodulate(x: np.ndarray, fs: int,
               target_fs: int = 12000) -> tuple[np.ndarray, int]:
    """Instantaneous frequency (Hz) of the band-passed signal.

    The SSTV band is only ~1.0-2.6 kHz, so after band-passing we decimate to
    ~``target_fs`` before the Hilbert transform: 4x fewer FFT points with no
    loss for this signal. Returns ``(freq, fs_used)``.
    """
    xb = _bandpass(x, fs)
    d = max(1, fs // target_fs)
    if d > 1:
        xb = xb[::d]
    fs2 = fs / d
    phase = np.unwrap(np.angle(_hilbert(xb)))
    freq = np.diff(phase) * fs2 / (2.0 * np.pi)
    return _boxcar(freq, max(1, int(fs2 * 0.0003) | 1)), int(round(fs2))


def find_syncs(freq: np.ndarray, fs: int, sync_ms: float = 9.0) -> list[int]:
    """Centres (sample index) of the sync pulses: windows mostly below 1350 Hz."""
    low = (freq < 1350.0).astype(np.float64)
    n = max(1, int(fs * sync_ms / 1000.0))
    half = n // 2
    cs = np.concatenate([[0.0], np.cumsum(low)])
    i = np.arange(len(low))
    a = np.clip(i - half, 0, len(low))
    b = np.clip(i - half + n, 0, len(low))
    score = (cs[b] - cs[a]) / np.maximum(1, b - a)
    on = score > 0.6
    edges = np.diff(on.astype(np.int8))
    starts = list(np.where(edges == 1)[0] + 1)
    ends = list(np.where(edges == -1)[0] + 1)
    if on[0]:
        starts = [0, *starts]
    if on[-1]:
        ends = [*ends, len(on)]
    return [(s + e) // 2 for s, e in zip(starts, ends, strict=False)]


def _periodic_train(centers: list[int], fs: int, period_ms: float,
                    tol_ms: float = 25.0) -> list[int]:
    """Longest run of sync centres spaced ~period_ms apart."""
    period = period_ms / 1000.0 * fs
    tol = tol_ms / 1000.0 * fs
    best: list[int] = []
    cur: list[int] = []
    for c in centers:
        if not cur or abs(c - cur[-1] - period) <= tol:
            cur.append(c)
        else:
            if len(cur) > len(best):
                best = cur
            cur = [c]
    if len(cur) > len(best):
        best = cur
    return best


def select_mode(centers: list[int], fs: int) -> Optional[tuple[Mode, list[int]]]:
    """Pick the supported mode whose sync spacing best matches the signal."""
    best: Optional[tuple[Mode, list[int]]] = None
    for mode in MODES.values():
        train = _periodic_train(centers, fs, mode.period_ms)
        # a periodic train of ~9 ms 1200 Hz pulses is already a strong SSTV sign
        if len(train) >= 8:
            if best is None or len(train) > len(best[1]):
                best = (mode, train)
    return best


def _scan(freq: np.ndarray, fs: int, start: float, scan_ms: float, width: int) -> np.ndarray:
    """Average frequency over the central part of each of ``width`` pixels."""
    pt = scan_ms / 1000.0 * fs / width
    i = np.arange(width)
    a = np.clip((start + (i + 0.15) * pt).astype(np.int64), 0, len(freq) - 1)
    b = np.clip((start + (i + 0.85) * pt).astype(np.int64), 1, len(freq))
    cs = np.concatenate([[0.0], np.cumsum(freq)])
    return (cs[b] - cs[a]) / np.maximum(1, b - a)


def _freq_to_byte(f: np.ndarray) -> np.ndarray:
    return np.clip((f - BLACK_HZ) / SPAN * 255.0, 0, 255)


def fit_lines(train: list[int], fs: int, mode: Mode) -> Optional[tuple[float, float, int]]:
    """Least-squares line clock from the sync train: ``(t0, period, inliers)``.

    A sender's sample clock is never exact (m00nwalk runs 0.2 % slow): fitting
    all the mid-line syncs gives the real line period ("auto slant" in QSSTV),
    which also scales the porch/scan offsets inside a line. Pulses off the
    fitted grid are dropped: the VIS header (low 1100-1300 Hz tones) looks like
    one more sync about a period before line 0 and used to become a garbage
    first row. Missing syncs leave a gap in ``k`` instead of shifting lines.
    """
    c = np.asarray(train, dtype=np.float64)
    if len(c) < 8:
        return None
    period = float(np.median(np.diff(c)))
    tol = 0.002 * fs                                    # 2 ms around the grid
    t0 = float(np.median(c - np.round((c - c[0]) / period) * period))
    keep = np.ones(len(c), dtype=bool)
    for _ in range(4):
        k = np.round((c - t0) / period)
        keep = np.abs(c - t0 - k * period) <= tol
        if keep.sum() < 8:
            return None
        a = np.vstack([np.ones(int(keep.sum())), k[keep]]).T
        t0, period = (float(v) for v in np.linalg.lstsq(a, c[keep], rcond=None)[0])
    t0 += float(k[keep].min()) * period                 # first in-grid sync = line 0
    nominal = mode.period_ms / 1000.0 * fs
    if abs(period / nominal - 1.0) > 0.02:              # not this mode's clock
        return None
    return t0, period, int(keep.sum())


def decode_frame(freq: np.ndarray, fs: int, mode: Mode, syncs: list[float],
                 scale: float = 1.0) -> np.ndarray:
    """Reconstruct the RGB frame (H x W x 3 uint8) from a Scottie-style line set.

    ``syncs`` are the mid-line sync centres of lines 0..n; ``scale`` is the
    measured/nominal line period, applied to every offset inside the line.
    """
    h, w = mode.height, mode.width
    ms = scale / 1000.0 * fs                           # samples per nominal ms
    img = np.zeros((h, w, 3), dtype=np.uint8)
    for k in range(min(h, len(syncs))):
        line_start = syncs[k] - (mode.sync_ms / 2.0 + mode.sync_offset_ms) * ms
        if line_start >= len(freq):                    # transmission cut short
            break
        vals = {}
        for idx, colour in enumerate(mode.channels):
            start = line_start + mode.channel_offset_ms(idx) * ms
            vals[colour] = _freq_to_byte(_scan(freq, fs, start, mode.scan_ms * scale, w))
        img[k, :, 0] = vals["R"]
        img[k, :, 1] = vals["G"]
        img[k, :, 2] = vals["B"]
    return img


def decode_sstv(path: Path) -> Optional[tuple[np.ndarray, Mode, dict]]:
    """Decode an SSTV audio file. Returns (rgb, mode, info) or None."""
    try:
        x, fs = _read_wav(path)
    except Exception:
        return None
    if len(x) < fs:  # < 1 s of audio cannot hold a frame
        return None
    freq, fs = demodulate(x, fs)
    centers = find_syncs(freq, fs)
    picked = select_mode(centers, fs)
    if not picked:
        return None
    mode, train = picked
    fit = fit_lines(train, fs, mode)
    if fit is None:
        return None
    t0, period, inliers = fit
    lines = [t0 + k * period for k in range(mode.height)]
    img = decode_frame(freq, fs, mode, lines, period / (mode.period_ms / 1000.0 * fs))
    info = {"mode": mode.name, "width": mode.width, "height": mode.height,
            "syncs": len(centers), "lines": min(mode.height, inliers),
            "clock": round(period / (mode.period_ms / 1000.0 * fs), 5)}
    return img, mode, info


def _stroke_mask(gray):
    """Pixels far from their local mean: the strokes of text, either polarity."""
    from PIL import Image, ImageFilter
    g = gray.filter(ImageFilter.MedianFilter(3))
    a = np.asarray(g, dtype=np.float64)
    m = np.asarray(g.filter(ImageFilter.BoxBlur(8)), dtype=np.float64)
    return Image.fromarray((np.abs(a - m) > 20).astype(np.uint8) * 255)


def text_layout(frame, max_deg: int = 30) -> tuple[str, float]:
    """``(channel, angle)`` that best shows a tilted line of text, or ``("", 0.0)``.

    Projection profile: on a stroke mask the row sums vary most when the rows
    are aligned with the text. Tried on R, G, B: ink on coloured paper (dark
    on yellow) has contrast in one channel only, and the winning channel is
    also the one handed to OCR. ``angle`` uses PIL's rotate convention.
    Returns no change unless a tilt beats the level frame by 15 %
    (level text, or a photo with no text). numpy + PIL only: ~180 rotations
    of a 320x256 mask, well under a second.
    """
    best = ("", 0.0, 0.0)
    for ch in ("R", "G", "B"):
        mask = frame.convert("RGB").getchannel(ch)
        mask = _stroke_mask(mask)
        prof = {ang: float(np.asarray(mask.rotate(float(ang)), dtype=np.float64).sum(axis=1).var())
                for ang in range(-max_deg, max_deg + 1)}
        ang = max(prof, key=prof.get)
        if ang and prof[ang] > prof[0] * 1.15 and prof[ang] > best[2]:
            best = (ch, float(ang), prof[ang])
        elif prof[0] >= best[2]:
            best = ("", 0.0, prof[0])
    return best[0], best[1]


# ---------------------------------------------------------------------------
# analyzer
# ---------------------------------------------------------------------------

class SstvAnalyzer(Analyzer):
    name = "sstv"
    category = "audio"
    description = "Decode an SSTV audio transmission (Scottie S1/S2) into an image (m00nwalk)."
    accepts = AV_EXT
    display_order = 421

    def _to_wav(self, ctx: ToolContext) -> Path:
        """Return a WAV path, converting with ffmpeg when the input is not PCM."""
        if _is_pcm16_wav(ctx.input):   # header only: decode_sstv reads the samples once
            return ctx.input
        if not which("ffmpeg"):
            return ctx.input
        out = ctx.sub(self.name) / "input.wav"
        ctx.run(["ffmpeg", "-y", "-i", str(ctx.input), "-ac", "1", "-ar", "48000", str(out)],
                timeout=300)
        return out if out.exists() else ctx.input

    def run(self, ctx: ToolContext) -> ToolResult:
        if np is None:
            return ToolResult(self.name, status="skipped", summary="numpy not installed")
        result = decode_sstv(self._to_wav(ctx))
        if result is None:
            return ToolResult(self.name, status="skipped", summary="no SSTV signal")
        img, mode, info = result
        from PIL import Image
        out = ctx.sub(self.name) / f"sstv_{mode.name}.png"
        frame = Image.fromarray(img)
        frame.save(out)

        text = self._ocr(frame, ctx)
        body = (f"mode: {mode.name}\n"
                f"sync pulses: {info['syncs']}  lines decoded: {info['lines']}  "
                f"clock: x{info['clock']}")
        if text:
            body += "\n== OCR ==\n" + text
        return ToolResult(
            self.name, status="done", output=body,
            summary=f"{mode.name} {info['width']}x{info['height']}",
            artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}],
        )

    @staticmethod
    def _ocr(frame, ctx: ToolContext) -> str:
        """OCR the frame upright and upside-down (SSTV images often arrive flipped),
        first straightened when its text is tilted (a photo of a handwritten
        note): tesseract reads nothing past ~5 degrees. Still one OCR per image."""
        try:
            from .vision import ocr_image
        except Exception:
            return ""
        import shutil
        if not shutil.which("tesseract"):
            return ""
        from PIL import Image
        d = ctx.workdir / "sstv"
        d.mkdir(parents=True, exist_ok=True)
        channel, skew = text_layout(frame)
        if skew:   # a tilted note: OCR the straightened channel where the ink stands out
            frame = frame.getchannel(channel).rotate(skew, resample=Image.BICUBIC, fillcolor=255)
        texts: list[str] = []
        for angle in (0, 180):
            p = d / f"frame_{angle}.png"
            frame.rotate(angle).save(p)
            t = ocr_image(p)
            if t and t not in texts:
                texts.append(t)
        return "\n".join(texts)


register(SstvAnalyzer())
