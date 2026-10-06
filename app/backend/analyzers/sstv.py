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

import numpy as np

from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register

AV_EXT = (".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".au", ".snd")

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
    return [(s + e) // 2 for s, e in zip(starts, ends)]


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


def decode_frame(freq: np.ndarray, fs: int, mode: Mode, syncs: list[int]) -> np.ndarray:
    """Reconstruct the RGB frame (H x W x 3 uint8) from a Scottie-style line set."""
    h, w = mode.height, mode.width
    sync_half = mode.sync_ms / 2.0 / 1000.0 * fs
    img = np.zeros((h, w, 3), dtype=np.uint8)
    for k in range(min(h, len(syncs))):
        line_start = (syncs[k] - sync_half) - mode.sync_offset_ms / 1000.0 * fs
        vals = {}
        for idx, colour in enumerate(mode.channels):
            start = line_start + mode.channel_offset_ms(idx) / 1000.0 * fs
            vals[colour] = _freq_to_byte(_scan(freq, fs, start, mode.scan_ms, w))
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
    img = decode_frame(freq, fs, mode, train)
    info = {"mode": mode.name, "width": mode.width, "height": mode.height,
            "syncs": len(centers), "lines": min(mode.height, len(train))}
    return img, mode, info


# ---------------------------------------------------------------------------
# analyzer
# ---------------------------------------------------------------------------

class SstvAnalyzer(Analyzer):
    name = "sstv"
    category = "audio"
    description = "Decode an SSTV audio transmission (Scottie S1/S2) into an image (m00nwalk)."
    accepts = AV_EXT
    display_order = 420

    def _to_wav(self, ctx: ToolContext) -> Path:
        """Return a WAV path, converting with ffmpeg when the input is not PCM."""
        try:
            _read_wav(ctx.input)
            return ctx.input
        except Exception:
            pass
        if not which("ffmpeg"):
            return ctx.input
        out = ctx.sub(self.name) / "input.wav"
        ctx.run(["ffmpeg", "-y", "-i", str(ctx.input), "-ac", "1", "-ar", "48000", str(out)],
                timeout=300)
        return out if out.exists() else ctx.input

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            import numpy  # noqa: F401
        except Exception:
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
                f"sync pulses: {info['syncs']}  lines decoded: {info['lines']}")
        if text:
            body += "\n== OCR ==\n" + text
        return ToolResult(
            self.name, status="done", output=body,
            summary=f"{mode.name} {info['width']}x{info['height']}",
            artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}],
        )

    @staticmethod
    def _ocr(frame, ctx: ToolContext) -> str:
        """OCR the frame upright and upside-down (SSTV images often arrive flipped)."""
        try:
            from .vision import ocr_image
        except Exception:
            return ""
        import shutil
        if not shutil.which("tesseract"):
            return ""
        d = ctx.workdir / "sstv"
        d.mkdir(parents=True, exist_ok=True)
        texts: list[str] = []
        for angle in (0, 180):
            p = d / f"frame_{angle}.png"
            frame.rotate(angle).save(p)
            t = ocr_image(p)
            if t and t not in texts:
                texts.append(t)
        return "\n".join(texts)


register(SstvAnalyzer())
