"""Generic ASK (Amplitude Shift Keying) demodulator for audio.

The modulator is not assumed: the carrier is the strongest narrow pure tone
above the music band, the baud is estimated from the length of the shortest
stable amplitude run (bit cells are equal length), and the three amplitude
levels (separator / bit 0 / bit 1) are clustered from the demodulated envelope.
Bytes are reassembled MSB-first and closed by a near-zero separator cell.

A stereo file is also demodulated as ``left - right``: a signal added to one
channel only (the common way to hide data "on top of" music) cancels the music
and leaves the keyed carrier clean.
"""
from __future__ import annotations

import time
import wave
from pathlib import Path

import numpy as np

from .base import Analyzer, ToolContext, ToolResult, which
from .morse import _read_wav_mono
from .registry import register
from .util import AV_EXT, magic_ext, printable_ratio

MAX_BYTES = 64 << 20           # input file cap
MAX_SAMPLES = 8_000_000        # ~3 min at 44.1 kHz
MAX_OUTPUT = 200_000
DEADLINE = 120.0
MIN_CARRIER_HZ = 4000.0
MAX_CARRIERS = 3
SMOOTHINGS = (0.0005, 0.002)   # envelope averaging, seconds
PHASES = 32
MIN_PRINTABLE = 6


def _moving_avg_complex(z: np.ndarray, win: int) -> np.ndarray:
    """Mean of ``z`` over a forward window of ``win`` samples."""
    cs = np.concatenate(([0j], np.cumsum(z)))
    return (cs[win:] - cs[:-win]) / win


def _kmeans3(values: np.ndarray):
    """Three deterministic 1-D clusters (sorted low -> high) or None."""
    v = values[np.isfinite(values)]
    if v.size < 9:
        return None
    lo, hi = float(np.min(v)), float(np.max(v))
    if hi - lo <= 1e-9:
        return None
    centers = np.percentile(v, [10.0, 50.0, 90.0]).astype(np.float64)
    if centers[2] - centers[0] < 1e-3 * (hi - lo):     # signal is a minority
        centers = np.array([lo, (lo + hi) / 2.0, hi])
    for _ in range(30):
        labels = np.abs(v[:, None] - centers[None, :]).argmin(axis=1)
        new = centers.copy()
        for k in range(3):
            if np.any(labels == k):
                new[k] = float(v[labels == k].mean())
        if np.allclose(new, centers):
            centers = new
            break
        centers = new
    order = np.argsort(centers)
    remap = np.empty(3, dtype=np.int64)
    remap[order] = np.arange(3)
    labels = np.abs(v[:, None] - centers[None, :]).argmin(axis=1)
    return centers[order], remap[labels]


def _thresholds(centers: np.ndarray) -> np.ndarray:
    return (centers[:-1] + centers[1:]) / 2.0


def _estimate_period(env: np.ndarray, win: int):
    """Bit period (in samples) from the shortest stable envelope run."""
    stride = max(1, env.size // 200_000)
    sub = env[::stride]
    kres = _kmeans3(sub)
    if kres is None:
        return None
    centers, _ = kres
    gaps = np.diff(centers)
    if gaps[0] < 1e-9 or gaps[1] < 1e-9:
        return None
    thr = _thresholds(centers)
    sym = np.digitize(env, thr)
    edges = np.flatnonzero(np.diff(sym)) + 1
    starts = np.concatenate(([0], edges))
    lengths = np.diff(np.concatenate((starts, [len(sym)])))
    runs = lengths[sym[starts] != 0].astype(np.float64)
    min_run = 4.0 * win
    runs = runs[runs >= min_run]
    if runs.size < 3:
        return None
    if runs.size > 20_000:                  # keep the fit cheap on long files
        runs = runs[:: runs.size // 20_000]
    max_period = float(runs.max()) / 1.5
    if max_period <= min_run:
        return None
    best = None
    for period in np.linspace(min_run, max_period, 400):
        residual = np.abs(runs / period - np.rint(runs / period))
        score = float(np.mean(np.minimum(residual, 0.5)))
        if best is None or score < best[0]:
            best = (score, float(period))
    period = best[1]
    for _ in range(3):
        period = float(np.median(runs / np.maximum(1.0, np.rint(runs / period))))
    if not (min_run * 0.9 <= period <= max_period * 1.2):
        return None
    return period


def _cells(cum: np.ndarray, period: float, phase: float) -> np.ndarray:
    count = int((len(cum) - 1.0 - phase) // period)
    if count < 9:
        return np.zeros(0)
    idx = np.rint(phase + np.arange(count + 1) * period).astype(np.int64)
    idx = np.clip(idx, 0, len(cum) - 1)
    return np.abs(cum[idx[1:]] - cum[idx[:-1]]) / period


def _decode(cells: np.ndarray) -> bytes | None:
    """Cluster the cell magnitudes and assemble MSB-first bytes at separators."""
    stride = max(1, cells.size // 4000)
    kres = _kmeans3(cells[::stride])
    if kres is None:
        return None
    centers, _ = kres
    if centers[1] - centers[0] < 1e-9 or centers[2] - centers[1] < 1e-9:
        return None
    sym = np.digitize(cells, _thresholds(centers))
    out = bytearray()
    bits: list[int] = []
    for s in sym.tolist():
        if s == 0:                         # separator cell
            if len(bits) == 8:
                out.append(_pack(bits))
            bits = []
        else:
            bits.append(0 if s == 1 else 1)
            if len(bits) > 8:              # not byte aligned: drop
                bits = []
    if len(bits) == 8:                     # signal may end without a separator
        out.append(_pack(bits))
    return bytes(out)


def _pack(bits: list[int]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _quality(cells: np.ndarray) -> float:
    """Between/within cluster variance: high when three levels are well split."""
    stride = max(1, cells.size // 4000)
    sub = cells[::stride]
    kres = _kmeans3(sub)
    if kres is None:
        return -1.0
    centers, labels = kres
    if centers[1] - centers[0] < 1e-9 or centers[2] - centers[1] < 1e-9:
        return -1.0
    total = float(np.sum((sub - sub.mean()) ** 2)) + 1e-9
    within = 0.0
    for k in range(3):
        if np.any(labels == k):
            within += float(np.sum((sub[labels == k] - centers[k]) ** 2))
    return 1.0 - within / total


def _carrier_candidates(samples: np.ndarray, rate: int) -> list[float]:
    """Strongest narrow pure tones above the music band (refined frequencies)."""
    n = samples.size
    if n < 1024:
        return []
    frame = 8192 if n >= 8192 else 1 << max(9, int(np.log2(n)))
    hop = frame // 2
    windows = np.hanning(frame)
    nframes = max(1, (n - frame) // hop + 1)
    power = np.zeros(frame // 2 + 1, dtype=np.float64)
    for i in range(nframes):
        seg = samples[i * hop:i * hop + frame]
        power += np.abs(np.fft.rfft(seg * windows)) ** 2
    power /= nframes
    freqs = np.fft.rfftfreq(frame, 1.0 / rate)
    total = float(power.sum())
    if total <= 0.0:
        return []
    rel = power / total
    half = max(8, int(200.0 / (rate / frame)))
    kernel = np.ones(2 * half + 1)
    baseline = np.convolve(power, kernel / kernel.sum(), mode="same")
    prominence = power / (baseline + 1e-30)
    local = np.zeros(power.size, dtype=bool)
    local[1:-1] = (power[1:-1] >= power[:-2]) & (power[1:-1] >= power[2:])
    mask = (freqs >= MIN_CARRIER_HZ) & (rel >= 1e-6) & local
    idx = np.flatnonzero(mask)
    if idx.size == 0:
        idx = np.flatnonzero((freqs >= MIN_CARRIER_HZ) & (rel >= 1e-6))
    picked: list[int] = []
    for j in idx[np.argsort(rel[idx])[::-1]]:
        if prominence[j] < 2.0:
            continue
        if any(abs(freqs[j] - freqs[k]) < 100.0 for k in picked):
            continue
        picked.append(int(j))
        if len(picked) >= MAX_CARRIERS:
            break
    out: list[float] = []
    for j in picked:
        freq = float(freqs[j])
        if 0 < j < power.size - 1:
            y0 = np.log(power[j - 1] + 1e-30)
            y1 = np.log(power[j] + 1e-30)
            y2 = np.log(power[j + 1] + 1e-30)
            denom = y0 - 2.0 * y1 + y2
            if abs(denom) > 1e-12:
                freq += 0.5 * (y0 - y2) / denom * (freqs[1] - freqs[0])
        out.append(freq)
    return out


def _demodulate(samples: np.ndarray, rate: int, carrier: float,
                smoothing: float, deadline: float):
    """Return (bytes, baud) for one carrier/smoothing, or None."""
    if time.monotonic() > deadline:
        return None
    n = samples.size
    win = max(1, int(round(smoothing * rate)))
    if win >= n // 8:
        return None
    t = np.arange(n, dtype=np.float64)
    z = samples.astype(np.float64) * np.exp(-2j * np.pi * carrier * t / rate)
    cum = np.concatenate(([0j], np.cumsum(z)))
    env = np.abs(cum[win:] - cum[:-win]) / win
    period = _estimate_period(env, win)
    if period is None:
        return None

    base = int(round(period))
    candidates = sorted({base - 1, base, base + 1, period,
                         period * 0.995, period * 1.005})
    candidates = [p for p in candidates if p > 0]
    best = None
    for cand in candidates:
        phases = np.linspace(0.0, cand, PHASES, endpoint=False)
        for phase in phases:
            if time.monotonic() > deadline:
                return None
            cells = _cells(cum, cand, float(phase))
            if cells.size < 9:
                continue
            q = _quality(cells)
            if best is None or q > best[0]:
                best = (q, cand, float(phase))
    if best is None or best[0] <= 0.0:
        return None

    # refine phase around the coarse winner, then decode
    _, cand, phase = best
    step = cand / PHASES
    refined = None
    for delta in np.linspace(-step, step, 9):
        p = (phase + float(delta)) % cand
        cells = _cells(cum, cand, p)
        if cells.size < 9:
            continue
        q = _quality(cells)
        if refined is None or q > refined[0]:
            refined = (q, p)
    if refined is not None:
        phase = refined[1]

    data = _decode(_cells(cum, cand, phase))
    if not data:
        return None
    baud = rate / cand
    return data, baud


def _capped_wav(path: Path, workdir: Path) -> tuple[Path | None, str]:
    """Validate the WAV header and truncate a huge file before reading it."""
    try:
        with wave.open(str(path), "rb") as w:
            channels = w.getnchannels()
            width = w.getsampwidth()
            rate = w.getframerate()
            frames = w.getnframes()
            comptype = w.getcomptype()
    except Exception as exc:
        return None, f"not a readable WAV ({exc})"
    if comptype != "NONE" or width not in (1, 2, 4):
        return None, "unsupported WAV codec"
    if channels < 1 or rate <= 0 or frames <= 0:
        return None, "empty WAV"
    if frames <= MAX_SAMPLES:
        return path, ""
    out = workdir / "ask-capped.wav"
    try:
        with wave.open(str(path), "rb") as src, wave.open(str(out), "wb") as dst:
            dst.setnchannels(channels)
            dst.setsampwidth(width)
            dst.setframerate(rate)
            dst.writeframes(src.readframes(MAX_SAMPLES))
    except Exception as exc:
        return None, f"cannot truncate WAV ({exc})"
    return out, ""


def _read_wav_diff(path: Path):
    """(left - right) as float32, or None for a mono WAV."""
    with wave.open(str(path), "rb") as w:
        channels = w.getnchannels()
        width = w.getsampwidth()
        frames = min(w.getnframes(), MAX_SAMPLES)
        raw = w.readframes(frames)
    if channels < 2:
        return None
    if width == 2:
        data = np.frombuffer(raw, dtype="<i2").astype(np.float32)
    elif width == 1:
        data = np.frombuffer(raw, dtype="u1").astype(np.float32) - 128.0
    else:
        data = np.frombuffer(raw, dtype="<i4").astype(np.float32)
    data = data.reshape(-1, channels)
    return data[:, 0] - data[:, 1]


class AskAnalyzer(Analyzer):
    name = "ask"
    category = "radio"
    description = "Demodulate generic ASK (amplitude-shift-keyed) data hidden in audio."
    accepts = AV_EXT
    display_order = 428
    tier = "normal"

    def run(self, ctx: ToolContext) -> ToolResult:
        deadline = time.monotonic() + DEADLINE
        try:
            size = ctx.input.stat().st_size
        except OSError as exc:
            return ToolResult(self.name, status="skipped", summary=f"not readable ({exc})")
        if size <= 0:
            return ToolResult(self.name, status="skipped", summary="empty file")
        if size > MAX_BYTES:
            return ToolResult(self.name, status="skipped", summary="file too large")

        if ctx.input.suffix.lower() not in AV_EXT:
            try:
                with open(ctx.input, "rb") as fh:
                    head = fh.read(16)
            except OSError as exc:
                return ToolResult(self.name, status="skipped",
                                  summary=f"not readable ({exc})")
            if magic_ext(head) not in AV_EXT:
                return ToolResult(self.name, status="skipped", summary="not audio")

        workdir = ctx.sub(self.name)
        wav = ctx.input
        if ctx.input.suffix.lower() != ".wav":
            if not which("ffmpeg"):
                return ToolResult(self.name, status="skipped", summary="ffmpeg not installed")
            wav = workdir / "audio.wav"
            proc = ctx.run(["ffmpeg", "-y", "-i", str(ctx.input), "-vn",
                            "-ar", "44100", "-t", str(MAX_SAMPLES / 44100.0), str(wav)],
                           timeout=300)
            if proc.returncode != 0 or not wav.is_file():
                return ToolResult(self.name, status="skipped",
                                  summary="cannot decode the audio (ffmpeg)")

        wav, err = _capped_wav(wav, workdir)
        if wav is None:
            return ToolResult(self.name, status="skipped", summary=err)

        try:
            mono, rate = _read_wav_mono(wav)
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"WAV not readable ({exc})")
        if mono.size == 0 or rate <= 0:
            return ToolResult(self.name, status="skipped", summary="empty WAV")

        waveforms: list[tuple[np.ndarray, int]] = []
        try:
            diff = _read_wav_diff(wav)
        except Exception:
            diff = None
        if diff is not None and diff.size and float(np.max(np.abs(diff))) > 0.0:
            waveforms.append((diff, rate))
        waveforms.append((mono, rate))

        if not all(np.isfinite(sig).all() for sig, _ in waveforms):
            return ToolResult(self.name, status="skipped", summary="non-finite audio")

        best: tuple[int, bytes, float, float] | None = None
        for samples, srate in waveforms:
            if samples.size < max(2048, srate // 4):
                continue
            carriers = _carrier_candidates(samples, srate)
            if not carriers:
                continue
            for carrier in carriers:
                for smoothing in SMOOTHINGS:
                    if time.monotonic() > deadline:
                        break
                    res = _demodulate(samples, srate, carrier, smoothing, deadline)
                    if not res:
                        continue
                    data, baud = res
                    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
                    if printable < MIN_PRINTABLE or printable_ratio(data) < 0.9:
                        continue
                    if not any(chr(b).isalpha() for b in data if 32 <= b < 127):
                        continue
                    score = printable * printable_ratio(data)
                    if best is None or score > best[0]:
                        best = (int(score * 1000), data, carrier, baud)
                    break
                if best is not None and best[0] >= 9 * 1000:
                    break
            if best is not None:
                break

        if best is None:
            return ToolResult(self.name, status="skipped", summary="no ASK data")
        _, data, carrier, baud = best
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        summary = f"ASK: {len(data)} bytes at {carrier:.0f} Hz, {baud:.2f} baud"
        return ToolResult(self.name, status="done", output=text[:MAX_OUTPUT],
                          summary=summary)


register(AskAnalyzer())
