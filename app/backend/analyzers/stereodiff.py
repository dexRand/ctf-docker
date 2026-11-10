"""Stereo audio: the L-R difference shows what one channel carries alone.

A hidden message (voice, Morse, a second song, SSTV) is often cancelled by the
other channel: subtracting R from L leaves only it. The difference is written
as a child WAV, so spectrogram/morse/sstv/... analyse it with the existing
tools — nothing is re-implemented here.
"""
from __future__ import annotations

import wave

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

MAX_SECONDS = 600                    # at most 10 minutes of audio are decoded
MAX_BYTES = 256 << 20                # ... and at most 256 MiB of samples
_MIN_RATIO = 0.01                    # diff energy / signal energy: below this, identical


def data_payload(path, limit: int) -> bytes:
    """Bytes of the `data` chunk, read without trusting the RIFF size.

    Python 3.13's `wave` reads through a chunk bounded by RIFF's length field:
    a wrong value (0x24 instead of the file size — BuckeyeCTF "couch potato")
    makes `readframes` return nothing even though the samples are intact. The
    chunks are walked directly instead (fmt is already parsed by `wave`)."""
    try:
        with open(path, "rb") as fh:
            if fh.read(4) != b"RIFF" or fh.read(4) is None or fh.read(4) != b"WAVE":
                return b""
            while True:
                head = fh.read(8)
                if len(head) < 8:
                    return b""
                cid, size = head[:4], int.from_bytes(head[4:8], "little")
                if cid == b"data":
                    return fh.read(min(size, limit))
                fh.seek(size + (size & 1), 1)      # chunks are word aligned
    except OSError:
        return b""


class StereoDiffAnalyzer(Analyzer):
    name = "stereo-diff"
    category = "audio"
    description = "WAV stereo: write the L-R difference as a child (data hidden in one channel)."
    accepts = (".wav",)
    display_order = 405

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            with wave.open(str(ctx.input), "rb") as w:
                channels = w.getnchannels()
                width = w.getsampwidth()
                rate = w.getframerate()
                nframes = w.getnframes()
                comptype = w.getcomptype()
                if comptype != "NONE":
                    return ToolResult(self.name, status="skipped",
                                      summary=f"compressed WAV ({comptype})")
                if channels != 2:
                    return ToolResult(self.name, status="skipped",
                                      summary=("mono WAV" if channels == 1
                                               else f"not stereo ({channels} channels)"))
                if width not in (1, 2):
                    return ToolResult(self.name, status="skipped",
                                      summary=f"unsupported sample width ({width * 8} bit)")
                if rate <= 0:
                    return ToolResult(self.name, status="skipped", summary="bad sample rate")
                # cap *before* reading: a long capture must not be decoded whole
                frames = min(nframes, rate * MAX_SECONDS, MAX_BYTES // (channels * width))
                raw = w.readframes(max(0, frames))
                if not raw and nframes:
                    raw = data_payload(ctx.input, max(0, frames) * channels * width)
        except Exception as exc:
            return ToolResult(self.name, status="skipped",
                              summary=f"WAV not readable ({exc})")
        try:
            import numpy as np
        except Exception as exc:                       # pragma: no cover - numpy ships
            return ToolResult(self.name, status="skipped", summary=f"numpy missing: {exc}")

        dtype = "u1" if width == 1 else "<i2"
        usable = len(raw) // (channels * width)
        if usable < 8:
            return ToolResult(self.name, status="skipped", summary="no audio frames")
        data = np.frombuffer(raw[:usable * channels * width], dtype=dtype)
        data = data.reshape(-1, channels).astype(np.int32)
        if width == 1:
            data -= 128                               # 8-bit PCM is unsigned
        left, right = data[:, 0], data[:, 1]
        diff = left - right
        as_float = data.astype(np.float64)
        signal = float((as_float ** 2).mean())
        diff_energy = float((diff.astype(np.float64) ** 2).mean())
        if signal <= 0 or diff_energy < _MIN_RATIO * signal:
            return ToolResult(self.name, status="skipped",
                              summary="channels identical (no L-R difference)")

        out = ctx.sub(self.name) / f"{ctx.input.stem}_L-R.wav"
        if width == 1:
            payload = np.clip(diff + 128, 0, 255).astype("u1").tobytes()
        else:
            payload = np.clip(diff, -32768, 32767).astype("<i2").tobytes()
        with wave.open(str(out), "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(width)
            w.setframerate(rate)
            w.writeframes(payload)
        ratio = diff_energy / signal
        truncated = usable < nframes
        return ToolResult(
            self.name, status="done",
            summary=f"L-R written ({usable} sample(s)" + (", first 10 min" if truncated else "") + ")",
            output=(f"difference energy / signal energy: {ratio:.3f}\n"
                    f"samples: {usable} at {rate} Hz, {width * 8} bit"
                    + (" (truncated to 10 minutes)" if truncated else "")),
            extracted=[str(out)],
            artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])


register(StereoDiffAnalyzer())
