"""Audio/video steg analyzers (spectrogram, waveform)."""
from __future__ import annotations

import struct
import wave
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, which, out_of
from .registry import register

AV_EXT = (".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".mp4", ".mkv", ".avi", ".mov", ".webm")


def _bits_to_text(bits: list[int]) -> str:
    """Pack a bit stream (first bit = LSB of the byte) into printable text."""
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        b = sum((bits[i + j] & 1) << j for j in range(8))
        out.append(b)
    return out.decode("latin-1", "replace")


class SpectrogramAnalyzer(Analyzer):
    name = "spectrogram"
    category = "audio"
    description = "Render the audio spectrogram (hidden images in the spectrum)."
    accepts = AV_EXT
    display_order = 400

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("ffmpeg"):
            return ToolResult(self.name, status="skipped", summary="ffmpeg not installed")
        out = ctx.sub(self.name) / f"{ctx.input.stem}_spectrogram.png"
        proc = ctx.run(["ffmpeg", "-y", "-i", str(ctx.input),
                        "-lavfi", "showspectrumpic=s=1920x1080:legend=1", str(out)], timeout=300)
        if out.exists():
            return ToolResult(self.name, status="done", summary="spectrogram",
                              artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])
        return ToolResult(self.name, status="error", output=out_of(proc)[-8000:], exit_code=proc.returncode)


class WaveformAnalyzer(Analyzer):
    name = "waveform"
    category = "audio"
    description = "Render the audio waveform image (Morse / binary in the envelope)."
    accepts = AV_EXT
    display_order = 410

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("ffmpeg"):
            return ToolResult(self.name, status="skipped", summary="ffmpeg not installed")
        out = ctx.sub(self.name) / f"{ctx.input.stem}_waveform.png"
        proc = ctx.run(["ffmpeg", "-y", "-i", str(ctx.input),
                        "-lavfi", "showwavespic=s=1920x480:colors=white", str(out)], timeout=300)
        if out.exists():
            return ToolResult(self.name, status="done", summary="waveform",
                              artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])
        return ToolResult(self.name, status="error", output=out_of(proc)[-8000:], exit_code=proc.returncode)


class WavLsbAnalyzer(Analyzer):
    name = "wav-lsb"
    category = "audio"
    description = "Extract text hidden in the LSB/bit planes of WAV samples."
    accepts = (".wav",)
    display_order = 415

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            with wave.open(str(ctx.input), "rb") as w:
                nch, sw, _sr, nfr = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
                raw = w.readframes(min(nfr, 2_000_000))
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"WAV not readable ({exc})")
        views: list[tuple[str, str]] = []
        if sw == 2:
            vals = struct.unpack("<" + "h" * (len(raw) // 2), raw[:len(raw) // 2 * 2])
            for ch in range(nch):
                samples = vals[ch::nch]
                views.append((f"lsb16 ch{ch}", _bits_to_text([v & 1 for v in samples])))
                views.append((f"hibyte16 ch{ch}", _bits_to_text([(v >> 8) & 1 for v in samples])))
        elif sw == 1:
            for ch in range(nch):
                views.append((f"lsb8 ch{ch}", _bits_to_text([b & 1 for b in raw[ch::nch]])))
        else:
            return ToolResult(self.name, status="skipped", summary=f"unsupported sample width {sw * 8} bit")

        lines: list[str] = []
        for label, text in views:
            printable = "".join(c if 32 <= ord(c) < 127 else "." for c in text)
            if any(ch.isalpha() for ch in printable):
                lines.append(f"[{label}] {printable[:4000]}")
        return ToolResult(self.name, status="done", output="\n".join(lines),
                          summary=f"{nch}ch {sw * 8}bit")


class WavLevelsAnalyzer(Analyzer):
    name = "wav-levels"
    category = "audio"
    description = ("Detect WAV samples quantised into a few levels and decode them as "
                   "hex (samples mapped to digits 0..f -> bytes).")
    accepts = (".wav",)
    display_order = 416

    MAX_SAMPLES = 4_000_000

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            import numpy as np
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"numpy missing: {exc}")
        try:
            with wave.open(str(ctx.input), "rb") as w:
                nch, sw = w.getnchannels(), w.getsampwidth()
                raw = w.readframes(min(w.getnframes(), self.MAX_SAMPLES))
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"WAV not readable ({exc})")
        if sw == 2:
            x = np.frombuffer(raw, dtype="<i2").astype("float64")
        elif sw == 1:
            x = np.frombuffer(raw, dtype="uint8").astype("float64") - 128.0
        else:
            return ToolResult(self.name, status="skipped", summary=f"unsupported width {sw*8} bit")
        if nch > 1:
            x = x[0::nch]
        if x.size < 16:
            return ToolResult(self.name, status="done", summary="too few samples")

        vmin, vmax = float(x.min()), float(x.max())
        span = vmax - vmin
        if span <= 0:
            return ToolResult(self.name, status="done", summary="constant signal")
        hexmap = np.array(list("0123456789abcdef"))
        results: list[tuple[str, str]] = []
        for k in range(2, 17):                       # number of levels
            step = span / (k - 1)
            if step < 2:
                continue
            idx = np.rint((x - vmin) / step).astype("int64")
            if int(idx.min()) != 0 or int(idx.max()) != k - 1:
                continue
            if float(np.max(np.abs((x - vmin) - idx * step))) > step * 0.25:
                continue                          # values do not sit on the levels
            digits = "".join(hexmap[idx].tolist())
            if len(digits) % 2:
                digits = digits[:-1]
            try:
                dec = bytes.fromhex(digits)
            except ValueError:
                continue
            text = dec.decode("latin-1", "replace")
            printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t") / max(1, len(text))
            letters = sum(c.isalpha() for c in text) / max(1, len(text))
            if printable >= 0.8 and ("{" in text or letters > 0.4):
                results.append((f"levels={k} step={step:.1f}", text))
        if not results:
            return ToolResult(self.name, status="done", summary="no level mapping found")
        lines = []
        for label, text in results[:3]:
            clean = "".join(c if 32 <= ord(c) < 127 or c in "\n\t" else "." for c in text)
            lines.append(f"[{label}] {clean[:4000]}")
        return ToolResult(self.name, status="done", output="\n".join(lines),
                          summary=f"{len(results)} mapping(s)")


class DtmfAnalyzer(Analyzer):
    name = "dtmf"
    category = "radio"
    description = "Decode DTMF phone tones from audio (multimon-ng)."
    accepts = AV_EXT
    display_order = 425

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("multimon-ng"):
            return ToolResult(self.name, status="skipped", summary="multimon-ng not installed")
        wav = ctx.sub(self.name) / "audio.wav"
        ctx.run(["ffmpeg", "-y", "-i", str(ctx.input), "-ac", "1", "-ar", "22050", str(wav)],
                timeout=300)
        proc = ctx.run(["multimon-ng", "-t", "wav", "-a", "DTMF", "-q", str(wav)], timeout=300)
        return ToolResult(self.name, status="done", output=out_of(proc),
                          summary="DTMF")


register(SpectrogramAnalyzer())
register(WaveformAnalyzer())
register(WavLsbAnalyzer())
register(WavLevelsAnalyzer())
register(DtmfAnalyzer())
