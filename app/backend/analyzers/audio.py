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
            return ToolResult(self.name, status="done", summary="spettrogramma",
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
            return ToolResult(self.name, status="skipped", summary=f"WAV non leggibile ({exc})")
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
            return ToolResult(self.name, status="skipped", summary=f"sample width {sw * 8} bit non supportata")

        lines: list[str] = []
        for label, text in views:
            printable = "".join(c if 32 <= ord(c) < 127 else "." for c in text)
            if any(ch.isalpha() for ch in printable):
                lines.append(f"[{label}] {printable[:4000]}")
        return ToolResult(self.name, status="done", output="\n".join(lines),
                          summary=f"{nch}ch {sw * 8}bit")


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
register(DtmfAnalyzer())
