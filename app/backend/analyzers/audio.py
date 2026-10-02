"""Audio/video steg analyzers (spectrogram, waveform)."""
from __future__ import annotations

from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, which, out_of
from .registry import register

AV_EXT = (".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".mp4", ".mkv", ".avi", ".mov", ".webm")


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


register(SpectrogramAnalyzer())
register(WaveformAnalyzer())
