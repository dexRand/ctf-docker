"""Unit tests for the `wav-levels` analyzer (quantised samples -> hex -> text)."""
from __future__ import annotations

import struct
import wave
from pathlib import Path

from backend.analyzers.audio import WavLevelsAnalyzer
from backend.analyzers.base import ToolContext


def _write_levels(path: Path, text: str, level_step: int = 500, base: int = 1000) -> None:
    hexs = text.encode().hex()
    samps = [base + int(c, 16) * level_step for c in hexs]
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(struct.pack("<" + "h" * len(samps), *samps))


def test_wav_levels_decodes_hex(tmp_path: Path) -> None:
    flag = "ITS{wav_levels_unit}"
    p = tmp_path / "levels.wav"
    _write_levels(p, f"flag: {flag}")
    res = WavLevelsAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.status == "done"
    assert flag in res.output


def test_wav_levels_random_noise_is_ignored(tmp_path: Path) -> None:
    import random

    p = tmp_path / "noise.wav"
    samps = [random.randint(-32768, 32767) for _ in range(2000)]
    with wave.open(str(p), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(struct.pack("<" + "h" * len(samps), *samps))
    res = WavLevelsAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.status == "done"
    assert "ITS{" not in res.output
