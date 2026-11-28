"""Unit tests for the generic `ask` analyzer (issue #42).

The signals are generated in the test with numpy: a three-level ASK carrier
(0 = separator, low = bit 0, high = bit 1) over a low-frequency "music" bed,
then encoded as a WAV. No network, no external tools.
"""
from __future__ import annotations

import wave
from pathlib import Path

import numpy as np

from backend.analyzers.ask import AskAnalyzer
from backend.analyzers.base import ToolContext

RATE = 44100
FLAG = "ITS{ask_1}"


def _bits(byte: int) -> list[int]:
    return [(byte >> i) & 1 for i in range(7, -1, -1)]


def _ask(message: bytes, carrier: float = 8000.0, baud: float = 50.0,
         low: float = 2e-3, high: float = 5e-3) -> np.ndarray:
    """8 MSB-first cells per byte, one zero-amplitude separator between bytes."""
    cell = int(round(RATE / baud))
    parts: list[np.ndarray] = []
    for index, byte in enumerate(message):
        bits = _bits(byte)
        for bit in bits:
            t = np.arange(cell) / RATE
            amp = high if bit else low
            parts.append(amp * np.sin(2 * np.pi * carrier * t))
        if index != len(message) - 1:
            parts.append(np.zeros(cell))
    return np.concatenate(parts)


def _music(n: int, amp: float = 0.005) -> np.ndarray:
    t = np.arange(n) / RATE
    return amp * (np.sin(2 * np.pi * 220 * t) + 0.5 * np.sin(2 * np.pi * 660 * t))


def _write_wav(path: Path, samples: np.ndarray, channels: int = 1) -> None:
    pcm = np.clip(samples * 32767, -32768, 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(pcm.tobytes())


def _run(path: Path, tmp_path: Path):
    return AskAnalyzer().run(ToolContext(input=path, workdir=tmp_path / "w"))


def test_ask_recovers_flag_from_noisy_mono(tmp_path: Path) -> None:
    message = FLAG.encode()
    ask = _ask(message)
    rng = np.random.default_rng(7)
    signal = _music(ask.size) + ask + rng.standard_normal(ask.size) * 1e-3
    path = tmp_path / "mono.wav"
    _write_wav(path, signal)
    res = _run(path, tmp_path)
    assert res.status == "done", res.summary
    assert FLAG in res.output
    assert "8000 Hz" in res.summary


def test_ask_uses_the_channel_difference_when_signal_is_left_only(tmp_path: Path) -> None:
    message = FLAG.encode()
    ask = _ask(message, carrier=6800.0, baud=40.0)
    music = _music(ask.size)
    left = music + ask
    right = music
    stereo = np.stack([left, right], axis=1)
    path = tmp_path / "stereo.wav"
    _write_wav(path, stereo, channels=2)
    res = _run(path, tmp_path)
    assert res.status == "done", res.summary
    assert FLAG in res.output
    assert "Hz" in res.summary
    assert "40.0" in res.summary


def test_ask_non_audio_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("no audio here")
    res = _run(path, tmp_path)
    assert res.status == "skipped"


def test_ask_too_short_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "short.wav"
    _write_wav(path, np.zeros(100))
    res = _run(path, tmp_path)
    assert res.status == "skipped"


def test_ask_broken_wav_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "broken.wav"
    path.write_bytes(b"this is not a wav file at all")
    res = _run(path, tmp_path)
    assert res.status == "skipped"
