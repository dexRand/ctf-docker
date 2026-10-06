"""SSTV decoder tests.

The encoder below is written independently from the decoder (spec timings
hardcoded) so a round-trip failure means the two disagree; the real m00nwalk.wav
is the final ground-truth check (see docs/CHALLENGES.md).
"""
import wave
from pathlib import Path

import numpy as np

from backend.analyzers import sstv

FS = 48000
# (sep_ms, sync_ms, porch_ms, scan_ms, width) — independent copy of the spec
SPEC = {
    "ScottieS1": (1.5, 9.0, 1.5, 138.240, 320),
    "ScottieS2": (1.5, 9.0, 1.5, 88.064, 160),
}


def _tone(freqs: list, freq: float, ms: float) -> None:
    freqs.append(np.full(int(round(ms / 1000.0 * FS)), freq))


def _encode(mode_name: str, img: np.ndarray, path: Path) -> None:
    """Encode an HxWx3 uint8 RGB image as a Scottie transmission (G,B,R order)."""
    sep, sync, porch, scan, width = SPEC[mode_name]
    assert img.shape[1] == width
    freqs: list = []
    _tone(freqs, 1200, sync)          # leading "starting" sync
    for row in img:
        _tone(freqs, 1500, sep)
        for x in range(width):
            _tone(freqs, 1500 + row[x, 1] / 255 * 800, scan / width)   # Green
        _tone(freqs, 1500, sep)
        for x in range(width):
            _tone(freqs, 1500 + row[x, 2] / 255 * 800, scan / width)   # Blue
        _tone(freqs, 1200, sync)      # mid-line sync
        _tone(freqs, 1500, porch)
        for x in range(width):
            _tone(freqs, 1500 + row[x, 0] / 255 * 800, scan / width)   # Red
    f = np.concatenate(freqs)
    audio = np.sin(np.cumsum(2 * np.pi * f / FS))
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(FS)
        w.writeframes((audio * 32767).astype("<i2").tobytes())


def _halves(mode_name: str) -> np.ndarray:
    _, _, _, _, width = SPEC[mode_name]
    img = np.zeros((8, width, 3), dtype=np.uint8)
    img[:, width // 2:] = 255
    return img


def test_roundtrip_scottie_s1_recovers_geometry(tmp_path):
    src = _halves("ScottieS1")
    wav = tmp_path / "s1.wav"
    _encode("ScottieS1", src, wav)

    out = sstv.decode_sstv(wav)
    assert out is not None
    img, mode, info = out
    assert mode.name == "ScottieS1"
    assert img.shape == (256, 320, 3)
    # the 8 encoded rows must show black left / white right
    left = img[:8, :150].mean()
    right = img[:8, 170:].mean()
    assert left < 40 and right > 215


def test_roundtrip_scottie_s2(tmp_path):
    src = _halves("ScottieS2")
    wav = tmp_path / "s2.wav"
    _encode("ScottieS2", src, wav)
    out = sstv.decode_sstv(wav)
    assert out is not None
    img, mode, _ = out
    assert mode.name == "ScottieS2"
    assert img.shape == (256, 160, 3)
    assert img[:8, :70].mean() < 40 and img[:8, 90:].mean() > 215


def test_plain_tone_is_not_sstv(tmp_path):
    p = tmp_path / "tone.wav"
    audio = np.sin(2 * np.pi * 1000 * np.arange(FS * 2) / FS) * 0.6
    with wave.open(str(p), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(FS)
        w.writeframes((audio * 32767).astype("<i2").tobytes())
    assert sstv.decode_sstv(p) is None


def test_mode_periods_match_the_spec():
    assert round(sstv.MODES["ScottieS1"].period_ms, 2) == 428.22
    assert round(sstv.MODES["ScottieS2"].period_ms, 2) == 277.69
