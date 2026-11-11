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
    freqs.append((freq, ms))


def _render(tones: list) -> np.ndarray:
    """Tones -> per-sample frequency, rounding the running time (not each tone),
    so a sub-sample clock error is kept instead of being rounded away."""
    ends = np.round(np.cumsum([ms for _, ms in tones]) / 1000.0 * FS).astype(int)
    starts = np.concatenate(([0], ends[:-1]))
    return np.concatenate([np.full(e - b, f) for (f, _), b, e in zip(tones, starts, ends, strict=True)])


def _vis(freqs: list, code: int = 60) -> None:
    """VIS header: leader, break, leader, start bit, 7 bits LSB first, parity, stop."""
    _tone(freqs, 1900, 300)
    _tone(freqs, 1200, 10)
    _tone(freqs, 1900, 300)
    _tone(freqs, 1200, 30)
    bits = [(code >> i) & 1 for i in range(7)]
    for b in bits + [sum(bits) % 2]:
        _tone(freqs, 1100 if b else 1300, 30)
    _tone(freqs, 1200, 30)


def _encode(mode_name: str, img: np.ndarray, path: Path, vis: bool = False,
            stretch: float = 1.0) -> None:
    """Encode an HxWx3 uint8 RGB image as a Scottie transmission (G,B,R order).
    stretch multiplies every duration (a sender clock off by that factor)."""
    sep, sync, porch, scan, width = SPEC[mode_name]
    sep, sync, porch, scan = (v * stretch for v in (sep, sync, porch, scan))
    assert img.shape[1] == width
    freqs: list = []
    if vis:
        _vis(freqs)
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
    f = _render(freqs)
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


def test_vis_header_is_not_line_0(tmp_path):
    wav = tmp_path / "vis.wav"
    _encode("ScottieS1", _halves("ScottieS1"), wav, vis=True)
    img, _, _ = sstv.decode_sstv(wav)
    # row 0 is the first encoded row, not the VIS header
    assert img[0, :150].mean() < 40 and img[0, 170:].mean() > 215


def test_clock_offset_keeps_channels_registered(tmp_path):
    src = np.zeros((64, 320, 3), dtype=np.uint8)
    src[:, 160:] = 255
    wav = tmp_path / "slow.wav"
    _encode("ScottieS1", src, wav, vis=True, stretch=1.002)
    img, _, info = sstv.decode_sstv(wav)
    rows = img[8:56]
    edges = [int(np.argmax(rows[:, :, c].mean(axis=0) > 127)) for c in range(3)]
    assert max(edges) - min(edges) <= 0, edges
    assert abs(info["clock"] - 1.002) < 0.0005


def test_text_layout_finds_tilt():
    from PIL import Image, ImageDraw, ImageFont
    try:
        font = ImageFont.truetype("DejaVuSans-Bold.ttf", 28)
    except OSError:
        font = ImageFont.load_default()
    img = Image.new("RGB", (320, 256), (235, 220, 90))
    ImageDraw.Draw(img).text((20, 110), "CTF{tilted_text}", fill=(40, 30, 20), font=font)
    channel, angle = sstv.text_layout(img.rotate(12, fillcolor=(235, 220, 90)))
    assert channel and abs(angle + 12) <= 1.5, (channel, angle)
    assert sstv.text_layout(img) == ("", 0.0)
