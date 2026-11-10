"""stereo-diff: L-R of a stereo WAV becomes a child for the audio analyzers."""
from __future__ import annotations

import wave
from pathlib import Path

import numpy as np

from backend.analyzers.base import ToolContext
from backend.analyzers.stereodiff import StereoDiffAnalyzer

RATE = 8000


def _write(path, left, right, width=2):
    data = np.stack([left, right], axis=1).reshape(-1)
    if width == 2:
        raw = np.clip(data, -32768, 32767).astype("<i2").tobytes()
    else:                                  # 8-bit PCM is unsigned
        raw = np.clip(data + 128, 0, 255).astype("u1").tobytes()
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(width)
        w.setframerate(RATE)
        w.writeframes(raw)
    return path


def _run(tmp_path, p):
    return StereoDiffAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))


def _tone(freq, seconds=0.5, amp=8000.0):
    t = np.arange(int(RATE * seconds)) / RATE
    return np.round(amp * np.sin(2 * np.pi * freq * t)).astype(np.int32)


def _peak(path) -> float:
    with wave.open(str(path), "rb") as w:
        rate = w.getframerate()
        raw = w.readframes(w.getnframes())
    samples = np.frombuffer(raw, dtype="<i2").astype(np.float64)
    spectrum = np.abs(np.fft.rfft(samples))
    return float(np.fft.rfftfreq(len(samples), 1 / rate)[int(np.argmax(spectrum))])


def test_difference_is_written_and_contains_the_left_only_tone(tmp_path):
    common, extra = _tone(440), _tone(1200)
    p = _write(tmp_path / "stereo.wav", common + extra, common)
    r = _run(tmp_path, p)
    assert r.status == "done"
    assert len(r.extracted) == 1
    child = tmp_path / "w" / "stereo-diff" / "stereo_L-R.wav"
    assert child in [Path(x) for x in r.extracted]
    assert abs(_peak(child) - 1200) < 5


def test_identical_channels_are_skipped(tmp_path):
    tone = _tone(440)
    p = _write(tmp_path / "same.wav", tone, tone)
    r = _run(tmp_path, p)
    assert r.status == "skipped" and "identical" in r.summary.lower()


def test_mono_is_skipped(tmp_path):
    p = tmp_path / "mono.wav"
    with wave.open(str(p), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes((_tone(440) // 2).astype("<i2").tobytes())
    r = _run(tmp_path, p)
    assert r.status == "skipped" and "mono" in r.summary.lower()


def test_8_bit_pcm_is_supported(tmp_path):
    left = _tone(300, amp=40)
    right = _tone(600, amp=20)
    p = _write(tmp_path / "eight.wav", left + right, right, width=1)
    r = _run(tmp_path, p)
    assert r.status == "done"
    child = tmp_path / "w" / "stereo-diff" / "eight_L-R.wav"
    assert child.is_file()


def test_wrong_riff_size_still_reads_the_samples(tmp_path):
    # a RIFF size smaller than the file (Python's wave then reads no frames)
    common, extra = _tone(440), _tone(1200)
    p = _write(tmp_path / "riff.wav", common + extra, common)
    raw = bytearray(p.read_bytes())
    raw[4:8] = (36).to_bytes(4, "little")
    p.write_bytes(bytes(raw))
    r = _run(tmp_path, p)
    assert r.status == "done"
    child = tmp_path / "w" / "stereo-diff" / "riff_L-R.wav"
    assert abs(_peak(child) - 1200) < 5


def test_non_wav_is_skipped(tmp_path):
    p = tmp_path / "not.wav"
    p.write_bytes(b"ID3\x03\x00 this is not a wave file")
    r = _run(tmp_path, p)
    assert r.status == "skipped"


def test_24_bit_pcm_is_skipped(tmp_path):
    p = tmp_path / "wide.wav"
    with wave.open(str(p), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(3)
        w.setframerate(RATE)
        w.writeframes(b"\x00" * (RATE * 2 * 3))
    r = _run(tmp_path, p)
    assert r.status == "skipped"
