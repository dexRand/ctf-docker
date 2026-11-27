"""Unit tests for the `same` analyzer (SAME/EAS FSK + best-2-of-3).

The WAV is generated in the test with numpy: mark/space tones at the SAME
frequencies, a 0xAB x16 preamble, then an LSB-first ASCII message sent three
times with a few bits flipped in each copy (never more than one copy per bit).
"""
from __future__ import annotations

import wave
from pathlib import Path

import numpy as np

from backend.analyzers.base import ToolContext
from backend.analyzers.same import (
    SameAnalyzer,
    _error_channel,
    _reconcile,
)

RATE = 44100
BIT = 85                       # samples per bit (the real captures use ~85)
MARK = 2083.0 + 1.0 / 3.0
SPACE = 1562.5


def _tone(bit_value: int) -> np.ndarray:
    t = np.arange(BIT) / RATE
    return np.sin(2 * np.pi * (MARK if bit_value else SPACE) * t)


def _bits(data: bytes) -> list[int]:
    out: list[int] = []
    for byte in data:
        out.extend((byte >> i) & 1 for i in range(8))
    return out


def _transmission(message: bytes, flips: set[int]) -> np.ndarray:
    bits = _bits(bytes([0xAB] * 16) + message)
    for i in flips:
        bits[i] ^= 1
    return np.concatenate([_tone(b) for b in bits])


def _write_wav(path: Path, samples: np.ndarray) -> None:
    pcm = np.clip(samples * 32767, -32768, 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(pcm.tobytes())


def _three_copies(path: Path, message: bytes) -> None:
    """Three copies, round-robin flips (each bit flipped in at most one copy)."""
    nbits = len(_bits(bytes([0xAB] * 16) + message))
    flips = [set(), set(), set()]
    for i in range(0, nbits, 11):
        flips[i % 3].add(i)
    gap = np.zeros(int(0.4 * RATE))
    parts = [gap]
    for copy in range(3):
        parts.append(_transmission(message, flips[copy]))
        parts.append(gap)
    _write_wav(path, np.concatenate(parts) * 0.8)


def test_same_recovers_flag_from_three_noisy_copies(tmp_path: Path) -> None:
    message = b"ZCZC-TST-FLG-ITS{sa-me_f-sk_1}-"
    p = tmp_path / "same.wav"
    _three_copies(p, message)
    res = SameAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.status == "done"
    assert "3 transmissions reconciled" in res.summary
    # the reconciled message is the exact transmitted text ...
    assert "ZCZC-TST-FLG-ITS{sa-me_f-sk_1}" in res.output
    # ... and the de-chunked view carries the contiguous flag for the flag hunt
    assert "ITS{same_fsk_1}" in res.output


def test_same_reconcile_majority_and_ties() -> None:
    original = b"ZCZC-WXR-TOR-018007+0045-0910115-KIND/NWS-"
    copies = [bytearray(original) for _ in range(3)]
    for i in range(len(original)):
        copies[i % 3][i] ^= 0x01        # one flipped bit per byte, one copy only
    payload, arrays = _reconcile([bytes(c) for c in copies])
    assert payload == original
    assert len(arrays) == 3


def test_same_reconcile_handles_mismatched_lengths_and_ties() -> None:
    # different lengths, a column where all three copies differ (no majority),
    # and a column with only two votes: must not raise and must stay bytes
    payload, arrays = _reconcile([b"ZCZC-ABCDEFGH", b"ZCZC-ABCDEFG", b"CZC-ABCXEFGH"])
    assert isinstance(payload, bytes)
    assert payload
    assert len(arrays) == 3
    # 2 copies: ties fall back to the first transmission, no crash
    payload2, _ = _reconcile([b"AAAA\x00BBBB", b"AAAA\xffBBBB"])
    assert isinstance(payload2, bytes)


def test_same_error_channel_reads_the_disagreements() -> None:
    # every secret character replaces a filler in exactly one copy, so two
    # copies keep the original character: the odd ones out spell the secret
    header = bytearray(b"ZCZC-WXR-TOR-" + b"." * 12 + b"ND/NWS-")
    secret = b"ITS{hidden}"
    copies = []
    for copy in range(3):
        buf = bytearray(header)
        for i, ch in enumerate(secret):
            if copy == i % 3:
                buf[13 + i] = ch
        copies.append(bytes(buf))
    payload, arrays = _reconcile(copies)
    channel = _error_channel(arrays)
    assert secret in channel
    assert _error_channel(arrays[:2]) == b""


def test_same_non_wav_is_skipped(tmp_path: Path) -> None:
    p = tmp_path / "random.wav"
    p.write_bytes(b"this is not a wav file at all")
    res = SameAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.status == "skipped"


def test_same_random_audio_is_skipped(tmp_path: Path) -> None:
    rng = np.random.default_rng(1234)
    p = tmp_path / "noise.wav"
    _write_wav(p, rng.standard_normal(3 * RATE) * 0.3)
    res = SameAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.status == "skipped"
