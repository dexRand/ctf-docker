"""SAME/EAS FSK decoder with best-2-of-3 reconciliation.

The SAME (Specific Area Message Encoding) data burst is 8-bit LSB-first ASCII
sent as FSK: mark (bit 1) = 2083.33 Hz, space (bit 0) = 1562.5 Hz, 520.83 baud.
A burst starts with 16 bytes of 0xAB; emergency messages are sent three times
and the specification recovers the payload with a columnar (best-2-of-3)
majority, which also fixes a decoder that only sees corrupted copies.

The bit clock is *estimated* from the signal, not assumed: a WAV generated from
the standard parameters has ~84.67 samples per bit at 44.1 kHz, but resampled or
re-generated files differ. For every detected burst we search the bit period and
phase that maximise the preamble match plus the amount of printable payload.

The payload is plain SAME text (e.g. ``ZCZC-OSR-FLG-...``). The flag is often
chunked with ``-`` separators to stay inside the SAME field syntax, so the
output also carries a de-chunked variant (all ``-`` removed) for the flag hunt.
"""
from __future__ import annotations

import time
import wave

import numpy as np

from .base import Analyzer, ToolContext, ToolResult
from .morse import _read_wav_mono
from .registry import register
from .util import AV_EXT

MARK_HZ = 2083.0 + 1.0 / 3.0
SPACE_HZ = 1562.5
BAUD = 520.0 + 5.0 / 6.0

MAX_BYTES = 64 << 20          # input file cap
MAX_SAMPLES = 8_000_000       # ~3 min at 44.1 kHz
MAX_OUTPUT = 200_000
MAX_MSG_BYTES = 400
DEADLINE = 120.0

_PREAMBLE_BITS = 128
_PATTERN = np.array([(0xAB >> i) & 1 for i in range(8)] * 16, dtype=np.float64)


def _quad_mag(samples: np.ndarray, rate: int, freq: float, win: int) -> np.ndarray:
    """Magnitude of the matched filter at `freq`, one value per window start."""
    n = np.arange(len(samples), dtype=np.float64)
    z = samples.astype(np.float64) * np.exp(-2j * np.pi * freq * n / rate)
    cs = np.concatenate(([0j], np.cumsum(z)))
    return np.abs(cs[win:] - cs[:-win])


def _corr_scores(bits: np.ndarray) -> np.ndarray:
    """Match count of the 128-bit 0xAB preamble pattern at every bit offset."""
    n = len(bits)
    if n < _PREAMBLE_BITS:
        return np.zeros(0)
    nfft = 1 << int(np.ceil(np.log2(n + len(_PATTERN))))
    c = np.fft.irfft(np.fft.rfft(bits, nfft) * np.conj(np.fft.rfft(_PATTERN, nfft)), nfft)
    c = c[: n - len(_PATTERN) + 1]
    ones = np.concatenate(([0.0], np.cumsum(bits)))
    win = ones[len(_PATTERN):] - ones[:-len(_PATTERN)]
    return len(_PATTERN) - int(_PATTERN.sum()) - win + 2 * c


def _slice(cum: np.ndarray, eb: np.ndarray, phase: float, period: float,
           nbits: int) -> tuple[np.ndarray, np.ndarray]:
    """Integrate-and-dump one value (and the tone energy) per bit interval."""
    idx = np.clip(np.rint(phase + np.arange(nbits + 1) * period).astype(np.int64),
                  0, len(eb) - 1)
    bits = ((cum[idx[1:]] - cum[idx[:-1]]) > 0).astype(np.float64)
    ebits = (eb[idx[1:]] + eb[idx[:-1]]) / 2.0
    return bits, ebits


def _decode_bytes(bits: np.ndarray, ebits: np.ndarray, start: int) -> bytes:
    """Bytes after the preamble while the tone is active (silence ends a burst)."""
    out = bytearray()
    limit = min(len(bits), start + 8 * MAX_MSG_BYTES)
    ethr = 0.15 * float(np.max(ebits)) if ebits.size else 0.0
    i = start
    while i + 8 <= limit:
        if ebits[i] <= ethr:
            break
        out.append(sum(int(bits[i + j]) << j for j in range(8)))
        i += 8
    return bytes(out)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b < 127) / len(data)


def _best_window(d: np.ndarray, energy: np.ndarray, start: int, nominal: float,
                 deadline: float):
    """Search (period, phase) for one burst and return its payload bytes."""
    a = max(0, start - int(48 * nominal))
    if a >= len(d):
        return None
    cum = np.concatenate(([0.0], np.cumsum(d[a:])))
    eb = energy[a:]
    max_bits = int(min(1000, (len(d) - a - 1) / nominal))
    if max_bits < 300:
        return None

    def evaluate(period: float, phase: float):
        n = min(max_bits, int((len(cum) - phase - 1) / period))
        if n < 200:
            return None
        bits, ebits = _slice(cum, eb, phase, period, n)
        sc = _corr_scores(bits)
        if not len(sc):
            return None
        # the target preamble sits near the start of the window: never lock
        # onto the next burst's preamble
        st = int(np.argmax(sc[:min(len(sc), 300)]))
        payload = _decode_bytes(bits, ebits, st + _PREAMBLE_BITS)
        score = _printable_ratio(payload) + 2.0 * float(sc[st]) / _PREAMBLE_BITS
        return score, period, phase

    coarse = None
    for period in np.arange(0.985 * nominal, 1.02 * nominal, 0.05):
        if time.monotonic() > deadline:
            return None
        for phase in np.arange(0.0, period, 4.0):
            res = evaluate(period, phase)
            if res and (coarse is None or res[0] > coarse[0]):
                coarse = res
    if coarse is None:
        return None
    fine = None
    for period in np.arange(coarse[1] - 0.06, coarse[1] + 0.061, 0.01):
        if time.monotonic() > deadline:
            break
        for phase in np.arange(max(0.0, coarse[2] - 4.0), coarse[2] + 4.01, 0.5):
            res = evaluate(period, phase)
            if res and (fine is None or res[0] > fine[0]):
                fine = res
    best = fine or coarse
    _, period, phase = best
    n = min(max_bits, int((len(cum) - phase - 1) / period))
    bits, ebits = _slice(cum, eb, phase, period, n)
    sc = _corr_scores(bits)
    st = int(np.argmax(sc[:min(len(sc), 300)]))
    return _decode_bytes(bits, ebits, st + _PREAMBLE_BITS)


def _trim_preamble(data: bytes) -> bytes:
    i = 0
    while i < len(data) and data[i] == 0xAB:
        i += 1
    return data[i:]


def _best_shift(ref: np.ndarray, arr: np.ndarray):
    best = None
    for shift in range(-24, 25):
        lo, hi = max(0, -shift), min(len(ref), len(arr) - shift)
        if hi - lo < 8:
            continue
        agree = float(np.mean(ref[lo:hi] == arr[lo + shift:hi + shift]))
        if best is None or agree > best[0]:
            best = (agree, shift)
    return best


def _align(ref: np.ndarray, arr: np.ndarray) -> np.ndarray:
    best = _best_shift(ref, arr)
    if best is None:
        return np.full(len(ref), -1, dtype=np.int64)
    shift = best[1]
    aligned = np.full(len(ref), -1, dtype=np.int64)
    for k in range(len(ref)):
        j = k + shift
        if 0 <= j < len(arr):
            aligned[k] = arr[j]
    return aligned


def _same_burst(a: bytes, b: bytes) -> bool:
    """Two decodes of the same burst agree over most of their overlap."""
    if abs(len(a) - len(b)) > 16:
        return False
    aa = np.frombuffer(a, dtype=np.uint8).astype(np.int64)
    bb = np.frombuffer(b, dtype=np.uint8).astype(np.int64)
    best = _best_shift(aa, bb)
    return best is not None and best[0] >= 0.85


def _reconcile(seqs: list[bytes]) -> tuple[bytes, list[np.ndarray]]:
    """Align the transmissions, return the best-2-of-3 majority and the columns."""
    seqs = [s for s in seqs if s]
    if not seqs:
        return b"", []
    ref = max(seqs, key=len)
    ref_arr = np.frombuffer(ref, dtype=np.uint8).astype(np.int64)
    arrays = [ref_arr]
    for seq in seqs:
        if seq is ref:
            continue
        arrays.append(_align(ref_arr, np.frombuffer(seq, dtype=np.uint8).astype(np.int64)))
    out = bytearray()
    for k in range(len(ref_arr)):
        votes = [int(a[k]) for a in arrays if k < len(a) and a[k] >= 0]
        if not votes:
            out.append(0x2E)
            continue
        value = 0
        for bit in range(8):
            ones = sum((v >> bit) & 1 for v in votes)
            if ones * 2 > len(votes):
                value |= 1 << bit
            elif ones * 2 == len(votes) and (votes[0] >> bit) & 1:
                value |= 1 << bit          # tie: keep the first transmission's bit
        out.append(value)
    return bytes(out), arrays


def _error_channel(arrays: list[np.ndarray]) -> bytes:
    """Characters carried by the disagreements of the three copies.

    SAME repeats the header three times for error correction; an error is the
    character that appears in only one copy. Reading those "errors" in order is
    a covert channel. When all three copies agree the common character is kept
    too, because a secret character can coincide with the original one (the
    documented inverse of the columnar correction).
    """
    if len(arrays) != 3:
        return b""
    out = bytearray()
    length = max(len(a) for a in arrays)
    for k in range(length):
        chars = [int(a[k]) for a in arrays if k < len(a) and a[k] >= 0]
        if len(chars) < 3 or len(set(chars)) == 3:
            continue
        for c in chars:
            if chars.count(c) == 3 or chars.count(c) == 1:
                out.append(c)
                break
    return bytes(out)


def _render(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


class SameAnalyzer(Analyzer):
    name = "same"
    category = "radio"
    description = "Decode SAME/EAS FSK data bursts and recover the message by best-2-of-3."
    accepts = AV_EXT
    display_order = 427
    tier = "deep"

    def run(self, ctx: ToolContext) -> ToolResult:
        deadline = time.monotonic() + DEADLINE
        try:
            size = ctx.input.stat().st_size
            with open(ctx.input, "rb") as fh:
                head = fh.read(12)
        except OSError as exc:
            return ToolResult(self.name, status="skipped", summary=f"not readable ({exc})")
        if size > MAX_BYTES:
            return ToolResult(self.name, status="skipped", summary="file too large")
        if len(head) < 12 or head[:4] != b"RIFF" or head[8:12] != b"WAVE":
            return ToolResult(self.name, status="skipped", summary="not a RIFF/WAVE file")
        try:
            with wave.open(str(ctx.input), "rb") as w:
                nch, width, rate, frames = (w.getnchannels(), w.getsampwidth(),
                                            w.getframerate(), w.getnframes())
                comptype = w.getcomptype()
            if comptype != "NONE" or width not in (1, 2, 4) or nch < 1 or rate <= 0:
                return ToolResult(self.name, status="skipped", summary="unsupported WAV codec")
            if frames <= 0:
                return ToolResult(self.name, status="skipped", summary="empty WAV")
            if frames > MAX_SAMPLES:
                tmp = ctx.sub(self.name) / "same-head.wav"
                with wave.open(str(ctx.input), "rb") as src, wave.open(str(tmp), "wb") as dst:
                    dst.setnchannels(nch)
                    dst.setsampwidth(width)
                    dst.setframerate(rate)
                    dst.writeframes(src.readframes(MAX_SAMPLES))
                samples, rate = _read_wav_mono(tmp)
            else:
                samples, rate = _read_wav_mono(ctx.input)
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"WAV not readable ({exc})")
        if len(samples) < 2 * rate:
            return ToolResult(self.name, status="skipped", summary="too short for a SAME burst")

        nominal = rate / BAUD
        win = max(1, int(round(nominal)))
        mark = _quad_mag(samples, rate, MARK_HZ, win)
        space = _quad_mag(samples, rate, SPACE_HZ, win)
        d = (mark - space) / (mark + space + 1e-9)
        energy = mark + space
        del mark, space, samples

        nbits = int((len(d) - 1) / nominal)
        cum = np.concatenate(([0.0], np.cumsum(d)))

        # coarse pass: locate the data bursts with the nominal bit clock
        coarse_phase = 0.0
        best_val = -1.0
        best_scores = np.zeros(0)
        for phase in range(max(1, win)):
            if time.monotonic() > deadline:
                break
            bits, _eb = _slice(cum, energy, phase, nominal, nbits)
            scores = _corr_scores(bits)
            if not len(scores):
                continue
            val = float(np.sum(np.maximum(scores - 0.6 * _PREAMBLE_BITS, 0.0)))
            if val > best_val:
                best_val, coarse_phase, best_scores = val, phase, scores
        if not len(best_scores):
            return ToolResult(self.name, status="skipped", summary="no SAME preamble")
        cands: list[int] = []
        for i in np.argsort(best_scores)[::-1]:
            if best_scores[i] < 0.7 * _PREAMBLE_BITS or len(cands) >= 8:
                break
            if all(abs(int(i) - c) >= 2 * _PREAMBLE_BITS for c in cands):
                cands.append(int(i))
        cands.sort()
        if not cands:
            return ToolResult(self.name, status="skipped", summary="no SAME preamble")

        seqs: list[bytes] = []
        for c in cands:
            if time.monotonic() > deadline:
                break
            payload = _best_window(d, energy, int(c * nominal + coarse_phase),
                                   nominal, deadline)
            if not payload:
                continue
            payload = _trim_preamble(payload)
            if len(payload) < 24:
                continue                        # EOM ("NNNN") or noise
            seqs.append(payload)
        if not seqs:
            return ToolResult(self.name, status="skipped", summary="no SAME data")
        # drop duplicates of the same burst (the preamble match has a plateau)
        uniq: list[bytes] = []
        for seq in seqs:
            if any(_same_burst(seq, u) for u in uniq):
                continue
            uniq.append(seq)
        seqs = uniq

        payload, arrays = _reconcile(seqs)
        text = _render(payload)
        dashless = text.replace("-", "")
        out = text
        if dashless != text:
            out += "\n\n[de-chunked]\n" + dashless
        channel = _error_channel(arrays)
        if len(channel) >= 8 and _printable_ratio(channel) >= 0.6:
            ctext = _render(channel)
            out += "\n\n[errors]\n" + ctext
            if ctext.lower() != ctext:      # case-insensitive flags keep working
                out += "\n" + ctext.lower()
        return ToolResult(self.name, status="done", output=out[:MAX_OUTPUT],
                          summary=f"SAME: {len(seqs)} transmissions reconciled")


register(SameAnalyzer())
