"""MSB-plane flag bits (most significant bit of the image pixels)."""
from __future__ import annotations

import numpy as np

from backend.analyzers.lsb import find_msb_flag


def _encode(flag: str) -> np.ndarray:
    bits: list[int] = []
    for ch in flag:
        v = ord(ch)
        bits += [(v >> i) & 1 for i in range(7, -1, -1)]      # MSB first
    pixels = (len(bits) + 2) // 3
    arr = np.zeros((1, pixels, 4), dtype=np.uint8)
    arr[..., 3] = 255
    for k, bit in enumerate(bits):
        if bit:
            arr[0, k // 3, k % 3] |= 0x80                      # MSB of R/G/B
    return arr


def test_msb_flag_is_found():
    flag = "picoCTF{msb_bits_123}"
    assert flag in find_msb_flag(_encode(flag))


def test_plain_zeros_have_no_flag():
    assert find_msb_flag(np.zeros((1, 64, 4), dtype=np.uint8)) == []
