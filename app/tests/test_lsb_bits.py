"""LSB-of-raw-bytes flag bits (Investigative Reversing family)."""
from __future__ import annotations

from backend.analyzers.lsbbits import find_lsb_flags


def _encode(flag: str, shift: int = 5, lsb_first: bool = True,
            prefix_bytes: int = 2000) -> bytes:
    out = bytearray(b"\x00" * prefix_bytes)
    for ch in flag:
        v = (ord(ch) - shift) & 0xFF
        order = range(8) if lsb_first else range(7, -1, -1)
        for i in order:
            out.append((v >> i) & 1)      # the byte's LSB is the flag bit
    return bytes(out)


def test_finds_lsb_first_with_a_char_shift():
    flag = "picoCTF{test_lsb_bits_123}"
    assert flag in find_lsb_flags(_encode(flag, shift=5, lsb_first=True))


def test_finds_msb_first_without_shift():
    flag = "flag{other_order}"
    assert flag in find_lsb_flags(_encode(flag, shift=0, lsb_first=False))


def test_a_custom_prefix_is_found():
    flag = "CTF{plain_lsb}"
    assert flag in find_lsb_flags(_encode(flag, shift=3))


def test_no_flag_in_plain_zero_bytes():
    assert find_lsb_flags(b"\x00" * 500) == []
