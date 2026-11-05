"""Vigenere with the key recovered from a flag prefix, and rail fence."""
from __future__ import annotations

from backend.analyzers.decode import _vigenere, candidates


def _rail_encrypt(text: str, rails: int) -> str:
    """Classic zig-zag rail fence (the test writes its own cipher)."""
    period = 2 * rails - 2
    pattern = [min(i % period, period - i % period) for i in range(len(text))]
    rows: list[list[str]] = [[] for _ in range(rails)]
    for ch, r in zip(text, pattern, strict=True):
        rows[r].append(ch)
    return "".join("".join(row) for row in rows)


def test_vigenere_key_recovered_from_the_prefix():
    # the key is unknown to the decoder: it is derived from "picoCTF{" followed by
    # the ciphertext letters, then the period 3 ("KEY") is found
    flag = "picoCTF{vigenere_key_from_prefix}"
    cipher = _vigenere(flag, "KEY", decrypt=False)
    assert cipher != flag and cipher.endswith("}")
    res = candidates(cipher.encode())
    assert flag.encode() in res.values(), res
    assert any(k.startswith("vigenere") for k in res)


def test_vigenere_works_with_a_single_letter_key():
    flag = "DUCTF{one_letter_key}"
    cipher = _vigenere(flag, "z", decrypt=False)
    assert flag.encode() in candidates(cipher.encode()).values()


def test_rail_fence_three_rails():
    flag = "flag{rails_are_not_crypto}"
    cipher = _rail_encrypt(flag, 3)
    assert cipher != flag
    res = candidates(cipher.encode())
    assert flag.encode() in res.values(), res
    assert any(k.startswith("railfence") for k in res)


def test_plain_prose_produces_no_classic_cipher_results():
    text = (b"The quick brown fox jumps over the lazy dog. " * 8)
    names = list(candidates(text))
    assert not [n for n in names if n.startswith(("vigenere", "railfence"))]
