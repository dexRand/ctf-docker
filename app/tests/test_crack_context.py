"""Context wordlist: hints stored encoded in the challenge (TJCTF 2025 deep-layers)."""
from __future__ import annotations

from backend.crackflow import _decoded_forms


def test_base64_hint_is_decoded():
    assert _decoded_forms("cDBseWdsMHRwM3NzdzByZA==") == ["p0lygl0tp3ssw0rd"]


def test_hex_hint_is_decoded():
    assert "s3cr3t_pw" in _decoded_forms("73336372337" + "45f7077")


def test_plain_words_and_binary_decodings_are_ignored():
    assert _decoded_forms("hello") == []                  # too short to be an encoding
    assert _decoded_forms("AAAAAAAAAAAAAAAA") == []        # decodes to NUL bytes
