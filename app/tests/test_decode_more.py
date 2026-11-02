"""Extra decoders of the `decode` analyzer (issue #12)."""
from __future__ import annotations

import base64
import binascii
import codecs

from backend.analyzers.decode import _base45, candidates, chain

FLAG = b"picoCTF{d3c0d3_m3}"


def _b58(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return out


def test_base58():
    assert candidates(_b58(FLAG).encode())["base58"] == FLAG


def test_base45_roundtrip_known_vector():
    assert _base45("BB8") == b"AB"            # RFC 9285 example


def test_caesar_shift_is_kept_only_with_a_flag_prefix():
    shifted = FLAG.decode().translate(str.maketrans(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "defghijklmnopqrstuvwxyzabcDEFGHIJKLMNOPQRSTUVWXYZABC"))
    out = candidates(shifted.encode())
    assert out["caesar23"] == FLAG             # shift back by 3 == forward 23
    assert not [k for k in candidates(b"just some ordinary words here") if k.startswith("caesar")]


def test_atbash():
    enc = FLAG.decode().translate(str.maketrans(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"))
    assert candidates(enc.encode())["atbash"] == FLAG


def test_a1z26():
    assert candidates(b"6 12 1 7 9 19 8 5 18 5")["a1z26"] == b"flagishere"


def test_quoted_printable_and_uuencode():
    qp = b"flag=7Bq=75oted=7D"
    assert candidates(qp)["quoted-printable"] == b"flag{quoted}"
    uu = b"begin 644 f.txt\n" + binascii.b2a_uu(FLAG) + b"`\nend\n"
    assert candidates(uu)["uuencode"] == FLAG


def test_brainfuck_and_ook():
    bf = "+" * 72 + "." + "+" * 33 + "."          # "Hi"
    assert candidates(bf.encode())["brainfuck"] == b"Hi"
    to_ook = {">": "Ook. Ook?", "<": "Ook? Ook.", "+": "Ook. Ook.", "-": "Ook! Ook!",
              ".": "Ook! Ook.", ",": "Ook. Ook!", "[": "Ook! Ook?", "]": "Ook? Ook!"}
    ook = " ".join(to_ook[c] for c in bf)
    assert candidates(ook.encode())["ook"] == b"Hi"


def test_nested_chain_still_works():
    layered = base64.b64encode(codecs.encode(FLAG.decode(), "rot13").encode())
    assert any(FLAG.decode() in line for line in chain(layered))
