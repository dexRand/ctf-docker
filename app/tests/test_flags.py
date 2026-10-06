"""Unit tests for the flag-hunting logic (no external tools required)."""
from __future__ import annotations

import codecs

from backend.orchestrator import (
    _GENERIC_RE,
    _STRICT_RE,
    _canon_flag,
    _detect_ext,
    _is_known_prefix,
    _ok_flag,
    _rot13_candidates,
    _snippet,
    _url_decoded,
)


def search(data: bytes) -> set[str]:
    return {
        m.group(0).decode("latin-1")
        for pat in (*_STRICT_RE, *_GENERIC_RE)
        for m in pat.finditer(data)
    }


def test_ok_flag_accepts_valid() -> None:
    assert _ok_flag("picoCTF{s0_m3ta_43f253bb}")
    assert _ok_flag("ITS{a_b-c!d?e@f.g}")
    assert _ok_flag("flag{with space}")


def test_ok_flag_rejects_markup_entities_and_junk() -> None:
    # the false positive we hit on a .docm (XML entities / attributes)
    assert not _ok_flag("htb{BLAQIt&#xD;&#xA;Bg=1}")
    assert not _ok_flag("flag{has|pipe}")
    assert not _ok_flag("flag{two}}")
    assert not _ok_flag("flag{}")


def test_no_truncated_fragment_of_pico() -> None:
    found = search(b'Artist: picoCTF{s0_m3ta_43f253bb}')
    assert "picoCTF{s0_m3ta_43f253bb}" in found
    assert not any(v.startswith("CTF{") for v in found)


def test_standalone_ctf_still_matches() -> None:
    assert "CTF{standalone_1}" in search(b"xx CTF{standalone_1} yy")


def test_detect_ext_from_file_output() -> None:
    assert _detect_ext("PNG image data, 1697 x 608, 8-bit/color RGB") == ".png"
    assert _detect_ext("JPEG image data, JFIF standard") == ".jpg"
    assert _detect_ext("Zip archive data, at least v2.0") == ".zip"
    assert _detect_ext("ASCII text") == ""
    assert _detect_ext("") == ""


def test_snippet_marks_flag() -> None:
    v = b'here is a flag "picoCTF{abc_1}" end'
    start = v.find(b"picoCTF{abc_1}")
    snip = _snippet(v, start, start + len("picoCTF{abc_1}"))
    assert "«picoCTF{abc_1}»" in snip


def test_canon_collapses_rot13_twin() -> None:
    real = "ITS{stego_z1p_appended}"
    twin = codecs.encode(real, "rot13")  # VGF{fgrtb_m1c_nccraqrq}
    assert twin != real
    assert _canon_flag(real) == real
    assert _canon_flag(twin) == real


def test_is_known_prefix() -> None:
    assert _is_known_prefix("picoCTF{x}")
    assert _is_known_prefix("flag{x}")
    assert not _is_known_prefix("VGF{x}")


def test_url_decoded_view_finds_inline_percent_encoded_flag() -> None:
    views = _url_decoded(b"xx ITS%7Burl_flag%7D yy")
    assert any(b"ITS{url_flag}" in v for v in views)
    assert _url_decoded(b"nothing % here") == []


def test_rot13_candidates_decode_twin_prefixes() -> None:
    twin = codecs.encode("ITS{rot13_inline}", "rot13")
    assert twin.startswith("VGF")
    found = [c[0] for c in _rot13_candidates(twin.encode())]
    assert "ITS{rot13_inline}" in found


def test_rot13_candidates_ignore_unrelated_text() -> None:
    assert _rot13_candidates(b"nothing to see here") == []


def test_wav_lsb_bits_roundtrip() -> None:
    from backend.analyzers.audio import _bits_to_text

    text = "ITS{wav_lsb}"
    bits = [(ord(c) >> i) & 1 for c in text for i in range(8)]
    assert _bits_to_text(bits) == text
