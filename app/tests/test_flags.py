"""Unit tests for the flag-hunting logic (no external tools required)."""
from __future__ import annotations

from backend.orchestrator import (
    _GENERIC_RE,
    _STRICT_RE,
    _detect_ext,
    _ok_flag,
    _snippet,
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
