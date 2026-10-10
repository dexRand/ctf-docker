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


def test_custom_flag_pattern_with_braces(monkeypatch):
    import re

    from backend import orchestrator

    monkeypatch.setattr(orchestrator, "_CUSTOM_FLAG_RE", re.compile(rb"DUCTF\{[^}]+\}"))
    out = [v for v, _, _ in orchestrator.custom_flag_matches(b"xx DUCTF{custom_1} yy")]
    assert out == ["DUCTF{custom_1}"]


def test_custom_flag_pattern_without_braces(monkeypatch):
    import re

    from backend import orchestrator

    monkeypatch.setattr(orchestrator, "_CUSTOM_FLAG_RE", re.compile(rb"FLAG-[0-9a-f]{8}"))
    out = [v for v, _, _ in orchestrator.custom_flag_matches(b"here FLAG-deadbeef end")]
    assert out == ["FLAG-deadbeef"]


def test_no_custom_pattern_matches_nothing(monkeypatch):
    from backend import orchestrator

    monkeypatch.setattr(orchestrator, "_CUSTOM_FLAG_RE", None)
    assert orchestrator.custom_flag_matches(b"anything") == []


def test_wav_lsb_bits_roundtrip() -> None:
    from backend.analyzers.audio import _bits_to_text

    text = "ITS{wav_lsb}"
    bits = [(ord(c) >> i) & 1 for c in text for i in range(8)]
    assert _bits_to_text(bits) == text


def _hunt_values(pid: str, text: str, source: str) -> set[str]:
    from sqlmodel import Session, select

    from backend.db import engine, init_db
    from backend.models import Finding, Project
    from backend.orchestrator import _hunt

    init_db()
    with Session(engine) as s:
        s.add(Project(id=pid, name=pid, status="running"))
        s.commit()
        _hunt(s, pid, None, text, source)
        s.commit()
        return {f.value for f in s.exec(select(Finding).where(Finding.project_id == pid)).all()}


def test_collapsed_view_does_not_fabricate_flags() -> None:
    # `hello ITS{ui_smoke}` -> decode emits the rot13 layer `uryyb VGF{hv_fzbxr}`.
    # The generic matcher on the whitespace-collapsed copy used to glue the words
    # and report `uryybVGF{hv_fzbxr}` as a flag (a bogus "nested decode" finding).
    out = _hunt_values("fp-collapse", "[rot13] uryyb VGF{hv_fzbxr}", "decode:a.txt")
    assert "ITS{ui_smoke}" in out
    assert not any("VGF" in v or v.startswith("uryyb") for v in out)


def test_collapsed_view_still_joins_an_ocr_split_flag() -> None:
    # the fix keeps the collapsed copy useful: a flag broken across a newline by
    # OCR (`Corrupted flag`) is still recovered via the STRICT prefix matcher.
    out = _hunt_values("fp-split", "flag{Wh4t_\nth3_fl4g}", "gif-frames:frame-1.png")
    assert "flag{Wh4t_th3_fl4g}" in out
