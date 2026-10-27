"""Flag patterns: what a flag looks like and how to normalise it.

Pure functions and compiled regexes, no DB access (see `flaghunt.py`).
"""
from __future__ import annotations

import codecs
import os
import re
import urllib.parse

# The prefix must not be preceded by an alphanumeric/underscore, otherwise
# `CTF{...}` would match inside `picoCTF{...}` and produce a truncated flag.
_LB = r"(?<![0-9A-Za-z_])"
# Flag prefixes searched everywhere, even in noisy sources (raw bytes, strings,
# pcap). Matching is case-insensitive. A CTF's own format (Ctf.flag_format)
# is added per challenge; FLAG_PATTERN adds a global one.
FLAG_PREFIXES = ("picoCTF", "ITS", "flag", "CTF", "HTB", "DUCTF", "ictf", "tjctf", "lactf",
                 "uiuctf", "SEKAI", "corctf", "dice", "csawctf", "actf", "idek", "wctf", "SusCTF")
STRICT_PATTERNS = [_LB + p + r"\{[^}\n]{1,200}\}" for p in FLAG_PREFIXES]
GENERIC_PATTERNS = [_LB + r"[0-9A-Za-z_]{2,32}\{[A-Za-z0-9_\-!?.,:;@#$%^&*+=/ ]{1,120}\}"]
_STRICT_RE = [re.compile(p.encode(), re.IGNORECASE) for p in STRICT_PATTERNS]
# for the whitespace-collapsed view: collapsing glues the previous word to the
# prefix ("svg+xml p i c o C T F {" -> "xmlpicoCTF{"), so no look-behind there;
# a shorter twin (CTF{…} inside picoCTF{…}) is dropped by the fragment dedupe
_STRICT_GLUED_RE = [re.compile((p + r"\{[^}\n]{1,200}\}").encode(), re.IGNORECASE)
                    for p in FLAG_PREFIXES]
_GENERIC_RE = [re.compile(p.encode(), re.IGNORECASE) for p in GENERIC_PATTERNS]
# sources where the generic "<word>{...}" pattern is skipped (noisy OCR / raw bytes)
VISION_SOURCES = ("ocr", "bit-planes", "channel-remap", "image-enhance",
                  "gif-frames", "spectrogram", "waveform", "raw")
# sources where the generic "<word>{...}" pattern is skipped too: on raw dumps
# (strings/hex viewers) and pcap text it mostly matches binary noise
GENERIC_NOISY = ("strings", "hexyl", "xxd", "hexdump", "pcap",
                 "binwalk-scan", "binwalk-extract", "foremost", "nested-archive")
# a user-provided flag format (e.g. FLAG_PATTERN='DUCTF\{[^}]+\}' or even a
# pattern without braces). Applied to EVERY source, including the noisy ones.
_FLAG_PATTERN = os.environ.get("FLAG_PATTERN", "").strip()
_CUSTOM_FLAG_RE = re.compile(_FLAG_PATTERN.encode()) if _FLAG_PATTERN else None
# the fuzzy (OCR-confusion) matcher only makes sense on visual/audio output,
# not on raw file bytes where it matches markup/entities
FUZZY_SOURCES = tuple(s for s in VISION_SOURCES if s != "raw")


_FLAG_BODY_RE = re.compile(r"[A-Za-z0-9_\-!?@.,: ]{1,200}")


def _ok_flag(value: str) -> bool:
    if value.count("{") != 1 or value.count("}") != 1:
        return False
    if any(c in value for c in "|\n\r\t"):
        return False
    body = value[value.find("{") + 1:value.rfind("}")]
    if not body or len(body) > 200:
        return False
    # reject markup / entity / code snippets (`&#xD;`, `="..."`, `a=b`, …)
    if not _FLAG_BODY_RE.fullmatch(body):
        return False
    return sum(ch.isalnum() for ch in body) >= 3


# A flag found in a different encoding (typically rot13 of the whole value,
# e.g. `VGF{...}` for `ITS{...}`) should collapse to a single finding.
KNOWN_PREFIXES = {p.lower() for p in FLAG_PREFIXES}


def _is_known_prefix(value: str) -> bool:
    return value.split("{", 1)[0].lower() in KNOWN_PREFIXES


# Flags hidden as their rot13 twin (e.g. `VGF{...}` for `ITS{...}`) are common
# in tool outputs; on noisy sources (strings/hex) the generic pattern is skipped
# so we look for the rot13 form of the known prefixes explicitly.
_ROT13_PREFIXES = tuple(sorted({codecs.encode(p, "rot13") for p in KNOWN_PREFIXES}))
_ROT13_RE = [re.compile((_LB + re.escape(p) + r"\{[^}\n]{1,200}\}").encode(), re.IGNORECASE)
             for p in _ROT13_PREFIXES]

# inline URL-encoding: any %XX escape triggers a de-quoted view
_PCT_RE = re.compile(rb"%[0-9A-Fa-f]{2}")


def _url_decoded(data: bytes) -> list[bytes]:
    """Percent-decoded views (inline `%7B`-style flags), only when it changes."""
    if not _PCT_RE.search(data):
        return []
    try:
        out = urllib.parse.unquote_to_bytes(data)
    except Exception:
        return []
    return [out] if out != data else []


def _rot13_candidates(view: bytes) -> list[tuple[str, int, int]]:
    """(decoded_flag, start, end) for rot13-twin prefixes found in ``view``."""
    out: list[tuple[str, int, int]] = []
    for pat in _ROT13_RE:
        for m in pat.finditer(view):
            val = codecs.decode(m.group(0).decode("latin-1", "replace"), "rot13")
            out.append((val, m.start(), m.end()))
    return out


def custom_flag_matches(view: bytes) -> list[tuple[str, int, int]]:
    """Matches of the user-provided ``FLAG_PATTERN`` (braces not required)."""
    if _CUSTOM_FLAG_RE is None:
        return []
    out: list[tuple[str, int, int]] = []
    for m in _CUSTOM_FLAG_RE.finditer(view):
        val = m.group(0).decode("latin-1", "replace")
        if val and all(32 <= ord(c) < 127 or c in "\n\t" for c in val):
            out.append((val, m.start(), m.end()))
    return out


def _canon_flag(value: str) -> str:
    """Canonical key: a flag and its rot13 twin map to the same string."""
    alt = codecs.encode(value, "rot13")
    if _is_known_prefix(alt) and not _is_known_prefix(value):
        return alt
    if _is_known_prefix(value):
        return value
    return min(value, alt)
# OCR often reads '{' as f/F/l/L/[/( and ']'/'}' as ] or ). This fuzzy pattern
# rescues flags found by OCR/vision tools and normalises them back.
_FUZZY_RE = re.compile(
    rb"(?<![A-Za-z0-9_])([A-Za-z0-9_]{0,15}?(?:picoCTF|ITS|FLAG|flag|HTB|ctf|CTF))"
    rb"[\{\[\(fFlL]([ -~]{1,180}?)[\}\]\)]", re.IGNORECASE)
