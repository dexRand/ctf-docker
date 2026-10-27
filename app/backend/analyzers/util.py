"""Small helpers shared by analyzers (bits, printability, magic bytes, extensions).

Keep this module dependency-free (stdlib only): every analyzer imports it.
"""
from __future__ import annotations

import base64
import re

# --- file-type groups ---------------------------------------------------------
# union of what the text analyzers used to accept one by one: widening a list
# only adds (cheap) work on text files, it never drops a challenge
TEXT_EXT = (".txt", ".md", ".csv", ".log", ".dat", ".asc", ".b64", ".hex", ".out",
            ".json", ".xml", ".yaml", ".yml", ".html", ".htm", ".js", ".py", ".c",
            ".cpp", ".srt", ".vtt")
IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".ppm", ".qoi")
AV_EXT = (".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".au", ".snd",
          ".mp4", ".mkv", ".avi", ".mov", ".webm")
ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".tbz", ".tbz2", ".bz2",
               ".xz", ".txz", ".cab", ".iso")

# --- bits ---------------------------------------------------------------------

def bits_to_ints(bits, width: int = 8) -> list[int]:
    """MSB-first groups of `width` bits (a trailing partial group is dropped).

    Large streams (a 20 MB log has millions of letters) are packed with numpy:
    the per-bit Python loop is the reason those analyzers took tens of seconds."""
    n = len(bits) - len(bits) % width
    if n == 0:
        return []
    try:
        import numpy as np
        arr = bits if isinstance(bits, np.ndarray) else np.asarray(bits, dtype=np.uint8)
        if arr.dtype == np.bool_:
            arr = arr.astype(np.uint8)
        if n > 100_000:
            groups = arr[:n].reshape(-1, width).astype(np.uint32)
            weights = (1 << np.arange(width - 1, -1, -1)).astype(np.uint32)
            return (groups * weights).sum(axis=1).tolist()
    except Exception:
        pass
    out = []
    for i in range(0, n, width):
        val = 0
        for b in bits[i:i + width]:
            val = (val << 1) | int(b)
        out.append(val)
    return out


def bits_to_bytes(bits: list[int], width: int = 8) -> bytes:
    """MSB-first bit stream -> bytes (7-bit groups give 7-bit ASCII)."""
    return bytes(v & 0xFF for v in bits_to_ints(bits, width))


# --- printability -------------------------------------------------------------

def printable_ratio(blob: bytes) -> float:
    """Share of bytes that are printable ASCII or tab/newline/CR."""
    if not blob:
        return 0.0
    return sum(1 for c in blob if 32 <= c < 127 or c in (9, 10, 13)) / len(blob)


def is_printable(blob: bytes, threshold: float = 0.90) -> bool:
    return bool(blob) and printable_ratio(blob) >= threshold


# --- encodings ----------------------------------------------------------------

def b64decode_loose(raw: bytes) -> bytes:
    """base64 that tolerates missing padding (raises on invalid input)."""
    return base64.b64decode(raw + b"=" * ((4 - len(raw) % 4) % 4), validate=False)


B64_TOKEN = re.compile(rb"^[A-Za-z0-9+/]{2,}={0,2}$")


def join_b64_fragments(tokens: list[bytes]) -> str:
    """Decode base64 pieces (already in the right order) and join the ones that
    decode to text: a flag exfiltrated/logged a few characters at a time."""
    parts = []
    for tok in tokens:
        tok = tok.strip()
        if not B64_TOKEN.match(tok):
            continue
        try:
            dec = b64decode_loose(tok)
        except ValueError:
            continue
        if dec and printable_ratio(dec) >= 0.9:
            parts.append(dec.decode("latin-1"))
    return "".join(parts)


_FLAG_START = re.compile(r"[A-Za-z0-9_]{2,32}\{[A-Za-z0-9_\-!?@.,:]*$")
_FLAG_BODY = re.compile(r"[A-Za-z0-9_\-!?@.,:]+\}?$")


def assemble_flag_fragments(pieces: list[str]) -> list[str]:
    """Rebuild flags split into pieces mixed with noise (event logs, packets):
    start at a piece ending with `prefix{…`, append the following pieces that
    look like flag body (no brace), stop at the one that closes with `}`."""
    flags: list[str] = []
    cur: str | None = None
    for p in pieces:
        p = p.strip()
        if cur is None:
            if _FLAG_START.search(p):
                cur = p[_FLAG_START.search(p).start():]
            continue
        if _FLAG_BODY.fullmatch(p):
            cur += p
            if p.endswith("}"):
                flags.append(cur)
                cur = None
        elif _FLAG_START.search(p):        # a new start: drop the unfinished one
            cur = p[_FLAG_START.search(p).start():]
    return flags


# --- magic bytes --------------------------------------------------------------
# one table for signatures/extensions/mime lives in backend/magic.py
from ..magic import ext_of

# RIFF and a few container variants are not simple prefixes
_RIFF = ((b"RIFF", 8, b"WAVE", ".wav"), (b"RIFF", 8, b"AVI ", ".avi"),
         (b"RIFF", 8, b"WEBP", ".webp"))


def magic_ext(blob: bytes) -> str:
    """Extension for a known file signature at the start of `blob`, else ""."""
    ext = ext_of(blob)
    if ext:
        return ext
    for sig, off, marker, ri in _RIFF:
        if blob.startswith(sig) and blob[off:off + 4] == marker:
            return ri
    return ""
