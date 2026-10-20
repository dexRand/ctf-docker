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
IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".ppm")
AV_EXT = (".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".au", ".snd",
          ".mp4", ".mkv", ".avi", ".mov", ".webm")
ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".tbz", ".tbz2", ".bz2",
               ".xz", ".txz", ".cab", ".iso")

# --- bits ---------------------------------------------------------------------

def bits_to_ints(bits: list[int], width: int = 8) -> list[int]:
    """MSB-first groups of `width` bits (a trailing partial group is dropped)."""
    out = []
    for i in range(0, len(bits) - len(bits) % width, width):
        val = 0
        for b in bits[i:i + width]:
            val = (val << 1) | b
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
# (signature, extension); longer/more specific signatures first
MAGICS = (
    (b"\x89PNG\r\n\x1a\n", ".png"), (b"\xff\xd8\xff", ".jpg"), (b"GIF89a", ".gif"),
    (b"GIF87a", ".gif"), (b"PK\x03\x04", ".zip"), (b"%PDF", ".pdf"), (b"\x7fELF", ".elf"),
    (b"7z\xbc\xaf\x27\x1c", ".7z"), (b"Rar!", ".rar"), (b"\xfd7zXZ", ".xz"),
    (b"\x1f\x8b\x08", ".gz"), (b"BZh", ".bz2"), (b"RIFF", ".wav"), (b"BM", ".bmp"),
)


def magic_ext(blob: bytes) -> str:
    """Extension for a known file signature at the start of `blob`, else ""."""
    for sig, ext in MAGICS:
        if blob.startswith(sig):
            return ext
    return ""
