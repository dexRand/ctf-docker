"""Small helpers shared by analyzers (bits, printability, magic bytes, extensions).

Keep this module dependency-free (stdlib only): every analyzer imports it.
"""
from __future__ import annotations

import base64

# --- file-type groups ---------------------------------------------------------
# union of what the text analyzers used to accept one by one: widening a list
# only adds (cheap) work on text files, it never drops a challenge
TEXT_EXT = (".txt", ".md", ".csv", ".log", ".dat", ".asc", ".b64", ".hex", ".out",
            ".json", ".xml", ".yaml", ".yml", ".html", ".htm", ".js", ".py", ".c",
            ".cpp", ".srt", ".vtt")

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
