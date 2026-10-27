"""Single table of file signatures: extension + MIME type.

Used by `storage.sniff_mime` (preview), `analyzers/util.magic_ext` (carving) and
the pcap object filter — one table, so a new format is added in one place.
"""
from __future__ import annotations

# (signature, extension, mime)
SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", ".png", "image/png"),
    (b"\xff\xd8\xff", ".jpg", "image/jpeg"),
    (b"GIF87a", ".gif", "image/gif"),
    (b"GIF89a", ".gif", "image/gif"),
    (b"II*\x00", ".tiff", "image/tiff"),
    (b"MM\x00*", ".tiff", "image/tiff"),
    (b"BM", ".bmp", "image/bmp"),
    (b"%PDF-", ".pdf", "application/pdf"),
    (b"PK\x03\x04", ".zip", "application/zip"),
    (b"PK\x05\x06", ".zip", "application/zip"),
    (b"\x1f\x8b", ".gz", "application/gzip"),
    (b"7z\xbc\xaf\x27\x1c", ".7z", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", ".rar", "application/vnd.rar"),
    (b"BZh", ".bz2", "application/x-bzip2"),
    (b"\xfd7zXZ", ".xz", "application/x-xz"),
    (b"\x7fELF", ".elf", "application/x-elf"),
    (b"MZ", ".exe", "application/x-dosexec"),
    (b"OggS", ".ogg", "audio/ogg"),
    (b"fLaC", ".flac", "audio/flac"),
    (b"ID3", ".mp3", "audio/mpeg"),
    (b"\xff\xfb", ".mp3", "audio/mpeg"),
    (b"SQLite format 3\x00", ".sqlite", "application/vnd.sqlite3"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".doc", "application/x-ole-storage"),
)

# carving/extension table (signature, extension), kept as a tuple for callers
MAGICS = tuple((sig, ext) for sig, ext, _mime in SIGNATURES)

# RIFF containers: the marker sits at offset 8, not at the start
_RIFF = ((8, b"WAVE", ".wav", "audio/wav"),
         (8, b"AVI ", ".avi", "video/x-msvideo"),
         (8, b"WEBP", ".webp", "image/webp"))


def ext_of(blob: bytes) -> str:
    """Extension for a known signature at the start of `blob`, else ''."""
    for sig, ext, _mime in SIGNATURES:
        if blob.startswith(sig):
            return ext
    if blob[:4] == b"RIFF":
        for off, marker, ext, _mime in _RIFF:
            if blob[off:off + 4] == marker:
                return ext
    return ""


def mime_of(head: bytes) -> str | None:
    """MIME type for a known signature, else None."""
    for sig, _ext, mime in SIGNATURES:
        if head.startswith(sig):
            return mime
    if head[:4] == b"RIFF":
        for off, marker, _ext, mime in _RIFF:
            if head[off:off + 4] == marker:
                return mime
    return None
