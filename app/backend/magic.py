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
    (b"\x1f\x8b\x08", ".gz", "application/gzip"),
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
    (b"\xd4\xc3\xb2\xa1", ".pcap", "application/vnd.tcpdump.pcap"),
    (b"\xa1\xb2\xc3\xd4", ".pcap", "application/vnd.tcpdump.pcap"),
    (b"\x4d\x3c\xb2\xa1", ".pcap", "application/vnd.tcpdump.pcap"),
    (b"\xa1\xb2\x3c\x4d", ".pcap", "application/vnd.tcpdump.pcap"),
    (b"\x0a\x0d\x0d\x0a", ".pcapng", "application/x-pcapng"),
    (b"ElfFile\x00", ".evtx", "application/x-ms-evtx"),
    (b"regf", ".regf", "application/x-ms-registry"),
    (b"\x00\x00\x00\x01Bud1", ".DS_Store", "application/x-apple-ds-store"),
    (b"ANDROID!", ".img", "application/x-android-bootimg"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".doc", "application/x-ole-storage"),
)

# carving/extension table (signature, extension), kept as a tuple for callers
MAGICS = tuple((sig, ext) for sig, ext, _mime in SIGNATURES)


def by_ext(*exts: str, min_len: int = 3) -> tuple[tuple[bytes, str], ...]:
    """(signature, extension) for the given extensions, in table order. Short
    signatures (< min_len bytes, e.g. "BM", "MZ") are left out: in a random
    stream (LSB planes, junk prefixes) they match by chance."""
    return tuple((sig, ext) for sig, ext, _mime in SIGNATURES
                 if ext in exts and len(sig) >= min_len)

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


# Signatures that mark a whole file *embedded* in another one. Long enough not
# to show up by chance in a small binary (no "MZ", "BM", bare zlib headers).
_EMBEDDED = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", b"\xff\xd8\xff\xdb",
             b"GIF87a", b"GIF89a", b"%PDF-", b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07",
             b"\xfd7zXZ\x00", b"\x1f\x8b\x08", b"\x7fELF", b"OggS\x00", b"fLaC", b"ID3\x03",
             b"ID3\x04", b"SQLite format 3\x00", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"RIFF",
             b"BZh91AY&SY", b"ustar")
EMBED_SCAN = 64 << 20          # bytes scanned; a bigger file is always carved


def has_signature(data: bytes) -> bool:
    """A whole file signature anywhere in `data` (offset 0 included)."""
    return any(data.find(sig) != -1 for sig in _EMBEDDED)


def has_embedded(path) -> bool:
    """True when another file's signature appears *inside* `path` (offset > 0),
    so a carver has something to cut out. Files over EMBED_SCAN, or unreadable,
    count as True: carving is skipped only when it is provably useless."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(EMBED_SCAN + 1)
    except OSError:
        return True
    if len(data) > EMBED_SCAN:
        return True
    return any(data.find(sig, 1) != -1 for sig in _EMBEDDED)
