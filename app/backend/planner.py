"""Analysis plan: which analyzers run on a file, in which order."""
from __future__ import annotations

import os
import threading

from .analyzers import get as get_tool

# ordered analysis plan (order matters: metadata -> text -> steg -> extract)
DEFAULT_PLAN = [
    "file", "exiftool", "identify", "ffprobe", "pdfinfo",
    "strings", "hexyl", "xxd", "pdftotext", "pdfid", "elf", "readelf", "objdump",
    "binwalk-scan",
    "decode", "blobs", "zero-width", "whitespace", "case-bits", "homoglyph", "morse-text",
    "ocr", "qr",
    "zsteg", "lsb-carve", "psimage", "png-chunks", "png-pixels", "steghide", "outguess", "jsteg", "openstego",
    "bit-planes", "channel-remap", "image-enhance", "gif-frames",
    "morse", "dtmf", "spectrogram", "waveform", "wav-lsb", "wav-levels", "sstv",
    "pcap",
    "nested-archive", "git", "7z", "office", "eml", "binwalk-extract", "foremost", "pngcheck",
    "png-repair", "image-repair",
]
HEAVY_EXTRACT = {"binwalk-extract", "foremost"}
# cap how many heavy tools run at once across all projects (CPU bound)
_HEAVY_TOOLS = set(HEAVY_EXTRACT) | {"7z", "steghide", "outguess", "jsteg", "openstego", "sstv"}
_HEAVY_SEM = threading.Semaphore(max(1, int(os.environ.get("HEAVY_TOOLS", "1"))))
ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".tgz")


def _detect_ext(ftype: str) -> str:
    """Best-effort extension from the `file` description, so analyzers run even
    when the name lies (e.g. a PNG uploaded as flag.txt)."""
    low = (ftype or "").lower()
    for key, ext in (
        ("elf 64-bit", ".elf"), ("elf 32-bit", ".elf"),
        ("png image", ".png"), ("jpeg image", ".jpg"), ("gif image", ".gif"),
        ("bmp image", ".bmp"), ("tiff image", ".tiff"), ("web/p image", ".webp"),
        ("webp", ".webp"), ("pdf document", ".pdf"), ("zip archive", ".zip"),
        ("rfc 822", ".eml"), ("mail message", ".eml"),
        ("7-zip archive", ".7z"), ("rar archive", ".rar"), ("tar archive", ".tar"),
        ("gzip compressed", ".gz"), ("bzip2 compressed", ".bz2"),
        ("wave audio", ".wav"), ("mpeg audio", ".mp3"), ("mp3", ".mp3"),
        ("flac", ".flac"), ("ogg", ".ogg"), ("iso media", ".mp4"),
    ):
        if key in low:
            return ext
    return ""


def _plan_for(name: str, mime: str | None, is_text: bool) -> list[str]:
    plan = []
    for tool in DEFAULT_PLAN:
        a = get_tool(tool)
        if not a or not a.matches(mime, name):
            continue
        if tool in HEAVY_EXTRACT and is_text and not name.lower().endswith(ARCHIVE_EXT):
            continue
        plan.append(tool)
    return plan
