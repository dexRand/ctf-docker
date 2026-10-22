"""Analysis plan: which analyzers run on a file, in which order."""
from __future__ import annotations

import os
import re
import threading

from .analyzers import get as get_tool
from .analyzers.util import ARCHIVE_EXT

# ordered analysis plan (order matters: metadata -> text -> steg -> extract)
DEFAULT_PLAN = [
    "file", "exiftool", "identify", "ffprobe", "pdfinfo",
    "strings", "markup-text", "hexyl", "xxd", "pdftotext", "pdfid", "elf", "readelf", "objdump",
    "binwalk-scan",
    "decode", "chef", "blobs", "zero-width", "whitespace", "case-bits", "homoglyph", "morse-text",
    "ocr", "qr",
    "zsteg", "lsb-carve", "stepic", "psimage", "png-chunks", "png-pixels", "steghide", "outguess", "jsteg", "openstego",
    "pixel-bytes", "bit-planes", "channel-remap", "image-enhance", "gif-frames",
    "morse", "dtmf", "spectrogram", "waveform", "wav-lsb", "wav-levels", "sstv",
    "pcap", "evtx",
    "nested-archive", "git", "7z", "office", "eml", "binwalk-extract", "foremost", "pngcheck",
    "png-repair", "image-repair", "byte-swap",
]
# signature scans and binary/image repairs: nothing to do on a file `file`
# already reports as text (a pcap's HTTP objects can be hundreds of them)
BINARY_ONLY = {"binwalk-scan", "png-repair", "image-repair", "byte-swap", "pngcheck"}
HEAVY_EXTRACT = {"binwalk-extract", "foremost"}
# cap how many heavy tools run at once across all projects (CPU bound)
_HEAVY_TOOLS = set(HEAVY_EXTRACT) | {"7z", "steghide", "outguess", "jsteg", "openstego", "sstv"}
_HEAVY_SEM = threading.Semaphore(max(1, int(os.environ.get("HEAVY_TOOLS", "1"))))


def _detect_ext(ftype: str) -> str:
    """Best-effort extension from the `file` description, so analyzers run even
    when the name lies (e.g. a PNG uploaded as flag.txt)."""
    low = (ftype or "").lower()
    for key, ext in (
        ("elf 64-bit", ".elf"), ("elf 32-bit", ".elf"),
        ("png image", ".png"), ("jpeg image", ".jpg"), ("gif image", ".gif"),
        ("bmp image", ".bmp"), ("qoi image", ".qoi"), ("tiff image", ".tiff"), ("web/p image", ".webp"),
        ("webp", ".webp"), ("pdf document", ".pdf"), ("zip archive", ".zip"),
        ("rfc 822", ".eml"), ("mail message", ".eml"),
        ("7-zip archive", ".7z"), ("rar archive", ".rar"), ("tar archive", ".tar"),
        ("gzip compressed", ".gz"), ("bzip2 compressed", ".bz2"),
        ("wave audio", ".wav"), ("mpeg audio", ".mp3"), ("mp3", ".mp3"),
        ("flac", ".flac"), ("ogg", ".ogg"), ("iso media", ".mp4"),
        ("ms windows vista event log", ".evtx"),
    ):
        if key in low:
            return ext
    return ""


# Carving a file that a carver cut out of its parent finds nothing new:
# whatever it contains was inside the parent too, which was carved already.
CARVERS = {"binwalk-scan", "binwalk-extract", "foremost"}
# On a network capture foremost only re-cuts fragments of the payloads that the
# pcap analyzer exports whole (shark2: 310 extra files, never a flag in the
# real-challenge history); binwalk-extract still carves the capture.
CAPTURE_EXT = (".pcap", ".pcapng", ".cap")


# Tools whose output is a *decoded* stream (pixels, LSB planes, re-encoded
# images): a steghide/outguess "needs password" on their children is a false
# positive (they are not original carriers), and re-running a decoder on
# another decoder's output is mostly noise (it made the recursion explode).
STEG_DECODERS = {"zsteg", "bit-planes", "png-pixels", "lsb-carve", "channel-remap",
                 "image-enhance", "psimage", "gif-frames", "blobs", "decode",
                 "image-repair", "png-repair"}
IMG_DECODERS = {"zsteg", "bit-planes", "png-pixels", "lsb-carve", "channel-remap",
                "image-enhance", "psimage", "image-repair", "png-repair"}


def origin_tool(origin: str) -> str:
    """Tool that extracted a node ('extracted:<tool>:<parent>' -> '<tool>')."""
    origin = origin or ""
    parts = origin.split(":")
    return parts[1] if origin.startswith("extracted:") and len(parts) >= 3 else ""


def unreliable_lock(tool: str, origin: str) -> bool:
    """steghide/outguess can't tell "no payload" from "wrong passphrase": on a
    node a stego decoder produced, their "needs password" is a false positive."""
    return tool in ("steghide", "outguess") and origin_tool(origin) in STEG_DECODERS


_HEX_PIECE = re.compile(r"[0-9A-Fa-f]+(\.[A-Za-z0-9]+)?")


def _raw_carve(name: str, made_by: str) -> bool:
    """A byte range cut out of its parent (foremost, or binwalk's `<hex offset>.ext`
    pieces): whatever it contains was in the parent too, already carved. Files
    binwalk *decompressed* from an archive keep their member name and are new
    content (Matryoshka dolls: image -> zip -> image -> zip ...): carve those."""
    if made_by == "foremost":
        return True
    return made_by in CARVERS and bool(_HEX_PIECE.fullmatch(name))


def _plan_for(name: str, mime: str | None, is_text: bool, made_by: str = "") -> list[str]:
    """Analyzers for one file, in plan order. `made_by` is the tool that
    extracted it ('' for uploads)."""
    plan = []
    for tool in DEFAULT_PLAN:
        a = get_tool(tool)
        if not a or not a.matches(mime, name):
            continue
        if tool in HEAVY_EXTRACT and is_text and not name.lower().endswith(ARCHIVE_EXT):
            continue
        if tool in BINARY_ONLY and is_text:
            continue
        if tool in CARVERS and _raw_carve(name, made_by):
            continue
        if tool == "foremost" and name.lower().endswith(CAPTURE_EXT):
            continue
        if tool in IMG_DECODERS and made_by in IMG_DECODERS:
            continue
        if tool in HEAVY_EXTRACT and made_by in STEG_DECODERS:
            continue
        plan.append(tool)
    return plan
