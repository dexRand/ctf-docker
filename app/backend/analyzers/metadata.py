"""Metadata / identity analyzers."""
from __future__ import annotations

import re

from .registry import register, subprocess_analyzer
from .util import assemble_flag_fragments

subprocess_analyzer(
    "file", ["file", "-b", "{input}"], "metadata",
    "Identify the file type (libmagic).", order=10,
)
# fields where a challenge writes text; a flag is often split across them
# (TJCTF 2022 fake-geoguessr: Copyright "tjctf{thats_a_" + Comment "lot_of_metadata}")
_TEXT_FIELDS = re.compile(r"(?i)^(copyright|comment|user comment|artist|author|creator|title|"
                          r"description|image description|subject|keywords?|xp ?\w+|caption|"
                          r"headline|rights|software|make|model|label|note|instructions?|"
                          r"document name|owner name|by-?line)\s*$")


class _ExifTool(subprocess_analyzer(
        "exiftool", ["exiftool", "{input}"], "metadata",
        "All metadata: EXIF, GPS, comments, embedded data.", order=20, soft=True)):
    """exiftool + the flag rebuilt from pieces spread over descriptive fields."""

    def run(self, ctx):
        result = super().run(ctx)
        pieces = []
        for line in (result.output or "").splitlines():
            key, sep, value = line.partition(" : ")
            if sep and _TEXT_FIELDS.match(key.strip()) and value.strip():
                pieces.append(value.strip())
        joined = assemble_flag_fragments(pieces)
        if joined:
            result.output = (result.output or "") + "\n[flag rebuilt from metadata fields]\n" \
                + "\n".join(joined)
        return result


register(_ExifTool())
subprocess_analyzer(
    "identify", ["identify", "-verbose", "{input}"], "metadata",
    "Image info and properties (GraphicsMagick/ImageMagick).", order=30,
    accepts=(".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp"), soft=True,
)
subprocess_analyzer(
    "ffprobe", ["ffprobe", "-hide_banner", "{input}"], "metadata",
    "Audio/video stream and container info.", order=35,
    accepts=(".mp3", ".wav", ".flac", ".ogg", ".mp4", ".mkv", ".avi", ".mov", ".au"),
)
subprocess_analyzer(
    "pdfinfo", ["pdfinfo", "{input}"], "metadata",
    "PDF document info.", order=40, accepts=(".pdf",),
)
