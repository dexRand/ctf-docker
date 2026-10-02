"""Metadata / identity analyzers."""
from __future__ import annotations

from .registry import subprocess_analyzer

subprocess_analyzer(
    "file", ["file", "-b", "{input}"], "metadata",
    "Identify the file type (libmagic).", order=10,
)
subprocess_analyzer(
    "exiftool", ["exiftool", "{input}"], "metadata",
    "All metadata: EXIF, GPS, comments, embedded data.", order=20, soft=True,
)
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
