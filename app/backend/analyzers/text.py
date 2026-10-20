"""Text / string analyzers."""
from __future__ import annotations

from .registry import subprocess_analyzer

subprocess_analyzer(
    "strings", ["strings", "-n", "6", "{input}"], "text",
    "Printable strings (>=6 chars).", order=110,
)
subprocess_analyzer(
    "pdftotext", ["pdftotext", "{input}", "-"], "text",
    "Extract the text layer of a PDF.", order=115, accepts=(".pdf",),
)
subprocess_analyzer(
    "binwalk-scan", ["binwalk", "{input}"], "text",
    "Signatures / embedded data scan (binwalk, no extraction).", order=120,
)
subprocess_analyzer(
    "pdfid", ["pdfid", "{input}"], "text",
    "PDF structural keywords (objects, JS, launch actions).", order=118, accepts=(".pdf",),
    alt_bins=("pdfid.py",),
)
