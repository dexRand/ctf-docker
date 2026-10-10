"""Unit tests for the base64/hex blob extractor (no external tools)."""
from __future__ import annotations

import base64
import tempfile
from pathlib import Path

from backend.analyzers.base import ToolContext
from backend.analyzers.blobs import BlobsAnalyzer


def _run(data: bytes, name: str = "messages.log"):
    d = Path(tempfile.mkdtemp(prefix="blobs-"))
    src = d / name
    src.write_bytes(data)
    return BlobsAnalyzer().run(ToolContext(input=src, workdir=d / "work"))


def test_finds_base64_flag_in_log() -> None:
    secret = b"the hidden token is ITS{blob_in_log} keep it safe"
    log = b"[INFO] request\npayload=" + base64.b64encode(secret) + b"\n[INFO] done\n"
    res = _run(log)
    assert res.status == "done"
    assert "ITS{blob_in_log}" in res.output          # inlined text
    assert not res.extracted                        # text blob -> inline, no child


def test_finds_hex_blob() -> None:
    res = _run(b"hex=" + b"deadbeef" * 8 + b"\n")
    assert res.status == "done"


def test_extracts_base64_embedded_png() -> None:
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40          # just the magic + padding
    log = b"data:image/png;base64," + base64.b64encode(png)
    res = _run(log)
    assert res.extracted and res.extracted[0].endswith(".png")


def test_ignores_short_and_garbage() -> None:
    res = _run(b"short=QUJD\nnot-base64: !!!\n" + b"f" * 40)
    assert res.extracted == []
    assert res.summary.startswith("0 text blob")
