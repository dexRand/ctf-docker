"""Unit tests for the `office` analyzer (unzip + whitespace-split base64)."""
from __future__ import annotations

import base64
import zipfile
from pathlib import Path

from backend.analyzers.base import ToolContext
from backend.analyzers.extract import OfficeAnalyzer


def _run(tmp_path: Path, name: str, part: str, content: str):
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<?xml version='1.0'?><Types/>")
        z.writestr(part, content)
    return OfficeAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))


def test_office_decodes_whitespace_split_base64(tmp_path: Path) -> None:
    b64 = base64.b64encode(b"flag: ITS{office_unit}").decode()
    res = _run(tmp_path, "fun.pptm", "ppt/slideMasters/hidden", " ".join(b64))
    assert res.status == "done"
    assert "ITS{office_unit}" in res.output
    assert "1 base64" in res.summary


def test_office_without_payload_is_done(tmp_path: Path) -> None:
    res = _run(tmp_path, "plain.docx", "word/document.xml", "<w:document>hello</w:document>")
    assert res.status == "done"
    assert "ITS{" not in res.output


def test_office_rejects_non_zip(tmp_path: Path) -> None:
    p = tmp_path / "x.pptm"
    p.write_bytes(b"not a zip")
    res = OfficeAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.status == "skipped"
