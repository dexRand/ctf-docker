"""Unit tests for the .eml email analyzer (no external tools, no pytest fixtures)."""
from __future__ import annotations

import tempfile
from email.message import EmailMessage
from pathlib import Path

from backend.analyzers.base import ToolContext
from backend.analyzers.eml import EmlAnalyzer, safe_name


def _eml_bytes() -> bytes:
    msg = EmailMessage()
    msg["From"] = "attacker@evil.example"
    msg["To"] = "victim@example.com"
    msg["Subject"] = "Your invoice ITS{eml_subject}"
    msg.set_content("hello, the secret is ITS{eml_body_flag}\n")
    msg.add_attachment(b"WScript.Shell\nITS{eml_attach_flag}\n", maintype="application",
                       subtype="octet-stream", filename="evil.vbs")
    return msg.as_bytes()


def _run(data: bytes, name: str = "mail.eml"):
    d = Path(tempfile.mkdtemp(prefix="eml-"))
    src = d / name
    src.write_bytes(data)
    return EmlAnalyzer().run(ToolContext(input=src, workdir=d / "work"))


def test_eml_headers_body_and_attachment() -> None:
    res = _run(_eml_bytes())
    assert res.status == "done"
    assert "attacker@evil.example" in res.output          # header
    assert "ITS{eml_subject}" in res.output                # subject
    assert "ITS{eml_body_flag}" in res.output              # decoded text body
    assert "evil.vbs" in res.output
    assert "sospetti" in res.output                        # suspect-attachment warning
    assert len(res.extracted) == 1
    assert b"ITS{eml_attach_flag}" in Path(res.extracted[0]).read_bytes()
    assert res.artifacts and res.artifacts[0]["size"] > 0


def test_eml_multiple_attachments() -> None:
    msg = EmailMessage()
    msg["From"] = "a@b.c"
    msg["Subject"] = "two files"
    msg.set_content("see attachments")
    msg.add_attachment(b"A", maintype="application", subtype="octet-stream", filename="a.bin")
    msg.add_attachment(b"B", maintype="application", subtype="octet-stream", filename="b.jpg")
    res = _run(msg.as_bytes())
    assert len(res.extracted) == 2
    assert "a.bin" in res.output and "b.jpg" in res.output


def test_non_email_is_skipped() -> None:
    res = _run(b"just some bytes, not an email\n")
    assert res.status == "skipped"


def test_safe_name() -> None:
    assert safe_name("../../etc/passwd") == "passwd"
    assert safe_name("C:\\windows\\evil.vbs") == "evil.vbs"
    assert safe_name("") == "attachment.bin"
    assert safe_name("weird:*?name.pdf").endswith(".pdf")
