"""pdf-attachments + cryptojs (HeroCTF v5 PDF-Mess): embedded script, AES passphrase."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from backend.analyzers.base import ToolContext
from backend.analyzers.cryptojs import CryptoJsAnalyzer
from backend.analyzers.pdf import PdfAttachmentsAnalyzer


def _ctx(tmp_path: Path, f: Path) -> ToolContext:
    work = tmp_path / "p" / "work" / "1"
    work.mkdir(parents=True, exist_ok=True)
    return ToolContext(input=f, workdir=work)


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl missing")
def test_cryptojs_blob_decrypted_with_a_string_of_the_same_file(tmp_path):
    enc = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-md", "md5", "-salt",
                          "-k", "s3cretpass", "-a", "-A"], input=b"Hero{cryptojs_ok}",
                         capture_output=True, check=True).stdout.decode().strip()
    assert enc.startswith("U2FsdGVkX1")
    js = tmp_path / "script.js"
    js.write_text(f"const key='s3cretpass', other=\"noise-value\", cipher='{enc}';\n")
    r = CryptoJsAnalyzer().run(_ctx(tmp_path, js))
    assert r.status == "done" and "Hero{cryptojs_ok}" in r.output


def test_cryptojs_skips_files_without_ciphertext(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("nothing to see")
    assert CryptoJsAnalyzer().run(_ctx(tmp_path, f)).status == "skipped"


def _pdf_with_attachment(payload: bytes) -> bytes:
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(s.js) 4 0 R] >> >> >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>",
        b"<< /Type /Filespec /F (s.js) /EF << /F 5 0 R >> >>",
        b"<< /Type /EmbeddedFile /Length %d >>\nstream\n" % len(payload) + payload + b"\nendstream",
    ]
    out, offs = b"%PDF-1.4\n", []
    for i, body in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return out


@pytest.mark.skipif(not shutil.which("pdfdetach"), reason="pdfdetach missing")
def test_pdf_attachment_becomes_a_child(tmp_path):
    pdf = tmp_path / "doc.pdf"
    pdf.write_bytes(_pdf_with_attachment(b"var flag = 'x';"))
    r = PdfAttachmentsAnalyzer().run(_ctx(tmp_path, pdf))
    assert r.status == "done" and len(r.extracted) == 1
    assert Path(r.extracted[0]).read_bytes() == b"var flag = 'x';"
