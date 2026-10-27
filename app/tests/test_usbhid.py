"""USB HID keyboard decoding and the PDF guard analyzer."""
from __future__ import annotations

import pytest

from backend.analyzers.base import ToolContext
from backend.analyzers.pdf import PdfAnalyzer, PdfImagesAnalyzer
from backend.analyzers.usbhid import decode_reports


def test_hid_reports_decode_typed_text():
    # 8-byte boot reports: 1a=w, 06=c, 19=v, 2c=space, 2d='-', 04=a
    reports = ["00001a0000000000", "0000000000000000",
               "0000060000000000", "0000000000000000",
               "0000190000000000", "0000000000000000",
               "00002c0000000000", "0000000000000000",
               "0000040000000000", "0000000000000000"]
    assert decode_reports(reports) == "wcv a"


def test_hid_shift_and_digits():
    # modifier 0x02 = left shift: 0x1e -> '!' (1), 0x04 -> 'A'
    reports = ["02001e0000000000", "0000000000000000",
               "0200040000000000", "0000000000000000",
               "0000200000000000"]
    assert decode_reports(reports) == "!A3"


def test_hid_reports_accept_colon_separated_hex():
    assert decode_reports(["00:00:04:00:00:00:00:00", "00:00:00:00:00:00:00:00"]) == "a"


def test_pdf_guard_flags_an_encrypted_document(tmp_path):
    p = tmp_path / "locked.pdf"
    p.write_bytes(b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n"
                  b"trailer << /Root 1 0 R /Encrypt 9 0 R >>\n%%EOF\n")
    r = PdfAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.needs_password and "encrypted" in r.summary


def test_pdf_guard_leaves_a_plain_document_alone(tmp_path):
    p = tmp_path / "plain.pdf"
    p.write_bytes(b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\ntrailer << >>\n%%EOF\n")
    r = PdfAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert not r.needs_password and r.status == "skipped"


def test_pdf_images_skips_a_file_that_is_not_a_pdf(tmp_path):
    p = tmp_path / "not.pdf"
    p.write_bytes(b"hello")
    r = PdfImagesAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and not r.extracted
