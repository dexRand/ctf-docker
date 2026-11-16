"""Unit tests for the `office` analyzer: text from every package part.

The analyzer used to decode base64 only; Word keeps a flag in header/footer,
notes, comments, docProps or customXml, so those XML parts must reach the
output too.  Limits are checked before decompressing anything.
"""
from __future__ import annotations

import base64
import zipfile
from pathlib import Path

from backend.analyzers import extract as ex
from backend.analyzers.base import ToolContext
from backend.analyzers.extract import OfficeAnalyzer

CONTENT_TYPES = (
    "<?xml version='1.0'?><Types "
    "xmlns='http://schemas.openxmlformats.org/package/2006/content-types'/>"
)


def _docx(tmp_path: Path, parts: dict[str, bytes | str], name: str = "doc.docx") -> Path:
    p = tmp_path / name
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CONTENT_TYPES)
        for part, content in parts.items():
            z.writestr(part, content)
    return p


def _run(path: Path, tmp_path: Path):
    return OfficeAnalyzer().run(ToolContext(input=path, workdir=tmp_path / "w"))


def test_footer_text_reaches_the_output(tmp_path: Path) -> None:
    p = _docx(tmp_path, {
        "word/document.xml": "<w:document><w:body><w:t>hello</w:t></w:body></w:document>",
        "word/footer1.xml": "<w:ftr><w:t>ITS{footer_part}</w:t></w:ftr>",
    })
    res = _run(p, tmp_path)
    assert res.status == "done"
    assert "ITS{footer_part}" in res.output


def test_comments_and_docprops_text_reach_the_output(tmp_path: Path) -> None:
    p = _docx(tmp_path, {
        "word/document.xml": "<w:document/>",
        "word/comments.xml": "<w:comments><w:t>ITS{comment_part}</w:t></w:comments>",
        "docProps/core.xml": "<cp:coreProperties><dc:title>ITS{docprop_part}</dc:title></cp:coreProperties>",
    })
    res = _run(p, tmp_path)
    assert res.status == "done"
    assert "ITS{comment_part}" in res.output
    assert "ITS{docprop_part}" in res.output


def test_customxml_text_reaches_the_output(tmp_path: Path) -> None:
    p = _docx(tmp_path, {
        "word/document.xml": "<w:document/>",
        "customXml/item1.xml": "<root><value>ITS{customxml_part}</value></root>",
    })
    res = _run(p, tmp_path)
    assert res.status == "done"
    assert "ITS{customxml_part}" in res.output


def test_zip_without_extension_is_accepted(tmp_path: Path) -> None:
    # `du22-doxme` ships a docx with no extension: the mime is application/zip
    assert OfficeAnalyzer().matches("application/zip", "doxme")


def test_odf_package_without_content_types_is_still_analyzed(tmp_path: Path) -> None:
    # ODF has no [Content_Types].xml: mimetype + content.xml. The base64
    # decoding that already worked on .odt must not be lost.
    token = base64.b64encode(b"ITS{odt_base64}").decode()
    p = tmp_path / "doc.odt"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        z.writestr("META-INF/manifest.xml", "<?xml version='1.0'?><manifest/>")
        z.writestr("content.xml", f"<office:document-content><text:p>{token}</text:p></office:document-content>")
    res = _run(p, tmp_path)
    assert res.status == "done"
    assert "ITS{odt_base64}" in res.output


def test_epub_container_is_analyzed(tmp_path: Path) -> None:
    p = tmp_path / "book.epub"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("mimetype", "application/epub+zip")
        z.writestr("META-INF/container.xml", "<?xml version='1.0'?><container/>")
        z.writestr("OEBPS/chapter.xhtml", "<html><body><p>ITS{epub_part}</p></body></html>")
    res = _run(p, tmp_path)
    assert res.status == "done"
    assert "ITS{epub_part}" in res.output


def test_extensionless_docx_is_analyzed_end_to_end(tmp_path: Path) -> None:
    p = _docx(tmp_path, {
        "word/document.xml": "<w:document/>",
        "word/footer1.xml": "<w:ftr><w:t>ITS{noext_docx}</w:t></w:ftr>",
    }, name="doxme")
    analyzer = OfficeAnalyzer()
    assert analyzer.matches("application/zip", p.name)
    res = analyzer.run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.status == "done"
    assert "ITS{noext_docx}" in res.output


def test_extensionless_odt_is_analyzed_end_to_end(tmp_path: Path) -> None:
    p = tmp_path / "doxme-odt"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        z.writestr("content.xml", "<office:document-content><text:p>ITS{noext_odt}</text:p></office:document-content>")
    analyzer = OfficeAnalyzer()
    assert analyzer.matches("application/zip", p.name)
    res = analyzer.run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.status == "done"
    assert "ITS{noext_odt}" in res.output


def test_xml_comment_and_cdata_reach_the_output(tmp_path: Path) -> None:
    p = _docx(tmp_path, {
        "word/document.xml": (
            "<w:document><!-- ITS{xml_comment} -->"
            "<w:t><![CDATA[ITS{cdata_part}]]></w:t></w:document>"
        ),
    })
    res = _run(p, tmp_path)
    assert res.status == "done"
    assert "ITS{xml_comment}" in res.output
    assert "ITS{cdata_part}" in res.output


def test_non_office_zip_is_skipped(tmp_path: Path) -> None:
    p = tmp_path / "plain.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "ITS{not_office}")
    res = _run(p, tmp_path)
    assert res.status == "skipped"
    assert "ITS{not_office}" not in res.output
    assert res.extracted == []


def test_part_cap_is_respected(tmp_path: Path) -> None:
    # 205 parts, the flag is only in the last one: the 200-part cap must stop
    # before it instead of decompressing the whole package.
    token = base64.b64encode(b"ITS{after_part_cap}").decode()
    parts = {f"word/part{i:03d}.xml": f"<r><t>part {i}</t></r>" for i in range(1, 205)}
    parts["word/part205.xml"] = f"<r><t>{token}</t></r>"
    p = _docx(tmp_path, parts)
    res = _run(p, tmp_path)
    assert res.status == "done"
    assert "200 part(s)" in res.summary
    assert "ITS{after_part_cap}" not in res.output


def test_total_decompressed_budget_is_respected(tmp_path: Path) -> None:
    # Three 7 MB parts (each below _MAX_PART) exceed the 20 MB total budget:
    # the flag in the third one must never be decompressed.
    token = base64.b64encode(b"ITS{after_total_budget}").decode().encode()
    p = _docx(tmp_path, {
        "word/one.xml": b" " * 7_000_000,
        "word/two.xml": b" " * 7_000_000,
        "word/three.xml": b" " * 7_000_000 + token,
    })
    res = _run(p, tmp_path)
    names = {Path(x).name for x in res.extracted}
    assert res.status == "done"
    assert "one.xml" in names and "two.xml" in names
    assert "three.xml" not in names
    assert "ITS{after_total_budget}" not in res.output


def test_oversized_entry_is_not_read(tmp_path: Path) -> None:
    # A single entry above _MAX_PART is refused without being decompressed;
    # the small XML part is still extracted and its text appears in the output.
    huge = b" " * (ex._MAX_PART + 1024) + b"ITS{huge_part}"
    p = _docx(tmp_path, {
        "word/huge.xml": huge,
        "word/footer1.xml": "<w:ftr><w:t>ITS{small_part}</w:t></w:ftr>",
    })
    res = _run(p, tmp_path)
    names = {Path(x).name for x in res.extracted}
    assert res.status == "done"
    assert "ITS{small_part}" in res.output
    assert "ITS{huge_part}" not in res.output
    assert "footer1.xml" in names
    assert "huge.xml" not in names


def test_media_before_xml_does_not_hit_the_part_cap(tmp_path: Path) -> None:
    # 201 media entries precede the footer: only XML-first ordering keeps it
    # under the 200-part cap.
    parts: dict[str, bytes | str] = {f"media/m{i:03d}.bin": b"\x01" * 10 for i in range(201)}
    parts["word/footer1.xml"] = "<w:ftr><w:t>ITS{late_footer}</w:t></w:ftr>"
    res = _run(_docx(tmp_path, parts), tmp_path)
    assert res.status == "done"
    assert "ITS{late_footer}" in res.output


def test_entry_over_budget_is_skipped_not_fatal(tmp_path: Path) -> None:
    # All XML-like (the sort cannot help): the third 7.9 MB part exceeds the
    # remaining budget and must be skipped, not stop the loop.
    blob = b" " * 7_900_000
    p = _docx(tmp_path, {
        "word/a.xml": blob, "word/b.xml": blob, "word/c.xml": blob,
        "word/footer1.xml": "<w:ftr><w:t>ITS{after_skip}</w:t></w:ftr>",
    })
    res = _run(p, tmp_path)
    assert res.status == "done"
    assert "ITS{after_skip}" in res.output


def test_file_entry_blocking_a_directory_does_not_fail_the_result(tmp_path: Path) -> None:
    # XML-like names: the sort keeps zip order, so mkdir really hits the file.
    p = _docx(tmp_path, {
        "word.xml": "<a/>",
        "word.xml/footer1.xml": "<w:ftr><w:t>ITS{blocked}</w:t></w:ftr>",
        "docProps/core.xml": "<c><t>ITS{other_part}</t></c>",
    })
    res = _run(p, tmp_path)
    assert res.status == "done"
    assert "ITS{other_part}" in res.output


def test_lying_header_entry_is_discarded(tmp_path: Path, monkeypatch) -> None:
    # Header says 10 bytes, the stream inflates past the cap: must be dropped.
    import io
    p = _docx(tmp_path, {
        "word/bomb.xml": b"x" * 10,
        "word/footer1.xml": "<w:ftr><w:t>ITS{after_bomb}</w:t></w:ftr>",
    })
    real_open = zipfile.ZipFile.open

    def fake_open(self, name, *a, **kw):
        if getattr(name, "filename", name) == "word/bomb.xml":
            return io.BytesIO(b"B" * (ex._MAX_PART + 10))
        return real_open(self, name, *a, **kw)

    monkeypatch.setattr(zipfile.ZipFile, "open", fake_open)
    res = _run(p, tmp_path)
    assert res.status == "done"
    assert "bomb.xml" not in {Path(x).name for x in res.extracted}
    assert "ITS{after_bomb}" in res.output
