"""olevba: VBA macros of Office documents (gating + output parsing)."""
from __future__ import annotations

import subprocess
import zipfile

from backend.analyzers.base import ToolContext
from backend.analyzers.olevba import OlevbaAnalyzer, has_vba

MACRO = """olevba 0.60.2 on Python 3.14 - http://decalage.info/python/oletools
VBA MACRO ThisDocument.cls
in file: /tmp/x.docm - OLE stream: 'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Sub AutoOpen()
    Shell "calc.exe"
    var = "picoCTF{" & "from_a_macro" & "}"
End Sub
"""


def _docm_without_macro(tmp_path):
    p = tmp_path / "clean.docx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("word/document.xml", "<w:document/>")
    return p


def test_gating_skips_a_docx_without_a_vba_project(tmp_path):
    p = _docm_without_macro(tmp_path)
    assert has_vba(p) is False
    r = OlevbaAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and r.summary == "no VBA project"


def test_gating_skips_a_plain_text_file(tmp_path):
    p = tmp_path / "note.txt"
    p.write_text("hello")
    assert has_vba(p) is False


def test_zip_with_a_vba_project_is_gated_in(tmp_path):
    p = tmp_path / "macro.docm"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("word/vbaProject.bin", b"\x00" * 32)
    assert has_vba(p) is True


def test_macro_output_is_parsed(monkeypatch, tmp_path):
    p = tmp_path / "macro.docm"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("word/vbaProject.bin", b"\x00" * 32)
    seen = {}

    def fake_run(self, cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, MACRO, "")

    monkeypatch.setattr(ToolContext, "run", fake_run)
    r = OlevbaAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "done"
    assert "1 macro" in r.summary and "autoopen" in r.summary.lower()
    assert "from_a_macro" in (r.output or "") and "Sub AutoOpen()" in (r.output or "")
    # the venv's oletools module, not a console script on PATH
    assert "-m" in seen["cmd"] and "oletools.olevba" in seen["cmd"]
    assert "--decode" in seen["cmd"] and "--deobf" in seen["cmd"]


def test_no_macro_in_an_ole_container_is_skipped(monkeypatch, tmp_path):
    p = tmp_path / "plain.doc"
    p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64)
    fake = subprocess.CompletedProcess([], 0, "No VBA macros found.\n", "")
    monkeypatch.setattr(ToolContext, "run", lambda self, cmd, **kw: fake)
    r = OlevbaAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and "no VBA macros" in r.summary
