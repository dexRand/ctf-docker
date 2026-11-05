"""VBA macros of an Office document, decoded and deobfuscated with oletools.

Macro challenges hide the flag in the VBA source (a concatenated string, a
`Chr()` chain, an `AutoOpen` that downloads something). `olevba --decode --deobf`
prints the source plus the strings it decodes, and the flag hunt works on that
text like on any other output.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

OFFICE_EXT = (".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm",
              ".pptx", ".dotm", ".xlam")
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_MAX_OUTPUT = 200_000
_AUTO = ("autoopen", "document_open", "workbook_open", "auto_open", "shell",
         "wscript.shell", "createobject")


def has_vba(path: Path) -> bool:
    """OLE container, or a zip that lists a `vbaProject.bin` member (no extract)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    if head == _OLE:
        return True
    if head[:2] != b"PK":
        return False
    try:
        with zipfile.ZipFile(path) as z:
            return any(n.lower().endswith("vbaproject.bin") for n in z.namelist())
    except (zipfile.BadZipFile, OSError):
        return False


class OlevbaAnalyzer(Analyzer):
    name = "olevba"
    category = "extract"
    description = "VBA macros of an Office document (source + decoded strings) with olevba."
    accepts = OFFICE_EXT + ("application/x-ole-storage",)
    display_order = 219

    def run(self, ctx: ToolContext) -> ToolResult:
        if not has_vba(ctx.input):
            return ToolResult(self.name, status="skipped", summary="no VBA project")
        # oletools lives in the app venv, whose bin/ is not on PATH
        proc = ctx.run([sys.executable, "-m", "oletools.olevba",
                        "--decode", "--deobf", str(ctx.input)], timeout=120)
        out = proc.stdout or ""
        if proc.returncode != 0 and not out.strip():
            err = (proc.stderr or "").strip().splitlines()[-1:] or ["failed"]
            return ToolResult(self.name, status="skipped", summary=f"olevba: {err[0][:120]}")
        if "No VBA macros found" in out or "VBA MACRO" not in out:
            return ToolResult(self.name, status="skipped", summary="no VBA macros")
        macros = out.count("VBA MACRO")
        low = out.lower()
        flags = [k for k in _AUTO if k in low]
        summary = f"{macros} macro(s)" + (f" · {', '.join(flags[:3])}" if flags else "")
        return ToolResult(self.name, status="done", summary=summary,
                          output=out[:_MAX_OUTPUT])


register(OlevbaAnalyzer())
