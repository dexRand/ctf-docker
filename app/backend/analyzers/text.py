"""Text / string analyzers."""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult, which, out_of
from .registry import register, subprocess_analyzer

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


class PdfIdAnalyzer(Analyzer):
    name = "pdfid"
    category = "text"
    description = "PDF structural keywords (objects, JS, launch actions)."
    accepts = (".pdf",)
    display_order = 118

    def run(self, ctx: ToolContext) -> ToolResult:
        cmd = which("pdfid") or which("pdfid.py")
        if not cmd:
            return ToolResult(self.name, status="skipped", summary="pdfid not installed")
        proc = ctx.run([cmd, str(ctx.input)])
        return ToolResult(self.name, status="done" if proc.returncode == 0 else "error",
                          output=out_of(proc), exit_code=proc.returncode)


register(PdfIdAnalyzer())
