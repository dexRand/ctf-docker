"""Text / string analyzers."""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult
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
subprocess_analyzer(
    "pdfid", ["pdfid", "{input}"], "text",
    "PDF structural keywords (objects, JS, launch actions).", order=118, accepts=(".pdf",),
    alt_bins=("pdfid.py",),
)


class MarkupTextAnalyzer(Analyzer):
    """Text nodes of SVG/HTML/XML, joined: a flag split across <tspan>/<span>
    elements (picoCTF "Enhance!") is invisible in the raw markup."""
    name = "markup-text"
    category = "text"
    description = "Visible text of SVG/HTML/XML (text nodes joined), comments and hidden attributes."
    accepts = (".svg", ".html", ".htm", ".xhtml", ".xml")
    display_order = 112

    def run(self, ctx: ToolContext) -> ToolResult:
        from html.parser import HTMLParser

        texts: list[str] = []
        comments: list[str] = []

        class _P(HTMLParser):
            def handle_data(self, data: str) -> None:
                if data.strip():
                    texts.append(data.strip())

            def handle_comment(self, data: str) -> None:
                if data.strip():
                    comments.append(data.strip())

        with open(ctx.input, "rb") as fh:
            raw = fh.read(5_000_000).decode("utf-8", "replace")
        try:
            _P(convert_charrefs=True).feed(raw)
        except Exception as exc:  # malformed markup: keep what was parsed
            ctx.log(f"parse stopped: {exc}")
        if not texts and not comments:
            return ToolResult(self.name, status="skipped", summary="no text nodes")
        out = ["[text] " + " ".join(texts), "[joined] " + "".join(texts)]
        out += ["[comment] " + c for c in comments]
        return ToolResult(self.name, status="done", summary=f"{len(texts)} text node(s)",
                          output="\n".join(out)[:200_000])


register(MarkupTextAnalyzer())
