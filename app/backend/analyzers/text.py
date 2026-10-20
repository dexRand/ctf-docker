"""Text / string analyzers."""
from __future__ import annotations

import base64
import re

from .base import Analyzer, ToolContext, ToolResult, run_cmd
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


# Group Policy Preferences encrypt `cpassword` with a fixed AES-256 key that
# Microsoft published (MS14-025): anyone can decrypt it.
_GPP_KEY = "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
_GPP_RE = re.compile(r'cpassword="([A-Za-z0-9+/=]+)"')
_GPP_USER_RE = re.compile(r'(?:userName|runAs|accountName)="([^"]*)"')


def gpp_passwords(ctx: ToolContext, xml: str) -> list[tuple[str, str]]:
    """(user, password) for every GPP `cpassword` in the text (Groups.xml & co)."""
    out = []
    for m in _GPP_RE.finditer(xml):
        blob = m.group(1)
        user = _GPP_USER_RE.search(xml[max(0, m.start() - 600):m.end() + 600])
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except ValueError:
            continue
        enc = ctx.sub("gpp") / f"cpassword{len(out)}.bin"
        enc.write_bytes(raw)
        cmd = ["openssl", "enc", "-d", "-aes-256-cbc", "-K", _GPP_KEY, "-iv", "0" * 32, "-in", enc]
        ctx.log("$ " + " ".join(map(str, cmd)))
        proc = run_cmd(cmd, timeout=20, binary=True)
        if proc.returncode == 0 and proc.stdout:   # plaintext is UTF-16LE
            pw = proc.stdout.decode("utf-16-le", "replace").rstrip("\x00")
            out.append((user.group(1) if user else "?", pw))
    return out


class MarkupTextAnalyzer(Analyzer):
    """Text nodes of SVG/HTML/XML, joined: a flag split across <tspan>/<span>
    elements (picoCTF "Enhance!") is invisible in the raw markup."""
    name = "markup-text"
    category = "text"
    description = "Visible text of SVG/HTML/XML (text nodes joined), comments, GPP cpassword decrypted."
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
        gpp = [f"[gpp cpassword] {user}: {pw}" for user, pw in gpp_passwords(ctx, raw)]
        if not texts and not comments and not gpp:
            return ToolResult(self.name, status="skipped", summary="no text nodes")
        out = gpp + ["[text] " + " ".join(texts), "[joined] " + "".join(texts)]
        out += ["[comment] " + c for c in comments]
        return ToolResult(self.name, status="done", summary=f"{len(texts)} text node(s)",
                          output="\n".join(out)[:200_000])


register(MarkupTextAnalyzer())
