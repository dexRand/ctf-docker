"""Decrypt OpenSSL "Salted__" files with a password from a sibling history/log."""
from __future__ import annotations

import re

from .base import Analyzer, ToolContext, ToolResult, run_cmd, which
from .registry import register
from .util import printable_ratio

_EXT = (".enc", ".aes", ".encrypted", ".gpg", ".age")
_PW_RES = [re.compile(r"openssl[^\n\r]*?-k\s+(\S+)"), re.compile(r"-pass\s+pass:(\S+)")]
_CIPHERS = [(re.compile(r"aes-?256", re.I), "aes256"), (re.compile(r"aes-?128", re.I), "aes128")]


class OpensslAnalyzer(Analyzer):
    name = "openssl"
    category = "crypto"
    description = "Decrypt an OpenSSL salted file with the password found in a sibling history/log."
    accepts = _EXT
    display_order = 150

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("openssl"):
            return ToolResult(self.name, status="skipped", summary="openssl not installed")
        try:
            with ctx.input.open("rb") as fh:
                is_salted = fh.read(8) == b"Salted__"
            if not is_salted:
                return ToolResult(self.name, status="skipped", summary="not an OpenSSL salted file")
        except OSError as exc:
            return ToolResult(self.name, status="skipped", summary=f"cannot read: {exc}")

        passwords: list[str] = []
        cipher = "aes256"
        for _p, head, _size in ctx.siblings(200_000):
            text = head.decode("utf-8", "replace")
            if "openssl" not in text and "-pass" not in text:
                continue
            for rx, name in _CIPHERS:
                if rx.search(text):
                    cipher = name
            for rx in _PW_RES:
                for m in rx.finditer(text):
                    pw = m.group(1).strip("\"'")
                    if pw and pw not in passwords:
                        passwords.append(pw)
        if not passwords:
            return ToolResult(self.name, status="skipped", summary="no password in sibling files")

        outdir = ctx.sub(self.name)
        outdir.mkdir(parents=True, exist_ok=True)
        for pw in passwords:
            for md in ("md5", "sha256"):
                proc = run_cmd(["openssl", "enc", "-d", f"-{cipher}", "-salt", "-md", md,
                                "-k", pw, "-in", str(ctx.input)], timeout=120, binary=True)
                data = proc.stdout or b""
                # a file with a trailing junk byte still decrypts but openssl
                # exits 1 ("bad decrypt" padding); accept any printable {…}
                if data and printable_ratio(data) >= 0.9 and b"{" in data:
                    dest = outdir / (ctx.input.stem + ".decrypted.txt")
                    dest.write_bytes(data)
                    return ToolResult(self.name, status="done",
                                      summary=f"decrypted with {cipher} (password from sibling)",
                                      output=data.decode("latin-1", "replace")[:200_000],
                                      extracted=[str(dest)])
        return ToolResult(self.name, status="skipped", summary="no password worked")


register(OpensslAnalyzer())
