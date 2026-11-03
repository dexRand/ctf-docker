"""CryptoJS / OpenSSL passphrase ciphertexts written as base64 in a text file.

`CryptoJS.AES.encrypt(msg, "passphrase")` prints "U2FsdGVkX1..." (base64 of
"Salted__" + salt + data), the same format as `openssl enc -aes-256-cbc -md md5`.
The passphrase is often a string literal in the same script (HeroCTF v5
PDF-Mess: `key='3d3067e197cf4d0a'`): every quoted string of the file is tried.
"""
from __future__ import annotations

import base64
import binascii
import re

from .base import Analyzer, ToolContext, ToolResult, run_cmd, which
from .registry import register
from .util import TEXT_EXT, printable_ratio

_BLOB = re.compile(r"U2FsdGVkX1[A-Za-z0-9+/]{14,}={0,2}")
_QUOTED = re.compile(r"""["'`]([^"'`\r\n]{4,64})["'`]""")
_MAX_TRIES = 60


class CryptoJsAnalyzer(Analyzer):
    name = "cryptojs"
    category = "crypto"
    description = "CryptoJS/OpenSSL 'U2FsdGVkX1…' ciphertexts decrypted with the strings of the same file."
    accepts = TEXT_EXT
    display_order = 151

    def run(self, ctx: ToolContext) -> ToolResult:
        with open(ctx.input, "rb") as fh:
            text = fh.read(1 << 20).decode("utf-8", "replace")
        blobs = list(dict.fromkeys(_BLOB.findall(text)))[:5]
        if not blobs:
            return ToolResult(self.name, status="skipped", summary="no U2FsdGVkX1 ciphertext")
        if not which("openssl"):
            return ToolResult(self.name, status="skipped", summary="openssl not installed")
        keys = [k for k in dict.fromkeys(_QUOTED.findall(text)) if not k.startswith("U2FsdGVkX1")]
        outdir = ctx.sub(self.name)
        outdir.mkdir(parents=True, exist_ok=True)
        lines, tries = [], 0
        for i, blob in enumerate(blobs):
            try:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
            except (binascii.Error, ValueError):
                continue
            src = outdir / f"blob{i}.bin"
            src.write_bytes(raw)
            done = False
            for key in keys:
                for md in ("md5", "sha256"):
                    if tries >= _MAX_TRIES:
                        break
                    tries += 1
                    proc = run_cmd(["openssl", "enc", "-d", "-aes-256-cbc", "-md", md, "-k", key,
                                    "-in", str(src)], timeout=30, binary=True)
                    out = proc.stdout or b""
                    if proc.returncode == 0 and out and printable_ratio(out) >= 0.9:
                        lines.append(f"{blob[:24]}… with key {key!r} ({md}): "
                                     + out.decode("utf-8", "replace")[:4000])
                        done = True
                        break
                if done:
                    break
        if not lines:
            return ToolResult(self.name, status="skipped",
                              summary=f"{len(blobs)} ciphertext(s), no key among {len(keys)} string(s)")
        return ToolResult(self.name, status="done", summary=f"{len(lines)} decrypted",
                          output="\n".join(lines))


register(CryptoJsAnalyzer())
