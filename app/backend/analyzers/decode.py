"""Nested-encoding decoder (mini-Ciphey): base64/hex/binary/rot13/url/base32."""
from __future__ import annotations

import base64
import codecs
import re
import urllib.parse

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

TEXT_EXT = (".txt", ".md", ".csv", ".b64", ".hex", ".dat", ".log", ".asc")


def _ok(b: bytes, thr: float = 0.9) -> bool:
    if not b or len(b) > 2_000_000:
        return False
    text = b.decode("utf-8", "replace")
    good = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t")
    return good / max(1, len(text)) >= thr


def candidates(data: bytes) -> dict[str, bytes]:
    s = data.strip()
    out: dict[str, bytes] = {}
    compact = re.sub(rb"\s+", b"", s)
    for name, fn in (
        ("base64", lambda: base64.b64decode(compact, validate=True)),
        ("base32", lambda: base64.b32decode(compact.upper(), casefold=True)),
        ("base85", lambda: base64.b85decode(compact)),
    ):
        try:
            d = fn()
            if _ok(d):
                out[name] = d
        except Exception:
            pass
    h = re.sub(rb"[^0-9a-fA-F]", b"", s)
    if len(h) >= 4 and len(h) % 2 == 0:
        try:
            d = bytes.fromhex(h.decode())
            if _ok(d):
                out["hex"] = d
        except Exception:
            pass
    b = re.sub(rb"[^01]", b"", s)
    if len(b) >= 8 and len(b) % 8 == 0:
        try:
            d = bytes(int(b[i:i + 8], 2) for i in range(0, len(b), 8))
            if _ok(d):
                out["binary"] = d
        except Exception:
            pass
    # "0x30"/"0x31" tokens -> '0'/'1' binary string (the Dashed challenge chain)
    if re.search(rb"0[xX]3[01]", s):
        mapped = re.sub(rb"0[xX]3([01])", lambda m: b"0" if m.group(1) == b"0" else b"1", s)
        mapped = re.sub(rb"[^01]", b"", mapped)
        if mapped and len(mapped) % 8 == 0:
            try:
                d = bytes(int(mapped[i:i + 8], 2) for i in range(0, len(mapped), 8))
                if _ok(d):
                    out["hexascii"] = d
            except Exception:
                pass
    t = codecs.encode(s.decode("utf-8", "replace"), "rot13").encode()
    if t != s and _ok(t, 0.8):
        out["rot13"] = t
    try:
        u = urllib.parse.unquote(s.decode("utf-8", "replace")).encode()
        if u != s and _ok(u, 0.8):
            out["url"] = u
    except Exception:
        pass
    return out


def chain(data: bytes, depth: int = 5) -> list[str]:
    """BFS over decoders; returns printable layers found ('path: text')."""
    seen: set[bytes] = {data}
    frontier: list[tuple[bytes, str]] = [(data, "")]
    lines: list[str] = []
    for _ in range(depth):
        nxt: list[tuple[bytes, str]] = []
        for data2, path in frontier:
            for enc, out in candidates(data2).items():
                if out in seen:
                    continue
                seen.add(out)
                lines.append(f"[{path}{enc}] {out[:400].decode('utf-8', 'replace').strip()}")
                nxt.append((out, f"{path}{enc}>"))
        frontier = nxt
        if not frontier:
            break
    return lines


class DecodeAnalyzer(Analyzer):
    name = "decode"
    category = "text"
    description = "Try nested encodings (base64/hex/binary/rot13/url/base32) to reveal the flag."
    accepts = TEXT_EXT
    display_order = 125

    def run(self, ctx: ToolContext) -> ToolResult:
        lines = chain(ctx.input.read_bytes())
        return ToolResult(self.name, status="done", output="\n".join(lines[:300]),
                          summary=f"{len(lines)} decodifiche")


register(DecodeAnalyzer())
