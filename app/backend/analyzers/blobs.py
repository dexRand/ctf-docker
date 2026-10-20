"""Find base64 / hex blobs embedded in text and reveal their content.

A very common CTF trick: the flag (or a whole file) is hidden inside a base64/hex
run in a log, JSON, "messages.log", etc. This analyzer decodes every blob it can,
extracts the interesting ones as children (so the rest of the pipeline recurses
into them) and inlines the printable text so the flag hunt scans it directly.
"""
from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import TEXT_EXT, b64decode_loose, is_printable, magic_ext


_B64 = re.compile(rb"[A-Za-z0-9+/]{64,}={0,2}")
_HEX = re.compile(rb"(?:[0-9a-fA-F]{2}){32,}")
_MIN = {"b64": 64, "hex": 32}


_MAX_BLOBS = 400
_MAX_DECODED = 8_000_000        # per blob
_INLINE_PER = 600_000           # inline at most this much per blob
_INLINE_TOTAL = 3_000_000       # ... and this much overall


class BlobsAnalyzer(Analyzer):
    name = "blobs"
    category = "decode"
    description = "Extract base64/hex blobs embedded in text and reveal their content."
    accepts = TEXT_EXT + ("text/",)
    display_order = 126

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            data = ctx.input.read_bytes()
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        outdir = ctx.sub(self.name)
        seen: set[bytes] = set()
        extracted: list[Path] = []
        inline: list[str] = []
        inline_total = 0
        for kind, pat in (("b64", _B64), ("hex", _HEX)):
            for m in pat.finditer(data):
                raw = m.group(0)
                if len(raw) < _MIN[kind]:
                    continue
                try:
                    blob = b64decode_loose(raw) if kind == "b64" else bytes.fromhex(raw.decode())
                except Exception:  # noqa: BLE001
                    continue
                if not blob or len(blob) > _MAX_DECODED or blob in seen:
                    continue
                seen.add(blob)
                ext = magic_ext(blob)
                if ext and len(extracted) < _MAX_BLOBS:
                    # a real file hidden in base64/hex: extract it (child, recursed)
                    dest = outdir / f"{len(extracted):03d}-{kind}{ext}"
                    try:
                        dest.write_bytes(blob)
                        extracted.append(dest)
                    except OSError:
                        pass
                elif is_printable(blob) and inline_total < _INLINE_TOTAL:
                    # printable text: inline it so the flag hunt scans it
                    chunk = blob[:_INLINE_PER].decode("latin-1", "replace")
                    inline.append(chunk)
                    inline_total += len(chunk)
        summary = f"{len(inline)} text blob(s)" + (f", {len(extracted)} file(s)" if extracted else "")
        return ToolResult(
            self.name, status="done", summary=summary,
            output="\n".join(inline)[:_INLINE_TOTAL + 100_000],
            extracted=[str(p) for p in extracted],
            artifacts=[{"name": str(p.relative_to(ctx.workdir)), "path": str(p),
                        "size": p.stat().st_size} for p in extracted],
        )


register(BlobsAnalyzer())
