"""Windows event logs (.evtx): events as text, base64 pieces decoded.

Flags in event logs are often split into base64 pieces spread over several
events (picoCTF "Event-Viewing"); the pieces are decoded in record order and
a flag assembled from them.
"""
from __future__ import annotations

import re

from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import B64_TOKEN, assemble_flag_fragments, b64decode_loose, printable_ratio

_MAGIC = b"ElfFile\x00"
_MAX_RECORDS = 50_000
_MAX_OUT = 2_000_000
_TAG = re.compile(r"<[^>]+>")
_B64 = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")


class EvtxAnalyzer(Analyzer):
    name = "evtx"
    category = "forensics"
    description = "Windows event log: every event as text, base64 pieces decoded and joined."
    accepts = (".evtx",)
    display_order = 214

    def run(self, ctx: ToolContext) -> ToolResult:
        with open(ctx.input, "rb") as fh:
            if fh.read(8) != _MAGIC:
                return ToolResult(self.name, status="skipped", summary="not an EVTX file")
        try:
            import Evtx.Evtx as evtx
        except ImportError:
            return ToolResult(self.name, status="skipped", summary="python-evtx not installed")
        lines: list[str] = []
        pieces: list[str] = []
        n = 0
        with evtx.Evtx(str(ctx.input)) as log:
            for rec in log.records():
                n += 1
                if n > _MAX_RECORDS:
                    break
                try:
                    text = " ".join(_TAG.sub(" ", rec.xml()).split())
                except Exception:   # one damaged record must not stop the dump
                    continue
                lines.append(f"#{rec.record_num()} {text}")
                for tok in _B64.findall(text):
                    if B64_TOKEN.match(tok.encode()):
                        try:
                            dec = b64decode_loose(tok.encode())
                        except ValueError:
                            continue
                        if dec and printable_ratio(dec) >= 0.95:
                            pieces.append(dec.decode("latin-1"))
        out = []
        flags = assemble_flag_fragments(pieces)
        if flags:
            out += [f"[base64 pieces joined] {f}" for f in flags]
        out += [f"[base64] {p}" for p in pieces[:500]]
        out += lines
        return ToolResult(self.name, status="done",
                          summary=f"{n} event(s), {len(pieces)} base64 piece(s)",
                          output="\n".join(out)[:_MAX_OUT])


register(EvtxAnalyzer())
