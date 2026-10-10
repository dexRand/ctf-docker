"""Find base64 / hex blobs embedded in text and reveal their content.

A very common CTF trick: the flag (or a whole file) is hidden inside a base64/hex
run in a log, JSON, "messages.log", etc. This analyzer decodes every blob it can,
extracts the interesting ones as children (so the rest of the pipeline recurses
into them) and inlines the printable text so the flag hunt scans it directly.
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

TEXT_EXT = (".txt", ".log", ".md", ".json", ".csv", ".dat", ".asc", ".b64", ".hex",
            ".xml", ".yaml", ".yml", ".out")

_B64 = re.compile(rb"[A-Za-z0-9+/]{64,}={0,2}")
_HEX = re.compile(rb"(?:[0-9a-fA-F]{2}){32,}")
_MIN = {"b64": 64, "hex": 32}

# decoded blob -> file extension when it starts with a known magic
_MAGIC = ((b"\x89PNG\r\n", ".png"), (b"\xff\xd8\xff", ".jpg"), (b"GIF8", ".gif"),
          (b"PK\x03\x04", ".zip"), (b"%PDF", ".pdf"), (b"\x7fELF", ".elf"),
          (b"RIFF", ".wav"), (b"BM", ".bmp"), (b"\x1f\x8b", ".gz"),
          (b"7z\xbc\xaf\x27\x1c", ".7z"), (b"Rar!", ".rar"), (b"BZh", ".bz2"),
          (b"\xfd7zXZ", ".xz"))

_MAX_BLOBS = 400
_MAX_DECODED = 8_000_000        # per blob
_INLINE_PER = 600_000           # inline at most this much per blob
_INLINE_TOTAL = 3_000_000       # ... and this much overall


def _printable(blob: bytes) -> bool:
    if not blob:
        return False
    good = sum(1 for c in blob if 32 <= c < 127 or c in (9, 10, 13))
    return good / len(blob) >= 0.90


def _magic_ext(blob: bytes) -> str:
    for magic, ext in _MAGIC:
        if blob.startswith(magic):
            return ext
    return ""


def _b64(raw: bytes) -> bytes:
    return base64.b64decode(raw + b"=" * ((4 - len(raw) % 4) % 4), validate=False)


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
                    blob = _b64(raw) if kind == "b64" else bytes.fromhex(raw.decode())
                except Exception:  # noqa: BLE001
                    continue
                if not blob or len(blob) > _MAX_DECODED or blob in seen:
                    continue
                seen.add(blob)
                ext = _magic_ext(blob)
                if ext and len(extracted) < _MAX_BLOBS:
                    # a real file hidden in base64/hex: extract it (child, recursed)
                    dest = outdir / f"{len(extracted):03d}-{kind}{ext}"
                    try:
                        dest.write_bytes(blob)
                        extracted.append(dest)
                    except OSError:
                        pass
                elif _printable(blob) and inline_total < _INLINE_TOTAL:
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
