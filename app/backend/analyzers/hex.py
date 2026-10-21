"""Hex viewers: xxd, hexdump and hexyl (coloured)."""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register, subprocess_analyzer

LIMIT = 131072  # bytes to dump (128 KiB) to keep output bounded
MAX_OUT = 400000


class HexylAnalyzer(Analyzer):
    name = "hexyl"
    category = "hex"
    description = "Coloured hex viewer with byte classification (first 128 KiB)."
    display_order = 145

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("hexyl"):
            return ToolResult(self.name, status="skipped", summary="hexyl not installed")
        proc = ctx.run(["hexyl", "--color=always", "--length", str(LIMIT), str(ctx.input)])
        if proc.returncode != 0 and "unexpected argument" in (proc.stderr or "").lower():
            proc = ctx.run(["hexyl", "--length", str(LIMIT), str(ctx.input)])
        return ToolResult(self.name, status="done" if proc.returncode == 0 else "error",
                          output=(proc.stdout or "")[:MAX_OUT], exit_code=proc.returncode,
                          summary="colored hex")


register(HexylAnalyzer())
subprocess_analyzer("xxd", ["xxd", "-g", "1", "-l", str(LIMIT), "{input}"], "hex",
                    "Plain hex dump with offsets (xxd -g1, first 128 KiB).", order=146,
                    max_output=MAX_OUT)
subprocess_analyzer("hexdump", ["hexdump", "-C", "-n", str(LIMIT), "{input}"], "hex",
                    "Canonical hex + ASCII dump (hexdump -C, first 128 KiB).", order=147,
                    max_output=MAX_OUT)
