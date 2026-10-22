"""Hex viewers: xxd, hexdump and hexyl (coloured)."""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register, subprocess_analyzer

LIMIT = 32768   # bytes to dump (32 KiB): three hex tools per file, and the
                # flag hunt scans each output several times (128 KiB was 4x this)
MAX_OUT = 120000


class HexylAnalyzer(Analyzer):
    name = "hexyl"
    category = "hex"
    description = "Coloured hex viewer with byte classification (first 32 KiB)."
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
                    "Plain hex dump with offsets (xxd -g1, first 32 KiB).", order=146,
                    max_output=MAX_OUT)
subprocess_analyzer("hexdump", ["hexdump", "-C", "-n", str(LIMIT), "{input}"], "hex",
                    "Canonical hex + ASCII dump (hexdump -C, first 32 KiB).", order=147,
                    max_output=MAX_OUT)
