"""Hex viewers: xxd, hexdump and hexyl (coloured)."""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register

LIMIT = 131072  # bytes to dump (128 KiB) to keep output bounded


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
                          output=(proc.stdout or "")[:400000], exit_code=proc.returncode,
                          summary="colored hex")


class XxdAnalyzer(Analyzer):
    name = "xxd"
    category = "hex"
    description = "Plain hex dump with offsets (xxd -g1, first 128 KiB)."
    display_order = 146

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("xxd"):
            return ToolResult(self.name, status="skipped", summary="xxd not installed")
        proc = ctx.run(["xxd", "-g", "1", "-l", str(LIMIT), str(ctx.input)])
        return ToolResult(self.name, status="done" if proc.returncode == 0 else "error",
                          output=(proc.stdout or "")[:400000], exit_code=proc.returncode)


class HexDumpAnalyzer(Analyzer):
    name = "hexdump"
    category = "hex"
    description = "Canonical hex + ASCII dump (hexdump -C, first 128 KiB)."
    display_order = 147

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("hexdump"):
            return ToolResult(self.name, status="skipped", summary="hexdump not installed")
        proc = ctx.run(["hexdump", "-C", "-n", str(LIMIT), str(ctx.input)])
        return ToolResult(self.name, status="done" if proc.returncode == 0 else "error",
                          output=(proc.stdout or "")[:400000], exit_code=proc.returncode)


register(HexylAnalyzer())
register(XxdAnalyzer())
register(HexDumpAnalyzer())
