"""Extraction / carving analyzers."""
from __future__ import annotations

import shutil
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, list_files, which, out_of
from .registry import register, subprocess_analyzer


def _arts(files: list[Path], workdir: Path) -> list[dict]:
    out = []
    for f in files:
        try:
            out.append({"name": str(f.relative_to(workdir)), "path": str(f), "size": f.stat().st_size})
        except (OSError, ValueError):
            continue
    return out


class BinwalkExtractAnalyzer(Analyzer):
    name = "binwalk-extract"
    category = "extract"
    description = "Recursively carve embedded files (binwalk -e --matryoshka)."
    has_archive = True
    display_order = 200

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("binwalk"):
            return ToolResult(self.name, status="skipped", summary="binwalk not installed")
        d = ctx.sub(self.name)
        proc = ctx.run(
            ["binwalk", "--matryoshka", "--depth=2", "--count=100",
             "--size=10485760", "-e", str(ctx.input), "--run-as=root"],
            timeout=600, cwd=d,
        )
        produced = d / f"_{ctx.input.name}.extracted"
        files = list_files(produced)
        return ToolResult(
            self.name, status="done" if files else "done",
            output=out_of(proc)[-20000:], exit_code=proc.returncode,
            summary=f"{len(files)} file estratti",
            extracted=[str(f) for f in files], artifacts=_arts(files, ctx.workdir),
        )


class ForemostAnalyzer(Analyzer):
    name = "foremost"
    category = "extract"
    description = "Carve files by file signature (foremost)."
    has_archive = True
    display_order = 210

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("foremost"):
            return ToolResult(self.name, status="skipped", summary="foremost not installed")
        d = ctx.sub(self.name)
        proc = ctx.run(["foremost", "-q", "-i", str(ctx.input), "-o", str(d)], timeout=600)
        files = list_files(d)
        return ToolResult(
            self.name, status="done", output=out_of(proc)[-20000:], exit_code=proc.returncode,
            summary=f"{len(files)} file", extracted=[str(f) for f in files],
            artifacts=_arts(files, ctx.workdir),
        )


class SevenZipAnalyzer(Analyzer):
    name = "7z"
    category = "extract"
    description = "Extract archives (7z/zip/tar/rar/gz…), detects passwords."
    has_archive = True
    needs_password = True
    display_order = 220

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("7z"):
            return ToolResult(self.name, status="skipped", summary="7z not installed")
        d = ctx.sub(self.name)
        proc = ctx.run(["7z", "x", "-y", f"-p{ctx.password or ''}", f"-o{d}", str(ctx.input)], timeout=600)
        blob = out_of(proc).lower()
        needs = ("password" in blob or "encrypted" in blob or "wrong" in blob) and proc.returncode != 0
        if proc.returncode != 0:
            shutil.rmtree(d, ignore_errors=True)
            files: list[Path] = []
        else:
            files = list_files(d)
        return ToolResult(
            self.name,
            status="needs_password" if needs else ("done" if proc.returncode == 0 else "error"),
            needs_password=needs, output=blob[-20000:], exit_code=proc.returncode,
            summary="password richiesta" if needs else f"{len(files)} file",
            extracted=[str(f) for f in files], artifacts=_arts(files, ctx.workdir),
        )


subprocess_analyzer(
    "pngcheck", ["pngcheck", "-v", "{input}"], "extract",
    "Validate PNG chunks and integrity.", order=230, accepts=(".png",),
)

register(BinwalkExtractAnalyzer())
register(ForemostAnalyzer())
register(SevenZipAnalyzer())
