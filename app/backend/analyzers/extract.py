"""Extraction / carving analyzers."""
from __future__ import annotations

import base64
import re
import shutil
import zipfile
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
            summary=f"{len(files)} file(s) extracted",
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
            summary=f"{len(files)} file(s)", extracted=[str(f) for f in files],
            artifacts=_arts(files, ctx.workdir),
        )


ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".iso")


class SevenZipAnalyzer(Analyzer):
    name = "7z"
    category = "extract"
    description = "Extract archives (7z/zip/tar/rar/gz…), detects passwords."
    has_archive = True
    needs_password = True
    accepts = ARCHIVE_EXT
    display_order = 220

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("7z"):
            return ToolResult(self.name, status="skipped", summary="7z not installed")
        d = ctx.sub(self.name)
        proc = ctx.run(["7z", "x", "-y", f"-p{ctx.password or ''}", f"-o{d}", str(ctx.input)], timeout=600)
        blob = out_of(proc)
        low = blob.lower()
        if proc.returncode != 0:
            shutil.rmtree(d, ignore_errors=True)
            files: list[Path] = []
            if "can't open as archive" in low or "is not archive" in low:
                return ToolResult(self.name, status="skipped", summary="not an archive", output=blob[-4000:])
        else:
            files = list_files(d)
        needs = ("password" in low or "encrypted" in low or "wrong" in low) and proc.returncode != 0
        return ToolResult(
            self.name,
            status="needs_password" if needs else ("done" if proc.returncode == 0 else "error"),
            needs_password=needs, output=blob[-20000:], exit_code=proc.returncode,
            summary="password required" if needs else f"{len(files)} file",
            extracted=[str(f) for f in files], artifacts=_arts(files, ctx.workdir),
        )


subprocess_analyzer(
    "pngcheck", ["pngcheck", "-v", "{input}"], "extract",
    "Validate PNG chunks and integrity.", order=230, accepts=(".png",), soft=True,
)


# Zip-based Office / OpenDocument containers. Their XML parts often hide
# base64 (or macros), sometimes split by whitespace between every character
# (picoCTF "MacroHard WeakEdge": ppt/slideMasters/hidden). We unzip the parts
# and also decode whitespace-separated base64 directly.
OFFICE_EXT = (".pptm", ".pptx", ".potm", ".ppsx", ".docm", ".docx", ".dotm",
              ".xlsm", ".xlsx", ".xltm", ".odt", ".ods", ".odp", ".odg", ".epub")
_B64_JOINED = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
_MAX_PART = 8_000_000
_MAX_PARTS = 300


class OfficeAnalyzer(Analyzer):
    name = "office"
    category = "extract"
    description = "Unzip Office/OpenDocument parts and decode whitespace-split base64."
    accepts = OFFICE_EXT
    display_order = 218

    def run(self, ctx: ToolContext) -> ToolResult:
        if not zipfile.is_zipfile(ctx.input):
            return ToolResult(self.name, status="skipped", summary="not a Zip-based Office file")
        outdir = ctx.sub(self.name)
        extracted: list[Path] = []
        hits: list[str] = []
        try:
            with zipfile.ZipFile(ctx.input) as z:
                for info in z.infolist()[: _MAX_PARTS * 4]:
                    if info.is_dir() or info.file_size == 0 or info.file_size > _MAX_PART:
                        continue
                    if ".." in info.filename or info.filename.startswith("/"):
                        continue
                    if len(extracted) >= _MAX_PARTS:
                        break
                    dest = outdir / info.filename
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        dest.write_bytes(z.read(info))
                    except (OSError, zipfile.BadZipFile):
                        continue
                    extracted.append(dest)
                    text = dest.read_bytes().decode("latin-1", "replace")
                    # collapse whitespace so "Z m x h Z z" becomes one base64 token
                    joined = re.sub(r"\s+", "", text).encode("latin-1", "replace")
                    for m in _B64_JOINED.finditer(joined):
                        tok = m.group(0) + b"=" * ((4 - len(m.group(0)) % 4) % 4)
                        try:
                            dec = base64.b64decode(tok, validate=False)
                        except Exception:
                            continue
                        if b"{" in dec and all(32 <= c < 127 or c in (9, 10, 13) for c in dec):
                            hits.append(f"{info.filename}: {dec.decode('latin-1', 'replace')[:200]}")
        except (OSError, zipfile.BadZipFile) as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        summary = f"{len(extracted)} part(s)"
        if hits:
            summary += f", {len(hits)} base64"
        return ToolResult(
            self.name, status="done", summary=summary,
            output="\n".join(dict.fromkeys(hits))[:20000],
            extracted=[str(f) for f in extracted], artifacts=_arts(extracted, ctx.workdir),
        )


register(BinwalkExtractAnalyzer())
register(ForemostAnalyzer())
register(SevenZipAnalyzer())
register(OfficeAnalyzer())
