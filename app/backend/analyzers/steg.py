"""Steganography analyzers (image / audio payloads)."""
from __future__ import annotations

from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, list_files, which, out_of
from .registry import register, subprocess_analyzer

subprocess_analyzer(
    "zsteg", ["zsteg", "-a", "{input}"], "steg",
    "LSB / bit-plane data extraction for PNG/BMP.", order=300,
    accepts=(".png", ".bmp"),
)


def _first(d: Path) -> list[Path]:
    return list_files(d)


class SteghideAnalyzer(Analyzer):
    name = "steghide"
    category = "steg"
    description = "Extract embedded data from JPEG/BMP/WAV/AU (steghide)."
    needs_password = True
    accepts = (".jpg", ".jpeg", ".bmp", ".wav", ".au")
    display_order = 310

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("steghide"):
            return ToolResult(self.name, status="skipped", summary="steghide not installed")
        out = ctx.sub(self.name) / (ctx.input.name + ".steghide")
        proc = ctx.run(["steghide", "extract", "-sf", str(ctx.input),
                        "-p", ctx.password or "", "-xf", str(out), "-f"], timeout=120)
        if proc.returncode == 0 and out.exists():
            return ToolResult(self.name, status="done", summary="dato estratto",
                              extracted=[str(out)],
                              artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])
        blob = out_of(proc)
        needs = "passphrase" in blob.lower() or proc.returncode != 0
        return ToolResult(self.name, status="needs_password" if needs else "done",
                          needs_password=needs, output=blob[-8000:], exit_code=proc.returncode,
                          summary="password richiesta" if needs else "nessun dato")


class OutguessAnalyzer(Analyzer):
    name = "outguess"
    category = "steg"
    description = "Extract data embedded with outguess (JPEG), optional key."
    needs_password = True
    accepts = (".jpg", ".jpeg",)
    display_order = 320

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("outguess"):
            return ToolResult(self.name, status="skipped", summary="outguess not installed")
        out = ctx.sub(self.name) / (ctx.input.name + ".outguess")
        cmd = ["outguess"]
        if ctx.password:
            cmd += ["-k", ctx.password]
        cmd += ["-r", str(ctx.input), str(out)]
        proc = ctx.run(cmd, timeout=120)
        if proc.returncode == 0 and out.exists():
            return ToolResult(self.name, status="done", summary="dato estratto",
                              extracted=[str(out)],
                              artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])
        return ToolResult(self.name, status="error", output=out_of(proc)[-8000:], exit_code=proc.returncode,
                          summary="nessun dato / chiave errata")


class JstegAnalyzer(Analyzer):
    name = "jsteg"
    category = "steg"
    description = "Reveal data hidden with jsteg (JPEG LSB)."
    accepts = (".jpg", ".jpeg",)
    display_order = 330

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("jsteg"):
            return ToolResult(self.name, status="skipped", summary="jsteg not installed")
        out = ctx.sub(self.name) / (ctx.input.name + ".jsteg")
        proc = ctx.run(["jsteg", "reveal", str(ctx.input), str(out)], timeout=120)
        if out.exists() and out.stat().st_size:
            return ToolResult(self.name, status="done", summary="dato estratto",
                              extracted=[str(out)],
                              artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])
        return ToolResult(self.name, status="done", output=out_of(proc)[-8000:], exit_code=proc.returncode,
                          summary="nessun dato")


class OpenStegoAnalyzer(Analyzer):
    name = "openstego"
    category = "steg"
    description = "Extract data embedded with OpenStego (needs password)."
    needs_password = True
    accepts = (".png", ".bmp", ".gif", ".jpg", ".jpeg", ".tiff", ".tif", ".webp")
    display_order = 340

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("openstego"):
            return ToolResult(self.name, status="skipped", summary="openstego not installed")
        out = ctx.sub(self.name) / (ctx.input.name + ".openstego")
        proc = ctx.run(["openstego", "extract", "-sf", str(ctx.input),
                        "-xf", str(out), "-p", ctx.password or ""], timeout=120)
        blob = out_of(proc)
        if proc.returncode == 0 and out.exists():
            return ToolResult(self.name, status="done", output=blob[-8000:],
                              summary="dato estratto", extracted=[str(out)],
                              artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])
        # no OpenStego payload (or unsupported): not an error
        return ToolResult(self.name, status="skipped", output=blob[-4000:],
                          exit_code=proc.returncode, summary="nessun dato OpenStego")


register(SteghideAnalyzer())
register(OutguessAnalyzer())
register(JstegAnalyzer())
register(OpenStegoAnalyzer())
