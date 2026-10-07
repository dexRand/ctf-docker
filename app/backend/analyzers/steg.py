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
            return ToolResult(self.name, status="done", summary="data extracted",
                              extracted=[str(out)],
                              artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])
        blob = out_of(proc)
        needs = "passphrase" in blob.lower() or proc.returncode != 0
        return ToolResult(self.name, status="needs_password" if needs else "done",
                          needs_password=needs, output=blob[-8000:], exit_code=proc.returncode,
                          summary="password required" if needs else "no data")


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
            return ToolResult(self.name, status="done", summary="data extracted",
                              extracted=[str(out)],
                              artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])
        return ToolResult(self.name, status="error", output=out_of(proc)[-8000:], exit_code=proc.returncode,
                          summary="no data / wrong key")


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
            return ToolResult(self.name, status="done", summary="data extracted",
                              extracted=[str(out)],
                              artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])
        return ToolResult(self.name, status="done", output=out_of(proc)[-8000:], exit_code=proc.returncode,
                          summary="no data")


def _openstego_cmd(input_path, out_path, password: str | None = None) -> list:
    """OpenStego extract args.

    NOTE: passing an *empty* ``-p ""`` makes OpenStego print its help and never
    extract, so the flag is added only when a password is actually known.
    """
    cmd = ["openstego", "extract", "-sf", str(input_path), "-xf", str(out_path)]
    if password:
        cmd += ["-p", password]
    return cmd


class OpenStegoAnalyzer(Analyzer):
    name = "openstego"
    category = "steg"
    description = "Extract data embedded with OpenStego (unencrypted or with a known password)."
    needs_password = True
    accepts = (".png", ".bmp", ".gif", ".jpg", ".jpeg", ".tiff", ".tif")
    display_order = 340

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("openstego"):
            return ToolResult(self.name, status="skipped", summary="openstego not installed")
        out = ctx.sub(self.name) / (ctx.input.name + ".openstego")
        proc = ctx.run(_openstego_cmd(ctx.input, out, ctx.password), timeout=120)
        blob = out_of(proc)
        if proc.returncode == 0 and out.exists() and out.stat().st_size:
            return ToolResult(self.name, status="done", output=blob[-8000:],
                              summary="data extracted", extracted=[str(out)],
                              artifacts=[{"name": out.name, "path": str(out), "size": out.stat().st_size}])
        # no payload, wrong/absent password, or an unsupported image: not an error.
        # Collapse OpenStego's output/usage into a single concise summary line.
        if "corrupt OR invalid password" in blob:
            summary = "no OpenStego data (or password required)"
        elif "OpenStego is a steganography" in blob or "command line interface" in blob:
            summary = "unsupported image or invalid arguments"
        else:
            lines = [ln for ln in blob.splitlines() if ln.strip() and "Enter Password" not in ln]
            summary = (lines[0] if lines else "no OpenStego data")[:160]
        tail = "" if summary.startswith("unsupported") else blob[-600:]
        return ToolResult(self.name, status="skipped", output=tail,
                          exit_code=proc.returncode, summary=summary)


register(SteghideAnalyzer())
register(OutguessAnalyzer())
register(JstegAnalyzer())
register(OpenStegoAnalyzer())
