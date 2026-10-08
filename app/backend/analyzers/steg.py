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


class PsImageAnalyzer(Analyzer):
    name = "psimage"
    category = "steg"
    description = ("Extract payloads embedded with Invoke-PSImage: one byte per "
                   "pixel from the low nibbles of the blue and green channels.")
    # PSImage only ever writes into a raster, so PNG/BMP covers the real cases.
    accepts = (".png", ".bmp")
    display_order = 305
    MAX_PIXELS = 4_000_000

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            import numpy as np
            from PIL import Image
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"PIL/numpy missing: {exc}")
        try:
            img = Image.open(ctx.input).convert("RGB")
        except Exception as exc:
            return ToolResult(self.name, status="error", summary=f"cannot open image: {exc}")
        w, h = img.size
        if w * h > self.MAX_PIXELS:
            return ToolResult(self.name, status="skipped", summary=f"image too big ({w}x{h})")
        arr = np.asarray(img)
        # Invoke-PSImage: byte = (B & 0x0F) << 4 | (G & 0x0F), in reading order.
        raw = (((arr[:, :, 2] & 0x0F).astype("uint8") << 4)
               | (arr[:, :, 1] & 0x0F)).tobytes()
        # A real payload starts at offset 0 and is printable (map/PS1/aspx…);
        # random image noise does not survive this gate, so normal PNGs are skipped.
        if len(raw) < 8 or not all(32 <= c < 127 or c in (9, 10, 13) for c in raw[:8]):
            return ToolResult(self.name, status="done", summary="no Invoke-PSImage payload")
        nul = raw.find(0)
        payload = raw[:nul] if nul != -1 else raw
        while payload and not (32 <= payload[-1] < 127 or payload[-1] in (9, 10, 13)):
            payload = payload[:-1]
        if len(payload) < 8:
            return ToolResult(self.name, status="done", summary="no Invoke-PSImage payload")
        printable = sum(1 for c in payload
                        if 32 <= c < 127 or c in (9, 10, 13)) / len(payload)
        markers = (b"$out", b"flag.txt", b"powershell", b"System.", b"Encoding", b"IEX")
        if printable < 0.85 and not any(m in payload for m in markers):
            return ToolResult(self.name, status="done", summary="no Invoke-PSImage payload")
        fn = ctx.sub(self.name) / (ctx.input.stem + ".psimage.txt")
        fn.write_bytes(payload)
        return ToolResult(self.name, status="done",
                          summary=f"Invoke-PSImage payload ({len(payload)} bytes, text)",
                          output=payload.decode("latin-1", "replace")[:4000],
                          extracted=[str(fn)],
                          artifacts=[{"name": fn.name, "path": str(fn), "size": fn.stat().st_size}])


register(SteghideAnalyzer())
register(OutguessAnalyzer())
register(JstegAnalyzer())
register(OpenStegoAnalyzer())
register(PsImageAnalyzer())
