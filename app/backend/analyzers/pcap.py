"""Capture (pcap/pcapng) analyzer: protocols, HTTP/DNS fields, object export."""
from __future__ import annotations

from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, list_files, out_of, which
from .registry import register

PCAP_EXT = (".pcap", ".pcapng", ".cap")


class PcapAnalyzer(Analyzer):
    name = "pcap"
    category = "network"
    description = "Parse a capture with tshark: protocols, HTTP/DNS fields, objects."
    accepts = PCAP_EXT
    display_order = 262

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("tshark"):
            return ToolResult(self.name, status="skipped", summary="tshark not installed")
        parts: list[str] = []
        proc = ctx.run(["tshark", "-r", str(ctx.input), "-q", "-z", "io,phs"], timeout=180)
        if proc.returncode == 0 and (proc.stdout or "").strip():
            parts.append("== protocols ==\n" + proc.stdout.strip())
        # flags are often in request URIs, DNS queries or raw HTTP bodies
        proc = ctx.run([
            "tshark", "-r", str(ctx.input), "-T", "fields",
            "-e", "http.request.full_uri", "-e", "http.host", "-e", "dns.qry.name",
            "-e", "http.file_data", "-e", "data.data",
        ], timeout=180)
        fields = " ".join(line for line in (proc.stdout or "").splitlines() if line.strip())
        if fields:
            parts.append("== fields ==\n" + fields[:20000])
        # export HTTP objects (become children to recurse into)
        outdir = ctx.sub(self.name)
        ctx.run(["tshark", "-r", str(ctx.input), "--export-objects", f"http,{outdir}"], timeout=180)
        files = list_files(outdir)
        extracted = [str(f) for f in files]
        artifacts = [{"name": f.name, "path": str(f), "size": f.stat().st_size} for f in files]
        summary = f"{len(extracted)} oggetti esportati" if extracted else "nessun oggetto HTTP"
        return ToolResult(self.name, status="done", output="\n\n".join(parts),
                          summary=summary, extracted=extracted, artifacts=artifacts)


register(PcapAnalyzer())
