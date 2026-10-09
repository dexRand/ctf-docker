"""Capture (pcap/pcapng) analyzer: protocols, HTTP/DNS fields, object export.

Also reassembles data exfiltrated via DNS tunneling: each query leaks one
chunk (usually the first label, sharing a fixed base domain); concatenating
them and base32/base64-decoding yields the payload.

If a private key or an SSLKEYLOGFILE is uploaded next to the capture (WebNet0/1),
TLS traffic is decrypted with tshark and the plaintext HTTP is inspected too.
"""
from __future__ import annotations

import base64
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, list_files, out_of, which
from .registry import register

PCAP_EXT = (".pcap", ".pcapng", ".cap")


def _key_files(ctx: ToolContext) -> list[Path]:
    """Private keys / TLS keylog files uploaded alongside the capture.

    Analyzers only receive the current file, so we look at the sibling uploads
    and analysed nodes of the same project (that is how WebNet0/1 ship the key).
    """
    proj = ctx.workdir.parent.parent
    found: list[Path] = []
    for sub in ("uploads", "files"):
        d = proj / sub
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            if not p.is_file() or p == ctx.input:
                continue
            try:
                head = p.read_bytes()[:4096]
            except OSError:
                continue
            if (b"PRIVATE KEY-----" in head or b"CLIENT_RANDOM" in head
                    or b"TRAFFIC_SECRET" in head or b"EXPORTER_SECRET" in head
                    or b"SSLKEYLOGFILE" in head or b"sslkeylog" in head.lower()):
                found.append(p)
    seen: set[tuple] = set()
    uniq: list[Path] = []
    for p in found:  # a key may appear both as upload and as analysed node
        sig = (p.stat().st_size, p.name.split("__", 1)[-1])
        if sig not in seen:
            seen.add(sig)
            uniq.append(p)
    return uniq


def _tls_options(keys: list[Path]) -> list[str]:
    """tshark ``-o`` options to decrypt with the given keys / keylog files."""
    opts: list[str] = []
    for k in keys:
        try:
            head = k.read_bytes()[:4096]
        except OSError:
            continue
        # a keylog file has CLIENT_RANDOM (TLS1.2) or the TLS1.3 *_SECRET labels
        if (b"CLIENT_RANDOM" in head or b"TRAFFIC_SECRET" in head
                or b"EXPORTER_SECRET" in head or b"SSLKEYLOGFILE" in head):
            opts += ["-o", f"tls.keylog_file:{k}"]
        else:
            opts += ["-o", f"tls.keys_list:0.0.0.0,0,http,{k}"]
    return opts



def _printable(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t")
    return good / len(text)


def _try_decodes(joined: str) -> list[tuple[str, str]]:
    """Best-effort base32/base64 decode of a glued label stream."""
    out: list[tuple[str, str]] = []
    if len(joined) < 8:
        return out
    try:
        b32 = joined.upper() + "=" * ((8 - len(joined) % 8) % 8)
        text = base64.b32decode(b32).decode("utf-8", "replace")
        if _printable(text) >= 0.9 and len(text) >= 4:
            out.append(("base32", text))
    except Exception:
        pass
    try:
        b64 = joined + "=" * ((4 - len(joined) % 4) % 4)
        text = base64.b64decode(b64, validate=False).decode("utf-8", "replace")
        if _printable(text) >= 0.9 and len(text) >= 4:
            out.append(("base64", text))
    except Exception:
        pass
    return out


def dns_tunnel_candidates(queries: list[str]) -> list[str]:
    """Try to reassemble DNS-exfiltrated plaintext from query names.

    Two heuristics feed the same printable-gated base32/base64 decode:
    (A) queries sharing a fixed base domain (last 1-2 labels) leak one chunk
        per query in their varying prefix labels;
    (B) a fixed label position across all queries.
    Case is preserved: base32 is decoded case-insensitively, base64 needs it.
    """
    names = list(dict.fromkeys((q or "").rstrip(".") for q in queries if q))
    if len(names) < 2:
        return []
    found: list[tuple[float, str]] = []

    def consider(label: str, joined: str) -> None:
        if len(joined) < 8:
            return
        for kind, text in _try_decodes(joined):
            score = _printable(text) + (1.0 if "{" in text else 0.0)
            found.append((score, f"{label} {kind}: {text}"))

    for k in (1, 2):  # (A) share a fixed base domain
        groups: dict[str, list[str]] = {}
        for n in names:
            parts = n.split(".")
            if len(parts) <= k:
                continue
            groups.setdefault(".".join(parts[-k:]), []).append("".join(parts[:-k]))
        for base, prefixes in groups.items():
            if len(prefixes) >= 2:
                consider(f"base {base}", "".join(prefixes))
    max_parts = max(len(n.split(".")) for n in names)
    for pos in range(max_parts):  # (B) fixed label position
        consider(f"label[{pos}]",
                 "".join(n.split(".")[pos] for n in names if len(n.split(".")) > pos))

    found.sort(key=lambda x: x[0], reverse=True)
    out: list[str] = []
    for _, text in found:
        if text not in out:
            out.append(text)
        if len(out) >= 5:
            break
    return out


def _expand_http_response(line: str) -> str:
    """Pretty-print one ``http.request.full_uri<TAB>http.response.line`` row.

    tshark joins the response's header lines with ``,`` inside a single field, so
    a header like ``Pico-Flag:`` ends up buried in a very long line. Split it back
    into one header per line, with the request URL on its own line. Rows that only
    carry the request URL (no response headers) collapse to ``""``.
    """
    if not line:
        return ""
    if "\t" not in line:
        return line.strip()
    url, _, rest = line.partition("\t")
    for sep in ("\\r\\n,", "\r\n,", "\\n,", "\n,"):   # header separators
        rest = rest.replace(sep, "\n")
    for sep in ("\\r\\n", "\r\n", "\\n", "\n"):        # trailing line breaks
        rest = rest.replace(sep, "\n")
    headers = [h.strip() for h in rest.split("\n") if h.strip()]
    if not headers:
        return ""
    return "\n".join([url.strip()] + [f"  {h}" for h in headers])


class PcapAnalyzer(Analyzer):
    name = "pcap"
    category = "network"
    description = "Parse a capture with tshark: protocols, HTTP/DNS fields, DNS tunneling, objects."
    accepts = PCAP_EXT
    display_order = 262

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("tshark"):
            return ToolResult(self.name, status="skipped", summary="tshark not installed")
        keys = _key_files(ctx)
        tls = _tls_options(keys)
        parts: list[str] = []
        proc = ctx.run(["tshark", "-r", str(ctx.input), *tls, "-q", "-z", "io,phs"], timeout=180)
        if proc.returncode == 0 and (proc.stdout or "").strip():
            parts.append("== protocols ==\n" + proc.stdout.strip())
        # TLS with a provided key: decrypted HTTP request/response rows. This is the
        # highest-signal section (flags often live in headers, e.g. Pico-Flag), so it
        # is kept right after the protocols and *before* the bulky request-body hex:
        # that way it survives the report/transcript truncation.
        if tls:
            proc = ctx.run(["tshark", "-r", str(ctx.input), *tls, "-Y", "http",
                            "-T", "fields", "-e", "http.request.full_uri",
                            "-e", "http.response.line"], timeout=180)
            rows = [l for l in (proc.stdout or "").splitlines() if l.strip()]
            if rows:
                plain = "\n".join(
                    x for x in (_expand_http_response(l) for l in rows) if x)
                if plain:
                    parts.append("== TLS decrypted (key) ==\n" + plain[:20000])
        # HTTP/2 sits behind TLS; tshark decodes its headers (custom headers such
        # as `flag-header` carry the flag). Only meaningful with a key.
        if tls:
            proc = ctx.run(["tshark", "-r", str(ctx.input), *tls, "-Y", "http2",
                            "-T", "fields", "-e", "http2.header.name",
                            "-e", "http2.header.value"], timeout=180)
            rows = [l for l in (proc.stdout or "").splitlines() if l.strip()]
            if rows:
                parts.append("== TLS decrypted (HTTP/2) ==\n" + "\n".join(rows)[:20000])
        # pcapng per-packet comments often hide a flag ("comments are hard to find")
        proc = ctx.run(["tshark", "-r", str(ctx.input), "-T", "fields",
                        "-e", "frame.comment"], timeout=180)
        comments = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip()]
        if comments:
            parts.append("== comments ==\n" + "\n".join(dict.fromkeys(comments))[:12000])
        # flags are often in request URIs or raw HTTP bodies
        proc = ctx.run([
            "tshark", "-r", str(ctx.input), *tls, "-T", "fields",
            "-e", "http.request.full_uri", "-e", "http.host", "-e", "http.file_data",
            "-e", "data.data",
        ], timeout=180)
        fields = " ".join(line for line in (proc.stdout or "").splitlines() if line.strip())
        if fields:
            parts.append("== fields ==\n" + fields[:20000])
        # DNS tunneling: chunk-per-query exfiltration (ExtractionD'ADNs style)
        proc = ctx.run(["tshark", "-r", str(ctx.input), "-T", "fields",
                        "-e", "dns.qry.name"], timeout=180)
        queries = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip()]
        if queries:
            parts.append("== dns queries ==\n"
                         + "\n".join(dict.fromkeys(queries))[:12000])
        tunnel = dns_tunnel_candidates(queries)
        if tunnel:
            parts.append("== DNS tunneling ==\n" + "\n".join(tunnel))
        # export HTTP objects (become children to recurse into)
        outdir = ctx.sub(self.name)
        ctx.run(["tshark", "-r", str(ctx.input), *tls, "--export-objects",
                 f"http,{outdir}"], timeout=180)
        files = list_files(outdir)
        extracted = [str(f) for f in files]
        artifacts = [{"name": f.name, "path": str(f), "size": f.stat().st_size} for f in files]
        summary = f"{len(extracted)} object(s) exported" if extracted else "no HTTP object"
        if tunnel:
            summary += f", {len(tunnel)} tunnel DNS"
        if keys:
            summary += f", TLS decrypted ({len(keys)} key)"
        return ToolResult(self.name, status="done", output="\n\n".join(parts),
                          summary=summary, extracted=extracted, artifacts=artifacts)


register(PcapAnalyzer())