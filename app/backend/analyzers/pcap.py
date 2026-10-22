"""Capture (pcap/pcapng) analyzer: protocols, HTTP/DNS fields, object export.

Also reassembles data exfiltrated via DNS tunneling: each query leaks one
chunk (usually the first label, sharing a fixed base domain); concatenating
them and base32/base64-decoding yields the payload.

If a private key or an SSLKEYLOGFILE is uploaded next to the capture (WebNet0/1),
TLS traffic is decrypted with tshark and the plaintext HTTP is inspected too.
"""
from __future__ import annotations

import base64
import struct
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, list_files, which
from .registry import register
from .util import B64_TOKEN, join_b64_fragments, printable_ratio

PCAP_EXT = (".pcap", ".pcapng", ".cap")

_PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")


def repaired_pcap(data: bytes) -> bytes | None:
    """Rebuild a capture whose global-header magic and per-record incl_len were
    corrupted (ictf23 "forensics"): the original length is still in orig_len and
    the packets are intact, so the chain is walked and fixed."""
    if len(data) < 24 or data[:4] in _PCAP_MAGICS:
        return None
    snaplen = struct.unpack_from("<I", data, 16)[0]
    if not 0 < snaplen <= 64 << 20:
        snaplen = 262144
    network = struct.unpack_from("<I", data, 20)[0]
    if network > 1024:
        network = 1
    out = bytearray(data)
    struct.pack_into("<IHHiiii", out, 0, 0xA1B2C3D4, 2, 4, 0, 0, snaplen, network)
    off, n = 24, 0
    while off + 16 <= len(out):
        incl, orig = struct.unpack_from("<II", out, off + 8)
        if incl != orig and 0 < orig <= snaplen:
            struct.pack_into("<I", out, off + 8, orig)
            incl = orig
        if incl <= 0 or off + 16 + incl > len(out):
            return None
        off += 16 + incl
        n += 1
    if n < 1 or off != len(out):
        return None
    return bytes(out)




def _key_files(ctx: ToolContext) -> list[Path]:
    """Private keys / TLS keylog files uploaded alongside the capture.

    Analyzers only receive the current file, so we look at the sibling uploads
    and analysed nodes of the same project (that is how WebNet0/1 ship the key).
    """
    found = [p for p, head, _ in ctx.siblings(4096)
             if b"PRIVATE KEY-----" in head or b"CLIENT_RANDOM" in head
             or b"TRAFFIC_SECRET" in head or b"EXPORTER_SECRET" in head
             or b"SSLKEYLOGFILE" in head or b"sslkeylog" in head.lower()]
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
            with open(k, "rb") as fh:
                head = fh.read(4096)
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


def dns_tunnel_candidates(queries: list[str],
                          by_server: dict[str, list[str]] | None = None) -> list[str]:
    """Try to reassemble DNS-exfiltrated plaintext from query names.

    Two heuristics feed the same printable-gated base32/base64 decode:
    (A) queries sharing a fixed base domain (last 1-2 labels) leak one chunk
        per query in their varying prefix labels;
    (B) a fixed label position across all queries;
    (C) the same, per DNS server the queries were sent to: the exfil often goes
        to its own server, hidden among random lookups (picoCTF "shark2").
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
    for server, qs in (by_server or {}).items():   # (C) per destination server
        uniq = list(dict.fromkeys(q.rstrip(".") for q in qs))
        if len(uniq) < 2 or len(uniq) == len(names):
            continue
        groups2: dict[str, list[str]] = {}
        for n in uniq:
            parts = n.split(".")
            if len(parts) > 2:
                groups2.setdefault(".".join(parts[-2:]), []).append("".join(parts[:-2]))
        for base, prefixes in groups2.items():
            if len(prefixes) >= 2:
                consider(f"server {server} base {base}", "".join(prefixes))
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


_MAX_STREAM = 1_000_000      # bytes kept per conversation
_MAX_STREAMS_OUT = 200


def _streams_text(ctx: ToolContext, tls: list[str]) -> str:
    """Payload of every UDP/TCP conversation joined in order, shown as text
    (non-printables as '.') when it reads like text or holds a brace."""
    proc = ctx.run(["tshark", "-r", str(ctx.input), *tls, "-T", "fields", "-E", "separator=\t",
                    "-e", "frame.time_epoch", "-e", "udp.stream", "-e", "udp.payload",
                    "-e", "tcp.stream", "-e", "tcp.payload"], timeout=180)
    joined: dict[tuple[str, str], bytearray] = {}
    timed: list[tuple[float, bytes]] = []
    for line in (proc.stdout or "").splitlines():
        cols = line.split("\t") + ["", "", "", "", ""]
        for proto, sid, payload in (("udp", cols[1], cols[2]), ("tcp", cols[3], cols[4])):
            if not sid or not payload:
                continue
            try:
                chunk = bytes.fromhex(payload.replace(":", "").split(",")[0])
            except ValueError:
                continue
            try:
                timed.append((float(cols[0] or 0), chunk))
            except ValueError:
                pass
            buf = joined.setdefault((proto, sid), bytearray())
            if len(buf) < _MAX_STREAM:
                buf += chunk
    out = []
    for (proto, sid), buf in joined.items():
        if len(buf) < 4:
            continue
        if b"{" in buf or printable_ratio(bytes(buf)) >= 0.7:
            text = "".join(chr(b) if 32 <= b < 127 or b in (9, 10) else "." for b in buf)
            out.append(f"[{proto} stream {sid}, {len(buf)} B] {text[:4000]}")
        if len(out) >= _MAX_STREAMS_OUT:
            break
    tokens = _b64_per_packet(timed)
    if tokens:
        out.append(f"[base64 per packet, time order] {tokens}")
    out += _port_text(ctx)
    return "\n".join(out)


def _port_text(ctx: ToolContext) -> list[str]:
    """Data hidden in UDP/TCP source ports (port = base + ASCII code, picoCTF
    "shark on wire 2"): per destination port, ports minus their base as text."""
    proc = ctx.run(["tshark", "-r", str(ctx.input), "-T", "fields", "-E", "separator=\t",
                    "-e", "udp.srcport", "-e", "udp.dstport", "-e", "tcp.srcport", "-e", "tcp.dstport"],
                   timeout=180)
    by_dst: dict[str, list[int]] = {}
    for line in (proc.stdout or "").splitlines():
        cols = (line.split("\t") + ["", "", "", ""])[:4]
        for src, dst in ((cols[0], cols[1]), (cols[2], cols[3])):
            if src.isdigit() and dst.isdigit():
                by_dst.setdefault(dst, []).append(int(src))
    out = []
    for dst, ports in by_dst.items():
        if len(ports) < 8:
            continue
        base = min(ports) // 1000 * 1000
        vals = [p - base for p in ports]
        text = "".join(chr(v) for v in vals if 32 <= v < 127)
        if len(text) >= 8 and len(text) >= 0.8 * len(vals) and len(set(text)) > 3:
            out.append(f"[source ports - {base} -> dst {dst}] {text}")
    return out


def _b64_per_packet(timed: list[tuple[float, bytes]]) -> str:
    """Packets that each carry one base64 token (exfil split across packets,
    possibly out of order): decode them in capture-time order and join."""
    toks = [(t, c.strip()) for t, c in timed if 4 <= len(c.strip()) <= 512 and B64_TOKEN.match(c.strip())]
    if len(toks) < 3 or len(toks) < 0.5 * len(timed):
        return ""
    return join_b64_fragments([tok for _t, tok in sorted(toks, key=lambda x: x[0])])


def evil_bit_streams(rows: str) -> list[tuple[str, str]]:
    """(side, text) for captures that hide one character per packet behind the
    IPv4 reserved ("evil") bit: the packets with it and the ones without it.
    Only one-byte payloads count, and a side must be mostly printable."""
    sides: dict[str, list[int]] = {"without the evil bit": [], "with the evil bit": []}
    for line in rows.splitlines():
        rb, data = (line.split("\t") + ["", ""])[:2]
        data = data.strip()
        if len(data) != 2:                          # only one-byte payloads
            continue
        try:
            key = "with the evil bit" if rb.strip() in ("1", "True") else "without the evil bit"
            sides[key].append(int(data, 16))
        except ValueError:
            continue
    out: list[tuple[str, str]] = []
    for side, chars in sides.items():
        if len(chars) < 8:
            continue
        raw = bytes(chars)
        if sum(32 <= b < 127 for b in raw) / len(raw) < 0.7:
            continue
        out.append((side, raw.decode("latin-1")))
    return out


class PcapAnalyzer(Analyzer):
    name = "pcap"
    category = "network"
    description = "Parse a capture with tshark: protocols, HTTP/DNS fields, DNS tunneling, objects."
    accepts = PCAP_EXT
    display_order = 262

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("tshark"):
            return ToolResult(self.name, status="skipped", summary="tshark not installed")
        cap = ctx.input
        fixed = repaired_pcap(cap.read_bytes())
        if fixed:
            cap = ctx.sub(self.name) / "repaired.pcap"
            cap.write_bytes(fixed)
        keys = _key_files(ctx)
        tls = _tls_options(keys)
        parts: list[str] = []
        proc = ctx.run(["tshark", "-r", str(cap), *tls, "-q", "-z", "io,phs"], timeout=180)
        if proc.returncode == 0 and (proc.stdout or "").strip():
            parts.append("== protocols ==\n" + proc.stdout.strip())
        # TLS with a provided key: decrypted HTTP request/response rows. This is the
        # highest-signal section (flags often live in headers, e.g. Pico-Flag), so it
        # is kept right after the protocols and *before* the bulky request-body hex:
        # that way it survives the report/transcript truncation.
        if tls:
            proc = ctx.run(["tshark", "-r", str(cap), *tls, "-Y", "http",
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
            proc = ctx.run(["tshark", "-r", str(cap), *tls, "-Y", "http2",
                            "-T", "fields", "-e", "http2.header.name",
                            "-e", "http2.header.value"], timeout=180)
            rows = [l for l in (proc.stdout or "").splitlines() if l.strip()]
            if rows:
                parts.append("== TLS decrypted (HTTP/2) ==\n" + "\n".join(rows)[:20000])
        # pcapng per-packet comments often hide a flag ("comments are hard to find")
        proc = ctx.run(["tshark", "-r", str(cap), "-T", "fields",
                        "-e", "frame.comment"], timeout=180)
        comments = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip()]
        if comments:
            parts.append("== comments ==\n" + "\n".join(dict.fromkeys(comments))[:12000])
        # flags are often in request URIs or raw HTTP bodies
        proc = ctx.run([
            "tshark", "-r", str(cap), *tls, "-T", "fields",
            "-e", "http.request.full_uri", "-e", "http.host", "-e", "http.file_data",
            "-e", "data.data",
        ], timeout=180)
        fields = " ".join(line for line in (proc.stdout or "").splitlines() if line.strip())
        if fields:
            parts.append("== fields ==\n" + fields[:20000])
        # reassembled UDP/TCP conversations: a flag sent one char per packet
        # ("follow UDP stream") only appears when the payloads are joined
        streams = _streams_text(ctx, tls)
        if streams:
            parts.append("== streams ==\n" + streams)
        # DNS tunneling: chunk-per-query exfiltration (ExtractionD'ADNs style)
        proc = ctx.run(["tshark", "-r", str(cap), "-T", "fields", "-E", "separator=\t",
                        "-e", "ip.dst", "-e", "dns.qry.name", "-e", "dns.flags.response"], timeout=180)
        queries: list[str] = []
        by_server: dict[str, list[str]] = {}
        for line in (proc.stdout or "").splitlines():
            dst, name, resp = (line.split("\t") + ["", "", ""])[:3]
            if not name.strip():
                continue
            queries.append(name.strip())
            if resp.strip() in ("0", "False"):          # a query, sent to `dst`
                by_server.setdefault(dst.strip(), []).append(name.strip())
        if queries:
            parts.append("== dns queries ==\n"
                         + "\n".join(dict.fromkeys(queries))[:12000])
        tunnel = dns_tunnel_candidates(queries, by_server)
        if tunnel:
            parts.append("== DNS tunneling ==\n" + "\n".join(tunnel))
        # RFC 3514 "evil bit": one character per packet, the IP reserved bit
        # separating payload from noise. Authors may set it on the noise (EBE:
        # the flag is in the packets *without* it) or on the data, so show both.
        proc = ctx.run(["tshark", "-r", str(cap), "-T", "fields",
                        "-E", "separator=\t", "-e", "ip.flags.rb", "-e", "data.data"],
                       timeout=180)
        for side, text in evil_bit_streams(proc.stdout or ""):
            parts.append(f"== evil bit ({side}) ==\n{text}")
        # export HTTP objects (become children to recurse into)
        outdir = ctx.sub(self.name)
        ctx.run(["tshark", "-r", str(cap), *tls, "--export-objects",
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