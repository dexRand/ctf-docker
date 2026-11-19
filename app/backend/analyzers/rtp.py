"""RTP/H.264 reconstruction from a packet capture (RFC 3550 + RFC 6184).

An RTSP session sends the video as RTP: the SDP ``DESCRIBE`` names the H.264
payload type (usually the dynamic 96) and the capture carries the H.264 NAL
units, fragmented with FU-A (or packed with STAP-A). This analyzer parses the
capture itself (no tshark: it also works where tshark is missing), picks the
video flow, depacketises H.264 into an Annex B ``.264``, converts it with
ffmpeg and returns a few video frames as children: OCR then reads the flag
shown in the video (WaniCTF 2024 "I wanna be a streamer").

Everything is bounded: the gate walks the whole capture under a packet/byte
budget, the scan stops after a packet/byte budget and caps both the retained
bytes across all SSRCs and the number of candidate SSRCs. External commands go
through ``ctx.run`` under one shared deadline for the whole analysis.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, which
from .pcap import PCAP_EXT
from .registry import register

# --- caps (checked before doing any work) ----------------------------------
GATE_BYTES = 4 << 20            # payload bytes kept during the gate
MAX_SCAN_PACKETS = 500_000      # frames walked in the full pass (and the gate)
MAX_STREAM_BYTES = 64 << 20     # payload bytes kept per RTP stream
MAX_TOTAL_BYTES = 96 << 20      # payload bytes kept across all streams
MAX_SSRCS = 32                  # candidate SSRCs kept (only a couple are written)
MAX_STREAM_PACKETS = 60_000     # packets kept per RTP stream (one seq wrap)
MAX_FRAME_BYTES = 4 << 20       # a single captured frame larger than this is skipped
MAX_SDP_BYTES = 256 << 10       # RTSP text inspected for the SDP
MAX_STREAMS_OUT = 2             # H.264 streams written as children
MIN_ANNEXB = 64                 # bytes below which the result is noise
MAX_FRAMES = 2                  # frames extracted in total (OCR cost)
FRAME_INTERVAL_S = 2            # one frame every ~2 s
FFMPEG_BUDGET_S = 240           # total wall-clock budget for all ffmpeg calls
FFMPEG_CALL_TIMEOUT_S = 240     # per-call cap, never more than the remaining budget

_now = time.monotonic            # injectable clock (tests)

# classic pcap magic -> (struct endianness, nanosecond timestamps)
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_RTSP_STARTS = (b"RTSP/", b"OPTIONS ", b"DESCRIBE ", b"SETUP ", b"PLAY ",
                b"TEARDOWN ", b"GET_PARAMETER", b"SET_PARAMETER", b"PAUSE ")


@dataclass(frozen=True)
class RtpPacket:
    seq: int
    timestamp: int
    marker: bool
    payload_type: int
    ssrc: int
    payload: bytes


@dataclass
class CaptureScan:
    streams: dict[int, list[RtpPacket]] = field(default_factory=dict)
    sdp_pts: set[int] = field(default_factory=set)
    packets: int = 0            # capture frames walked
    rtp_packets: int = 0        # candidate RTP packets kept


# ---------------------------------------------------------------------------
# capture / packet parsing (no external tool)
# ---------------------------------------------------------------------------

def _iter_frames(path: Path, max_packets: int):
    """Yield ``(linktype, frame)`` from a classic pcap, bounded by packet count."""
    with path.open("rb") as fh:
        head = fh.read(24)
        if len(head) < 24 or head[:4] not in _PCAP_MAGICS:
            return
        endian, _nano = _PCAP_MAGICS[head[:4]]
        linktype = int.from_bytes(head[20:24], "little" if endian == "<" else "big")
        count = 0
        while count < max_packets:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            incl = int.from_bytes(rec[8:12], "little" if endian == "<" else "big")
            if incl <= 0 or incl > MAX_FRAME_BYTES:
                fh.seek(incl, 1)        # skip a huge/empty record without reading it
                count += 1
                continue
            frame = fh.read(incl)
            if len(frame) < incl:       # truncated capture
                return
            count += 1
            yield linktype, frame


def _parse_ip(data: bytes, off: int):
    """``(protocol, l4 bytes)`` for an IPv4/IPv6 packet at ``off``, else None."""
    if len(data) <= off:
        return None
    version = data[off] >> 4
    if version == 4:
        if len(data) < off + 20:
            return None
        ihl = (data[off] & 0x0F) * 4
        if ihl < 20 or len(data) < off + ihl:
            return None
        total = int.from_bytes(data[off + 2:off + 4], "big")
        end = min(len(data), off + total) if total >= ihl else len(data)
        frag = int.from_bytes(data[off + 6:off + 8], "big")
        if frag & 0x1FFF:               # a non-first fragment has no UDP header
            return None
        return data[off + 9], data[off + ihl:end]
    if version == 6:
        if len(data) < off + 40:
            return None
        proto = data[off + 6]
        plen = int.from_bytes(data[off + 4:off + 6], "big")
        end = min(len(data), off + 40 + plen) if plen else len(data)
        return proto, data[off + 40:end]
    return None


def _l3(frame: bytes, linktype: int):
    """``(protocol, payload)`` after a supported link layer, else None."""
    if linktype == 1:                                   # Ethernet II (+ VLAN)
        if len(frame) < 14:
            return None
        etype = int.from_bytes(frame[12:14], "big")
        off = 14
        while etype in (0x8100, 0x88A8, 0x9100):
            if len(frame) < off + 4:
                return None
            etype = int.from_bytes(frame[off + 2:off + 4], "big")
            off += 4
        if etype not in (0x0800, 0x86DD):
            return None
        return _parse_ip(frame, off)
    if linktype == 101:                                 # raw IP
        return _parse_ip(frame, 0)
    if linktype == 113:                                 # Linux cooked v1
        if len(frame) < 16:
            return None
        return _parse_ip(frame, 16) if int.from_bytes(frame[14:16], "big") in (0x0800, 0x86DD) else None
    if linktype == 276:                                 # Linux cooked v2
        if len(frame) < 20:
            return None
        return _parse_ip(frame, 20) if int.from_bytes(frame[0:2], "big") in (0x0800, 0x86DD) else None
    return None


def udp_datagram(frame: bytes, linktype: int = 1):
    """``(src port, dst port, payload)`` for a UDP frame, else None."""
    parsed = _l3(frame, linktype)
    if not parsed or parsed[0] != 17:
        return None
    data = parsed[1]
    if len(data) < 8:
        return None
    sport, dport, length = int.from_bytes(data[0:2], "big"), \
        int.from_bytes(data[2:4], "big"), int.from_bytes(data[4:6], "big")
    if length < 8:
        return None
    return sport, dport, data[8:min(len(data), length)]


def tcp_segment(frame: bytes, linktype: int = 1):
    """``(src port, dst port, payload)`` for a TCP frame, else None."""
    parsed = _l3(frame, linktype)
    if not parsed or parsed[0] != 6:
        return None
    data = parsed[1]
    if len(data) < 20:
        return None
    off = (data[12] >> 4) * 4
    if off < 20 or len(data) < off:
        return None
    return int.from_bytes(data[0:2], "big"), int.from_bytes(data[2:4], "big"), data[off:]


def rtp_packet(data: bytes) -> RtpPacket | None:
    """Parse one RTP datagram (RFC 3550), or None when it is not RTP."""
    if len(data) < 12 or data[0] >> 6 != 2:
        return None
    csrc = data[0] & 0x0F
    off = 12 + csrc * 4
    if len(data) < off:
        return None
    if data[0] & 0x10:                          # header extension
        if len(data) < off + 4:
            return None
        words = int.from_bytes(data[off + 2:off + 4], "big")
        off += 4 + words * 4
        if len(data) < off:
            return None
    end = len(data)
    if data[0] & 0x20:                          # padding
        pad = data[-1]
        if pad == 0 or pad > end - off:
            return None
        end -= pad
    if end <= off:
        return None
    return RtpPacket(
        seq=int.from_bytes(data[2:4], "big"),
        timestamp=int.from_bytes(data[4:8], "big"),
        marker=bool(data[1] & 0x80),
        payload_type=data[1] & 0x7F,
        ssrc=int.from_bytes(data[8:12], "big"),
        payload=data[off:end],
    )


def parse_sdp(text: str) -> set[int]:
    """H.264 payload types declared by an SDP (RTSP ``DESCRIBE`` response)."""
    pts: set[int] = set()
    media = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("m="):
            parts = line[2:].split()
            media = parts[0] if parts else ""
        elif line.startswith("a=rtpmap:") and media == "video":
            spec = line[len("a=rtpmap:"):]
            pt, _, enc = spec.partition(" ")
            if pt.isdigit() and enc.split("/", 1)[0].upper() in ("H264", "H264-RCDO"):
                pts.add(int(pt))
    return pts


# ---------------------------------------------------------------------------
# H.264 depacketisation (RFC 6184)
# ---------------------------------------------------------------------------

def _looks_like_h264(payload: bytes) -> bool:
    """A payload whose NAL header is plausible: single NAL, STAP-A or FU-A."""
    if not payload:
        return False
    nal_type = payload[0] & 0x1F
    if nal_type == 28:
        return len(payload) >= 3 and 1 <= (payload[1] & 0x1F) <= 23
    if nal_type in (24, 25):
        return len(payload) >= 3
    return nal_type in (1, 5, 6, 7, 8, 9)


def _stream_is_h264(packets: list[RtpPacket], sdp_pts: set[int]) -> bool:
    """Reject a dynamic payload type that only looks like H.264 by chance."""
    if len(packets) < 2:
        return False
    declared = any(p.payload_type in sdp_pts for p in packets)
    valid = sum(_looks_like_h264(p.payload) for p in packets)
    if not declared and valid < 0.8 * len(packets):
        return False
    types = [p.payload[0] & 0x1F for p in packets if p.payload]
    return bool({7, 8, 24, 28} & set(types)) or \
        sum(t in (1, 5) for t in types) >= 5


def order_packets(packets: list[RtpPacket]) -> list[RtpPacket]:
    """Deduplicate by sequence number and sort across any number of 16-bit wraps.

    The sequence is unwrapped in arrival order: each arrival adds its signed
    distance from the previous one to a 32-bit extended counter, so a wrap at
    65535 and captures longer than 32768 packets keep their real order. Duplicate
    sequence numbers (retransmissions) keep their first arrival.
    """
    uniq: dict[int, RtpPacket] = {}
    last_seq: int | None = None
    last_ext = 0
    for p in packets:
        if last_seq is None:
            ext = p.seq
        else:
            ext = last_ext + (((p.seq - last_seq + 32768) & 0xFFFF) - 32768)
        last_seq, last_ext = p.seq, ext
        uniq.setdefault(ext, p)          # a retransmission repeats its seq
    return [uniq[ext] for ext in sorted(uniq)]


def _stap_nals(payload: bytes, off: int) -> list[bytes]:
    """NAL units inside a STAP-A (off=1) / STAP-B (off=3, skips the DON)."""
    nals: list[bytes] = []
    while off + 2 <= len(payload):
        size = int.from_bytes(payload[off:off + 2], "big")
        off += 2
        if size == 0 or off + size > len(payload):
            break
        nals.append(payload[off:off + size])
        off += size
    return nals


def _emit(out: bytearray, nal: bytes, max_bytes: int) -> bool:
    if not nal or len(out) + 4 + len(nal) > max_bytes:
        return False
    out += b"\x00\x00\x00\x01" + nal
    return True


def depacketize_h264(packets: list[RtpPacket],
                     max_bytes: int = MAX_STREAM_BYTES) -> bytes:
    """Annex B (``00 00 00 01`` start codes) from the RTP H.264 payloads.

    Handles single NAL units, STAP-A/STAP-B and FU-A. The output is capped on
    NAL boundaries, so a truncated stream is still a valid Annex B file.
    """
    out = bytearray()
    fu: bytearray | None = None
    fu_next: int | None = None
    for pkt in order_packets(packets):
        payload = pkt.payload
        if fu is not None and pkt.seq != fu_next:
            fu = None                              # sequence gap: drop the partial NAL
            fu_next = None
        if not payload:
            continue
        nal_type = payload[0] & 0x1F
        if 1 <= nal_type <= 23:
            if not _emit(out, payload, max_bytes):
                break
        elif nal_type == 24:                       # STAP-A
            for nal in _stap_nals(payload, 1):
                if not _emit(out, nal, max_bytes):
                    return bytes(out)
        elif nal_type == 25:                       # STAP-B (2-byte DON first)
            for nal in _stap_nals(payload, 3):
                if not _emit(out, nal, max_bytes):
                    return bytes(out)
        elif nal_type == 28 and len(payload) >= 3:  # FU-A
            fu_header = payload[1]
            start, end = bool(fu_header & 0x80), bool(fu_header & 0x40)
            inner = fu_header & 0x1F
            if not 1 <= inner <= 23:
                continue
            if start:
                fu = bytearray([(payload[0] & 0xE0) | inner])
            elif fu is None:
                continue                            # lost the fragment that started it
            if fu is not None:
                fu += payload[2:]
                fu_next = (pkt.seq + 1) & 0xFFFF
            if end and fu is not None:
                if not _emit(out, bytes(fu), max_bytes):
                    return bytes(out)
                fu = None
                fu_next = None
    return bytes(out)


# ---------------------------------------------------------------------------
# capture scan
# ---------------------------------------------------------------------------

def parse_capture(path: Path, max_packets: int = MAX_SCAN_PACKETS,
                  max_bytes: int = MAX_STREAM_BYTES,
                  max_total: int | None = None,
                  max_ssrcs: int | None = None) -> CaptureScan:
    """Read RTP candidate packets from a pcap and parse the RTSP SDP.

    Only UDP/RTP packets whose payload type is declared H.264 in the SDP or
    whose payload holds a plausible H.264 NAL header are kept, grouped by SSRC.
    ``max_bytes`` caps one stream, ``max_total`` caps all streams together and
    ``max_ssrcs`` caps the number of candidate SSRCs; both are checked before
    the payload is retained.
    """
    if max_total is None:
        max_total = MAX_TOTAL_BYTES
    if max_ssrcs is None:
        max_ssrcs = MAX_SSRCS
    scan = CaptureScan()
    sdp_text = ""
    used: dict[int, int] = {}
    total = 0
    for linktype, frame in _iter_frames(path, max_packets):
        scan.packets += 1
        seg = tcp_segment(frame, linktype)
        if seg:
            sport, dport, data = seg
            if data and (554 in (sport, dport) or data.startswith(_RTSP_STARTS)):
                if len(sdp_text) < MAX_SDP_BYTES:
                    sdp_text += data[:MAX_SDP_BYTES - len(sdp_text)].decode("latin-1", "replace")
                    scan.sdp_pts |= parse_sdp(sdp_text)
            continue
        dgram = udp_datagram(frame, linktype)
        if not dgram:
            continue
        pkt = rtp_packet(dgram[2])
        if pkt is None:
            continue
        if not (pkt.payload_type in scan.sdp_pts
                or (pkt.payload_type >= 96 and _looks_like_h264(pkt.payload))):
            continue
        scan.rtp_packets += 1
        if pkt.ssrc not in scan.streams:
            if len(scan.streams) >= max_ssrcs:
                continue
            scan.streams[pkt.ssrc] = []
        stream = scan.streams[pkt.ssrc]
        if len(stream) >= MAX_STREAM_PACKETS:
            continue
        if used.get(pkt.ssrc, 0) + len(pkt.payload) > max_bytes:
            continue
        if total + len(pkt.payload) > max_total:
            continue
        used[pkt.ssrc] = used.get(pkt.ssrc, 0) + len(pkt.payload)
        total += len(pkt.payload)
        stream.append(pkt)
    return scan


def video_streams(scan: CaptureScan) -> list[tuple[int, list[RtpPacket]]]:
    """H.264 streams, largest first, capped at ``MAX_STREAMS_OUT``."""
    found = [(ssrc, pkts) for ssrc, pkts in scan.streams.items()
             if _stream_is_h264(pkts, scan.sdp_pts)]
    found.sort(key=lambda item: sum(len(p.payload) for p in item[1]), reverse=True)
    return found[:MAX_STREAMS_OUT]


# ---------------------------------------------------------------------------
# analyzer
# ---------------------------------------------------------------------------

def _extract_frames(ctx: ToolContext, raw: Path, limit: int,
                    deadline: float) -> tuple[list[Path], Path | None]:
    """Convert the Annex B stream to MP4 and extract a few frames.

    ``deadline`` is the single wall-clock deadline shared by every external
    command of the analysis: no ffmpeg call starts once it has passed.
    """
    if limit <= 0 or not which("ffmpeg"):
        return [], None

    def remaining() -> float:
        return deadline - _now()

    left = remaining()
    if left <= 0:
        return [], None
    mp4 = raw.with_suffix(".mp4")
    ctx.run(["ffmpeg", "-y", "-loglevel", "error", "-fflags", "+genpts", "-r", "25",
             "-i", str(raw), "-c", "copy", str(mp4)],
            timeout=min(FFMPEG_CALL_TIMEOUT_S, max(1, int(left))))
    left = remaining()
    if left <= 0:
        return [], mp4 if mp4.exists() else None
    src = mp4 if mp4.exists() and mp4.stat().st_size > 0 else raw
    pattern = raw.parent / f"{raw.stem}_frame_%03d.png"
    ctx.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(src), "-vf",
             f"fps=1/{FRAME_INTERVAL_S}", "-frames:v", str(limit), str(pattern)],
            timeout=min(FFMPEG_CALL_TIMEOUT_S, max(1, int(left))))
    frames = sorted(raw.parent.glob(f"{raw.stem}_frame_*.png"))[:limit]
    return frames, mp4 if mp4.exists() else None


class RtpAnalyzer(Analyzer):
    name = "rtp"
    category = "network"
    description = "Reassemble H.264 video carried in RTP/RTSP (FU-A/STAP-A) and extract frames."
    accepts = PCAP_EXT
    display_order = 263

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            with ctx.input.open("rb") as fh:
                magic = fh.read(4)
        except OSError:
            return ToolResult(self.name, status="skipped", summary="capture unreadable")
        if magic == _PCAPNG_MAGIC:
            return ToolResult(self.name, status="skipped", summary="pcapng not supported")
        if magic not in _PCAP_MAGICS:
            return ToolResult(self.name, status="skipped", summary="not a pcap")
        # Presence gate: the whole capture is walked (bounded by the scan
        # packet limit) with only a small payload budget, so RTP that starts
        # late is still found while a capture without RTP stops before the
        # heavier full scan.
        gate = parse_capture(ctx.input, max_packets=MAX_SCAN_PACKETS,
                             max_bytes=GATE_BYTES, max_total=GATE_BYTES)
        if not video_streams(gate):
            return ToolResult(self.name, status="skipped", summary="no RTP/H.264 stream")
        del gate
        scan = parse_capture(ctx.input)
        streams = video_streams(scan)
        if not streams:
            return ToolResult(self.name, status="skipped", summary="no RTP/H.264 stream")
        deadline = _now() + FFMPEG_BUDGET_S

        outdir = ctx.sub(self.name)
        artifacts: list[dict] = []
        extracted: list[str] = []
        parts: list[str] = []
        frames_total = 0
        written = 0
        for idx, (ssrc, packets) in enumerate(streams):
            data = depacketize_h264(packets)
            if len(data) < MIN_ANNEXB:
                parts.append(f"[ssrc {ssrc:08x}] too little H.264 data ({len(data)} B)")
                continue
            raw = outdir / f"stream{idx}_ssrc{ssrc:08x}.264"
            raw.write_bytes(data)
            written += 1
            artifacts.append({"name": raw.name, "path": str(raw), "size": len(data)})
            nals = data.count(b"\x00\x00\x00\x01")
            parts.append(f"ssrc {ssrc:08x}: {len(packets)} RTP packets, "
                         f"{nals} NAL, {len(data)} B")
            frames, mp4 = _extract_frames(ctx, raw, MAX_FRAMES - frames_total, deadline)
            if mp4:
                artifacts.append({"name": mp4.name, "path": str(mp4),
                                  "size": mp4.stat().st_size})
            for frame in frames:
                extracted.append(str(frame))
                artifacts.append({"name": frame.name, "path": str(frame),
                                  "size": frame.stat().st_size})
            frames_total += len(frames)
            parts.append(f"  -> {len(frames)} frame(s)")
        if not written:
            return ToolResult(self.name, status="skipped", summary="no H.264 NAL units")
        if not which("ffmpeg"):
            parts.append("ffmpeg not installed: only the .264 stream was written")
        return ToolResult(
            self.name, status="done", output="\n".join(parts),
            summary=(f"{written} H.264 stream(s), {scan.rtp_packets} RTP packet(s), "
                     f"{frames_total} frame(s)"),
            extracted=extracted, artifacts=artifacts,
        )


register(RtpAnalyzer())
