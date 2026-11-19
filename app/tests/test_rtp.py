"""RTP/H.264 reconstruction (issue #11): pcap -> Annex B -> video frames.

The capture is built by hand here (Ethernet/IPv4/UDP/RTP) so the tests need no
network and no external tool: ffmpeg is mocked or reported as missing.
"""
from __future__ import annotations

import socket
import struct
import subprocess
from pathlib import Path

from backend.analyzers import rtp
from backend.analyzers.base import ToolContext


# ---------------------------------------------------------------------------
# a minimal pcap writer
# ---------------------------------------------------------------------------

def _frame(payload: bytes, sport: int = 22000, dport: int = 59974) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton("192.168.0.105"),
                     socket.inet_aton("192.168.0.100")) + udp
    return b"\x00" * 12 + b"\x08\x00" + ip


def _rtp(pt: int, seq: int, ts: int, ssrc: int, payload: bytes,
         marker: bool = False) -> bytes:
    return struct.pack("!BBHII", 0x80, (0x80 if marker else 0) | (pt & 0x7F),
                       seq & 0xFFFF, ts, ssrc) + payload


def _pcap(frames: list[bytes], linktype: int = 1) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", i, 0, len(frame), len(frame)) + frame
    return out


def _ctx(tmp_path: Path, data: bytes) -> ToolContext:
    cap = tmp_path / "capture.pcap"
    cap.write_bytes(data)
    work = tmp_path / "work" / "1"
    work.mkdir(parents=True)
    return ToolContext(input=cap, workdir=work)


def _fua(nal_type: int, body: bytes, nri: int = 3) -> list[bytes]:
    """Split one NAL unit into FU-A payloads (without the RTP header)."""
    indicator = (nri << 5) | 28
    third = max(1, (len(body) + 2) // 3)
    parts = [body[i:i + third] for i in range(0, len(body), third)]
    out = []
    for i, part in enumerate(parts):
        fu = (0x80 if i == 0 else 0) | (0x40 if i == len(parts) - 1 else 0) | nal_type
        out.append(bytes([indicator, fu]) + part)
    return out


SPS = bytes([0x67, 0x4D, 0x00, 0x28, 0xAB, 0xCD])
PPS = bytes([0x68, 0xEE, 0x3C, 0x80])
IDR_BODY = b"IDR-PAYLOAD-" + bytes(range(64)) * 4


# ---------------------------------------------------------------------------
# packet / SDP parsing
# ---------------------------------------------------------------------------

def test_rtp_header_is_parsed_and_non_rtp_is_rejected() -> None:
    pkt = rtp.rtp_packet(_rtp(96, 7, 1234, 0x1234, b"\x65hello", marker=True))
    assert pkt is not None
    assert (pkt.payload_type, pkt.seq, pkt.timestamp, pkt.ssrc,
            pkt.marker, pkt.payload) == (96, 7, 1234, 0x1234, True, b"\x65hello")
    # version 1 is not RTP; a short buffer is not either
    assert rtp.rtp_packet(b"\x40\x60\x00\x01" + b"\x00" * 8) is None
    assert rtp.rtp_packet(b"\x80\x60") is None


def test_sdp_h264_payload_type_is_taken_from_rtpmap() -> None:
    sdp = ("v=0\nm=video 0 RTP/AVP 96\na=rtpmap:96 H264/90000\n"
           "a=fmtp:96 packetization-mode=1\n"
           "m=audio 0 RTP/AVP 0\na=rtpmap:0 PCMU/44100/1\n")
    assert rtp.parse_sdp(sdp) == {96}
    assert rtp.parse_sdp("m=video 0 RTP/AVP 97\na=rtpmap:97 H265/90000\n") == set()


def test_sequence_numbers_out_of_order_are_reordered_and_deduplicated() -> None:
    def pkt(seq: int, data: bytes) -> rtp.RtpPacket:
        return rtp.RtpPacket(seq, 0, False, 96, 1, data)

    pkts = [pkt(3, b"c"), pkt(1, b"a"), pkt(2, b"b"), pkt(2, b"DUPLICATE")]
    assert [p.payload for p in rtp.order_packets(pkts)] == [b"a", b"b", b"c"]


def test_sequence_wraparound_is_kept_in_order() -> None:
    def pkt(seq: int) -> rtp.RtpPacket:
        return rtp.RtpPacket(seq, 0, False, 96, 1, bytes([seq & 0xFF]))

    # 65535 -> 0 must not sort as 0 -> 65535
    pkts = [pkt(0), pkt(65535), pkt(1)]
    assert [p.seq for p in rtp.order_packets(pkts)] == [65535, 0, 1]


# ---------------------------------------------------------------------------
# depacketisation: NAL single, FU-A, STAP-A
# ---------------------------------------------------------------------------

def test_fua_fragments_are_reassembled_into_one_nal() -> None:
    frags = _fua(5, IDR_BODY)
    pkts = [rtp.RtpPacket(i + 1, 0, i == len(frags) - 1, 96, 9, f)
            for i, f in enumerate(frags)]
    out = rtp.depacketize_h264(pkts)
    assert out == b"\x00\x00\x00\x01" + bytes([0x65]) + IDR_BODY


def test_stap_a_is_split_into_its_nal_units() -> None:
    payload = bytes([24]) + struct.pack("!H", len(SPS)) + SPS \
        + struct.pack("!H", len(PPS)) + PPS
    out = rtp.depacketize_h264([rtp.RtpPacket(1, 0, True, 96, 2, payload)])
    assert out == b"\x00\x00\x00\x01" + SPS + b"\x00\x00\x00\x01" + PPS


def test_single_nal_packets_are_copied() -> None:
    pkts = [rtp.RtpPacket(1, 0, False, 96, 3, SPS),
            rtp.RtpPacket(2, 0, False, 96, 3, PPS),
            rtp.RtpPacket(3, 0, True, 96, 3, b"\x65" + IDR_BODY)]
    out = rtp.depacketize_h264(pkts)
    assert out.count(b"\x00\x00\x00\x01") == 3
    assert b"\x00\x00\x00\x01" + SPS in out
    assert b"\x00\x00\x00\x01" + PPS in out
    assert b"\x00\x00\x00\x01\x65" + IDR_BODY in out


def test_output_byte_cap_is_respected_on_nal_boundaries() -> None:
    pkts = [rtp.RtpPacket(i, 0, False, 96, 4, b"\x65" + b"x" * 100)
            for i in range(1, 20)]
    out = rtp.depacketize_h264(pkts, max_bytes=250)
    assert len(out) <= 250
    assert out.count(b"\x00\x00\x00\x01") == 2       # 2 * (4 + 101) = 210


# ---------------------------------------------------------------------------
# capture scan and caps
# ---------------------------------------------------------------------------

def test_pcap_without_rtp_is_skipped(tmp_path: Path) -> None:
    frames = [_frame(b"\x00\x01\x02\x03" * 4, sport=5353, dport=5353)
              for _ in range(20)]
    result = rtp.RtpAnalyzer().run(_ctx(tmp_path, _pcap(frames)))
    assert result.status == "skipped"
    assert "RTP" in result.summary or "rtp" in result.summary


def test_pcap_packet_cap_is_respected(tmp_path: Path) -> None:
    frames = [_frame(_rtp(96, i, i, 7, b"\x65" + b"x" * 100))
              for i in range(1, 40)]
    cap = tmp_path / "many.pcap"
    cap.write_bytes(_pcap(frames))
    scan = rtp.parse_capture(cap, max_packets=10)
    assert scan.packets == 10


def test_capture_payload_byte_cap_is_respected(tmp_path: Path) -> None:
    frames = [_frame(_rtp(96, i, i, 7, b"\x65" + b"x" * 100))
              for i in range(1, 40)]
    cap = tmp_path / "many.pcap"
    cap.write_bytes(_pcap(frames))
    scan = rtp.parse_capture(cap, max_bytes=250)
    kept = sum(len(p.payload) for pkts in scan.streams.values() for p in pkts)
    assert kept <= 250


# ---------------------------------------------------------------------------
# end to end
# ---------------------------------------------------------------------------

def test_analyzer_writes_annexb_child_from_fua_and_stap(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(rtp, "which", lambda _name: None)   # no ffmpeg: .264 only
    ssrc = 0x1234
    frames = []
    seq = 1
    # SPS + PPS in a STAP-A, then an IDR split into FU-A fragments, sent out of order
    stap = bytes([24]) + struct.pack("!H", len(SPS)) + SPS \
        + struct.pack("!H", len(PPS)) + PPS
    frames.append(_frame(_rtp(96, seq, 0, ssrc, stap)))
    seq += 1
    frags = []
    for frag in _fua(5, IDR_BODY):
        frags.append((seq, _rtp(96, seq, 1, ssrc, frag)))
        seq += 1
    frames += [_frame(p) for _s, p in reversed(frags)]       # arrival order scrambled
    ctx = _ctx(tmp_path, _pcap(frames))
    result = rtp.RtpAnalyzer().run(ctx)
    assert result.status == "done", result.summary
    raw = next((ctx.workdir / "rtp").glob("*.264"))
    data = raw.read_bytes()
    assert data.startswith(b"\x00\x00\x00\x01" + SPS)
    assert b"\x00\x00\x00\x01" + PPS in data
    assert b"\x00\x00\x00\x01\x65" + IDR_BODY in data
    assert any(a["name"].endswith(".264") for a in result.artifacts)


def test_analyzer_returns_extracted_frames(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(rtp, "which", lambda _name: "/usr/bin/ffmpeg")

    def fake_run(cmd, timeout=300, cwd=None, env=None):
        cmd = [str(c) for c in cmd]
        if "-vf" in cmd:                       # frame extraction: more than the cap
            pattern = Path(cmd[-1])
            pattern.parent.mkdir(parents=True, exist_ok=True)
            for i in range(1, 6):
                p = pattern.parent / pattern.name.replace("%03d", f"{i:03d}")
                p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
        else:                                  # .264 -> .mp4
            Path(cmd[-1]).write_bytes(b"\x00\x00\x00\x18ftypmp42")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    frames = [_frame(_rtp(96, 1, 0, 5, SPS)),
              _frame(_rtp(96, 2, 0, 5, b"\x65" + IDR_BODY))]
    ctx = _ctx(tmp_path, _pcap(frames))
    monkeypatch.setattr(ctx, "run", fake_run)
    result = rtp.RtpAnalyzer().run(ctx)
    assert result.status == "done", result.summary
    assert len(result.extracted) == rtp.MAX_FRAMES   # cap respected
    assert all(p.endswith(".png") for p in result.extracted)
    assert all(Path(p).is_file() for p in result.extracted)


# ---------------------------------------------------------------------------
# issue #26: ordering past 32768, late RTP, caps, deadline, FU-A gaps
# ---------------------------------------------------------------------------

def test_order_packets_keeps_40000_in_order_packets_in_order() -> None:
    pkts = [rtp.RtpPacket(seq, 0, False, 96, 1, b"") for seq in range(40000)]
    assert [p.seq for p in rtp.order_packets(pkts)] == list(range(40000))


def test_order_packets_unwraps_a_real_wrap_mid_stream() -> None:
    # cross 65535 -> 0 and keep going for more than 32k packets: a signed
    # distance from the first packet wraps and mis-sorts this.
    seqs = list(range(65500, 65536)) + list(range(40000))
    pkts = [rtp.RtpPacket(seq, 0, False, 96, 1, b"") for seq in seqs]
    assert [p.seq for p in rtp.order_packets(pkts)] == seqs


def test_rtp_after_the_old_gate_window_is_still_found(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(rtp, "which", lambda _name: None)   # no ffmpeg: .264 only
    frames = [_frame(b"\x00\x01\x02\x03" * 4, sport=5353, dport=5353)
              for _ in range(6000)]
    frames += [_frame(_rtp(96, 1, 0, 0x77, SPS)),
               _frame(_rtp(96, 2, 0, 0x77, PPS)),
               _frame(_rtp(96, 3, 0, 0x77, b"\x65" + IDR_BODY))]
    result = rtp.RtpAnalyzer().run(_ctx(tmp_path, _pcap(frames)))
    assert result.status == "done", result.summary


def _many_ssrc_frames(n_ssrc: int, per_ssrc: int = 20) -> list[bytes]:
    return [_frame(_rtp(96, seq, seq, ssrc, b"\x65" + b"x" * 99))
            for ssrc in range(n_ssrc) for seq in range(1, per_ssrc + 1)]


def test_global_byte_budget_across_ssrcs_is_enforced(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(rtp, "MAX_TOTAL_BYTES", 500, raising=False)
    monkeypatch.setattr(rtp, "MAX_SSRCS", 100, raising=False)
    cap = tmp_path / "many-ssrc.pcap"
    cap.write_bytes(_pcap(_many_ssrc_frames(10)))
    scan = rtp.parse_capture(cap)
    kept = sum(len(p.payload) for pkts in scan.streams.values() for p in pkts)
    assert kept <= 500


def test_number_of_ssrc_candidates_is_capped(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(rtp, "MAX_SSRCS", 3, raising=False)
    monkeypatch.setattr(rtp, "MAX_TOTAL_BYTES", 10 << 20, raising=False)
    cap = tmp_path / "many-ssrc.pcap"
    cap.write_bytes(_pcap(_many_ssrc_frames(10)))
    scan = rtp.parse_capture(cap)
    assert len(scan.streams) <= 3


def test_external_work_stops_at_one_total_deadline(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(rtp, "which", lambda _name: "/usr/bin/ffmpeg")
    clock = {"now": 0.0}
    monkeypatch.setattr(rtp, "_now", lambda: clock["now"], raising=False)
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=300, cwd=None, env=None):
        calls.append([str(c) for c in cmd])
        clock["now"] += rtp.FFMPEG_BUDGET_S + 1   # the first call burns the budget
        return subprocess.CompletedProcess(cmd, 0, "", "")

    frames = []
    for ssrc in (1, 2):
        frames += [_frame(_rtp(96, 1, 0, ssrc, SPS)),
                   _frame(_rtp(96, 2, 0, ssrc, PPS)),
                   _frame(_rtp(96, 3, 0, ssrc, b"\x65" + IDR_BODY))]
    ctx = _ctx(tmp_path, _pcap(frames))
    monkeypatch.setattr(ctx, "run", fake_run)
    result = rtp.RtpAnalyzer().run(ctx)
    assert result.status == "done", result.summary
    assert len(calls) == 1                    # no ffmpeg after the deadline


def test_fua_with_a_lost_middle_fragment_is_dropped() -> None:
    frags = _fua(5, IDR_BODY)
    assert len(frags) >= 3
    pkts = [rtp.RtpPacket(1, 0, False, 96, 9, frags[0]),
            rtp.RtpPacket(3, 0, True, 96, 9, frags[-1])]   # seq 2 is lost
    out = rtp.depacketize_h264(pkts)
    assert out == b""                          # no half-reassembled NAL emitted
