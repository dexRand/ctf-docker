"""pcap-creds: plaintext credentials from a capture (one tshark pass).

The captures are built by hand (pcap global header + Ethernet/IPv4/TCP frames)
so the test needs neither a fixture file nor the network.
"""
from __future__ import annotations

import base64
import shutil
import struct

from backend.analyzers import pcapcreds
from backend.analyzers.base import ToolContext
from backend.analyzers.pcapcreds import PcapCredsAnalyzer

import pytest

needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"
_IP_ID = [0]   # unique IPv4 id per frame (tshark does not care, keep them distinct)


def _ip(text: str) -> bytes:
    return bytes(int(x) for x in text.split("."))


def _frame(src, dst, sport, dport, seq, ack, flags, payload, ip_id=1) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ip_id, 0x4000, 64, 6, 0,
                     _ip(src), _ip(dst))
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    frame = eth + ip + tcp + payload
    return struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame


def _conversation(cport: int, sport: int, steps):
    """SYN/SYN-ACK/ACK + payloads with consistent sequence numbers: tshark
    reassembles the stream (no gaps, no retransmissions)."""
    frames = []
    cseq, sseq = 1000, 5000
    for src, dst, sp, dp, seq, ack, flags, data in (
            (CLIENT, SERVER, cport, sport, cseq - 1, 0, 0x02, b""),
            (SERVER, CLIENT, sport, cport, sseq - 1, cseq, 0x12, b""),
            (CLIENT, SERVER, cport, sport, cseq, sseq, 0x10, b"")):
        _IP_ID[0] += 1
        frames.append(_frame(src, dst, sp, dp, seq, ack, flags, data, _IP_ID[0]))
    for who, data in steps:
        _IP_ID[0] += 1
        if who == "c":
            frames.append(_frame(CLIENT, SERVER, cport, sport, cseq, sseq, 0x18,
                                 data, _IP_ID[0]))
            cseq += len(data)
        else:
            frames.append(_frame(SERVER, CLIENT, sport, cport, sseq, cseq, 0x18,
                                 data, _IP_ID[0]))
            sseq += len(data)
    return frames


def _pcap(path, frames, link_type: int = 1):
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type)
    path.write_bytes(header + b"".join(frames))
    return path


def _run(tmp_path, p, name="w"):
    return PcapCredsAnalyzer().run(ToolContext(input=p, workdir=tmp_path / name))


@needs_tshark
def test_ftp_and_http_basic_are_reported(tmp_path):
    frames = _conversation(40000, 21, [
        ("s", b"220 hello\r\n"),
        ("c", b"USER bob\r\n"),
        ("c", b"PASS s3cr3t\r\n"),
        ("s", b"230 ok\r\n"),
    ])
    frames += _conversation(40001, 80, [
        ("c", b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic "
              + base64.b64encode(b"bob:s3cr3t") + b"\r\n\r\n"),
        ("s", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
    ])
    p = _pcap(tmp_path / "creds.pcap", frames)
    r = _run(tmp_path, p)
    assert r.status == "done"
    assert r.output.count("bob:s3cr3t") == 2
    assert "ftp" in r.output and "http" in r.output


@needs_tshark
def test_capture_without_credentials_is_skipped(tmp_path):
    frames = _conversation(40001, 80, [
        ("c", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("s", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
    ])
    p = _pcap(tmp_path / "plain.pcap", frames)
    r = _run(tmp_path, p)
    assert r.status == "skipped"


@needs_tshark
def test_telnet_prompts_are_paired(tmp_path):
    frames = _conversation(40002, 23, [
        ("s", b"login: "),
        ("c", b"root\r\n"),
        ("s", b"Password: "),
        ("c", b"toor\r\n"),
    ])
    p = _pcap(tmp_path / "telnet.pcap", frames)
    r = _run(tmp_path, p)
    assert r.status == "done"
    assert "root:toor" in r.output


@needs_tshark
def test_pop_imap_and_smtp_are_decoded(tmp_path):
    frames = _conversation(40003, 25, [
        ("s", b"220 mail ESMTP\r\n"),
        ("c", b"EHLO x\r\n"),
        ("s", b"250-AUTH PLAIN LOGIN\r\n250 ok\r\n"),
        ("c", b"AUTH PLAIN " + base64.b64encode(b"\0bob\0s3cr3t") + b"\r\n"),
        ("s", b"235 ok\r\n"),
        ("c", b"AUTH LOGIN\r\n"),
        ("s", b"334 VXNlcm5hbWU6\r\n"),
        ("c", base64.b64encode(b"alice") + b"\r\n"),
        ("s", b"334 UGFzc3dvcmQ6\r\n"),
        ("c", base64.b64encode(b"w0rth") + b"\r\n"),
        ("s", b"235 ok\r\n"),
    ])
    frames += _conversation(40004, 110, [
        ("s", b"+OK pop\r\n"),
        ("c", b"USER dave\r\n"),
        ("c", b"PASS hunter2\r\n"),
        ("s", b"+OK logged in\r\n"),
    ])
    frames += _conversation(40005, 143, [
        ("s", b"* OK imap\r\n"),
        ("c", b"a1 LOGIN erin s3cr3t\r\n"),
        ("s", b"a1 OK done\r\n"),
    ])
    p = _pcap(tmp_path / "mail.pcap", frames)
    r = _run(tmp_path, p)
    assert r.status == "done"
    assert "bob:s3cr3t" in r.output          # SMTP AUTH PLAIN
    assert "alice:w0rth" in r.output         # SMTP AUTH LOGIN
    assert "dave:hunter2" in r.output        # POP3
    assert "erin:s3cr3t" in r.output         # IMAP


def test_usb_capture_is_skipped_without_running_tshark(tmp_path):
    p = _pcap(tmp_path / "usb.pcap", [], link_type=186)
    r = _run(tmp_path, p)
    assert r.status == "skipped" and "link type" in r.summary


def test_missing_tshark_is_skipped(monkeypatch, tmp_path):
    p = _pcap(tmp_path / "creds.pcap", [])
    monkeypatch.setattr(pcapcreds, "which", lambda name: None)
    r = _run(tmp_path, p)
    assert r.status == "skipped" and "tshark" in r.summary
