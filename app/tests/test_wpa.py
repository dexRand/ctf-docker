"""wpa: 802.11 captures -> hashcat 22000 (gating, extraction, crack parsing)."""
from __future__ import annotations

import struct
import subprocess

from backend.analyzers import wpa as wpa_mod
from backend.analyzers.base import ToolContext
from backend.analyzers.wpa import WpaAnalyzer, _parse_show, _ssid_of

HASH = ("WPA*02*7b8c0d1e2f30415263748596a7b8c9d0*001122334455*"
        "aabbccddeeff*6d656761636f7270*39c0f1a2b3*01020077000a00")


def _pcap(path, link_type: int):
    """A capture with one interface and no packets."""
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
    return path


def test_gating_skips_an_ethernet_capture(tmp_path):
    p = _pcap(tmp_path / "eth.pcap", 1)
    r = WpaAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and "802.11" in r.summary


def test_radiotap_capture_without_handshake_is_skipped(tmp_path):
    p = _pcap(tmp_path / "wifi.pcap", 127)
    r = WpaAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and r.summary in ("no handshake",
                                                   "hcxpcapngtool not installed")


def test_ssid_is_decoded_from_the_22000_line():
    assert _ssid_of(HASH) == "megacorp"


def test_hashcat_show_lines_are_parsed():
    # mode 22000 `--show` prints MIC:MAC_AP:MAC_STA:ESSID:PASSWORD, not the raw line
    show = ("26d1570d08ed13bdc5f5cb40ca4b84c1:e4956e459024:96a3481e2f4d:"
            "joesheer:nanotechnology\nc3b0:aa:bb:ssid:pa:ss\n")
    assert _parse_show(show) == [("joesheer", "nanotechnology"), ("ssid", "pa:ss")]


def test_cracked_password_is_reported(monkeypatch, tmp_path):
    p = _pcap(tmp_path / "wifi.pcap", 127)
    monkeypatch.setattr(wpa_mod, "which", lambda name: f"/usr/bin/{name}")
    words = tmp_path / "words.txt"
    words.write_text("nanotechnology\n")
    monkeypatch.setattr(wpa_mod.cracking, "resolve_wordlists", lambda *a, **kw: [words])

    def fake_run(self, cmd, **kw):
        if "hcxpcapngtool" in cmd[0]:
            out = cmd[cmd.index("-o") + 1]
            with open(out, "w") as fh:
                fh.write(HASH + "\n")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "--show" in cmd:                     # hashcat --show
            return subprocess.CompletedProcess(
                cmd, 0, "26d1570d08ed13bdc5f5cb40ca4b84c1:e4956e459024:"
                        "96a3481e2f4d:joesheer:nanotechnology\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")   # the crack run

    monkeypatch.setattr(ToolContext, "run", fake_run)
    r = WpaAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "done"
    assert "1 hash(es), 1 cracked" in r.summary
    assert "password: nanotechnology  (joesheer)" in (r.output or "")
    assert r.artifacts and r.artifacts[0]["path"].endswith("handshake.22000")
