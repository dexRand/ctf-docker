"""WPA handshake / PMKID in an 802.11 capture: extract it and crack the phrase.

UIUCTF 2021 "CEO" ships a Wi-Fi capture: `hcxpcapngtool` converts the EAPOL or
PMKID exchange into a hashcat 22000 line, hashcat tries the small wordlists and
the passphrase is reported with the SSID it belongs to.
"""
from __future__ import annotations

import time
from pathlib import Path

from .. import cracking
from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register
from .usbhid import PCAP_EXT, link_types

WIFI_LINK_TYPES = {105, 127, 163}          # 802.11, radiotap, 802.11+AVS
_BUDGET = 120                              # seconds of hashcat, like the auto-crack


def _parse_show(show: str) -> list[tuple[str, str]]:
    """(ssid, password) from `hashcat --show`.

    For mode 22000 hashcat prints a normalised `MIC:MAC_AP:MAC_STA:ESSID:PASSWORD`
    line, not the original `WPA*02*...` one (the password may contain colons).
    """
    out: list[tuple[str, str]] = []
    for line in show.splitlines():
        parts = line.strip().split(":")
        if len(parts) < 5 or not parts[0]:
            continue
        out.append((parts[3], ":".join(parts[4:])))
    return out


def _ssid_of(line: str) -> str:
    """The SSID is the sixth `*` field of a 22000 line, hex encoded:
    WPA*02*MIC*MAC_AP*MAC_STA*ESSID*EAPOL*..."""
    parts = line.split("*")
    if len(parts) < 6:
        return ""
    try:
        return bytes.fromhex(parts[5]).decode("utf-8", "replace")
    except ValueError:
        return ""


class WpaAnalyzer(Analyzer):
    name = "wpa"
    category = "network"
    description = "WPA handshake/PMKID: extract to hashcat 22000 and crack the passphrase."
    accepts = PCAP_EXT
    display_order = 266

    def run(self, ctx: ToolContext) -> ToolResult:
        types = link_types(ctx.input)
        if types is None or not (types & WIFI_LINK_TYPES):
            return ToolResult(self.name, status="skipped", summary="not an 802.11 capture")
        tool = which("hcxpcapngtool")
        if not tool:
            return ToolResult(self.name, status="skipped", summary="hcxpcapngtool not installed")
        out = ctx.sub(self.name) / "handshake.22000"
        ctx.run([tool, "-o", str(out), str(ctx.input)], timeout=120)
        if not out.is_file():          # nothing to convert: no EAPOL/PMKID inside
            return ToolResult(self.name, status="skipped", summary="no handshake")
        lines = [ln.strip() for ln in out.read_text("utf-8", "replace").splitlines()
                 if ln.strip().startswith("WPA*")]
        if not lines:
            return ToolResult(self.name, status="skipped", summary="no handshake")
        found = self._crack(ctx, out)
        report = ["== 22000 ==", *lines]
        for ssid, pw in found:
            report.append(f"password: {pw}  ({ssid or _ssid_of(lines[0]) or '?'})")
        return ToolResult(self.name, status="done",
                          summary=f"{len(lines)} hash(es), {len(found)} cracked",
                          output="\n".join(report)[:200_000],
                          artifacts=[{"name": out.name, "path": str(out),
                                      "size": out.stat().st_size}])

    @staticmethod
    def _crack(ctx: ToolContext, hashfile: Path) -> list[tuple[str, str]]:
        # the small wordlists only, like the auto-crack: a 22000 hash on CPU is
        # far slower than an NT hash, rockyou would eat the whole project budget
        wordlists = [p for p in cracking.resolve_wordlists(
            max_bytes=cracking.AUTO_CRACK_MAX_BYTES) if p.is_file()]
        if not wordlists or not which("hashcat"):
            return []
        pot = hashfile.with_suffix(".pot")
        found: list[tuple[str, str]] = []
        deadline = time.monotonic() + _BUDGET      # one budget for all the wordlists
        for wl in sorted(wordlists, key=lambda p: p.stat().st_size):
            left = int(deadline - time.monotonic())
            if left < 5:
                break
            ctx.run(cracking.hashcat_args(22000, str(hashfile), wordlist=str(wl),
                                          potfile=str(pot), runtime=left),
                    timeout=left + 60)
            show = ctx.run(["hashcat", "-m", "22000", str(hashfile), "--show",
                            "--potfile-path", str(pot)], timeout=60)
            found = _parse_show(show.stdout or "")
            if found:
                break
        return found


register(WpaAnalyzer())
