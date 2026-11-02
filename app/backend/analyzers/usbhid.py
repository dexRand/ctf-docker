"""USB HID keyboard captures: turn keystroke reports into text.

A USB keyboard sends 8-byte boot-protocol reports (modifier, reserved, up to six
key codes). Challenges ship a capture of someone typing the flag, so decoding the
reports is enough — no driver or gadget needed.
"""
from __future__ import annotations

import struct
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register

PCAP_EXT = (".pcap", ".pcapng", ".cap")
# DLT/LINKTYPE values of USB captures (usbmon, USBPcap, Darwin, USB 2.0 sniffers)
USB_LINKTYPES = {186, 189, 220, 249, 266, 288, 293, 294, 295}


def link_types(path: Path, head_bytes: int = 1 << 16) -> set[int] | None:
    """Link types declared in a pcap/pcapng header (first 64 KiB only).
    None when the file is not a capture we can parse: the caller then runs tshark."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(head_bytes)
    except OSError:
        return None
    if len(head) >= 24 and head[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        return {struct.unpack_from("<I", head, 20)[0] & 0x0FFFFFFF}
    if len(head) >= 24 and head[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        return {struct.unpack_from(">I", head, 20)[0] & 0x0FFFFFFF}
    if head[:4] != b"\x0a\x0d\x0d\x0a" or len(head) < 12:
        return None
    bom = head[8:12]
    end = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
    if not end:
        return None
    types: set[int] = set()
    off = 0
    while off + 12 <= len(head):
        btype, blen = struct.unpack_from(end + "II", head, off)
        if blen < 12 or blen % 4:
            break
        if btype == 1 and off + 10 <= len(head):          # Interface Description Block
            types.add(struct.unpack_from(end + "H", head, off + 8)[0])
        elif btype in (3, 6) and types:                   # first packet: all IDBs seen
            break
        off += blen
    return types or None

# HID usage id -> (unshifted, shifted)
_KEYS = {
    0x04: ("a", "A"), 0x05: ("b", "B"), 0x06: ("c", "C"), 0x07: ("d", "D"),
    0x08: ("e", "E"), 0x09: ("f", "F"), 0x0A: ("g", "G"), 0x0B: ("h", "H"),
    0x0C: ("i", "I"), 0x0D: ("j", "J"), 0x0E: ("k", "K"), 0x0F: ("l", "L"),
    0x10: ("m", "M"), 0x11: ("n", "N"), 0x12: ("o", "O"), 0x13: ("p", "P"),
    0x14: ("q", "Q"), 0x15: ("r", "R"), 0x16: ("s", "S"), 0x17: ("t", "T"),
    0x18: ("u", "U"), 0x19: ("v", "V"), 0x1A: ("w", "W"), 0x1B: ("x", "X"),
    0x1C: ("y", "Y"), 0x1D: ("z", "Z"),
    0x1E: ("1", "!"), 0x1F: ("2", "@"), 0x20: ("3", "#"), 0x21: ("4", "$"),
    0x22: ("5", "%"), 0x23: ("6", "^"), 0x24: ("7", "&"), 0x25: ("8", "*"),
    0x26: ("9", "("), 0x27: ("0", ")"),
    0x28: ("\n", "\n"), 0x29: ("", ""), 0x2A: ("\b", "\b"), 0x2B: ("\t", "\t"),
    0x2C: (" ", " "), 0x2D: ("-", "_"), 0x2E: ("=", "+"), 0x2F: ("[", "{"),
    0x30: ("]", "}"), 0x31: ("\\", "|"), 0x32: (";", ":"), 0x33: ("'", '"'),
    0x34: ("`", "~"), 0x35: (",", "<"), 0x36: (".", ">"), 0x37: ("/", "?"),
}
_SHIFT = 0x22          # left shift (0x02) and right shift (0x20)
_SKIP = {0x00, 0x01}   # no key / rollover error

# a HID text run: printable enough to be the typed message
_MIN_CHARS = 8


def _bytes_of(report: str) -> bytes:
    """`00001a0600000000` or `00:00:1a:06:00:00:00:00` -> bytes."""
    clean = report.strip().replace(":", "").replace(" ", "")
    if len(clean) % 2 or not clean:
        return b""
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return b""


def decode_reports(reports: list[str]) -> str:
    """Decode HID boot-protocol reports into the typed text."""
    out: list[str] = []
    last: bytes | None = None
    for report in reports:
        data = _bytes_of(report)
        if len(data) < 8:
            continue
        if data == last:
            continue                       # the key is still held down
        last = data
        mod, keys = data[0], data[2:8]
        shift = bool(mod & _SHIFT)
        for code in keys:
            if code in _SKIP:
                continue
            pair = _KEYS.get(code)
            if not pair:
                continue
            ch = pair[1] if shift else pair[0]
            if ch == "\b":                     # backspace erases what was typed
                if out:
                    out.pop()
                continue
            out.append(ch)
    return "".join(out)


class UsbHidAnalyzer(Analyzer):
    name = "usb-hid"
    category = "network"
    description = "Decode USB HID keyboard reports (usbhid.data) into the typed text."
    accepts = PCAP_EXT
    display_order = 263

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("tshark"):
            return ToolResult(self.name, status="skipped", summary="tshark not installed")
        types = link_types(ctx.input)
        if types is not None and not types & USB_LINKTYPES:
            return ToolResult(self.name, status="skipped",
                              summary=f"not a USB capture (link type {sorted(types)})")
        # one pass for both fields: usbhid.data (parsed HID) wins over raw capdata
        proc = ctx.run(["tshark", "-r", str(ctx.input), "-Y", "usbhid.data || usb.capdata",
                        "-T", "fields", "-e", "usbhid.data", "-e", "usb.capdata"], timeout=180)
        hid: list[str] = []
        cap: list[str] = []
        for ln in (proc.stdout or "").splitlines():
            a, _, b = ln.partition("\t")
            if a.strip():
                hid.append(a.strip())
            elif b.strip():
                cap.append(b.strip())
        reports = hid or cap
        if not reports:
            return ToolResult(self.name, status="skipped", summary="no HID reports")
        text = decode_reports(reports)
        printable = sum(ch.isprintable() or ch in "\n\t" for ch in text)
        if len(text) < _MIN_CHARS or printable < len(text) * 0.9:
            return ToolResult(self.name, status="skipped",
                              summary=f"{len(reports)} report(s), no readable text")
        return ToolResult(self.name, status="done",
                          summary=f"{len(reports)} report(s), {len(text)} typed char(s)",
                          output=text[:200_000])


register(UsbHidAnalyzer())
