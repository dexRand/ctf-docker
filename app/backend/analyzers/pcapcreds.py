"""Plaintext credentials in a capture: FTP, Telnet, HTTP Basic, POP3, IMAP, SMTP.

Classic forensics challenges ship a capture of somebody logging in ("shark on
wire"): the flag is the password, or the password opens the next stage. One
tshark pass reads the dissector fields of every cleartext session; the
credentials are then paired (USER/PASS, AUTH LOGIN) and printed as
``proto  src -> dst  user:password``.

Only cleartext protocols are handled: TLS sessions need the key, which the
`pcap` analyzer already uses when a key/keylog file ships next to the capture.
"""
from __future__ import annotations

import base64
import binascii
import re

from .base import Analyzer, ToolContext, ToolResult, which
from .registry import register
from .usbhid import PCAP_EXT, link_types

# link types where a cleartext application protocol can be dissected: Ethernet,
# BSD loopback/NULL, raw IP (12/101), Linux SLL/SLL2, IPv4/IPv6
CLEARTEXT_LINK_TYPES = {0, 1, 12, 101, 113, 228, 229, 276}

_FIELDS = [
    "frame.protocols", "ip.src", "ip.dst", "tcp.stream", "tcp.srcport", "tcp.dstport",
    "ftp.request.command", "ftp.request.arg",
    "telnet.data",
    "http.authbasic", "http.authorization",
    "pop.request.command", "pop.request.parameter",
    "imap.request",
    "smtp.req.command", "smtp.req.parameter",
    "smtp.auth.username", "smtp.auth.password",
]
_FILTER = ("ftp.request || telnet || http.authorization || pop.request || "
           "imap.request || smtp")
_MAX_LINES = 200
_MAX_TEXT = 200_000

_USER_PROMPT = re.compile(r"(?i)\b(?:login|user(?:name)?|account)\s*:\s*$")
_PASS_PROMPT = re.compile(r"(?i)\b(?:password|passcode)\s*:\s*$")
_IAC = re.compile(b"\xff[\xfb-\xfe][\x00-\xff]|\xff[\xf0-\xfa]")


def _unescape_telnet(raw: str) -> str:
    """telnet.data is a byte field: tshark prints printable bytes as text and
    escapes the others (``\\r``, ``\\n``, ``\\x1b``...). Undo that, then drop the
    IAC negotiations (0xff <cmd> <option>) that a raw capture still carries."""
    out = bytearray()
    data = raw.encode("latin-1", "replace")
    i = 0
    while i < len(data):
        if data[i] == 0x5C and i + 1 < len(data):          # backslash escape
            nxt = data[i + 1]
            if nxt == ord("x") and i + 3 < len(data):
                try:
                    out.append(int(data[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            simple = {ord("r"): b"\r", ord("n"): b"\n", ord("t"): b"\t",
                      ord("\\"): b"\\"}
            if nxt in simple:
                out += simple[nxt]
                i += 2
                continue
        out.append(data[i])
        i += 1
    return _IAC.sub(b"", bytes(out)).decode("latin-1")


def _decode_token(token: str) -> str | None:
    """A base64 credential field (SMTP AUTH LOGIN): the decoded printable text,
    or None when it is not base64. Some servers send it in clear."""
    token = token.strip()
    if not token:
        return None
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    text = raw.decode("latin-1")
    if text and all(32 <= ord(ch) < 127 for ch in text):
        return text
    return None


def _split_lines(text: str) -> list[str]:
    return [ln.strip("\x00 ") for ln in text.replace("\r", "\n").split("\n") if ln.strip("\x00 ")]


def auth_plain(token: str) -> tuple[str, str] | None:
    """``AUTH PLAIN`` payload: base64(authzid NUL authcid NUL passwd)."""
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    parts = raw.split(b"\x00")
    if len(parts) < 3:
        return None
    user = parts[-2].decode("latin-1")
    password = parts[-1].decode("latin-1")
    if not user or not password:
        return None
    return user, password


def _basic(value: str) -> str | None:
    """`Basic <base64>` -> `user:password`."""
    value = (value or "").strip()
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "basic" or not token:
        return None
    try:
        raw = base64.b64decode(token.strip() + "=" * (-len(token.strip()) % 4))
    except (binascii.Error, ValueError):
        return None
    text = raw.decode("latin-1")
    if ":" not in text or not all(32 <= ord(ch) < 127 for ch in text):
        return None
    return text


class PcapCredsAnalyzer(Analyzer):
    name = "pcap-creds"
    category = "network"
    description = "Find cleartext credentials in a capture (FTP, Telnet, HTTP Basic, POP3, IMAP, SMTP)."
    accepts = PCAP_EXT
    display_order = 264

    def run(self, ctx: ToolContext) -> ToolResult:
        # link type from the header first: a USB/Bluetooth capture is skipped
        # without any tool
        types = link_types(ctx.input)
        if types is not None and not types & CLEARTEXT_LINK_TYPES:
            return ToolResult(self.name, status="skipped",
                              summary=f"not an IP capture (link type {sorted(types)})")
        if not which("tshark"):
            return ToolResult(self.name, status="skipped", summary="tshark not installed")
        proc = ctx.run(["tshark", "-r", str(ctx.input), "-Y", _FILTER,
                        "-T", "fields", "-E", "separator=\t",
                        "-E", "aggregator=\x1f",
                        *[arg for field in _FIELDS for arg in ("-e", field)]],
                       timeout=180)
        lines = self._parse(proc.stdout or "")
        if not lines:
            return ToolResult(self.name, status="skipped", summary="no cleartext credentials")
        shown = lines[:_MAX_LINES]
        output = "\n".join(shown)[:_MAX_TEXT]
        if len(lines) > len(shown):
            output += f"\n… {len(lines) - len(shown)} more"
        return ToolResult(self.name, status="done",
                          summary=f"{len(lines)} credential(s)", output=output)

    @staticmethod
    def _parse(rows: str) -> list[str]:
        """Rows of `_FIELDS`, in capture order (tshark does the reassembly)."""
        pending: dict[str, str] = {}       # tcp.stream -> user waiting for a password
        prompts: dict[str, str] = {}       # tcp.stream -> what the server asked
        telnet: dict[str, dict] = {}       # tcp.stream -> {"src","dst","client":[]}
        found: dict[str, None] = {}        # ordered set: no duplicate lines

        def add(line: str) -> None:
            found.setdefault(line, None)

        for row in rows.splitlines():
            if not row:
                continue
            cols = (row.split("\t") + [""] * len(_FIELDS))[:len(_FIELDS)]
            (_proto, src, dst, stream, sport, dport, ftp_cmd, ftp_arg,
             tdata, authbasic, authz, pop_cmd, pop_arg, imap,
             smtp_cmd, smtp_arg, smtp_user, smtp_pass) = cols
            src, dst = src.strip(), dst.strip()
            where = f"{src} -> {dst}"

            if ftp_cmd.strip():
                cmd = ftp_cmd.strip().upper()
                if cmd == "USER":
                    pending[stream] = ftp_arg.strip()
                elif cmd == "PASS":
                    user = pending.pop(stream, "")
                    password = ftp_arg.strip()
                    if password:
                        add(f"ftp  {where}  {user + ':' if user else ''}{password}")
            if pop_cmd.strip():
                cmd = pop_cmd.strip().upper()
                if cmd == "USER":
                    pending[stream] = pop_arg.strip()
                elif cmd == "PASS":
                    user = pending.pop(stream, "")
                    password = pop_arg.strip()
                    if password:
                        add(f"pop  {where}  {user + ':' if user else ''}{password}")
            if imap.strip():
                text = imap.strip()
                parts = text.split()
                if len(parts) >= 4 and parts[1].upper() == "LOGIN":
                    add(f"imap  {where}  {parts[2]}:{parts[3]}")
                elif len(parts) >= 4 and parts[1].upper() == "AUTHENTICATE" \
                        and parts[2].upper() == "PLAIN":
                    pair = auth_plain(parts[3])
                    if pair:
                        add(f"imap  {where}  {pair[0]}:{pair[1]}")
            cred = (authbasic or "").strip()
            if not cred and authz.strip():
                cred = _basic(authz) or ""
            if cred and ":" in cred:
                add(f"http  {where}  {cred}")
            cmd = smtp_cmd.strip().upper()
            if cmd == "AUTH" and smtp_arg.strip():
                mech, _, token = smtp_arg.strip().partition(" ")
                mech = mech.upper()
                if mech == "PLAIN" and token:
                    pair = auth_plain(token.strip())
                    if pair:
                        add(f"smtp  {where}  {pair[0]}:{pair[1]}")
                elif mech == "LOGIN" and token:
                    user = _decode_token(token)
                    if user:
                        pending[stream] = user
            user = _decode_token(smtp_user)
            if user:
                pending[stream] = user
            password = _decode_token(smtp_pass)
            if password:
                login = pending.pop(stream, "")
                add(f"smtp  {where}  {login + ':' if login else ''}{password}")
            if tdata:
                state = telnet.setdefault(stream, {"src": src, "dst": dst,
                                                   "client": [], "paired": False})
                text_lines = _split_lines(_unescape_telnet(tdata.strip()))
                if str(dport) == "23":                    # the client is typing
                    for ln in text_lines:
                        state["client"].append(ln)
                        asked = prompts.get(stream, "")
                        if asked == "user":
                            pending[stream] = ln
                            prompts[stream] = ""
                        elif asked == "pass":
                            user = pending.pop(stream, "")
                            prompts[stream] = ""
                            state["paired"] = True
                            add(f"telnet  {state['src']} -> {state['dst']}  "
                                f"{user + ':' if user else ''}{ln}")
                elif text_lines:                          # server prompt
                    tail = text_lines[-1]
                    if _USER_PROMPT.search(tail):
                        prompts[stream] = "user"
                    elif _PASS_PROMPT.search(tail):
                        prompts[stream] = "pass"
        # a telnet session with no recognisable prompt: still show what was typed
        for state in telnet.values():
            typed = [ln for ln in state["client"] if ln]
            if typed and not state["paired"]:
                add(f"telnet  {state['src']} -> {state['dst']}  " + " ".join(typed)[:500])
        return list(found)


register(PcapCredsAnalyzer())
