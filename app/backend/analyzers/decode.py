"""Nested-encoding decoder (mini-Ciphey): base64/32/58/62/85/91/45, hex,
binary, rot13 and the other Caesar shifts, Atbash, A1Z26, url, quoted-printable,
uuencode, Brainfuck/Ook!. The brute-forced ciphers (Caesar, Atbash) only keep a
result that contains a known flag prefix, so they add no noise."""
from __future__ import annotations

import base64
import binascii
import codecs
import quopri
import re
import string
import urllib.parse

from ..flagpatterns import FLAG_PREFIXES
from .base import Analyzer, ToolContext, ToolResult
from .registry import register
from .util import TEXT_EXT

_KNOWN = re.compile(r"(?i)(" + "|".join(re.escape(p) for p in FLAG_PREFIXES) + r")\{")
_SMALL = 64 << 10            # brute-forced ciphers only on short texts
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
_B91 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")
_B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_BF_STEPS = 2_000_000


def _base_n(text: str, alphabet: str) -> bytes:
    """Big-integer base-N decoding (base58/base62), leading zero digits kept."""
    n = 0
    for ch in text:
        n = n * len(alphabet) + alphabet.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(text) - len(text.lstrip(alphabet[0]))
    return b"\x00" * pad + raw


def _base91(text: str) -> bytes:
    v, b, n, out = -1, 0, 0, bytearray()
    for ch in text:
        c = _B91.find(ch)
        if c < 0:
            raise ValueError(ch)
        if v < 0:
            v = c
            continue
        v += c * 91
        b |= v << n
        n += 13 if (v & 8191) > 88 else 14
        while n > 7:
            out.append(b & 255)
            b >>= 8
            n -= 8
        v = -1
    if v + 1:
        out.append((b | v << n) & 255)
    return bytes(out)


def _base45(text: str) -> bytes:
    vals = [_B45.index(c) for c in text]
    out = bytearray()
    for i in range(0, len(vals), 3):
        chunk = vals[i:i + 3]
        if len(chunk) == 3:
            n = chunk[0] + chunk[1] * 45 + chunk[2] * 2025
            if n > 0xFFFF:
                raise ValueError("base45")
            out += bytes((n >> 8, n & 255))
        elif len(chunk) == 2:
            n = chunk[0] + chunk[1] * 45
            if n > 0xFF:
                raise ValueError("base45")
            out.append(n)
        else:
            raise ValueError("base45")
    return bytes(out)


def _caesar_shifts(text: str) -> dict[str, bytes]:
    """Every Caesar shift (rot13 excluded: it has its own entry) that reveals a
    known flag prefix. str.translate keeps 25 passes cheap on a short text."""
    out: dict[str, bytes] = {}
    low, up = string.ascii_lowercase, string.ascii_uppercase
    for k in range(1, 26):
        if k == 13:
            continue
        table = str.maketrans(low + up, low[k:] + low[:k] + up[k:] + up[:k])
        t = text.translate(table)
        if _KNOWN.search(t):
            out[f"caesar{k}"] = t.encode()
    atbash = text.translate(str.maketrans(low + up, low[::-1] + up[::-1]))
    if _KNOWN.search(atbash):
        out["atbash"] = atbash.encode()
    return out


def _brainfuck(code: str, steps: int = _BF_STEPS) -> bytes:
    prog = [c for c in code if c in "+-<>[].,"]
    jump, stack = {}, []
    for i, c in enumerate(prog):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                raise ValueError("unbalanced")
            j = stack.pop()
            jump[i], jump[j] = j, i
    if stack:
        raise ValueError("unbalanced")
    tape, ptr, pc, out = bytearray(30000), 0, 0, bytearray()
    while pc < len(prog) and steps:
        c = prog[pc]
        if c == "+":
            tape[ptr] = (tape[ptr] + 1) & 255
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 255
        elif c == ">":
            ptr = (ptr + 1) % 30000
        elif c == "<":
            ptr = (ptr - 1) % 30000
        elif c == ".":
            out.append(tape[ptr])
        elif c == "[" and not tape[ptr]:
            pc = jump[pc]
        elif c == "]" and tape[ptr]:
            pc = jump[pc]
        pc += 1
        steps -= 1
    return bytes(out)


_OOK = {("Ook.", "Ook?"): ">", ("Ook?", "Ook."): "<", ("Ook.", "Ook."): "+",
        ("Ook!", "Ook!"): "-", ("Ook!", "Ook."): ".", ("Ook.", "Ook!"): ",",
        ("Ook!", "Ook?"): "[", ("Ook?", "Ook!"): "]"}


def _esolang(text: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    ook = re.findall(r"Ook[.?!]", text)
    if len(ook) >= 16 and len(ook) % 2 == 0:
        code = "".join(_OOK.get((ook[i], ook[i + 1]), "") for i in range(0, len(ook), 2))
        try:
            d = _brainfuck(code)
            if _ok(d):
                out["ook"] = d
        except Exception:
            pass
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) >= 16 and sum(c in "+-<>[].," for c in stripped) >= 0.95 * len(stripped):
        try:
            d = _brainfuck(stripped)
            if _ok(d):
                out["brainfuck"] = d
        except Exception:
            pass
    return out



def _ok(b: bytes, thr: float = 0.9) -> bool:
    if not b or len(b) > 2_000_000:
        return False
    text = b.decode("utf-8", "replace")
    good = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t")
    return good / max(1, len(text)) >= thr


def candidates(data: bytes) -> dict[str, bytes]:
    s = data.strip()
    out: dict[str, bytes] = {}
    compact = re.sub(rb"\s+", b"", s)
    for name, fn in (
        ("base64", lambda: base64.b64decode(compact, validate=True)),
        ("base32", lambda: base64.b32decode(compact.upper(), casefold=True)),
        ("base85", lambda: base64.b85decode(compact)),
    ):
        try:
            d = fn()
            if _ok(d):
                out[name] = d
        except Exception:
            pass
    # every byte with the high bit set (`c | 0x80`, LA CTF "extended"): strip it
    if len(s) >= 4 and sum(b >= 0x80 for b in s) >= 0.8 * len(s):
        d = bytes(b & 0x7F for b in s)
        if _ok(d):
            out["high-bit"] = d
    h = re.sub(rb"[^0-9a-fA-F]", b"", s)
    if len(h) >= 4 and len(h) % 2 == 0:
        try:
            d = bytes.fromhex(h.decode())
            if _ok(d):
                out["hex"] = d
        except Exception:
            pass
    b = re.sub(rb"[^01]", b"", s)
    if len(b) >= 8 and len(b) % 8 == 0:
        try:
            d = bytes(int(b[i:i + 8], 2) for i in range(0, len(b), 8))
            if _ok(d):
                out["binary"] = d
        except Exception:
            pass
    # "0x30"/"0x31" tokens -> '0'/'1' binary string (the Dashed challenge chain)
    if re.search(rb"0[xX]3[01]", s):
        mapped = re.sub(rb"0[xX]3([01])", lambda m: b"0" if m.group(1) == b"0" else b"1", s)
        mapped = re.sub(rb"[^01]", b"", mapped)
        if mapped and len(mapped) % 8 == 0:
            try:
                d = bytes(int(mapped[i:i + 8], 2) for i in range(0, len(mapped), 8))
                if _ok(d):
                    out["hexascii"] = d
            except Exception:
                pass
    text0 = s.decode("utf-8", "replace")
    tok = compact.decode("latin-1")
    for name, alphabet, fn in (("base58", _B58, lambda: _base_n(tok, _B58)),
                               ("base62", _B62, lambda: _base_n(tok, _B62)),
                               ("base91", _B91, lambda: _base91(tok)),
                               ("base45", _B45, lambda: _base45(s.decode("latin-1")))):
        src = s.decode("latin-1") if name == "base45" else tok
        cap = 4096 if name in ("base58", "base62") else _SMALL   # big-int decoding is O(n^2)
        if len(src) < 6 or len(src) > cap or any(c not in alphabet for c in src):
            continue
        try:
            d = fn()
            if _ok(d):
                out[name] = d
        except Exception:
            pass
    if b"=" in s and re.search(rb"=[0-9A-F]{2}", s):
        try:
            d = quopri.decodestring(s)
            if d != s and _ok(d):
                out["quoted-printable"] = d
        except Exception:
            pass
    m = re.search(rb"^begin [0-7]{3} \S+\r?\n(.*?)^end", s, re.S | re.M)
    if m:
        try:
            d = b"".join(binascii.a2b_uu(ln) for ln in m.group(1).splitlines() if ln.strip())
            if _ok(d):
                out["uuencode"] = d
        except Exception:
            pass
    nums = re.findall(rb"\d+", s)
    if len(nums) >= 6 and all(1 <= int(x) <= 26 for x in nums) \
            and not re.sub(rb"[\d\s,.;:/-]", b"", s):
        out["a1z26"] = bytes(96 + int(x) for x in nums)
    if len(text0) <= _SMALL:
        out.update(_caesar_shifts(text0))
        out.update(_esolang(text0))
    t = codecs.encode(s.decode("utf-8", "replace"), "rot13").encode()
    if t != s and _ok(t, 0.8):
        out["rot13"] = t
    # characters drawn in ASCII-art boxes: "( p ) ( i ) ( c ) ..." -> "pico..."
    # (the flag is often split across several boxed rows with art between them,
    # so collect every single-char box in the text and require a brace)
    text = s.decode("utf-8", "replace")
    boxed = re.findall(r"\(\s*([^)\s])\s*\)", text)
    if len(boxed) >= 8:
        joined = "".join(boxed).encode()
        if _ok(joined) and b"{" in joined and b"}" in joined:
            out["boxed"] = joined
    try:
        u = urllib.parse.unquote(s.decode("utf-8", "replace")).encode()
        if u != s and _ok(u, 0.8):
            out["url"] = u
    except Exception:
        pass
    return out


def chain(data: bytes, depth: int = 5) -> list[str]:
    """BFS over decoders; returns printable layers found ('path: text')."""
    seen: set[bytes] = {data}
    frontier: list[tuple[bytes, str]] = [(data, "")]
    lines: list[str] = []
    for _ in range(depth):
        nxt: list[tuple[bytes, str]] = []
        for data2, path in frontier:
            for enc, out in candidates(data2).items():
                if out in seen:
                    continue
                seen.add(out)
                lines.append(f"[{path}{enc}] {out[:400].decode('utf-8', 'replace').strip()}")
                nxt.append((out, f"{path}{enc}>"))
        frontier = nxt
        if not frontier:
            break
    return lines


class DecodeAnalyzer(Analyzer):
    name = "decode"
    category = "text"
    description = ("Try nested encodings (base64/32/58/62/85/91/45, hex, binary, Caesar/rot13, "
                   "Atbash, A1Z26, url, quoted-printable, uuencode, Brainfuck/Ook!).")
    accepts = TEXT_EXT
    display_order = 125

    def run(self, ctx: ToolContext) -> ToolResult:
        with open(ctx.input, "rb") as fh:   # encoded text is small; don't load huge files
            lines = chain(fh.read(2_000_000))
        return ToolResult(self.name, status="done", output="\n".join(lines[:300]),
                          summary=f"{len(lines)} decode(s)")


register(DecodeAnalyzer())
