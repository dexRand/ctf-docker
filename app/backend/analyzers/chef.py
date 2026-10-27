"""Chef esolang: a recipe whose two unknown quantities hide a flag.

DownUnderCTF 2024 "Wacky Recipe" leaves two ingredient amounts as `??` and asks
for the secret ingredient. Each `Put water ... Combine ... Add/Remove <ing>
... Add effort` block produces one character as `water*x + amount + y` (x and y
are the two unknown quantities). Brute-forcing x and y over a small range and
keeping the printable reads that contain a flag yields the plaintext.
"""
from __future__ import annotations

import re

from ..flagpatterns import FLAG_PREFIXES
from .base import Analyzer, ToolContext, ToolResult
from .registry import register

_QUANTITY = re.compile(r"^(\d+)\s+\S+\s+(.+?)\.?$")
_OP = re.compile(r"^(Add|Remove)\s+(.+?)\s+(?:to|from)\s+", re.I)
_FLAG = re.compile(r"[A-Za-z0-9_.-]{2,}\{[ -~]{2,}\}")
# a decoding is only trusted when it starts with a known CTF prefix: the
# brute force produces dozens of printable strings that contain braces
_PREFIXES = tuple(FLAG_PREFIXES) + ("hxp", "amateursCTF", "buckeye")
_KNOWN = re.compile(r"(?i)^(" + "|".join(re.escape(p) for p in _PREFIXES) + r")\{")
_CLEAN = re.compile(r"^[A-Za-z0-9_{}!@#$%^&*()+=:;,.?/ \-]+$")


def _ingredients(lines: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in lines:
        m = _QUANTITY.match(line)
        if m:
            out[m.group(2).strip().rstrip(".")] = int(m.group(1))
    return out


def _groups(lines: list[str]) -> list[dict]:
    groups: list[dict] = []
    cur: dict | None = None
    for line in lines:
        if line.lower().startswith("put water"):
            if cur:
                groups.append(cur)
            cur = {"water": 1, "op": None, "ing": None}
        elif cur is None:
            continue
        elif line.lower().startswith("add water"):
            cur["water"] += 1
        elif "effort" not in line.lower():
            m = _OP.match(line)
            if m:
                cur["op"], cur["ing"] = m.group(1).lower(), m.group(2).strip()
    if cur:
        groups.append(cur)
    return groups


def decode_chef(text: str, max_value: int = 80) -> list[tuple[int, int, str]]:
    """Printable decodings of a Chef recipe, as (x, y, text) candidates."""
    lines = [l.strip() for l in text.splitlines()]
    if not any(l.startswith("Method.") for l in lines):
        return []
    ing = _ingredients(lines)
    groups = [g for g in _groups(lines) if g.get("ing")]
    if not groups:
        return []
    out: list[tuple[int, int, str]] = []
    for x in range(max_value + 1):
        for y in range(max_value + 1):
            chars: list[str] = []
            for g in groups:
                amount = ing.get(g["ing"], 0)
                v = g["water"] * x + (amount if g["op"] == "add" else -amount) + y
                if not 32 <= v < 127:
                    chars = []
                    break
                chars.append(chr(v))
            if chars:
                out.append((x, y, "".join(chars)))
    return out


class ChefAnalyzer(Analyzer):
    name = "chef"
    category = "decode"
    description = "Chef esolang: solve a recipe with unknown quantities (one char per block)."
    accepts = ()
    display_order = 158

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            text = ctx.input.read_text("utf-8", "replace")[:20000]
        except OSError:
            return ToolResult(self.name, status="skipped", summary="unreadable")
        if "Ingredients." not in text or "Method." not in text:
            return ToolResult(self.name, status="skipped", summary="not a Chef recipe")
        for x, y, s in decode_chef(text):
            for cand in (s, s[::-1]):           # the recipe may print it reversed
                if _KNOWN.match(cand) and _CLEAN.match(cand):
                    m = _FLAG.search(cand)
                    if m:
                        return ToolResult(
                            self.name, status="done", summary="flag decoded",
                            output=f"x={x} (first ??), y={y} (second ??)\n"
                                   f"{cand}\nflag: {m.group(0)}")
        return ToolResult(self.name, status="skipped", summary="no flag in any decoding")


register(ChefAnalyzer())
