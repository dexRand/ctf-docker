"""Windows registry hives: the user activity keys that usually hold the flag.

A hive shipped in a challenge (`NTUSER.DAT`, `SOFTWARE`, `SYSTEM`…) can hide the
flag in a typed path, a recent document, a Run entry or a UserAssist value whose
name is ROT13-encoded. `regipy` parses the file offline; the output is text for
the flag hunt. SYSTEM+SAM hash extraction is `sam.py`'s job, not this one.
"""
from __future__ import annotations

import codecs
import time

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

_MAX_HIVE = 256 << 20          # bigger than this is not a challenge handout
_MAX_VALUES = 20_000           # string values printed
_MAX_OUT = 200_000             # characters of output
_DEADLINE = 90                 # seconds: a huge SOFTWARE hive must not stall a job

# keys worth reading first (lowercase, matched anywhere in the path)
_INTERESTING = ("\\run", "runonce", "recentdocs", "typedpaths", "runmru",
                "wordwheelquery", "userassist", "environment", "shellfolders",
                "bagmru", "mapper\\scancode")


def _binary_text(value: str) -> str:
    """REG_BINARY comes as hex: show the UTF-16LE/ASCII text inside, else a size."""
    try:
        raw = bytes.fromhex(value)
    except (ValueError, TypeError):
        return str(value)[:200]
    if not raw:
        return ""
    even = raw[: len(raw) - (len(raw) % 2)]        # a trailing odd byte is common
    if even:
        try:
            text = even.decode("utf-16-le").split("\x00")[0]
            if text and all(32 <= ord(c) < 127 for c in text):
                return text
        except UnicodeDecodeError:
            pass
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in raw).strip(".")
    return printable if len(printable) >= 4 else f"<{len(raw)} B>"


def _format_value(value) -> str:
    if isinstance(value, bytes):
        return _binary_text(value.hex())
    text = str(value)
    if getattr(value, "__class__", None) is str and len(text) >= 8 and len(text) % 2 == 0:
        # regipy hands REG_BINARY over as a hex string
        try:
            bytes.fromhex(text)
            return _binary_text(text)
        except ValueError:
            pass
    return text[:400]


class WinregAnalyzer(Analyzer):
    name = "winreg"
    category = "windows"
    description = "Windows registry hive: Run/RunOnce, RecentDocs, TypedPaths, RunMRU, UserAssist, Environment."
    # hives have no reliable extension (NTUSER.DAT, SOFTWARE, SYSTEM, ...): the
    # `regf` signature decides, so every file is offered to the analyzer
    accepts = ()
    display_order = 267

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            size = ctx.input.stat().st_size
            with open(ctx.input, "rb") as fh:
                head = fh.read(4)
        except OSError as exc:
            return ToolResult(self.name, status="skipped", summary=f"cannot read: {exc}")
        if head != b"regf":
            return ToolResult(self.name, status="skipped", summary="not a registry hive")
        if size > _MAX_HIVE:
            return ToolResult(self.name, status="skipped",
                              summary=f"hive too big ({size >> 20} MiB)")
        try:
            from regipy.registry import RegistryHive
        except Exception as exc:
            return ToolResult(self.name, status="skipped", summary=f"regipy missing: {exc}")
        try:
            hive = RegistryHive(str(ctx.input))
        except Exception as exc:            # corrupt / truncated hive
            return ToolResult(self.name, status="skipped",
                              summary=f"cannot parse hive: {type(exc).__name__}")
        started = time.monotonic()
        interesting: list[str] = []
        plain: list[str] = []
        values = 0
        keys = 0
        truncated = False
        try:
            for entry in hive.recurse_subkeys():
                keys += 1
                if time.monotonic() - started > _DEADLINE:
                    truncated = True
                    break
                path = entry.path or entry.subkey_name or ""
                low = path.lower()
                hot = any(k in low for k in _INTERESTING)
                userassist = "userassist" in low
                lines: list[str] = []
                for v in entry.values or []:
                    name = v.name or "(default)"
                    if userassist:                       # UserAssist names are ROT13
                        name = codecs.decode(name, "rot13")
                    lines.append(f"  {name} = {_format_value(v.value)}")
                    values += 1
                    if values >= _MAX_VALUES:
                        truncated = True
                        break
                if not lines:
                    continue
                if hot:
                    interesting.append(path + "\n" + "\n".join(lines))
                else:
                    plain.append(path + "\n" + "\n".join(lines))
                if (values >= _MAX_VALUES
                        or sum(len(x) for x in interesting) >= _MAX_OUT // 2):
                    truncated = True
                    break
        except Exception as exc:             # a corrupt subkey must not lose the rest
            ctx.log(f"stopped at {keys} keys: {type(exc).__name__}: {exc}")
        if not interesting and not plain:
            return ToolResult(self.name, status="skipped", summary="no values")
        head_text = "== interesting keys ==\n" + "\n".join(interesting)
        body = ("\n== all string values ==\n" + "\n".join(plain)) if plain else ""
        text = (head_text + body)[:_MAX_OUT]
        summary = f"{keys} keys, {values} value(s)"
        if truncated:
            summary += " (truncated)"
        return ToolResult(self.name, status="done", summary=summary, output=text)


register(WinregAnalyzer())
