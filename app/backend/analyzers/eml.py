"""Email (.eml / RFC 822) analyzer.

Parses an email, prints the interesting headers, decodes the bodies
(base64 / quoted-printable) so the flag hunt can scan them, and extracts the
attachments as children (recursed by the pipeline). Flags suspicious attachment
types (.vbs/.js/.exe…) — handy for the "malicious email" forensics genre.
"""
from __future__ import annotations

import email
import email.policy
import re
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

EML_EXT = (".eml",)
EML_MIME = ("message/rfc822", "application/mbox")

_HEADERS = ("From", "Reply-To", "Return-Path", "To", "Cc", "Subject", "Date",
            "Message-ID", "Authentication-Results", "Received-SPF")
# attachment extensions that usually mean "malware" in a phishing .eml
_SUSPECT = {".vbs": "VBScript", ".vbe": "VBScript", ".js": "JavaScript", ".jse": "JScript",
            ".wsf": "Windows Script", ".wsh": "Windows Script", ".exe": "executable",
            ".dll": "DLL", ".scr": "screensaver", ".lnk": "shortcut", ".bat": "batch",
            ".cmd": "batch", ".ps1": "PowerShell", ".hta": "HTML app", ".iso": "disk image",
            ".img": "disk image", ".jar": "Java archive", ".7z": "archive", ".zip": "archive"}
_MAX_ATT = 20_000_000
_MAX_ATTACHMENTS = 40
_MAX_TEXT = 40_000


def safe_name(name: str) -> str:
    name = (name or "").replace("\\", "/").split("/")[-1].strip()
    name = re.sub(r"[^\w.\-() ]+", "_", name)
    return name or "attachment.bin"


def _decode_text(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, "replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("latin-1", "replace")


class EmlAnalyzer(Analyzer):
    name = "eml"
    category = "forensics"
    description = "Parse .eml email: headers, decoded bodies and attachments."
    accepts = EML_EXT + EML_MIME
    display_order = 165

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            raw = ctx.input.read_bytes()
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        try:
            msg = email.message_from_bytes(raw, policy=email.policy.default)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(self.name, status="error", summary=f"parse error: {exc}")
        if not (msg.get("From") or msg.get("Subject") or msg.get("Received")):
            return ToolResult(self.name, status="skipped", summary="not an email message")

        lines: list[str] = []
        for h in _HEADERS:
            value = msg.get(h)
            if value:
                lines.append(f"{h}: {' '.join(str(value).split())[:300]}")

        outdir = ctx.sub(self.name)
        attachments: list[Path] = []
        bodies: list[str] = []
        suspect: list[str] = []
        for i, part in enumerate(msg.walk()):
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            disp = (part.get_content_disposition() or "").lower()
            fname = part.get_filename()
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            if disp == "attachment" or fname:
                name = safe_name(fname or f"part{i}")
                if len(payload) > _MAX_ATT:
                    lines.append(f"attachment (skipped, {len(payload)} B): {name}")
                else:
                    dest = outdir / f"{i:02d}-{name}"
                    try:
                        dest.write_bytes(payload)
                    except OSError:
                        continue
                    attachments.append(dest)
                    ext = Path(name).suffix.lower()
                    tag = f" ⚠ {_SUSPECT[ext]}" if ext in _SUSPECT else ""
                    lines.append(f"attachment: {name} ({ctype}, {len(payload)} B){tag}")
                    if tag:
                        suspect.append(name)
                    if len(attachments) >= _MAX_ATTACHMENTS:
                        break
            elif ctype in ("text/plain", "text/html", "text/calendar"):
                text = _decode_text(part)
                if text.strip():
                    bodies.append(f"--- {ctype} ---\n{text[:_MAX_TEXT]}")

        output = "\n".join(lines)
        if bodies:
            output += "\n\n" + "\n\n".join(bodies)
        if suspect:
            output = "⚠ allegati sospetti: " + ", ".join(suspect) + "\n" + output
        summary = f"{len(lines)} part(s)"
        if attachments:
            summary += f", {len(attachments)} attachment(s)"
        return ToolResult(
            self.name, status="done", summary=summary, output=output[:60000],
            extracted=[str(f) for f in attachments],
            artifacts=[{"name": str(f.relative_to(ctx.workdir)), "path": str(f),
                        "size": f.stat().st_size} for f in attachments],
        )


register(EmlAnalyzer())
