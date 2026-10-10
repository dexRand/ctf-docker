"""Recursive, ordered analysis orchestrator.

For each file node, in discovery order: run the applicable analyzers, store
their output, hunt flags, create child nodes for extracted files and recurse
until the tree is exhausted (or the depth limit is reached).
"""
from __future__ import annotations

import base64
import codecs
import datetime as dt
import os
import re
import shutil
import threading
import time
import traceback
import urllib.parse
import uuid
from pathlib import Path

from sqlmodel import Session, select

from . import storage
from .analyzers import get as get_tool
from .bus import bus
from .analyzers.base import ToolContext, ToolResult
from .config import MAX_DEPTH, PROJECTS_DIR
from .db import engine
from .models import Artifact, Event, FileNode, Finding, Project, ToolRun

# The prefix must not be preceded by an alphanumeric/underscore, otherwise
# `CTF{...}` would match inside `picoCTF{...}` and produce a truncated flag.
_LB = r"(?<![0-9A-Za-z_])"
STRICT_PATTERNS = [
    _LB + p + r"\{[^}\n]{1,200}\}"
    for p in ("ITS", "flag", "FLAG", "CTF", "ctf", "HTB", "picoCTF")
]
GENERIC_PATTERNS = [_LB + r"[0-9A-Za-z_]{2,32}\{[A-Za-z0-9_\-!?.,:;@#$%^&*+=/ ]{1,120}\}"]
_STRICT_RE = [re.compile(p.encode(), re.IGNORECASE) for p in STRICT_PATTERNS]
_GENERIC_RE = [re.compile(p.encode(), re.IGNORECASE) for p in GENERIC_PATTERNS]
# sources where the generic "<word>{...}" pattern is skipped (noisy OCR / raw bytes)
VISION_SOURCES = ("ocr", "bit-planes", "channel-remap", "image-enhance",
                  "gif-frames", "spectrogram", "waveform", "raw")
# sources where the generic "<word>{...}" pattern is skipped too: on raw dumps
# (strings/hex viewers) and pcap text it mostly matches binary noise
GENERIC_NOISY = ("strings", "hexyl", "xxd", "hexdump", "pcap",
                 "binwalk-scan", "binwalk-extract", "foremost", "nested-archive")
# a user-provided flag format (e.g. FLAG_PATTERN='DUCTF\{[^}]+\}' or even a
# pattern without braces). Applied to EVERY source, including the noisy ones.
_FLAG_PATTERN = os.environ.get("FLAG_PATTERN", "").strip()
_CUSTOM_FLAG_RE = re.compile(_FLAG_PATTERN.encode()) if _FLAG_PATTERN else None
# the fuzzy (OCR-confusion) matcher only makes sense on visual/audio output,
# not on raw file bytes where it matches markup/entities
FUZZY_SOURCES = tuple(s for s in VISION_SOURCES if s != "raw")


_FLAG_BODY_RE = re.compile(r"[A-Za-z0-9_\-!?@.,: ]{1,200}")


def _ok_flag(value: str) -> bool:
    if value.count("{") != 1 or value.count("}") != 1:
        return False
    if any(c in value for c in "|\n\r\t"):
        return False
    body = value[value.find("{") + 1:value.rfind("}")]
    if not body or len(body) > 200:
        return False
    # reject markup / entity / code snippets (`&#xD;`, `="..."`, `a=b`, …)
    if not _FLAG_BODY_RE.fullmatch(body):
        return False
    return sum(ch.isalnum() for ch in body) >= 3


# A flag found in a different encoding (typically rot13 of the whole value,
# e.g. `VGF{...}` for `ITS{...}`) should collapse to a single finding.
KNOWN_PREFIXES = {"ITS", "flag", "FLAG", "ctf", "CTF", "HTB", "picoCTF"}


def _is_known_prefix(value: str) -> bool:
    return value.split("{", 1)[0] in KNOWN_PREFIXES


# Flags hidden as their rot13 twin (e.g. `VGF{...}` for `ITS{...}`) are common
# in tool outputs; on noisy sources (strings/hex) the generic pattern is skipped
# so we look for the rot13 form of the known prefixes explicitly.
_ROT13_PREFIXES = tuple(sorted({codecs.encode(p, "rot13") for p in KNOWN_PREFIXES}))
_ROT13_RE = [re.compile((_LB + re.escape(p) + r"\{[^}\n]{1,200}\}").encode())
             for p in _ROT13_PREFIXES]

# inline URL-encoding: any %XX escape triggers a de-quoted view
_PCT_RE = re.compile(rb"%[0-9A-Fa-f]{2}")


def _url_decoded(data: bytes) -> list[bytes]:
    """Percent-decoded views (inline `%7B`-style flags), only when it changes."""
    if not _PCT_RE.search(data):
        return []
    try:
        out = urllib.parse.unquote_to_bytes(data)
    except Exception:
        return []
    return [out] if out != data else []


def _rot13_candidates(view: bytes) -> list[tuple[str, int, int]]:
    """(decoded_flag, start, end) for rot13-twin prefixes found in ``view``."""
    out: list[tuple[str, int, int]] = []
    for pat in _ROT13_RE:
        for m in pat.finditer(view):
            val = codecs.decode(m.group(0).decode("latin-1", "replace"), "rot13")
            out.append((val, m.start(), m.end()))
    return out


def custom_flag_matches(view: bytes) -> list[tuple[str, int, int]]:
    """Matches of the user-provided ``FLAG_PATTERN`` (braces not required)."""
    if _CUSTOM_FLAG_RE is None:
        return []
    out: list[tuple[str, int, int]] = []
    for m in _CUSTOM_FLAG_RE.finditer(view):
        val = m.group(0).decode("latin-1", "replace")
        if val and all(32 <= ord(c) < 127 or c in "\n\t" for c in val):
            out.append((val, m.start(), m.end()))
    return out


def _canon_flag(value: str) -> str:
    """Canonical key: a flag and its rot13 twin map to the same string."""
    alt = codecs.encode(value, "rot13")
    if _is_known_prefix(alt) and not _is_known_prefix(value):
        return alt
    if _is_known_prefix(value):
        return value
    return min(value, alt)
# OCR often reads '{' as f/F/l/L/[/( and ']'/'}' as ] or ). This fuzzy pattern
# rescues flags found by OCR/vision tools and normalises them back.
_FUZZY_RE = re.compile(
    rb"(picoCTF|ITS|FLAG|flag|HTB|ctf|CTF)[\{\[\(fFlL]([ -~]{1,180}?)[\}\]\)]", re.IGNORECASE)

# ordered analysis plan (order matters: metadata -> text -> steg -> extract)
DEFAULT_PLAN = [
    "file", "exiftool", "identify", "ffprobe", "pdfinfo",
    "strings", "hexyl", "xxd", "pdftotext", "pdfid", "elf", "readelf", "objdump",
    "binwalk-scan",
    "decode", "blobs", "zero-width", "whitespace", "case-bits", "homoglyph", "morse-text",
    "ocr", "qr",
    "zsteg", "lsb-carve", "psimage", "png-chunks", "png-pixels", "steghide", "outguess", "jsteg", "openstego",
    "bit-planes", "channel-remap", "image-enhance", "gif-frames",
    "morse", "dtmf", "spectrogram", "waveform", "wav-lsb", "wav-levels", "sstv",
    "pcap",
    "nested-archive", "git", "7z", "office", "eml", "binwalk-extract", "foremost", "pngcheck",
    "png-repair", "image-repair",
]
HEAVY_EXTRACT = {"binwalk-extract", "foremost"}
# cap how many heavy tools run at once across all projects (CPU bound)
_HEAVY_TOOLS = set(HEAVY_EXTRACT) | {"7z", "steghide", "outguess", "jsteg", "openstego", "sstv"}
_HEAVY_SEM = threading.Semaphore(max(1, int(os.environ.get("HEAVY_TOOLS", "1"))))
ARCHIVE_EXT = (".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".tgz")


class Job:
    def __init__(self, project_id: str) -> None:
        self.project_id = project_id
        self.cancelled = False
        self.paused = False
        self.gate = threading.Event()
        self.gate.set()
        self.thread: threading.Thread | None = None
        self.processed = 0

    def wait(self) -> None:
        self.gate.wait()

    def pause(self) -> None:
        self.paused = True
        self.gate.clear()

    def resume(self) -> None:
        self.paused = False
        self.gate.set()

    def cancel(self) -> None:
        self.cancelled = True
        self.gate.set()


JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _event(session: Session, pid: str, message: str, level: str = "info") -> None:
    session.add(Event(project_id=pid, message=message, level=level))
    bus.publish(f"project:{pid}", {"type": "event", "level": level, "message": message})


def _emit(pid: str, event: dict) -> None:
    bus.publish(f"project:{pid}", event)


def _printable(b: bytes) -> bool:
    if not b:
        return False
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not t:
        return False
    good = sum(1 for c in t if 32 <= ord(c) < 127 or c in "\n\r\t")
    return good / len(t) >= 0.85


def _views(data: bytes) -> list[bytes]:
    """Byte views to hunt in: raw, plus UTF-16 LE/BE when the data is null-heavy."""
    views = [data]
    if data and data.count(0) > len(data) // 4:
        # UTF-16 without the usual decode (keeps a trailing odd byte, e.g. "}")
        views.append(data[0::2])
        views.append(data[1::2])
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                views.append(data.decode(enc, "ignore").encode("latin-1", "replace"))
            except Exception:
                pass
    return views


def _snippet(view: bytes, start: int, end: int, width: int = 80) -> str:
    """A short, printable excerpt around a match (the flag is marked with «»)."""
    def clean(b: bytes) -> str:
        s = b.decode("latin-1", "replace")
        s = "".join(ch if (32 <= ord(ch) < 127 or ch in "\n\t") else "." for ch in s)
        return " ".join(s.split())
    left = clean(view[max(0, start - width):start])
    right = clean(view[end:end + width])
    flag = view[start:end].decode("latin-1", "replace")
    return (f"{left}  «{flag}»  {right}").strip()[:400]


def _hunt(session: Session, project_id: str, file_id: int | None, text: str,
          source: str, depth: int = 0) -> None:
    if not text:
        return
    data = text.encode("latin-1", "replace")
    # Text logs escape newlines as `\n`, which glues a stray `n` onto a flag that
    # starts right after it (`...is\nSEKAI{...}` -> `nSEKAI{...}`). Decode the
    # common escapes (n/r/t) before hunting so the token is clean.
    if b"\\" in data:
        data = re.sub(rb"\\([nrt])",
                      lambda m: b"\n" if m.group(1) == b"n" else (b"\r" if m.group(1) == b"r" else b"\t"),
                      data)
    views = _views(data) + _url_decoded(data)
    # A flag can be split across lines by OCR (e.g. `flag{Wh4t_\nth3_fl4g}`), so we
    # also scan a whitespace-collapsed copy. But collapsing also glues unrelated
    # words together (`hello VGF{..}` -> `helloVGF{..}`), which the *generic*
    # `word{...}` matcher would then report as a flag — the source of the bogus
    # "nested decode found ITS{...}" findings. So the collapsed copy is scanned
    # with the STRICT (known-prefix) and rot13 matchers only.
    collapsed_views: list[bytes] = []
    if len(data) <= 200_000:
        collapsed = re.sub(rb"\s+", b"", data)
        if collapsed != data:
            collapsed_views.append(collapsed)
    existing = {f.value for f in session.exec(select(Finding).where(Finding.project_id == project_id)).all()}
    existing_norm = {v.replace(" ", "") for v in existing}
    canon_index = {_canon_flag(v): v for v in existing}
    head = source.split(":", 1)[0]
    is_vision = head in VISION_SOURCES
    fuzzy_ok = head in FUZZY_SOURCES
    noisy = any(p in VISION_SOURCES or p in GENERIC_NOISY for p in source.split(":"))
    generic = [] if noisy else list(_GENERIC_RE)

    def add(value: str, src: str, ctx: str = "") -> None:
        if not _ok_flag(value) or value in existing:
            return
        # treat values that differ only by whitespace as the same flag
        norm = value.replace(" ", "")
        if norm in existing_norm:
            return
        # collapse rot13 twins (`VGF{..}` vs `ITS{..}`); prefer the known prefix
        canon = _canon_flag(value)
        prev = canon_index.get(canon)
        if prev is not None and prev != value:
            if _is_known_prefix(value) and not _is_known_prefix(prev):
                old = session.exec(select(Finding).where(Finding.project_id == project_id)
                                   .where(Finding.value == prev)).first()
                if old:
                    session.delete(old)
                existing.discard(prev)
                existing_norm.discard(prev.replace(" ", ""))
                canon_index.pop(canon, None)
            else:
                return
        # skip fragments of a longer flag (e.g. `CTF{x}` inside `picoCTF{x}`)
        if any(value != ex and value in ex for ex in existing):
            return
        # and remove shorter fragments already stored in favour of this one
        for ex in list(existing):
            if ex != value and ex in value:
                old = session.exec(select(Finding).where(Finding.project_id == project_id)
                                   .where(Finding.value == ex)).first()
                if old:
                    session.delete(old)
                existing.discard(ex)
                existing_norm.discard(ex.replace(" ", ""))
                canon_index.pop(_canon_flag(ex), None)
        existing.add(value)
        existing_norm.add(norm)
        canon_index[canon] = value
        session.add(Finding(project_id=project_id, file_id=file_id, kind="flag",
                            value=value, source=src, context=ctx))

    def add_raw(value: str, src: str, ctx: str = "") -> None:
        # for a user-provided FLAG_PATTERN: no brace heuristics, just dedupe
        if not value or value in existing:
            return
        norm = value.replace(" ", "")
        if norm in existing_norm or any(value != ex and value in ex for ex in existing):
            return
        existing.add(value)
        existing_norm.add(norm)
        canon_index[_canon_flag(value)] = value
        session.add(Finding(project_id=project_id, file_id=file_id, kind="flag",
                            value=value, source=src, context=ctx))

    def scan(view: bytes, with_generic: bool) -> None:
        for val, s, e in custom_flag_matches(view):
            add_raw(val, f"custom:{source}", _snippet(view, s, e))
        for pat in _STRICT_RE:
            for m in pat.finditer(view):
                add(m.group(0).decode("latin-1", "replace"), source,
                    _snippet(view, m.start(), m.end()))
        if with_generic:
            for pat in generic:
                for m in pat.finditer(view):
                    add(m.group(0).decode("latin-1", "replace"), source,
                        _snippet(view, m.start(), m.end()))
        if fuzzy_ok:
            for m in _FUZZY_RE.finditer(view):
                add((m.group(1) + b"{" + m.group(2) + b"}").decode("latin-1", "replace"),
                    f"fuzzy:{source}", _snippet(view, m.start(), m.end()))
        for val, s, e in _rot13_candidates(view):
            add(val, f"rot13:{source}", _snippet(view, s, e))

    for view in views:
        scan(view, with_generic=True)
    for view in collapsed_views:
        scan(view, with_generic=False)
    if depth >= 2:
        return
    # inline encodings in tool outputs (e.g. base64 in EXIF metadata)
    decoders: list[tuple[str, object]] = [
        ("b64", lambda t: base64.b64decode(t + b"=" * ((4 - len(t) % 4) % 4), validate=False)),
        ("hex", lambda t: bytes.fromhex(t.decode())),
    ]
    for name, fn in decoders:
        pat = rb"[A-Za-z0-9+/]{16,}={0,2}" if name == "b64" else rb"(?:[0-9a-fA-F]{2}){8,}"
        for view in views:
            for m in re.finditer(pat, view):
                try:
                    dec = fn(m.group(0))
                except Exception:
                    continue
                if b"{" in dec and _printable(dec):
                    _hunt(session, project_id, file_id, dec.decode("latin-1", "replace"),
                          f"{name}:{source}", depth + 1)
    # Two equal-length quoted strings XORed together: a common script
    # obfuscation (e.g. the PowerShell "map" left behind by Invoke-PSImage).
    # This only *adds* a candidate, so existing findings are untouched.
    if len(data) <= 200_000:
        lits: list[bytes] = []
        for q in (rb'"([^"]{8,4096})"', rb"'([^']{8,4096})'"):
            for m in re.finditer(q, data):
                s = m.group(1)
                if s not in lits:
                    lits.append(s)
                if len(lits) >= 32:
                    break
        by_len: dict[int, list[bytes]] = {}
        for s in lits:
            by_len.setdefault(len(s), []).append(s)
        for group in by_len.values():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    x = bytes(a ^ b for a, b in zip(group[i], group[j]))
                    if b"{" in x and _printable(x):
                        _hunt(session, project_id, file_id, x.decode("latin-1", "replace"),
                              f"xor:{source}", depth + 1)


def _detect_ext(ftype: str) -> str:
    """Best-effort extension from the `file` description, so analyzers run even
    when the name lies (e.g. a PNG uploaded as flag.txt)."""
    low = (ftype or "").lower()
    for key, ext in (
        ("elf 64-bit", ".elf"), ("elf 32-bit", ".elf"),
        ("png image", ".png"), ("jpeg image", ".jpg"), ("gif image", ".gif"),
        ("bmp image", ".bmp"), ("tiff image", ".tiff"), ("web/p image", ".webp"),
        ("webp", ".webp"), ("pdf document", ".pdf"), ("zip archive", ".zip"),
        ("rfc 822", ".eml"), ("mail message", ".eml"),
        ("7-zip archive", ".7z"), ("rar archive", ".rar"), ("tar archive", ".tar"),
        ("gzip compressed", ".gz"), ("bzip2 compressed", ".bz2"),
        ("wave audio", ".wav"), ("mpeg audio", ".mp3"), ("mp3", ".mp3"),
        ("flac", ".flac"), ("ogg", ".ogg"), ("iso media", ".mp4"),
    ):
        if key in low:
            return ext
    return ""


def _plan_for(name: str, mime: str | None, is_text: bool) -> list[str]:
    plan = []
    for tool in DEFAULT_PLAN:
        a = get_tool(tool)
        if not a or not a.matches(mime, name):
            continue
        if tool in HEAVY_EXTRACT and is_text and not name.lower().endswith(ARCHIVE_EXT):
            continue
        plan.append(tool)
    return plan


def _store_extracted(session: Session, pid: str, parent: FileNode, src: Path, order: int,
                     tool: str | None = None) -> FileNode:
    name = storage.sanitize_name(src.name)
    rel = f"files/{order:04d}__{name}"
    dest = storage.project_dir(pid) / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(src), str(dest))
    except (OSError, shutil.Error):
        shutil.copy2(src, dest)
    sha, md5, size = storage.hashes_of(dest)
    origin = f"extracted:{tool}:{parent.id}" if tool else f"extracted:{parent.id}"
    node = FileNode(project_id=pid, parent_id=parent.id, name=name, rel_path=rel,
                    size=size, mime=None, sha256=sha, md5=md5, depth=parent.depth + 1,
                    order_index=order, origin=origin)
    session.add(node)
    session.flush()
    return node


def _run(pid: str, job: Job) -> None:
    work = storage.project_dir(pid)
    with Session(engine) as session:
        proj = session.get(Project, pid)
        if not proj:
            return
        proj.status = "running"
        proj.updated_at = _now()
        session.add(proj)
        _event(session, pid, "analysis started")
        session.commit()
        _emit(pid, {"type": "status", "status": "running"})

        nodes = session.exec(select(FileNode).where(FileNode.project_id == pid)
                             .order_by(FileNode.order_index, FileNode.id)).all()
        pending: list[FileNode] = list(nodes)
        order = max((n.order_index for n in nodes), default=-1) + 1
        processed: set[str] = set()
        depth_limit = MAX_DEPTH  # nested archives (Matryoshka doll) can be several levels deep

        def analyze(node: FileNode) -> None:
            nonlocal order
            if node.depth >= depth_limit or (node.sha256 and node.sha256 in processed):
                return
            if node.sha256:
                processed.add(node.sha256)

            _emit(pid, {"type": "file", "file_id": node.id, "name": node.name,
                        "depth": node.depth, "size": node.size,
                        "total": job.processed + 1 + len(pending)})
            abs_path = work / node.rel_path
            if not abs_path.is_file():
                return
            out_dir = work / "work" / str(node.id)
            out_dir.mkdir(parents=True, exist_ok=True)

            # hunt the raw file content too (catches UTF-16 flags, inline encodings…)
            try:
                raw = abs_path.read_bytes()[:5_000_000]
                _hunt(session, pid, node.id, raw.decode("latin-1", "replace"), f"raw:{node.name}")
            except OSError:
                pass

            def record(tool_name: str, result, logs=None) -> None:
                content = result.output or ""
                if logs:
                    content = "# commands:\n# " + "\n# ".join(logs) + "\n\n" + content
                rel_out = None
                if content:
                    op = out_dir / f"{tool_name}.out"
                    op.write_text(content, errors="replace")
                    rel_out = str(op.relative_to(work))
                run = ToolRun(project_id=pid, file_id=node.id, tool=tool_name,
                              status=result.status, needs_password=result.needs_password,
                              exit_code=result.exit_code, summary=result.summary[:500],
                              output_path=rel_out, started_at=_now(), finished_at=_now())
                session.add(run)
                session.flush()
                # files moved into the tree as children must not stay as artifacts
                # too (their old path would no longer exist)
                moved = {str(x) for x in result.extracted}
                for art in result.artifacts:
                    if str(art.get("path", "")) in moved:
                        continue
                    p = Path(str(art.get("path", "")))
                    try:
                        rel_art = str(p.relative_to(work))
                    except ValueError:
                        rel_art = str(art.get("name", ""))
                    session.add(Artifact(project_id=pid, run_id=run.id, file_id=node.id,
                                         name=str(art.get("name", p.name)),
                                         path=rel_art, size=int(art.get("size", 0))))
                if result.output:
                    _hunt(session, pid, node.id, result.output, f"{tool_name}:{node.name}")
                if result.needs_password:
                    note_val = f"password required: {node.name}"
                    exists = session.exec(select(Finding).where(Finding.project_id == pid)
                                          .where(Finding.kind == "note")
                                          .where(Finding.value == note_val)).first()
                    if not exists:
                        session.add(Finding(project_id=pid, file_id=node.id, kind="note",
                                            value=note_val, source=tool_name))
                _emit(pid, {"type": "tool", "file_id": node.id, "name": node.name, "tool": tool_name,
                            "status": result.status, "needs_password": result.needs_password,
                            "summary": result.summary, "extracted": len(result.extracted)})
                # persist now: keep the SQLite write transaction short so a long
                # tool run never blocks other requests ("database is locked")
                session.commit()

            # detect type first, then build the plan (text files skip heavy carving)
            ftype = ""
            file_analyzer = get_tool("file")
            if file_analyzer:
                file_logs: list[str] = []
                r0 = file_analyzer.run(ToolContext(input=abs_path, workdir=out_dir, log=file_logs.append))
                ftype = r0.output
                record("file", r0, file_logs)
            is_text = any(k in ftype.lower() for k in ("text", "ascii", "unicode"))
            # if the name lies (PNG called .txt…), use the detected type for the plan
            detected = _detect_ext(ftype)
            plan_name = node.name
            if detected and not node.name.lower().endswith(detected):
                plan_name = node.name + detected
            plan = _plan_for(plan_name, node.mime, is_text)

            for tool_name in [t for t in plan if t != "file"]:
                if job.cancelled:
                    break
                job.wait()
                analyzer = get_tool(tool_name)
                logs: list[str] = []
                tctx = ToolContext(input=abs_path, workdir=out_dir, log=logs.append)
                try:
                    if tool_name in _HEAVY_TOOLS:  # bound concurrent heavy tools
                        with _HEAVY_SEM:
                            result = analyzer.run(tctx)
                    else:
                        result = analyzer.run(tctx)
                except Exception as exc:  # one broken analyzer must not kill the job
                    result = ToolResult(tool_name, status="error",
                                        summary=f"{type(exc).__name__}: {exc}"[:500],
                                        output=traceback.format_exc()[-8000:])
                record(tool_name, result, logs)
                for src in result.extracted:
                    child = _store_extracted(session, pid, node, Path(src), order, tool=tool_name)
                    order += 1
                    pending.append(child)
                if result.consumed:
                    break

            job.processed += 1
            proj.updated_at = _now()
            session.add(proj)
            session.commit()
            _emit(pid, {"type": "progress", "processed": job.processed,
                        "total": job.processed + len(pending)})

        rounds = 0
        try:
            while True:
                while pending:
                    if job.cancelled:
                        break
                    job.wait()
                    if job.cancelled:
                        break
                    analyze(pending.pop(0))
                if job.cancelled or proj.mode != "auto" or rounds >= 3:
                    break
                new_nodes = _auto_crack(session, pid, work, job)
                if not new_nodes:
                    break
                pending.extend(new_nodes)
                rounds += 1
        except Exception:  # never leave a project spinning in "running"
            _event(session, pid, "analysis failed: " + traceback.format_exc()[-800:], "error")
            proj = session.get(Project, pid) or proj
            proj.status = "error"
            proj.updated_at = _now()
            session.add(proj)
            session.commit()
            _emit(pid, {"type": "status", "status": "error"})
            with _JOBS_LOCK:
                JOBS.pop(pid, None)
            return

        proj = session.get(Project, pid) or proj
        proj.status = "cancelled" if job.cancelled else "done"
        proj.updated_at = _now()
        session.add(proj)
        _event(session, pid, f"analysis {proj.status}", "warn" if job.cancelled else "info")
        session.commit()
        _emit(pid, {"type": "status", "status": proj.status})
    with _JOBS_LOCK:
        JOBS.pop(pid, None)


def mark_unlocked(session: Session, pid: str, file_id: int) -> None:
    """After a successful crack, a file no longer needs a password.

    Clears ``needs_password`` on every run that asked for one, so the file
    stops being reported as locked/locked while keeping the failed run history.
    """
    for r in session.exec(select(ToolRun).where(ToolRun.project_id == pid)
                          .where(ToolRun.file_id == file_id)
                          .where(ToolRun.needs_password == True)).all():  # noqa: E712
        r.needs_password = False


def record_crack_run(session: Session, pid: str, file_id: int, work: Path,
                     res: dict, lines: list[str]) -> None:
    """Persist a ToolRun for a crack attempt.

    Cracking used to leave only a Finding/Event, so the crack step had no run,
    no command log and did not appear in the runs list / graph. This stores the
    executed commands and the outcome like any other analyzer run.
    """
    out_dir = work / "work" / str(file_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    body = ""
    if lines:
        body += "# commands:\n# " + "\n# ".join(lines) + "\n\n"
    if res.get("password"):
        hit = res.get("wordlist_hit") or ""
        body += "password: " + res["password"] + (f"  (via {hit})" if hit else "")
        summary = "password: " + res["password"] + (f" (via {hit})" if hit else "")
        status, code = "done", 0
    else:
        body += "password not found"
        summary, status, code = "password not found", "skipped", 1
    op = out_dir / "crack.out"
    op.write_text(body, errors="replace")
    # one crack run per file: update it across auto-crack rounds / manual retries
    run = session.exec(select(ToolRun).where(ToolRun.project_id == pid)
                       .where(ToolRun.file_id == file_id)
                       .where(ToolRun.tool == "crack")).first()
    if run is None:
        run = ToolRun(project_id=pid, file_id=file_id, tool="crack")
        session.add(run)
    run.status = status
    run.exit_code = code
    run.summary = summary[:500]
    run.output_path = str(op.relative_to(work))
    run.needs_password = False
    run.finished_at = _now()
    if run.started_at is None:
        run.started_at = _now()


def _auto_crack(session: Session, pid: str, work: Path, job: Job) -> list[FileNode]:
    """Auto mode: try the *small* wordlists on the locked files; return unlocked
    nodes. Bounded by ``AUTO_CRACK_MAX_MB`` (per list) and ``AUTO_CRACK_BUDGET_S``
    (per project) so a false "locked" (e.g. a JPEG with no steghide payload)
    cannot stall the analysis for hours."""
    from . import cracking
    already = {f.file_id for f in session.exec(
        select(Finding).where(Finding.project_id == pid).where(Finding.kind == "password")).all()}
    runs = session.exec(select(ToolRun).where(ToolRun.project_id == pid)
                        .where(ToolRun.needs_password == True)).all()  # noqa: E712
    fids: list[int] = []
    for r in runs:
        if r.file_id not in already and r.file_id not in fids:
            fids.append(r.file_id)
    if not fids:
        return []

    names = [p.name for p in cracking.resolve_wordlists(max_bytes=cracking.AUTO_CRACK_MAX_BYTES)]
    deadline = (time.time() + cracking.AUTO_CRACK_BUDGET_S) if cracking.AUTO_CRACK_BUDGET_S > 0 else None
    _event(session, pid, f"auto-crack: {len(names)} wordlists (≤ "
                         f"{cracking.AUTO_CRACK_MAX_BYTES // (1024 * 1024)} MB)"
                         + (f", budget {cracking.AUTO_CRACK_BUDGET_S}s" if deadline else ""))
    session.commit()

    new_nodes: list[FileNode] = []
    for fid in fids:
        if job.cancelled:
            break
        if deadline and time.time() > deadline:
            _event(session, pid, "auto-crack time budget reached", "warn")
            session.commit()
            break
        node = session.get(FileNode, fid)
        if not node:
            continue
        _emit(pid, {"type": "crack", "file_id": fid, "name": node.name, "status": "running"})
        lines: list[str] = []
        budget = max(1, int(deadline - time.time())) if deadline else None
        res = cracking.crack_file(work / node.rel_path, names, log=lines.append, budget_s=budget)
        record_crack_run(session, pid, fid, work, res, lines)
        if res["password"]:
            wl_hit = res.get("wordlist_hit") or ""
            session.add(Finding(project_id=pid, file_id=fid, kind="password",
                                value=res["password"], source=f"crack:{res['kind']}",
                                context=wl_hit))
            mark_unlocked(session, pid, fid)
            session.add(Event(project_id=pid, level="info",
                              message=f"password found for {node.name}: {res['password']}"
                                      + (f" via {wl_hit}" if wl_hit else "")))
            _emit(pid, {"type": "crack", "file_id": fid, "status": "found",
                        "password": res["password"], "wordlist": wl_hit or None})
            if res["extracted"]:
                ids = import_children(session, pid, fid, res["extracted"])
                session.flush()
                for i in ids:
                    nn = session.get(FileNode, i)
                    if nn:
                        new_nodes.append(nn)
            session.commit()
        else:
            _emit(pid, {"type": "crack", "file_id": fid, "status": "not_found"})
            session.add(Event(project_id=pid, level="warn", message=f"password not found for {node.name}"))
            session.commit()
    return new_nodes


def import_children(session: Session, pid: str, parent_id: int, paths: list[str],
                    tool: str = "crack") -> list[int]:
    """Store files recovered by cracking as children of an existing node."""
    parent = session.get(FileNode, parent_id)
    if not parent:
        return []
    last = session.exec(select(FileNode).where(FileNode.project_id == pid)
                        .order_by(FileNode.order_index.desc())).first()
    order = (last.order_index if last else -1) + 1
    ids: list[int] = []
    for src in paths:
        child = _store_extracted(session, pid, parent, Path(src), order, tool=tool)
        order += 1
        ids.append(child.id)
    session.flush()
    return ids


def start(pid: str) -> Job:
    with _JOBS_LOCK:
        if pid in JOBS:
            raise RuntimeError("already running")
        job = Job(pid)
        JOBS[pid] = job
    t = threading.Thread(target=_run, args=(pid, job), daemon=True)
    job.thread = t
    t.start()
    return job


def control(pid: str, action: str) -> bool:
    with _JOBS_LOCK:
        job = JOBS.get(pid)
    if not job:
        return False
    if action == "pause":
        job.pause()
    elif action == "resume":
        job.resume()
    elif action == "cancel":
        job.cancel()
    else:
        return False
    return True


def is_running(pid: str) -> bool:
    with _JOBS_LOCK:
        return pid in JOBS


def reconcile_orphans() -> list[str]:
    """After a restart there are no in-memory jobs, so any project still marked
    running/queued is orphaned. Mark it as interrupted so the GUI stops spinning.
    """
    with Session(engine) as session:
        projects = session.exec(
            select(Project).where(Project.status.in_(("running", "queued")))  # type: ignore[attr-defined]
        ).all()
        ids: list[str] = []
        for p in projects:
            # a project that already found a flag counts as solved, not failed:
            # the restart only cut the remaining (often slow) auto-crack short
            solved = session.exec(
                select(Finding).where(Finding.project_id == p.id)
                .where(Finding.kind == "flag")).first()
            if solved:
                p.status = "done"
                session.add(Event(project_id=p.id, level="warn",
                                  message="analysis interrupted by a restart "
                                          "(flag already found)"))
            else:
                p.status = "error"
                session.add(Event(project_id=p.id, level="warn",
                                  message="analysis interrupted by a restart"))
            session.add(p)
            ids.append(p.id)
        runs = session.exec(
            select(ToolRun).where(ToolRun.status.in_(("running", "queued")))  # type: ignore[attr-defined]
        ).all()
        for r in runs:
            r.status = "error"
            session.add(r)
        # a project that ended up in `error` but already holds a flag is really
        # solved (typically an old restart orphan): surface it as `done`
        for p in session.exec(select(Project).where(Project.status == "error")).all():
            flag = session.exec(select(Finding).where(Finding.project_id == p.id)
                                .where(Finding.kind == "flag")).first()
            if flag:
                p.status = "done"
                session.add(Event(project_id=p.id, level="warn",
                                  message="marked done (flag already found)"))
                session.add(p)
                ids.append(p.id)
        session.commit()
        return ids


def dedupe_findings() -> int:
    """Clean stored findings: collapse rot13 twins and whitespace variants of a
    flag, drop fragments of a longer flag, and drop duplicate notes. Older
    projects are cleaned at startup."""
    with Session(engine) as session:
        rows = session.exec(select(Finding)).all()
        by_proj: dict[str, list[Finding]] = {}
        for r in rows:
            by_proj.setdefault(r.project_id, []).append(r)
        removed = 0
        for items in by_proj.values():
            flags = [f for f in items if f.kind == "flag"]
            keep: dict[str, Finding] = {}
            # prefer a known prefix, then fewer spaces, then the shorter value
            flags.sort(key=lambda x: (0 if _is_known_prefix(x.value) else 1,
                                      x.value.count(" "), len(x.value)))
            for f in flags:
                key = _canon_flag(f.value).replace(" ", "")
                if key in keep:
                    session.delete(f)
                    removed += 1
                else:
                    keep[key] = f
            values = {f.value for f in keep.values()}
            for f in list(keep.values()):
                if any(f.value != o and f.value in o for o in values):
                    session.delete(f)
                    removed += 1
            # duplicate notes (same value+source) across auto-crack passes
            seen_notes: set[tuple[str, str]] = set()
            for f in items:
                if f.kind != "note":
                    continue
                key = (f.value, f.source)
                if key in seen_notes:
                    session.delete(f)
                    removed += 1
                else:
                    seen_notes.add(key)
        session.commit()
        return removed
