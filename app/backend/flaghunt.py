"""Flag hunt: scan tool output for flags and store them as findings.

Every text an analyzer produces goes through `_hunt`: several byte views
(raw, UTF-16, URL-decoded, whitespace-collapsed), strict/generic/fuzzy/rot13/
custom patterns, then one level of inline base64/hex and XOR-pair decoding.
Dedupe rules (rot13 twins, whitespace variants, fragments of a longer flag)
apply to flags only.
"""
from __future__ import annotations

import base64
import re

from sqlmodel import Session, select

from . import flagpatterns as fp
from .flagpatterns import (_FUZZY_RE, _GENERIC_RE, _STRICT_RE, FUZZY_SOURCES, GENERIC_NOISY,
                           VISION_SOURCES, _canon_flag, _is_known_prefix, _ok_flag,
                           _rot13_candidates, _url_decoded)
from .ctfs import format_regex, project_format
from .models import Finding

_GUID_BODY = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")

# tools whose output is an offset/hex/ASCII dump
HEX_DUMP_SOURCES = ("xxd", "hexyl", "hexdump")


def custom_flag_matches(view: bytes) -> list[tuple[str, int, int]]:
    return fp.custom_flag_matches(view)


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


# separates the shown context from the literal text to find in the output
MATCH_MARK = "\n[match] "


def _lit(view: bytes, start: int, end: int) -> str:
    """The matched text exactly as it appears in the view."""
    return view[start:end].decode("latin-1", "replace")


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



def hunt(session: Session, project_id: str, file_id: int | None, text: str, source: str) -> None:
    """Flag hunt without holding SQLite's write lock while scanning: pending
    findings are only flushed by the caller's commit (one short write)."""
    with session.no_autoflush:
        _hunt(session, project_id, file_id, text, source)


def _hunt(session: Session, project_id: str, file_id: int | None, text: str,
          source: str, depth: int = 0, origin: str = "") -> None:
    """`origin` is the text as it appears in the tool output when `text` is a
    decoded form of it (base64/hex token, XOR operand): stored with the flag so
    the report can point at the exact place in the output."""
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
    # Hex dumps are excluded: their lines start with offsets, so collapsing glues
    # an ASCII-column fragment to the next line's offset+hex
    # (`ITS{exif` + `00000080: 5f66…` -> bogus `ITS{exif00000080:5f66…}`).
    collapsed_views: list[bytes] = []
    if len(data) <= 200_000 and source.split(":", 1)[0] not in HEX_DUMP_SOURCES:
        collapsed = re.sub(rb"\s+", b"", data)
        if collapsed != data:
            collapsed_views.append(collapsed)
    # only flags take part in flag dedupe: a cracked password that happens to be
    # a substring of a flag must never be deleted as a "shorter fragment"
    flag_q = select(Finding).where(Finding.project_id == project_id).where(Finding.kind == "flag")
    existing = {f.value for f in session.exec(flag_q).all()}
    pending: dict[str, Finding] = {}   # added by this hunt, not flushed yet

    def drop(value: str) -> None:
        """Remove a stored or pending flag (pending ones are invisible to queries)."""
        if value in pending:
            session.expunge(pending.pop(value))
            return
        old = session.exec(flag_q.where(Finding.value == value)).first()
        if old:
            session.delete(old)

    def keep(f: Finding) -> None:
        pending[f.value] = f
        session.add(f)
    existing_norm = {v.replace(" ", "") for v in existing}
    canon_index = {_canon_flag(v): v for v in existing}
    head = source.split(":", 1)[0]
    fuzzy_ok = head in FUZZY_SOURCES
    noisy = any(p in VISION_SOURCES or p in GENERIC_NOISY for p in source.split(":"))
    generic = [] if noisy else list(_GENERIC_RE)
    # the challenge's CTF flag format (e.g. DUCTF{...}) applies to every source
    ctf_re, ctf_is_prefix = format_regex(project_format(session, project_id))

    def where(ctx: str, literal: str) -> str:
        """Context + the literal text to look for in the tool output."""
        lit = (origin or literal)[:300]
        return f"{ctx}{MATCH_MARK}{lit}" if lit else ctx

    def add(value: str, src: str, ctx: str = "", literal: str = "") -> None:
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
                drop(prev)
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
                drop(ex)
                existing.discard(ex)
                existing_norm.discard(ex.replace(" ", ""))
                canon_index.pop(_canon_flag(ex), None)
        existing.add(value)
        existing_norm.add(norm)
        canon_index[canon] = value
        keep(Finding(project_id=project_id, file_id=file_id, kind="flag",
                     value=value, source=src, context=where(ctx, literal or value)))

    def add_raw(value: str, src: str, ctx: str = "", literal: str = "") -> None:
        # for a user-provided FLAG_PATTERN: no brace heuristics, just dedupe
        if not value or value in existing:
            return
        norm = value.replace(" ", "")
        if norm in existing_norm or any(value != ex and value in ex for ex in existing):
            return
        existing.add(value)
        existing_norm.add(norm)
        canon_index[_canon_flag(value)] = value
        keep(Finding(project_id=project_id, file_id=file_id, kind="flag",
                     value=value, source=src, context=where(ctx, literal or value)))

    def scan(view: bytes, with_generic: bool) -> None:
        for val, s, e in custom_flag_matches(view):
            add_raw(val, f"custom:{source}", _snippet(view, s, e), _lit(view, s, e))
        if ctf_re is not None:
            for m in ctf_re.finditer(view):
                val = m.group(0).decode("latin-1", "replace")
                if ctf_is_prefix:   # brace format: same sanity rules as known prefixes
                    add(val, source, _snippet(view, m.start(), m.end()), _lit(view, m.start(), m.end()))
                else:
                    add_raw(val, f"custom:{source}", _snippet(view, m.start(), m.end()),
                            _lit(view, m.start(), m.end()))
        for pat in _STRICT_RE:
            for m in pat.finditer(view):
                add(m.group(0).decode("latin-1", "replace"), source,
                    _snippet(view, m.start(), m.end()), _lit(view, m.start(), m.end()))
        if with_generic:
            for pat in generic:
                for m in pat.finditer(view):
                    val = m.group(0).decode("latin-1", "replace")
                    # `word{GUID}` from an unknown prefix is an identifier (Windows
                    # `NPF_{…}` interface names, COM/registry keys), not a flag
                    if _GUID_BODY.fullmatch(val[val.find("{") + 1:-1]):
                        continue
                    add(val, source, _snippet(view, m.start(), m.end()), _lit(view, m.start(), m.end()))
        if fuzzy_ok:
            for m in _FUZZY_RE.finditer(view):
                add((m.group(1) + b"{" + m.group(2) + b"}").decode("latin-1", "replace"),
                    f"fuzzy:{source}", _snippet(view, m.start(), m.end()), _lit(view, m.start(), m.end()))
        for val, s, e in _rot13_candidates(view):
            add(val, f"rot13:{source}", _snippet(view, s, e), _lit(view, s, e))

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
                          f"{name}:{source}", depth + 1,
                          origin or m.group(0).decode("latin-1", "replace"))
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
                              f"xor:{source}", depth + 1,
                              origin or group[i].decode("latin-1", "replace"))
