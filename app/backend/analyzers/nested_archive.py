"""Deep single-chain archive unwrapper (e.g. picoCTF *like1000*).

Challenge authors hide a payload behind hundreds of nested archives
(`1000.tar` -> `999.tar` -> ... -> `flag.png`), usually with a small
non-archive sidecar (a `filler.txt`) at every level. The generic pipeline peels
only **one level per node** and stops at ``MAX_DEPTH``, so a 1000-deep chain is
never reached (and analysing every intermediate level with the heavy tools is
painfully slow).

This analyzer follows the chain **in-process** (tar/zip/gz/bz2/xz), ignoring
non-archive sidecars, and returns only the innermost file(s). Those become
normal children, so OCR / strings / flag-hunt still run on the real payload.
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import tarfile
import zipfile
from pathlib import Path
from typing import IO, Optional

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

ARCHIVE_EXT = (".tar", ".gz", ".tgz", ".tbz", ".tbz2", ".bz2", ".xz", ".txz", ".zip", ".7z")
MAX_LAYERS = 5000
MAX_SINGLE = 256 * 1024 * 1024  # cap for a single decompressed member


class Encrypted(Exception):
    """Raised when a member needs a password (leave it to 7z / the cracker)."""


def _safe_name(name: str) -> str:
    """Flatten a member path to a safe basename (no traversal, no NUL)."""
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = "".join(c for c in name if c >= " " and c != "\x7f")
    return (name or "file")[:150]


def _looks_like_archive(name: str) -> bool:
    return name.lower().endswith(ARCHIVE_EXT)


def _kind(path: Path) -> Optional[str]:
    """Classify a file as tar/zip/gz/bz2/xz, or None if it is not an archive."""
    try:
        if tarfile.is_tarfile(path):
            return "tar"
    except OSError:
        pass
    try:
        if zipfile.is_zipfile(path):
            return "zip"
    except OSError:
        pass
    low = path.name.lower()
    if low.endswith((".gz", ".tgz")):
        return "gz"
    if low.endswith((".bz2", ".tbz", ".tbz2")):
        return "bz2"
    if low.endswith((".xz", ".txz")):
        return "xz"
    return None


def _entries(path: Path, kind: str) -> list[tuple[str, bool, int, bool]]:
    """(name, is_file, size, encrypted) for every member of an archive."""
    if kind == "tar":
        with tarfile.open(path, "r:*") as t:
            return [(m.name, m.isfile(), m.size, False) for m in t.getmembers()]
    if kind == "zip":
        with zipfile.ZipFile(path) as z:
            return [(zi.filename, not zi.is_dir(), zi.file_size,
                     bool(zi.flag_bits & 0x1)) for zi in z.infolist()]
    stem = path.name
    for ext in (".tgz", ".tbz2", ".tbz", ".txz", ".gz", ".bz2", ".xz"):
        if stem.lower().endswith(ext):
            stem = stem[: -len(ext)]
            break
    return [(stem or "data", True, 0, False)]


def _copy_capped(src: IO[bytes], dst: Path, cap: int = MAX_SINGLE) -> None:
    with open(dst, "wb") as out:
        remaining = cap
        while remaining > 0:
            chunk = src.read(min(1 << 20, remaining))
            if not chunk:
                break
            out.write(chunk)
            remaining -= len(chunk)


def _extract(path: Path, kind: str, names: set[str], dest: Path, idx: int) -> list[Path]:
    """Extract the named members of ``path`` into ``dest`` (flat, prefixed)."""
    dest.mkdir(parents=True, exist_ok=True)
    produced: list[Path] = []
    if kind == "tar":
        with tarfile.open(path, "r:*") as t:
            for m in t.getmembers():
                if not m.isfile() or m.name not in names:
                    continue
                f = t.extractfile(m)
                if f is None:
                    continue
                out = dest / f"{idx:04d}_{_safe_name(m.name)}"
                with f:
                    _copy_capped(f, out)
                produced.append(out)
        return produced
    if kind == "zip":
        with zipfile.ZipFile(path) as z:
            for zi in z.infolist():
                if zi.is_dir() or zi.filename not in names:
                    continue
                if zi.flag_bits & 0x1:
                    raise Encrypted(zi.filename)
                with z.open(zi) as f:
                    out = dest / f"{idx:04d}_{_safe_name(zi.filename)}"
                    _copy_capped(f, out)
                produced.append(out)
        return produced
    opener = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}[kind]
    out = dest / f"{idx:04d}_{_safe_name(next(iter(names)))}"
    with opener(path, "rb") as f:  # type: ignore[operator]
        _copy_capped(f, out)
    produced.append(out)
    return produced


def peel(path: Path, workdir: Path,
         max_layers: int = MAX_LAYERS) -> tuple[list[str], list[Path]]:
    """Follow a chain of archives; return (layer_log, innermost_files).

    At each level the *largest archive member* is followed; a level with no
    archive member is the payload level, where every regular file is returned.
    Stops (returning what it has) when the chain is encrypted/unreadable.
    """
    layers: list[str] = []
    cur = path
    for i in range(max_layers):
        kind = _kind(cur)
        if kind is None:
            return layers, [cur]
        entries = _entries(cur, kind)
        files = [(n, sz) for (n, is_file, sz, _enc) in entries if is_file]
        archives = [f for f in files if _looks_like_archive(f[0])]
        try:
            if not archives:
                finals = _extract(cur, kind, {f[0] for f in files},
                                  workdir / f"L{i:04d}", i)
                return layers, finals or [cur]
            target = max(archives, key=lambda f: f[1])
            got = _extract(cur, kind, {target[0]}, workdir / f"L{i:04d}", i)
        except Encrypted:
            return layers, [cur]
        if not got:
            return layers, [cur]
        layers.append(f"L{i:04d}: {cur.name} -> {got[0].name}")
        cur = got[0]
    return layers, [cur]


class NestedArchiveAnalyzer(Analyzer):
    name = "nested-archive"
    category = "extract"
    description = "Unwrap deep chains of nested archives (like1000) in one pass."
    has_archive = True
    accepts = ARCHIVE_EXT
    display_order = 218

    def run(self, ctx: ToolContext) -> ToolResult:
        layers, finals = peel(ctx.input, ctx.sub(self.name))
        if not layers:
            return ToolResult(self.name, status="skipped", summary="not a nested chain")
        preview = ""
        for f in finals[:3]:
            try:
                data = f.read_bytes()[:20000]
            except OSError:
                continue
            preview += (f"\n== {f.name} ({len(data)} bytes) ==\n"
                        + data.decode("latin-1", "replace"))
        names = ", ".join(f.name for f in finals[:3])
        return ToolResult(
            self.name, status="done",
            output=("\n".join(layers) + "\n" + preview)[:60000],
            summary=f"{len(layers)} layers -> {names}",
            extracted=[str(f) for f in finals if f.is_file()],
            consumed=True,
        )


register(NestedArchiveAnalyzer())
