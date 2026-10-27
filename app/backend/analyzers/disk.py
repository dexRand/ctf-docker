"""Disk-image forensics with The Sleuth Kit (mmls / fls / icat).

Lists partitions and files, then extracts small text-like files (and files whose
name looks like a flag) as children so the rest of the pipeline (strings, OCR,
flag hunt) can read them. A `.gz` image is decompressed first.
"""
from __future__ import annotations

import gzip
import re
from pathlib import Path, PurePosixPath

from .base import Analyzer, ToolContext, ToolResult, run_cmd, which
from .registry import register
from .util import magic_ext, printable_ratio
from .. import storage

DISK_EXT = (".img", ".dd", ".raw", ".iso", ".vhd", ".vmdk", ".gz")
_MAX_FILES = 40
_MAX_FILE = 2 << 20          # 2 MB per extracted file
_MAX_CANDIDATES = 400
_MAX_LISTING = 20000

_FLS_RE = re.compile(r"^([rdv])/([rdv\-])[a-z\-/]*\s+\*?\s*(\d+):\s*(.*)$")
_MAX_IMAGE = 4 << 30          # 4 GiB: a bigger "disk image" is a decompression bomb
_HEAD = 1 << 17               # enough for the MBR/GPT and every FS superblock


def _looks_disk(head: bytes) -> bool:
    """MBR/GPT or a filesystem superblock in the first 128 KiB."""
    if len(head) >= 512 and head[510:512] == b"\x55\xaa":
        return True                                   # MBR boot signature
    checks = (
        (512, b"EFI PART"),                           # GPT
        (3, b"NTFS    "),                             # NTFS
        (54, b"FAT12"), (54, b"FAT16"), (82, b"FAT32"),  # FAT
        (1080, b"\x53\xef"),                          # ext2/3/4
        (0, b"XFSB"),                                 # XFS
        (65600, b"_BHRfS_M"),                         # btrfs
        (32769, b"CD001"),                            # ISO 9660
        (1024, b"H+"),                                # HFS+
        (0, b"QFI\xfb"),                              # qcow2
        (0, b"KDMV"), (0, b"# Disk DescriptorFile"),  # VMDK
        (0, b"conectix"),                             # VHD
        (64, b"<<< Oracle VM VirtualBox Disk Image >>>"),  # VDI
    )
    return any(len(head) >= off + len(sig) and head[off:off + len(sig)] == sig
               for off, sig in checks)


def _is_gzip(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"\x1f\x8b"
    except OSError:
        return False


def _decompress(ctx: ToolContext) -> Path | None:
    """`.gz` -> a plain image in the run's work dir (None when not gzip)."""
    if not _is_gzip(ctx.input):
        return None
    outdir = ctx.sub("disk")
    outdir.mkdir(parents=True, exist_ok=True)
    name = ctx.input.name
    if name.endswith(".gz"):
        name = name[:-3]
    dest = outdir / (name if name.endswith((".img", ".dd", ".raw", ".iso", ".vhd", ".vmdk"))
                     else name + ".img")
    try:
        with gzip.open(ctx.input, "rb") as src, open(dest, "wb") as out:
            head = src.read(_HEAD)
            if not _looks_disk(head):
                # most .gz files here are tar.gz/bombs: stop before unpacking
                out.close()
                dest.unlink(missing_ok=True)
                return None
            out.write(head)
            total = len(head)
            while chunk := src.read(1 << 20):
                total += len(chunk)
                if total > _MAX_IMAGE:
                    out.close()
                    dest.unlink(missing_ok=True)
                    return None
                out.write(chunk)
    except (OSError, EOFError):
        dest.unlink(missing_ok=True)
        return None
    return dest


def _partitions(image: Path) -> list[int]:
    proc = run_cmd(["mmls", str(image)], timeout=180)
    offs: list[int] = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[0].endswith(":"):
            continue
        if parts[1] in ("Meta", "-------") or parts[1].startswith("-"):
            continue
        try:
            offs.append(int(parts[2]))
        except (ValueError, IndexError):
            continue
    return offs


def _files_at(image: Path, offset: int) -> tuple[str, list[tuple[int, str]]]:
    proc = run_cmd(["fls", "-r", "-p", "-o", str(offset), str(image)], timeout=600)
    out = proc.stdout or ""
    files: list[tuple[int, str]] = []
    for line in out.splitlines():
        m = _FLS_RE.match(line.strip())
        if m and m.group(1) == "r":
            files.append((int(m.group(3)), m.group(4).strip()))
    return out, files


def _score(path: str) -> int:
    name = PurePosixPath(path).name.lower()
    s = 0
    if "flag" in name:
        s += 100
    if name in ("root.txt", "user.txt", "proof.txt"):
        s += 90
    if name in (".ash_history", ".bash_history", ".zsh_history") or "history" in name:
        s += 60
    if name.endswith((".enc", ".aes", ".encrypted", ".gpg", ".age")):
        s += 50
    if name.endswith((".txt", ".md", ".log", ".conf", ".json", ".sh", ".py")):
        s += 20
    return s


class DiskAnalyzer(Analyzer):
    name = "disk"
    category = "forensics"
    description = "Disk image (sleuthkit): list partitions/files and extract readable files."
    accepts = DISK_EXT
    display_order = 342

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("fls") or not which("icat"):
            return ToolResult(self.name, status="skipped", summary="sleuthkit not installed")
        image = ctx.input
        if image.suffix.lower() == ".gz" or _is_gzip(ctx.input):
            image = _decompress(ctx) or image
        if not image.is_file():
            return ToolResult(self.name, status="skipped", summary="cannot read image")

        listing_parts: list[str] = []
        tagged: list[tuple[int, int, int, str]] = []   # (score, offset, inode, path)
        seen: list[int] = []
        for off in (*(_partitions(image) or []), 0):
            if off in seen:
                continue
            out, found = _files_at(image, off)
            if not found:
                continue
            seen.append(off)
            listing_parts.append(f"[partition offset {off}] {len(found)} file(s)\n{out[:_MAX_LISTING]}")
            tagged.extend((_score(p), off, inode, p) for inode, p in found)
        if not tagged:
            return ToolResult(self.name, status="skipped", summary="no filesystem found")

        tagged.sort(key=lambda x: x[0], reverse=True)
        outdir = ctx.sub(self.name)
        outdir.mkdir(parents=True, exist_ok=True)
        produced: list[Path] = []
        for score, off, inode, path in tagged[:_MAX_CANDIDATES]:
            if len(produced) >= _MAX_FILES:
                break
            proc = run_cmd(["icat", "-o", str(off), str(image), str(inode)],
                           timeout=180, binary=True)
            data = proc.stdout or b""
            if not data or len(data) > _MAX_FILE:
                continue
            keep = (magic_ext(data) or printable_ratio(data) >= 0.85
                    or score >= 50 or data.startswith(b"Salted__"))
            if not keep:
                continue
            name = storage.sanitize_name(PurePosixPath(path).name or f"inode{inode}")
            dest = outdir / f"{inode:06d}__{name}"
            dest.write_bytes(data)
            produced.append(dest)

        head = "\n".join(listing_parts)[:_MAX_LISTING * 2]
        summary = f"{len(tagged)} file(s) over {len(seen)} partition(s), {len(produced)} extracted"
        return ToolResult(
            self.name, status="done", summary=summary, output=head,
            extracted=[str(p) for p in produced],
            artifacts=[{"name": p.name, "path": str(p), "size": p.stat().st_size} for p in produced],
        )


register(DiskAnalyzer())
