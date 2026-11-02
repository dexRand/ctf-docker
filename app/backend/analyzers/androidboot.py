"""Android boot.img: kernel + ramdisk, with the ramdisk cpio unpacked.

The ramdisk is a (usually gzip) cpio "newc" archive with the init scripts and
the charger/recovery images; challenges hide the flag in one of those files
(BuckeyeCTF 2023 "replace-me": res/images/charger/battery_fail.png). Header
versions 0-2 (page-aligned, page size in the header) and 3-4 (4096-byte pages)
are read in-process; nothing is executed.
"""
from __future__ import annotations

import gzip
import io
import struct
from pathlib import Path

from .. import storage
from .base import Analyzer, ToolContext, ToolResult
from .registry import register

MAGIC = b"ANDROID!"
_MAX_RAMDISK = 256 << 20          # decompressed cap
_MAX_FILES = 3000


def _align(n: int, page: int) -> int:
    return (n + page - 1) // page * page


def parts(data: bytes) -> dict[str, bytes]:
    """{'kernel': ..., 'ramdisk': ..., 'second': ...} from a boot image."""
    version = struct.unpack_from("<I", data, 40)[0]
    if version >= 3:
        kernel_size, ramdisk_size = struct.unpack_from("<II", data, 8)
        page, second_size = 4096, 0
    else:
        kernel_size, _ka, ramdisk_size, _ra, second_size, _sa, _ta, page = \
            struct.unpack_from("<8I", data, 8)
        if page not in (2048, 4096, 8192, 16384):
            raise ValueError(f"bad page size {page}")
    off = page                                   # header occupies the first page
    out = {"kernel": data[off:off + kernel_size]}
    off += _align(kernel_size, page)
    out["ramdisk"] = data[off:off + ramdisk_size]
    off += _align(ramdisk_size, page)
    if second_size:
        out["second"] = data[off:off + second_size]
    return {k: v for k, v in out.items() if v}


def unpack_ramdisk(blob: bytes) -> bytes | None:
    """Raw cpio bytes of a gzip or uncompressed ramdisk (None: other codec)."""
    if blob[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(blob)) as gz:
            return gz.read(_MAX_RAMDISK + 1)[:_MAX_RAMDISK]
    if blob[:6] in (b"070701", b"070702"):
        return blob
    return None


def cpio_files(raw: bytes):
    """(path, data) for every regular file of a cpio newc archive."""
    off, count = 0, 0
    while off + 110 <= len(raw) and count < _MAX_FILES:
        if raw[off:off + 6] not in (b"070701", b"070702"):
            break
        f = [int(raw[off + 6 + 8 * i: off + 14 + 8 * i], 16) for i in range(13)]
        mode, filesize, namesize = f[1], f[6], f[11]
        name_start = off + 110
        name = raw[name_start:name_start + namesize - 1].decode("utf-8", "replace")
        data_start = (name_start + namesize + 3) & ~3
        data_end = data_start + filesize
        if name == "TRAILER!!!":
            break
        if mode & 0o170000 == 0o100000:          # regular files only
            yield name, raw[data_start:data_end]
            count += 1
        off = (data_end + 3) & ~3


class AndroidBootAnalyzer(Analyzer):
    name = "android-boot"
    category = "extract"
    description = "Android boot.img: kernel and ramdisk out, ramdisk cpio unpacked."
    accepts = (".img", "application/x-android-bootimg")
    display_order = 167

    def run(self, ctx: ToolContext) -> ToolResult:
        with open(ctx.input, "rb") as fh:
            if fh.read(8) != MAGIC:
                return ToolResult(self.name, status="skipped", summary="not an Android boot image")
            data = MAGIC + fh.read()
        try:
            pieces = parts(data)
        except (struct.error, ValueError) as exc:
            return ToolResult(self.name, status="skipped", summary=f"bad header: {exc}")
        outdir = ctx.sub(self.name)
        outdir.mkdir(parents=True, exist_ok=True)
        extracted: list[Path] = []
        lines: list[str] = []
        for part, blob in pieces.items():
            p = outdir / part
            p.write_bytes(blob)
            lines.append(f"{part}: {len(blob)} B")
        raw = unpack_ramdisk(pieces.get("ramdisk", b""))
        if raw is None and "ramdisk" in pieces:
            lines.append("ramdisk: codec not supported in-process (lz4/xz?): kept as a file")
            extracted.append(outdir / "ramdisk")
        elif raw:
            used: set[str] = set()
            for path, content in cpio_files(raw):
                name = storage.sanitize_name(path.replace("/", "__"))
                while name in used:
                    name = "_" + name
                used.add(name)
                dest = outdir / "ramdisk_files" / name
                dest.parent.mkdir(exist_ok=True)
                dest.write_bytes(content)
                extracted.append(dest)
                lines.append(f"  {path}  {len(content)} B")
        if "kernel" in pieces:
            extracted.append(outdir / "kernel")
        return ToolResult(self.name, status="done",
                          summary=f"{len(extracted)} file(s): " + ", ".join(pieces),
                          output="\n".join(lines[:4000]), extracted=[str(p) for p in extracted])


register(AndroidBootAnalyzer())
