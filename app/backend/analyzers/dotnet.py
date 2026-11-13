""".NET/CLR assemblies: embedded managed resources extracted as child files.

`dnfile` parses the PE and the CLR metadata without executing anything. Every
``ManifestResource`` embedded in the assembly is written as a child named after
the resource, so the rest of the pipeline (binwalk, nested-archive, strings,
OCR…) recurses into it. A compressed resource is left as it is: gzip/deflate/zip
children are already decompressed downstream, so decompressing it here would
duplicate that work (and the bomb caps).

The gate is content-based: ``MZ`` + a PE optional header whose data directory
index 14 (the CLR header) is non-empty. Only the first 4 KB are read to decide.
"""
from __future__ import annotations

import struct
from pathlib import Path

from .. import storage
from .base import Analyzer, ToolContext, ToolResult
from .registry import register

try:                                   # pinned in app/backend/requirements.txt
    import dnfile
except ImportError:                    # pragma: no cover - the image ships it
    dnfile = None

_HEAD = 4096                           # DOS + COFF + optional header + directories
_MAX_INPUT = 256 << 20                 # dnfile keeps the whole file in memory
_MAX_RESOURCES = 100
_MAX_BYTES = 50 << 20
_DOTNET_EXT = (".dll", ".exe")
_DOTNET_MIME = ("x-dosexec", "x-msdownload", "vnd.microsoft.portable-executable",
                "application/x-dotnet")


def cli_directory(head: bytes) -> tuple[int, int] | None:
    """(rva, size) of the CLR header (data directory 14), or None.

    Everything comes from the bytes already read: DOS header -> e_lfanew at
    0x3c -> PE signature -> COFF -> optional header magic -> NumberOfRvaAndSizes
    -> the 15th data directory entry. PE32 and PE32+ are both handled.
    """
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if e_lfanew < 4 or e_lfanew + 24 > len(head):
        return None
    if head[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    opt = e_lfanew + 24
    if opt + 2 > len(head):
        return None
    magic = struct.unpack_from("<H", head, opt)[0]
    if magic == 0x10B:                 # PE32
        num_off, dirs_off = opt + 92, opt + 96
    elif magic == 0x20B:               # PE32+
        num_off, dirs_off = opt + 108, opt + 112
    else:
        return None
    if num_off + 4 > len(head):
        return None
    if struct.unpack_from("<I", head, num_off)[0] <= 14:
        return None                    # no CLR directory in this optional header
    entry = dirs_off + 14 * 8
    if entry + 8 > len(head):
        return None
    rva, size = struct.unpack_from("<II", head, entry)
    return (rva, size) if rva and size else None


def _load(path: Path):
    """The dnPE object (a small seam so the unit tests can mock dnfile)."""
    if dnfile is None:
        raise RuntimeError("dnfile not installed")
    return dnfile.dnPE(str(path))


def _row_name(row) -> str:
    name = getattr(row, "Name", None)
    return str(getattr(name, "value", name) or "")


def managed_resources(pe, max_resources: int | None = None,
                      max_bytes: int | None = None) -> list[tuple[str, bytes]]:
    """Embedded (name, raw bytes) resources, within the child/byte caps.

    External resources (``row.Implementation`` points at another file) are not
    in this assembly and are skipped. The 4-byte little-endian size that
    precedes each blob is checked against the remaining budget *before*
    ``get_data`` is asked for the data, so a huge resource is never read.
    """
    max_resources = _MAX_RESOURCES if max_resources is None else max_resources
    max_bytes = _MAX_BYTES if max_bytes is None else max_bytes
    net = getattr(pe, "net", None)
    table = getattr(getattr(net, "mdtables", None), "ManifestResource", None)
    rows = getattr(table, "rows", None) or []
    base = int(getattr(getattr(net, "struct", None), "ResourcesRva", 0))
    out: list[tuple[str, bytes]] = []
    total = 0
    for row in rows:
        if len(out) >= max_resources:
            break
        if getattr(row, "Implementation", None) is not None:
            continue
        rva = base + int(getattr(row, "Offset", 0) or 0)
        try:
            head = pe.get_data(rva, 4)
        except Exception:              # noqa: BLE001 - a broken row is not fatal
            continue
        if head is None or len(head) < 4:
            continue
        size = int.from_bytes(head[:4], "little")
        if size == 0 or size > max_bytes - total:
            continue                   # empty, or does not fit the remaining cap
        try:
            blob = pe.get_data(rva + 4, size)
        except Exception:              # noqa: BLE001
            continue
        if blob is None or len(blob) != size:
            continue
        out.append((_row_name(row) or f"resource{len(out)}", bytes(blob)))
        total += size
    return out


class DotNetAnalyzer(Analyzer):
    name = "dotnet"
    category = "elf"
    description = ".NET/CLR assembly: embedded managed resources extracted as files."
    accepts = _DOTNET_EXT + _DOTNET_MIME
    display_order = 269

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            size = ctx.input.stat().st_size
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        if size > _MAX_INPUT:
            return ToolResult(self.name, status="skipped",
                              summary=f"too large for the CLR parser ({size} B)")
        try:
            with open(ctx.input, "rb") as fh:
                head = fh.read(_HEAD)
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        if cli_directory(head) is None:
            return ToolResult(self.name, status="skipped",
                              summary="not a .NET assembly (no MZ/PE CLI header)")
        try:
            pe = _load(ctx.input)
        except Exception as exc:       # noqa: BLE001 - dnfile raises its own errors
            return ToolResult(self.name, status="skipped",
                              summary=f"CLR metadata unreadable: {exc}")
        if getattr(pe, "net", None) is None:
            return ToolResult(self.name, status="skipped", summary="no CLR metadata")
        found = managed_resources(pe)
        if not found:
            return ToolResult(self.name, status="skipped",
                              summary="no embedded managed resources")
        outdir = ctx.sub(self.name)
        outdir.mkdir(parents=True, exist_ok=True)
        used: set[str] = set()
        lines: list[str] = []
        extracted: list[str] = []
        artifacts: list[dict] = []
        for i, (name, blob) in enumerate(found):
            filename = storage.sanitize_name(name)
            if filename in used:       # two resource names differing only in unsafe chars
                stem, dot, ext = filename.rpartition(".")
                filename = (f"{stem or filename}_{i}" + (dot + ext if dot else ""))
            used.add(filename)
            dest = outdir / filename
            dest.write_bytes(blob)
            extracted.append(str(dest))
            artifacts.append({"name": str(dest.relative_to(ctx.workdir)),
                              "path": str(dest), "size": len(blob)})
            lines.append(f"{name}  {len(blob)} B -> {filename}")
        return ToolResult(self.name, status="done",
                          summary=f"{len(found)} managed resource(s)",
                          output="\n".join(lines)[:200_000],
                          extracted=extracted, artifacts=artifacts)


register(DotNetAnalyzer())
