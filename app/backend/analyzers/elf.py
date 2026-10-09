"""ELF analyzers (passive): structure + security features + readelf/objdump.

All pure-python for the summary/checksec (no dependency), then optional
``readelf`` / ``objdump`` for the full detail (binutils). No execution here:
running the binary is the job of the separate `rev` container.
"""
from __future__ import annotations

import struct

from .base import Analyzer, ToolContext, ToolResult, which, out_of
from .registry import register

ELF_EXT = (".elf", ".so")
ELF_MIME = ("x-executable", "x-sharedlib", "x-pie-executable", "application/x-elf")

_PT = {1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS",
       0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO",
       0x6474E553: "GNU_PROPERTY"}
_PF_X, _PF_W, _PF_R = 1, 2, 4
_EM = {3: "x86", 8: "MIPS", 0x14: "PowerPC", 0x28: "ARM", 0x3E: "x86-64",
       0xB7: "AArch64", 0xF3: "RISC-V", 0x102: "LoongArch"}
_ETYPE = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
_DT_BIND_NOW, _DT_FLAGS, _DT_FLAGS_1 = 24, 30, 0x6FFFFFFB
_DF_BIND_NOW, _DF_1_NOW = 0x8, 0x1


def is_elf(head: bytes) -> bool:
    return len(head) >= 4 and head[:4] == b"\x7fELF"


def elf_summary(data: bytes) -> dict | None:
    """Parse the ELF header + program headers -> structure and checksec flags."""
    if not is_elf(data):
        return None
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    is64 = ei_class == 2
    endian = "<" if ei_data == 1 else ">"
    try:
        e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
        if is64:
            e_entry, e_phoff = struct.unpack_from(endian + "QQ", data, 24)
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 54)
        else:
            e_entry, e_phoff = struct.unpack_from(endian + "II", data, 24)
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 42)
    except struct.error:
        return None

    out = {
        "class": "ELF64" if is64 else "ELF32",
        "endianness": "little" if ei_data == 1 else "big",
        "type": _ETYPE.get(e_type, str(e_type)),
        "machine": _EM.get(e_machine, hex(e_machine)),
        "entry": hex(e_entry),
        "interpreter": None,
        "segments": [],
    }
    has_relro = nx = bind_now = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        try:
            if is64:
                p_type, p_flags = struct.unpack_from(endian + "II", data, off)
                p_offset = struct.unpack_from(endian + "Q", data, off + 8)[0]
                p_filesz = struct.unpack_from(endian + "Q", data, off + 32)[0]
            else:
                p_type = struct.unpack_from(endian + "I", data, off)[0]
                p_offset = struct.unpack_from(endian + "I", data, off + 4)[0]
                p_filesz = struct.unpack_from(endian + "I", data, off + 16)[0]
                p_flags = struct.unpack_from(endian + "I", data, off + 24)[0]
        except struct.error:
            break
        name = _PT.get(p_type, hex(p_type))
        out["segments"].append(name)
        if p_type == 3 and out["interpreter"] is None:
            out["interpreter"] = data[p_offset:p_offset + p_filesz].split(b"\x00")[0].decode("latin-1", "replace")
        elif name == "GNU_STACK":
            nx = not bool(p_flags & _PF_X)
        elif name == "GNU_RELRO":
            has_relro = True
        elif name == "DYNAMIC" and p_filesz:
            bind_now = _dynamic_bind_now(data, p_offset, p_filesz, endian, is64)

    relro = "none"
    if has_relro:
        relro = "full" if bind_now else "partial"
    out["checksec"] = {
        "relro": relro,
        "canary": b"__stack_chk_fail" in data,
        "nx": nx,
        "pie": out["type"] == "DYN" and out["interpreter"] is not None,
        "fortify": b"__printf_chk" in data or b"__memcpy_chk" in data,
    }
    return out


def _dynamic_bind_now(data: bytes, off: int, size: int, endian: str, is64: bool) -> bool:
    entsize = 16 if is64 else 8
    for i in range(size // entsize):
        o = off + i * entsize
        try:
            if is64:
                tag, val = struct.unpack_from(endian + "QQ", data, o)
            else:
                tag, val = struct.unpack_from(endian + "II", data, o)
        except struct.error:
            return False
        if tag == 0:  # DT_NULL
            break
        if tag == _DT_BIND_NOW:
            return True
        if tag == _DT_FLAGS and (val & _DF_BIND_NOW):
            return True
        if tag == _DT_FLAGS_1 and (val & _DF_1_NOW):
            return True
    return False


class ElfAnalyzer(Analyzer):
    name = "elf"
    category = "elf"
    description = "ELF structure + security features (RELRO/Canary/NX/PIE/Fortify)."
    accepts = ELF_EXT + ELF_MIME
    display_order = 270

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            head = ctx.input.read_bytes()[:8_000_000]
        except OSError as exc:
            return ToolResult(self.name, status="error", summary=f"cannot read: {exc}")
        info = elf_summary(head)
        if not info:
            return ToolResult(self.name, status="skipped", summary="not an ELF file")
        cs = info["checksec"]
        yn = lambda v: "yes" if v else ("no" if v is False else "?")  # noqa: E731
        lines = [
            f"{info['class']} {info['endianness']}-endian {info['type']} {info['machine']}",
            f"entry {info['entry']}" + (f" · interpreter {info['interpreter']}" if info["interpreter"] else ""),
            "checksec: "
            f"RELRO={cs['relro']} · Canary={'yes' if cs['canary'] else 'no'} · "
            f"NX={yn(cs['nx'])} · PIE={'yes' if cs['pie'] else 'no'} · "
            f"Fortify={'yes' if cs['fortify'] else 'no'}",
            "segments: " + ", ".join(dict.fromkeys(info["segments"])),
        ]
        return ToolResult(self.name, status="done", output="\n".join(lines),
                          summary=f"{info['class']} {info['type']} {info['machine']}")


class ReadelfAnalyzer(Analyzer):
    name = "readelf"
    category = "elf"
    description = "ELF headers/sections/symbols/relocations (readelf)."
    accepts = ELF_EXT + ELF_MIME
    display_order = 271

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("readelf"):
            return ToolResult(self.name, status="skipped", summary="readelf not installed")
        proc = ctx.run(["readelf", "-h", "-l", "-S", "-s", "-d", "-r", "-n", str(ctx.input)], timeout=120)
        out = out_of(proc)
        if proc.returncode != 0 and not out:
            return ToolResult(self.name, status="error", summary="readelf failed", output=out[-8000:],
                              exit_code=proc.returncode)
        if len(out) > 40000:
            out = out[:40000] + f"\n… [truncated {len(out) - 40000} chars]"
        return ToolResult(self.name, status="done", output=out, summary="readelf ok")


class ObjdumpAnalyzer(Analyzer):
    name = "objdump"
    category = "elf"
    description = "Disassembly (objdump -d, Intel syntax)."
    accepts = ELF_EXT + ELF_MIME
    display_order = 272

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("objdump"):
            return ToolResult(self.name, status="skipped", summary="objdump not installed")
        proc = ctx.run(["objdump", "-d", "-M", "intel", str(ctx.input)], timeout=180)
        out = out_of(proc)
        if not out:
            return ToolResult(self.name, status="error", summary="objdump failed", exit_code=proc.returncode)
        total = len(out)
        if total > 60000:
            out = out[:60000] + f"\n… [truncated {total - 60000} chars of disassembly]"
        return ToolResult(self.name, status="done", output=out, summary=f"disassembly ({total} chars)")


register(ElfAnalyzer())
register(ReadelfAnalyzer())
register(ObjdumpAnalyzer())
