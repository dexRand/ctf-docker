"""ELF analyzers (passive): structure + security features + readelf/objdump.

All pure-python for the summary/checksec/sections/dynamic (no dependency), then
optional ``readelf`` / ``objdump`` for the full detail (binutils). No execution
here: running the binary is the job of the separate `rev` container.
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
# section types worth naming (everything else is shown as its hex type)
_SHT = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
        6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 10: "SHLIB", 11: "DYNSYM",
        14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY", 18: "GROUP"}
_DT_NEEDED, _DT_SONAME, _DT_RPATH, _DT_RUNPATH = 1, 14, 15, 29
_DT_BIND_NOW, _DT_FLAGS, _DT_FLAGS_1 = 24, 30, 0x6FFFFFFB
_DF_BIND_NOW, _DF_1_NOW = 0x8, 0x1
_UPX_MAGIC = b"UPX!"


def is_elf(head: bytes) -> bool:
    return len(head) >= 4 and head[:4] == b"\x7fELF"


def _cstr(blob: bytes, off: int) -> str:
    if not blob or off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    return blob[off:end if end >= 0 else None].decode("latin-1", "replace")


def _parse_sections(data: bytes, shoff: int, shentsize: int, shnum: int,
                    shstrndx: int, endian: str, is64: bool) -> list[dict]:
    """Section headers with resolved names (empty when the file has no sections)."""
    if not shoff or not shnum or not shentsize:
        return []
    raw: list[tuple[int, int, int, int]] = []
    for i in range(shnum):
        off = shoff + i * shentsize
        try:
            if is64:
                sh_name, sh_type = struct.unpack_from(endian + "II", data, off)
                sh_offset = struct.unpack_from(endian + "Q", data, off + 24)[0]
                sh_size = struct.unpack_from(endian + "Q", data, off + 32)[0]
            else:
                sh_name, sh_type = struct.unpack_from(endian + "II", data, off)
                sh_offset = struct.unpack_from(endian + "I", data, off + 16)[0]
                sh_size = struct.unpack_from(endian + "I", data, off + 20)[0]
        except struct.error:
            break
        raw.append((sh_name, sh_type, sh_offset, sh_size))
    strtab = b""
    if 0 <= shstrndx < len(raw):
        _, _, so, ss = raw[shstrndx]
        strtab = data[so:so + ss]
    out: list[dict] = []
    for sh_name, sh_type, sh_offset, sh_size in raw:
        out.append({"name": _cstr(strtab, sh_name), "type": _SHT.get(sh_type, hex(sh_type)),
                    "size": sh_size, "offset": sh_offset})
    return out


def _dynamic_info(data: bytes, off: int, size: int, endian: str, is64: bool,
                  dynstr: bytes) -> dict:
    """DT_BIND_NOW + DT_NEEDED (libs) + SONAME + RPATH/RUNPATH."""
    info = {"bind_now": False, "needed": [], "soname": None, "rpath": None}
    entsize = 16 if is64 else 8
    for i in range(size // entsize):
        o = off + i * entsize
        try:
            if is64:
                tag, val = struct.unpack_from(endian + "QQ", data, o)
            else:
                tag, val = struct.unpack_from(endian + "II", data, o)
        except struct.error:
            break
        if tag == 0:  # DT_NULL
            break
        if tag == _DT_BIND_NOW or (tag == _DT_FLAGS and val & _DF_BIND_NOW) \
                or (tag == _DT_FLAGS_1 and val & _DF_1_NOW):
            info["bind_now"] = True
        elif tag == _DT_NEEDED:
            name = _cstr(dynstr, val)
            if name and name not in info["needed"]:
                info["needed"].append(name)
        elif tag == _DT_SONAME:
            info["soname"] = _cstr(dynstr, val)
        elif tag in (_DT_RPATH, _DT_RUNPATH):
            info["rpath"] = _cstr(dynstr, val)
    return info


def elf_summary(data: bytes) -> dict | None:
    """Parse header + program headers + sections + dynamic -> structure/checksec."""
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
            e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 58)
        else:
            e_entry, e_phoff = struct.unpack_from(endian + "II", data, 24)
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 42)
            e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 46)
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
    has_relro = nx = None
    rwx = 0
    dyn_off, dyn_size = 0, 0
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
        if p_type == 3 and out["interpreter"] is None:  # PT_INTERP
            out["interpreter"] = data[p_offset:p_offset + p_filesz].split(b"\x00")[0].decode("latin-1", "replace")
        elif name == "GNU_STACK":
            nx = not bool(p_flags & _PF_X)
        elif name == "GNU_RELRO":
            has_relro = True
        elif name == "DYNAMIC":
            dyn_off, dyn_size = p_offset, p_filesz
        # LOAD segment that is writable AND executable (a classic exploitation aid)
        if p_type == 1 and (p_flags & _PF_W) and (p_flags & _PF_X):
            rwx += 1

    sections = _parse_sections(data, e_shoff, e_shentsize, e_shnum, e_shstrndx, endian, is64)
    names = [s["name"] for s in sections]
    dynstr = b""
    for s in sections:
        if s["name"] == ".dynstr":
            dynstr = data[s["offset"]:s["offset"] + s["size"]]
            break
    dyn = _dynamic_info(data, dyn_off, dyn_size, endian, is64, dynstr) if (dyn_off and dyn_size) \
        else {"bind_now": False, "needed": [], "soname": None, "rpath": None}

    relro = "full" if (has_relro and dyn["bind_now"]) else ("partial" if has_relro else "none")
    packer = "UPX" if (any(n.startswith("UPX") for n in names) or _UPX_MAGIC in data[:4096]) else None
    out.update({
        "section_count": len(sections),
        "sections": [s for s in sections if s["name"]],   # named only (skip the NULL section)
        "stripped": (".symtab" not in names) if names else True,
        "static": out["interpreter"] is None,
        "libs": dyn["needed"],
        "soname": dyn["soname"],
        "rpath": dyn["rpath"],
        "rwx": rwx,
        "packer": packer,
        "debug": any(n.startswith(".debug") for n in names),
    })
    out["checksec"] = {
        "relro": relro,
        "canary": b"__stack_chk_fail" in data,
        "nx": nx,
        "pie": out["type"] == "DYN" and out["interpreter"] is not None,
        "fortify": b"__printf_chk" in data or b"__memcpy_chk" in data,
    }
    return out


def _libs_line(out: dict) -> str:
    if out["static"]:
        return "linking: static (no PT_INTERP)"
    libs = out["libs"]
    head = f"linking: dynamic · interpreter {out['interpreter']}"
    if libs:
        head += f" · libs ({len(libs)}): " + ", ".join(libs)
    if out["soname"]:
        head += f" · soname {out['soname']}"
    return head


class ElfAnalyzer(Analyzer):
    name = "elf"
    category = "elf"
    description = "ELF structure + security features (RELRO/Canary/NX/PIE/Fortify) + sections/dynamic."
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
            _libs_line(info),
            f"sections: {info['section_count']} · stripped={'yes' if info['stripped'] else 'no'}"
            + (" · debug=yes" if info["debug"] else "")
            + (f" · RWX segments={info['rwx']}" if info["rwx"] else ""),
            "segments: " + ", ".join(dict.fromkeys(info["segments"])),
        ]
        if info["packer"]:
            lines.insert(3, f"⚠ packer rilevato: {info['packer']}")
        if info["rpath"]:
            lines.insert(3, f"⚠ RPATH/RUNPATH: {info['rpath']}")
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
        proc = ctx.run(["readelf", "-W", "-h", "-l", "-S", "-s", "-d", "-r", "-n", "-V",
                        str(ctx.input)], timeout=120)
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
