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
_DT_PLTRELSZ, _DT_PLTREL, _DT_JMPREL = 2, 20, 23
_DT_BIND_NOW, _DT_FLAGS, _DT_FLAGS_1 = 24, 30, 0x6FFFFFFB
_DF_BIND_NOW, _DF_1_NOW = 0x8, 0x1
_UPX_MAGIC = b"UPX!"
# GNU property note (type NT_GNU_PROPERTY_TYPE_0 = 5): x86 / aarch64 feature bits
_NT_GNU_PROPERTY = 5
_PROP_FEAT1 = {0xC0000002: ("IBT", "SHSTK"), 0xC0000000: ("BTI", "PAC")}


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
    raw: list[tuple[int, int, int, int, int, int]] = []
    for i in range(shnum):
        off = shoff + i * shentsize
        try:
            if is64:
                sh_name, sh_type = struct.unpack_from(endian + "II", data, off)
                sh_offset, sh_size = struct.unpack_from(endian + "QQ", data, off + 24)
                sh_link, _sh_info = struct.unpack_from(endian + "II", data, off + 40)
                sh_entsize = struct.unpack_from(endian + "Q", data, off + 56)[0]
            else:
                sh_name, sh_type = struct.unpack_from(endian + "II", data, off)
                sh_offset, sh_size = struct.unpack_from(endian + "II", data, off + 16)
                sh_link, _sh_info = struct.unpack_from(endian + "II", data, off + 24)
                sh_entsize = struct.unpack_from(endian + "I", data, off + 36)[0]
        except struct.error:
            break
        raw.append((sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize))
    strtab = b""
    if 0 <= shstrndx < len(raw):
        so, ss = raw[shstrndx][2], raw[shstrndx][3]
        strtab = data[so:so + ss]
    return [{"name": _cstr(strtab, n), "type": _SHT.get(t, hex(t)), "type_id": t, "size": sz,
             "offset": o, "link": lk, "entsize": es}
            for n, t, o, sz, lk, es in raw]


def _dynamic_info(data: bytes, off: int, size: int, endian: str, is64: bool,
                  dynstr: bytes) -> dict:
    """DT_BIND_NOW + DT_NEEDED (libs) + SONAME + RPATH/RUNPATH."""
    info = {"bind_now": False, "needed": [], "soname": None, "rpath": None,
            "pltrelsz": 0, "pltrel": 0}
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
        elif tag == _DT_PLTRELSZ:
            info["pltrelsz"] = val
        elif tag == _DT_PLTREL:
            info["pltrel"] = val
    return info


# funczioni importate che in CTF/pwn valgono un'occhiata (overflow, format string,
# esecuzione di comandi, W^X…)
_DANGEROUS = ("gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
              "system", "popen", "execve", "execl", "execlp", "execvp", "execv",
              "mprotect", "memcpy", "strncpy")


def _dyn_imports(data: bytes, sections: list[dict], is64: bool, endian: str) -> list[str]:
    """Imported function names (undefined symbols in .dynsym) — i.e. the PLT/GOT."""
    sym = next((s for s in sections if s["name"] == ".dynsym" and s["entsize"]), None)
    if not sym:
        return []
    strtab = b""
    if 0 <= sym["link"] < len(sections):
        st = sections[sym["link"]]
        strtab = data[st["offset"]:st["offset"] + st["size"]]
    imports: list[str] = []
    for i in range(sym["size"] // sym["entsize"]):
        o = sym["offset"] + i * sym["entsize"]
        try:
            if is64:
                st_name, st_info, _st_other, st_shndx = struct.unpack_from(endian + "IBBH", data, o)
            else:
                st_name, _v, _sz, st_info, _st_other, st_shndx = struct.unpack_from(endian + "IIIBBH", data, o)
        except struct.error:
            break
        if st_shndx == 0 and (st_info & 0xF) == 2 and st_name:   # SHN_UNDEF + STT_FUNC
            name = _cstr(strtab, st_name)
            if name and name not in imports:
                imports.append(name)
    return imports


def _gnu_property_hardening(data: bytes, sections: list[dict], endian: str) -> list[str]:
    """Hardware hardening from ``.note.gnu.property``: CET (IBT/SHSTK) or BTI/PAC."""
    note = next((s for s in sections if s["name"] == ".note.gnu.property"), None)
    if not note:
        return []
    feats: list[str] = []
    off, end = note["offset"], note["offset"] + note["size"]
    while off + 12 <= end:
        try:
            namesz, descsz, ntype = struct.unpack_from(endian + "III", data, off)
        except struct.error:
            break
        off += 12 + ((namesz + 3) & ~3)
        desc = data[off:off + descsz]
        off += (descsz + 3) & ~3
        if ntype != _NT_GNU_PROPERTY:
            continue
        j = 0
        while j + 8 <= len(desc):
            pr_type, pr_datasz = struct.unpack_from(endian + "II", desc, j)
            j += 8
            val = desc[j:j + pr_datasz]
            j += (pr_datasz + 7) & ~7
            names = _PROP_FEAT1.get(pr_type)
            if names and len(val) >= 4:
                bits = struct.unpack_from(endian + "I", val, 0)[0]
                for bit, feat in enumerate(names):
                    if bits & (1 << bit) and feat not in feats:
                        feats.append(feat)
    return feats


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
        else {"bind_now": False, "needed": [], "soname": None, "rpath": None,
              "pltrelsz": 0, "pltrel": 0}

    relro = "full" if (has_relro and dyn["bind_now"]) else ("partial" if has_relro else "none")
    packer = "UPX" if (any(n.startswith("UPX") for n in names) or _UPX_MAGIC in data[:4096]) else None
    imports = _dyn_imports(data, sections, is64, endian)
    ptr = 8 if is64 else 4

    def _arr(section_name: str) -> int:
        s = next((x for x in sections if x["name"] == section_name), None)
        return (s["size"] // ptr) if s else 0

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
        "imports": imports,
        "dangerous": [i for i in imports if i in _DANGEROUS],
        "init_array": _arr(".init_array"),
        "fini_array": _arr(".fini_array"),
        "plt_relocs": (dyn["pltrelsz"] // (24 if dyn["pltrel"] == 7 else 16)) if dyn["pltrelsz"] else 0,
        "hardening": _gnu_property_hardening(data, sections, endian),
    })
    out["checksec"] = {
        "relro": relro,
        "canary": b"__stack_chk_fail" in data,
        "nx": nx,
        "pie": out["type"] == "DYN" and out["interpreter"] is not None,
        "fortify": b"__printf_chk" in data or b"__memcpy_chk" in data,
        "bind_now": bool(dyn["bind_now"]),
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
            f"Fortify={'yes' if cs['fortify'] else 'no'} · BIND_NOW={'yes' if cs['bind_now'] else 'no'}",
        ]
        if info["packer"]:
            lines.append(f"⚠ packer rilevato: {info['packer']}")
        if info["rpath"]:
            lines.append(f"⚠ RPATH/RUNPATH: {info['rpath']}")
        if info["dangerous"]:
            lines.append("⚠ import pericolosi: " + ", ".join(info["dangerous"]))
        if info["hardening"]:
            lines.append("hardening: " + ", ".join(info["hardening"]))
        lines.append(_libs_line(info))
        lines.append(
            f"sections: {info['section_count']} · stripped={'yes' if info['stripped'] else 'no'}"
            + (" · debug=yes" if info["debug"] else "")
            + (f" · init_array={info['init_array']}" if info["init_array"] else "")
            + (f" · PLT={info['plt_relocs']}" if info["plt_relocs"] else "")
            + (f" · RWX segments={info['rwx']}" if info["rwx"] else ""))
        imp = info["imports"]
        if imp:
            shown = ", ".join(imp[:24]) + (f" …(+{len(imp) - 24})" if len(imp) > 24 else "")
            lines.append(f"imports ({len(imp)}): {shown}")
        lines.append("segments: " + ", ".join(dict.fromkeys(info["segments"])))
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
