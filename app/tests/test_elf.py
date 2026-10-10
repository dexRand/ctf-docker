"""Unit tests for the pure-python ELF summary / checksec parser (no binaries)."""
from __future__ import annotations

import struct

from backend.analyzers.elf import (
    _dyn_imports,
    _dynamic_info,
    _parse_sections,
    elf_summary,
    is_elf,
)

_IDENT64 = b"\x7fELF\x02\x01\x01\x00\x00" + b"\x00" * 7  # ELF64, little-endian


def _ehdr(e_type: int, e_machine: int, e_entry: int, e_phoff: int, e_phnum: int) -> bytes:
    return _IDENT64 + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, e_machine, 1, e_entry, e_phoff, 0, 0, 64, 56, e_phnum, 0, 0, 0)


def _phdr64(p_type: int, p_flags: int, p_offset: int, p_filesz: int) -> bytes:
    return struct.pack("<IIQQQQQQ", p_type, p_flags, p_offset, 0, 0, p_filesz, p_filesz, 1)


def _elf(phdrs: list[bytes], e_type: int = 3, trailer: bytes = b"") -> bytes:
    phoff = 64
    interp = b"/lib64/ld-linux-x86-64.so.2\x00"
    blobs = b"".join(phdrs)
    data = _ehdr(e_type, 0x3E, 0x401000, phoff, len(phdrs)) + blobs + interp + trailer
    return data


def test_is_elf() -> None:
    assert is_elf(b"\x7fELFrest")
    assert not is_elf(b"MZ\x90\x00")
    assert not is_elf(b"")
    assert elf_summary(b"not an elf") is None


def test_minimal_header() -> None:
    info = elf_summary(_ehdr(2, 0x3E, 0x401000, 0, 0))
    assert info is not None
    assert info["class"] == "ELF64"
    assert info["type"] == "EXEC"
    assert info["machine"] == "x86-64"
    assert info["entry"] == "0x401000"


def test_checksec_pie_nx_relro() -> None:
    interp_off = 64 + 3 * 56
    phdrs = [
        _phdr64(3, 4, interp_off, 28),        # PT_INTERP
        _phdr64(0x6474E551, 6, 0, 0),         # PT_GNU_STACK, R|W (no X) -> NX
        _phdr64(0x6474E552, 4, 0, 0),         # PT_GNU_RELRO
    ]
    info = elf_summary(_elf(phdrs))
    assert info is not None
    cs = info["checksec"]
    assert info["type"] == "DYN"
    assert info["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert cs["nx"] is True
    assert cs["pie"] is True
    assert cs["relro"] == "partial"
    assert cs["canary"] is False


def test_executable_stack_is_not_nx() -> None:
    phdrs = [_phdr64(0x6474E551, 7, 0, 0)]   # R|W|X -> executable stack
    info = elf_summary(_elf(phdrs, e_type=2))
    assert info is not None
    assert info["checksec"]["nx"] is False
    assert info["checksec"]["pie"] is False


def test_canary_and_fortify_strings() -> None:
    info = elf_summary(_elf([], trailer=b"\x00__stack_chk_fail\x00__printf_chk\x00"))
    assert info is not None
    assert info["checksec"]["canary"] is True
    assert info["checksec"]["fortify"] is True


def test_rwx_load_segment_and_static() -> None:
    assert elf_summary(_elf([_phdr64(1, 6, 0, 0)]))["rwx"] == 0        # LOAD R|W
    assert elf_summary(_elf([_phdr64(1, 7, 0, 0)]))["rwx"] == 1        # LOAD R|W|X
    info = elf_summary(_elf([]))
    assert info["static"] is True and info["libs"] == []
    assert info["stripped"] is True                                    # no .symtab


def test_upx_packer_magic() -> None:
    info = elf_summary(_elf([], trailer=b"....UPX!...."))
    assert info is not None
    assert info["packer"] == "UPX"
    assert elf_summary(_elf([]))["packer"] is None


def _shdr64(sh_name: int, sh_type: int, sh_offset: int, sh_size: int) -> bytes:
    return struct.pack("<IIQQQQIIQQ", sh_name, sh_type, 0, 0, sh_offset, sh_size, 0, 0, 0, 0)


def test_parse_sections_resolves_names_and_types() -> None:
    strtab = b"\x00.text\x00.dynstr\x00.shstrtab\x00"   # offsets 1 / 7 / 15
    shoff = 0x100
    shdrs = (_shdr64(0, 0, 0, 0)                       # NULL
             + _shdr64(1, 1, 0x1000, 0x20)              # .text  (PROGBITS)
             + _shdr64(7, 3, 0x2000, 0x10)              # .dynstr (STRTAB)
             + _shdr64(15, 3, 0, len(strtab)))          # .shstrtab
    buf = bytearray(shoff + len(shdrs))
    buf[:len(strtab)] = strtab
    buf[shoff:shoff + len(shdrs)] = shdrs
    secs = _parse_sections(bytes(buf), shoff, 64, 4, 3, "<", True)
    assert [s["name"] for s in secs] == ["", ".text", ".dynstr", ".shstrtab"]
    assert secs[1]["type"] == "PROGBITS" and secs[2]["type"] == "STRTAB"


def test_dynamic_info_needed_soname_rpath() -> None:
    dynstr = b"\x00libc.so.6\x00libm.so.6\x00mylib\x00/opt/lib\x00"  # 1 / 11 / 21 / 27
    entries = [
        struct.pack("<QQ", 1, 1),     # DT_NEEDED -> libc.so.6
        struct.pack("<QQ", 1, 11),    # DT_NEEDED -> libm.so.6
        struct.pack("<QQ", 14, 21),   # DT_SONAME -> mylib
        struct.pack("<QQ", 29, 27),   # DT_RUNPATH -> /opt/lib
        struct.pack("<QQ", 24, 0),    # DT_BIND_NOW
        struct.pack("<QQ", 0, 0),     # DT_NULL
    ]
    buf = b"".join(entries)
    info = _dynamic_info(buf, 0, len(buf), "<", True, dynstr)
    assert info["needed"] == ["libc.so.6", "libm.so.6"]
    assert info["soname"] == "mylib"
    assert info["rpath"] == "/opt/lib"
    assert info["bind_now"] is True


def test_dynamic_bind_now_sets_full_relro() -> None:
    interp_off = 64 + 3 * 56          # 3 phdrs -> interp sits right after them
    # DYNAMIC segment with a DT_BIND_NOW entry, placed right after the phdrs
    dyn_off = interp_off + 28
    dyn = struct.pack("<QQ", 24, 0) + struct.pack("<QQ", 0, 0)
    phdrs = [
        _phdr64(3, 4, interp_off, 28),                    # PT_INTERP
        _phdr64(2, 6, dyn_off, len(dyn)),                 # PT_DYNAMIC
        _phdr64(0x6474E552, 4, 0, 0),                     # PT_GNU_RELRO
    ]
    data = _elf(phdrs, trailer=dyn)
    info = elf_summary(data)
    assert info is not None
    assert info["checksec"]["relro"] == "full"
    assert info["checksec"]["bind_now"] is True


def test_dyn_imports_from_dynsym() -> None:
    dynstr = b"\x00gets\x00system\x00main\x00"          # 1 / 6 / 13
    sym = lambda off, shndx: struct.pack("<IBBHQQ", off, 0x12, 0, shndx, 0, 0)  # GLOBAL FUNC
    dynsym = sym(1, 0) + sym(6, 0) + sym(13, 1)          # gets/system undefined, main defined
    symtab_off = len(dynstr)
    buf = bytearray(symtab_off + len(dynsym))
    buf[:len(dynstr)] = dynstr
    buf[symtab_off:] = dynsym
    sections = [
        {"name": "", "offset": 0, "size": 0, "link": 0, "entsize": 0},
        {"name": ".dynsym", "offset": symtab_off, "size": len(dynsym), "link": 2, "entsize": 24},
        {"name": ".dynstr", "offset": 0, "size": len(dynstr), "link": 0, "entsize": 0},
    ]
    assert _dyn_imports(bytes(buf), sections, True, "<") == ["gets", "system"]


def _full_elf64(dynstr: bytes, dynsym: bytes, init_array: bytes) -> bytes:
    """Minimal ELF64 with .dynstr/.dynsym/.init_array/.shstrtab (for end-to-end)."""
    shstr = b"\x00.dynstr\x00.dynsym\x00.init_array\x00.shstrtab\x00"  # 1 / 9 / 17 / 29
    cur, body, off = 64 + 56, b"", {}
    for key, blob in (("dynstr", dynstr), ("dynsym", dynsym),
                      ("init_array", init_array), ("shstrtab", shstr)):
        off[key] = cur + len(body)
        body += blob
    shoff = cur + len(body)

    def shdr(name_off: int, type_: int, offset: int, size: int, link: int, entsize: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name_off, type_, 0, 0, offset, size, link, 0, 0, entsize)

    shdrs = (shdr(0, 0, 0, 0, 0, 0)                                   # NULL
             + shdr(1, 3, off["dynstr"], len(dynstr), 0, 0)           # .dynstr   (idx 1)
             + shdr(9, 11, off["dynsym"], len(dynsym), 1, 24)         # .dynsym -> .dynstr
             + shdr(17, 14, off["init_array"], len(init_array), 0, 8)  # .init_array
             + shdr(29, 3, off["shstrtab"], len(shstr), 0, 0))        # .shstrtab (idx 4)
    ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000,
                               64, shoff, 0, 64, 56, 1, 64, 5, 4)
    total = len(ehdr) + 56 + len(body) + len(shdrs)
    ph = struct.pack("<IIQQQQQQ", 1, 4, 0, 0x400000, 0x400000, total, total, 0x1000)
    return ehdr + ph + body + shdrs


def test_full_elf_imports_dangerous_and_init_array() -> None:
    dynstr = b"\x00gets\x00system\x00safe_fn\x00"       # 1 / 6 / 13
    dynsym = (struct.pack("<IBBHQQ", 1, 0x12, 0, 0, 0, 0)     # gets   (undefined)
              + struct.pack("<IBBHQQ", 6, 0x12, 0, 0, 0, 0)    # system (undefined)
              + struct.pack("<IBBHQQ", 13, 0x12, 0, 1, 0, 0))   # safe_fn (defined)
    init_array = struct.pack("<QQ", 0x401000, 0x401100)
    info = elf_summary(_full_elf64(dynstr, dynsym, init_array))
    assert info is not None
    assert info["imports"] == ["gets", "system"]
    assert info["dangerous"] == ["gets", "system"]
    assert info["init_array"] == 2
    assert info["checksec"]["bind_now"] is False
