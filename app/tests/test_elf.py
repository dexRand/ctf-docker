"""Unit tests for the pure-python ELF summary / checksec parser (no binaries)."""
from __future__ import annotations

import struct

from backend.analyzers.elf import elf_summary, is_elf

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
