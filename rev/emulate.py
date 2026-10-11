#!/usr/bin/env python3
"""emulate — run a self-contained x86-64 function with Unicorn.

Calls a function inside an ELF/PE (or a raw code blob), passes integer
arguments through the System V AMD64 registers (rdi, rsi, rdx, rcx, r8, r9),
and prints the return value (rax). Handy for reversing custom hash / crypto /
deobfuscation routines without re-implementing them by hand.

Only **self-contained** functions work: imports (PLT/IAT stubs) are not
resolved, so a call into libc / KERNEL32 stops with an "unmapped" error. That is
exactly the case for the small signature/KDF helpers these challenges hide.

Examples
--------
  # ELF symbol: call secret_hash(buf, 4)
  emulate BIN --func secret_hash --argbuf 41424344 --arg 4

  # brute-force the first argument until the return value matches
  emulate BIN --func check --brute 0:100000 --expected 0xdeadbeef

  # sweep a small list instead of a range
  emulate BIN --func check --brute 1,2,0x41,0x1337 --expected 42

  # raw code blob (its own base)
  emulate blob.bin --raw --arg 1 --arg 2

  # PIE ELF: --func auto-relocates; --vaddr is the objdump offset
  emulate BIN --func f --vaddr 0x1149 --arg 3

  # dump 16 bytes the routine wrote at 0x2000
  emulate BIN --func f --arg 1 --mem 0x2000:16

Arguments
---------
  --func NAME     resolve an ELF function symbol (static or dynamic)
  --addr ADDR     absolute entry address
  --vaddr ADDR    entry address relative to the load base (objdump style)
  --arg VALUE     positional arg (hex 0x.. or decimal): rdi,rsi,rdx,rcx,r8,r9
  --argbuf HEX    map these bytes and pass their address as the next argument
  --base ADDR     load base for PIE ELF / raw blob (default 0x1000000)
  --steps N       instruction budget (default 1000000)
  --mem ADDR:LEN  hex-dump LEN bytes at ADDR after the call
  --brute RANGE   sweep the FIRST argument (START:END[:STEP] or a comma list)
  --expected V    with --brute: stop at the first candidate whose rax == V
  --expected-mem A:L:H   with --brute: stop when that memory window matches
  --json          emit a JSON result
  --raw           treat the file as a flat code blob

Command-line args are assigned in order; --argbuf pointers come first (so
`--func f --argbuf 41 --arg 1` gives rdi=&buf, rsi=1). ELF/raw use the System V
AMD64 registers (rdi, rsi, rdx, rcx, r8, r9); PE uses the Microsoft x64
registers (rcx, rdx, r8, r9, and only the first four arguments).
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import time

try:
    from unicorn import (
        Uc, UcError, UC_ARCH_X86, UC_MODE_64,
        UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL,
    )
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    )
except ImportError:  # pragma: no cover
    sys.exit("emulate: the 'unicorn' python package is required (it ships with pwntools)")

PAGE = 0x1000
# ELF / raw use System V AMD64 (rdi,rsi,rdx,rcx,r8,r9);
# PE uses the Microsoft x64 convention (rcx,rdx,r8,r9) — first four args.
ARG_REGS_SYSV = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                 UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
ARG_REGS_MS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]

# general-purpose registers zeroed between brute-force runs (rsp is set last)
GP_REGS = [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
           UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP,
           UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
           UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]

STACK_BASE = 0x7FFF_0000_0000
STACK_SIZE = 0x10_0000
SENTINEL = 0x7FFF_1000_0000          # functions "return" here; we stop on entry
SCRATCH = 0x3000_0000_0000           # scratch pages handed to --argbuf

DEFAULT_BASE = 0x1000000
ELF_EXEC, ELF_DYN = 2, 3
PT_LOAD = 1
SHT_SYMTAB, SHT_DYNSYM = 2, 11


def die(msg: str) -> "NoReturn":  # noqa: F821
    sys.exit(f"emulate: {msg}")


def align_down(x: int) -> int:
    return x & ~(PAGE - 1)


def align_up(x: int) -> int:
    return (x + PAGE - 1) & ~(PAGE - 1)


class Image:
    def __init__(self, segments, load_base, default_entry, symbols):
        self.segments = segments            # list[(addr, bytes, perms)]
        self.load_base = load_base          # added for --vaddr
        self.default_entry = default_entry
        self.symbols = symbols              # {name: absolute addr}


def load_elf(data: bytes, base: int) -> Image:
    e_type = struct.unpack_from("<H", data, 16)[0]
    e_entry = struct.unpack_from("<Q", data, 24)[0]
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    e_shnum = struct.unpack_from("<H", data, 60)[0]

    is_dyn = e_type == ELF_DYN
    load_base = base if is_dyn else 0

    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _al = \
            struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type != PT_LOAD or p_memsz == 0:
            continue
        chunk = bytearray(data[p_offset:p_offset + p_filesz])
        if p_memsz > len(chunk):
            chunk += b"\x00" * (p_memsz - len(chunk))
        perms = 0
        if p_flags & 1:
            perms |= UC_PROT_READ
        if p_flags & 2:
            perms |= UC_PROT_WRITE
        if p_flags & 4:
            perms |= UC_PROT_EXEC
        segments.append((load_base + p_vaddr, bytes(chunk), perms or UC_PROT_ALL))

    sections = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
                for i in range(e_shnum)]
    symbols: dict[str, int] = {}
    for _name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link, _info, _align, sh_entsize in sections:
        if sh_type not in (SHT_SYMTAB, SHT_DYNSYM) or sh_entsize == 0 or sh_link >= len(sections):
            continue
        str_off = sections[sh_link][4]
        for j in range(sh_size // sh_entsize):
            st_name, _info, _other, _shndx, st_value, _size = \
                struct.unpack_from("<IBBHQQ", data, sh_offset + j * sh_entsize)
            if st_name == 0 or st_value == 0:
                continue
            end = data.index(b"\x00", str_off + st_name)
            symbols.setdefault(data[str_off + st_name:end].decode("latin1"),
                               load_base + st_value)

    return Image(segments, load_base, load_base + e_entry, symbols)


def load_pe(data: bytes, base: int) -> Image:
    if data[:2] != b"MZ":
        die("not a PE (missing MZ)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        die("not a PE (missing signature)")
    coff = e_lfanew + 4
    machine, nsec, _ts, _sym, _nsym, optsize, _chars = struct.unpack_from("<HHIIIHH", data, coff)
    if machine != 0x8664:
        die(f"PE machine 0x{machine:04x} is not x86-64 (0x8664)")
    opt = coff + 20
    if struct.unpack_from("<H", data, opt)[0] != 0x20B:
        die("only PE32+ (64-bit) is supported")
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
    entry_rva = struct.unpack_from("<I", data, opt + 16)[0]

    segments = [(image_base, data[:size_of_headers], UC_PROT_ALL)]
    sec = opt + optsize
    for i in range(nsec):
        o = sec + i * 40
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        perms = 0
        if chars & 0x40000000:
            perms |= UC_PROT_READ
        if chars & 0x80000000:
            perms |= UC_PROT_WRITE
        if chars & 0x20000000:
            perms |= UC_PROT_EXEC
        chunk = bytearray(data[rawptr:rawptr + rawsize])
        if max(vsize, rawsize) > len(chunk):
            chunk += b"\x00" * (max(vsize, rawsize) - len(chunk))
        segments.append((image_base + vaddr, bytes(chunk), perms or UC_PROT_ALL))

    return Image(segments, image_base, image_base + entry_rva, {})


def load_raw(data: bytes, base: int) -> Image:
    return Image([(base, data, UC_PROT_ALL)], base, base, {})


def detect_and_load(path: str, base, force_raw: bool):
    data = open(path, "rb").read()
    if not force_raw and data[:4] == b"\x7fELF":
        if data[4] != 2 or data[5] != 1:
            die("only 64-bit little-endian ELF is supported")
        e_type = struct.unpack_from("<H", data, 16)[0]
        if base is None:
            base = DEFAULT_BASE if e_type == ELF_DYN else 0
        return load_elf(data, base), "elf"
    if not force_raw and data[:2] == b"MZ":
        return load_pe(data, base if base is not None else 0), "pe"
    return load_raw(data, base if base is not None else DEFAULT_BASE), "raw"


class Emulator:
    def __init__(self, img: Image):
        self.img = img
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self._mapped: set[int] = set()
        self._writable: list[tuple[int, bytes]] = []
        for addr, chunk, perms in img.segments:
            self._map(addr, chunk, perms)
            if perms & UC_PROT_WRITE:
                self._writable.append((addr, chunk))
        self._map(SENTINEL, b"\xc3", UC_PROT_ALL)          # return trap
        self._map(STACK_BASE, b"\x00" * STACK_SIZE, UC_PROT_ALL)
        self.rsp0 = STACK_BASE + STACK_SIZE - 0x1000 - 8   # %16 == 8 at entry
        self._scratch_next = SCRATCH
        self.reset()

    def reset(self) -> None:
        """Restore the image (+ stack) to its initial state for a fresh call.

        Cheap enough to reuse one emulator across a brute-force sweep instead of
        rebuilding it (which costs ~25 ms per call)."""
        for addr, chunk in self._writable:
            if chunk:
                self.uc.mem_write(addr, chunk)
        self.uc.mem_write(STACK_BASE, b"\x00" * STACK_SIZE)
        for reg in GP_REGS:
            self.uc.reg_write(reg, 0)
        self.uc.reg_write(UC_X86_REG_RSP, self.rsp0)
        self.uc.mem_write(self.rsp0, struct.pack("<Q", SENTINEL))
        self._scratch_next = SCRATCH

    def _map(self, addr: int, chunk: bytes, perms: int) -> None:
        for page in range(align_down(addr), align_up(addr + max(len(chunk), 1)), PAGE):
            if page in self._mapped:
                continue
            try:
                self.uc.mem_map(page, PAGE, perms)
            except UcError:
                pass
            self._mapped.add(page)
        if chunk:
            self.uc.mem_write(addr, chunk)

    def argbuf(self, hexstr: str) -> int:
        try:
            raw = bytes.fromhex(hexstr.replace(" ", ""))
        except ValueError:
            die(f"--argbuf is not hex: {hexstr!r}")
        addr = self._scratch_next
        self._scratch_next = align_up(addr + max(len(raw), 1)) + PAGE
        self._map(addr, raw, UC_PROT_ALL)
        return addr

    def run(self, entry: int, args: list[int], steps: int, arg_regs, quiet: bool = False):
        for reg, val in zip(arg_regs, args):
            self.uc.reg_write(reg, val & 0xFFFFFFFFFFFFFFFF)
        try:
            self.uc.emu_start(entry, SENTINEL, timeout=0, count=steps)
        except UcError as exc:
            if quiet:
                return None
            die(f"emulation stopped: {exc}. An unmapped address usually means an "
                f"import (PLT/IAT) call — only self-contained functions run here.")
        return self.uc.reg_read(UC_X86_REG_RAX)

    def read(self, addr: int, length: int) -> bytes:
        return bytes(self.uc.mem_read(addr, length))


def parse_brute(spec: str):
    """--brute accepts START:END[:STEP] or a comma/space separated list."""
    spec = spec.strip()
    if "," in spec:
        return [int(t, 0) for t in spec.split(",") if t.strip()]
    if ":" in spec:
        parts = spec.split(":")
        start, end = int(parts[0], 0), int(parts[1], 0)
        step = int(parts[2], 0) if len(parts) > 2 and parts[2] else 1
        return range(start, end, step if step > 0 else 1)
    die("--brute expects START:END[:STEP] or a comma-separated list")


def parse_expected_mem(spec: str):
    """--expected-mem is ADDR:LEN:HEX."""
    parts = spec.split(":")
    if len(parts) != 3:
        die("--expected-mem expects ADDR:LEN:HEX")
    try:
        return int(parts[0], 0), int(parts[1], 0), bytes.fromhex(parts[2].replace(" ", ""))
    except ValueError:
        die("--expected-mem expects ADDR:LEN:HEX")


def printable(value: int) -> str:
    raw = value.to_bytes(8, "little").rstrip(b"\x00")
    if raw and all(0x20 <= c < 0x7F for c in raw):
        return f"  {raw.decode('latin1')!r}"
    return ""


def brute(img: Image, entry: int, arg_regs, a) -> int:
    if a.expected is None and not a.expected_mem:
        die("--brute needs --expected (rax) and/or --expected-mem")
    cands = parse_brute(a.brute)
    expmem = parse_expected_mem(a.expected_mem) if a.expected_mem else None
    mask = 0xFFFFFFFFFFFFFFFF
    t0 = time.time()
    n = 0
    emu = Emulator(img)
    for x in cands:
        n += 1
        emu.reset()
        ptrs = [emu.argbuf(h) for h in a.argbuf]
        args = ptrs + [x] + list(a.arg)
        rax = emu.run(entry, args, a.steps, arg_regs, quiet=True)
        if rax is None:
            continue
        hit = a.expected is not None and (rax & mask) == (a.expected & mask)
        if expmem is not None:
            try:
                if emu.read(expmem[0], expmem[1]) == expmem[2]:
                    hit = True
            except Exception:
                pass
        if hit:
            dt = time.time() - t0
            print(f"match  arg=0x{x:x} ({x}){printable(x)}")
            print(f"rax    0x{rax:x}  ({rax})")
            for spec in a.mem:
                if ":" in spec:
                    sa, sl = spec.split(":", 1)
                    try:
                        print(f"mem 0x{int(sa, 0):x} {emu.read(int(sa, 0), int(sl, 0)).hex()}")
                    except Exception:
                        pass
            print(f"# {n} candidati in {dt:.2f}s")
            return 0
        if n % 20000 == 0:
            print(f"# … {n} candidati ({time.time() - t0:.0f}s)", file=sys.stderr)
    print(f"nessun match su {n} candidati ({time.time() - t0:.1f}s)", file=sys.stderr)
    return 1


def main(argv) -> int:
    ap = argparse.ArgumentParser(prog="emulate",
                                 description="Run a self-contained x86-64 function with Unicorn.")
    ap.add_argument("binary", help="ELF / PE / raw code blob")
    ap.add_argument("--func", help="ELF function symbol to call")
    ap.add_argument("--addr", type=lambda s: int(s, 0), help="absolute entry address")
    ap.add_argument("--vaddr", type=lambda s: int(s, 0),
                    help="entry address relative to the load base")
    ap.add_argument("--arg", action="append", default=[], type=lambda s: int(s, 0),
                    help="positional integer argument (rdi,rsi,rdx,rcx,r8,r9)")
    ap.add_argument("--argbuf", action="append", default=[],
                    help="map hex bytes and pass their address as the next argument")
    ap.add_argument("--base", type=lambda s: int(s, 0), default=None,
                    help="load base for PIE ELF / raw blob (default 0x1000000)")
    ap.add_argument("--steps", type=lambda s: int(s, 0), default=1_000_000)
    ap.add_argument("--mem", action="append", default=[], help="ADDR:LEN hex-dump after the call")
    ap.add_argument("--brute", metavar="RANGE",
                    help="sweep the FIRST argument (START:END[:STEP] or a comma list)")
    ap.add_argument("--expected", type=lambda s: int(s, 0), metavar="VALUE",
                    help="with --brute: stop when rax == VALUE")
    ap.add_argument("--expected-mem", metavar="ADDR:LEN:HEX",
                    help="with --brute: stop when that memory window matches")
    ap.add_argument("--raw", action="store_true", help="force raw blob mode")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    img, kind = detect_and_load(a.binary, a.base, a.raw)

    if a.func:
        if a.func not in img.symbols:
            die(f"symbol {a.func!r} not found (stripped? use --addr/--vaddr)")
        entry = img.symbols[a.func]
    elif a.addr is not None:
        entry = a.addr
    elif a.vaddr is not None:
        entry = img.load_base + a.vaddr
    else:
        entry = img.default_entry

    arg_regs = ARG_REGS_MS if kind == "pe" else ARG_REGS_SYSV

    if a.brute:
        return brute(img, entry, arg_regs, a)

    emu = Emulator(img)
    ptrs = [emu.argbuf(h) for h in a.argbuf]
    args = ptrs + list(a.arg)
    rax = emu.run(entry, args, a.steps, arg_regs)

    mem = []
    for spec in a.mem:
        if ":" not in spec:
            die(f"--mem expects ADDR:LEN, got {spec!r}")
        sa, sl = spec.split(":", 1)
        addr, length = int(sa, 0), int(sl, 0)
        mem.append((addr, emu.read(addr, length).hex()))

    if a.json:
        print(json.dumps({"format": kind, "entry": entry, "load_base": img.load_base,
                          "argbuf": ptrs, "args": args, "rax": rax, "mem": mem}, indent=2))
        return 0

    print(f"format     {kind}")
    print(f"entry      0x{entry:x}")
    if img.load_base:
        print(f"load base  0x{img.load_base:x}")
    if ptrs:
        print("argbuf     " + " ".join(f"0x{p:x}" for p in ptrs))
    print(f"rax        0x{rax:x}  ({rax})")
    for addr, hexs in mem:
        print(f"mem 0x{addr:x} {hexs}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except BrokenPipeError:
        sys.exit(0)
