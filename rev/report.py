#!/usr/bin/env python3
"""rev-report — first-pass reversing report for a binary (ELF / PE / APK / other).

Runs the passive checks you would otherwise type one by one — type, hashes,
hardening, headers, sections/segments, imports, interesting strings, packer —
and, unless --fast, a Ghidra headless decompile. Writes a Markdown report to
./reports/ (visible in FileBrowser) and prints the path.

It is a *starting point*, not a solver: it removes the boilerplate so the real
analysis (and tools like `emulate`/angr) starts from facts instead of from zero.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

FLAG = re.compile(rb"[A-Za-z0-9_]{2,}\{[^}\n]{3,}\}")
INTERESTING = re.compile(rb"flag|secret|passw|token|api[_-]?key|/bin/|https?://|ssh|admin|\.onion", re.I)
DANGEROUS = {
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf", "system",
    "popen", "execve", "execl", "execlp", "execvp", "memcpy", "memmove", "alloca",
    "strncpy", "realpath", "getwd", "mktemp", "tmpnam", "printf", "fprintf",
}
LINE_CAP = 400


def run(cmd: list[str], timeout: int = 180) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return f"(strumento assente: {cmd[0]})"
    except subprocess.TimeoutExpired:
        return f"(timeout: {' '.join(cmd[:2])})"
    out = p.stdout or ""
    err = p.stderr or ""
    # many tools log to stderr (e.g. pwntools' checksec); prefer it when stdout is empty
    if not out.strip() and err.strip():
        out = err
    elif p.returncode != 0 and err.strip():
        out += "\n[stderr]\n" + err.strip()
    return out


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def cap(text: str, n: int = LINE_CAP) -> str:
    lines = text.rstrip("\n").splitlines()
    if len(lines) > n:
        return "\n".join(lines[:n]) + f"\n… (+{len(lines) - n} righe)"
    return "\n".join(lines)


def hashes(path: str) -> dict[str, str]:
    h = {a: hashlib.new(a) for a in ("md5", "sha1", "sha256")}
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            for d in h.values():
                d.update(chunk)
    return {k: v.hexdigest() for k, v in h.items()}


def kind(path: str) -> str:
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ":
        return "pe"
    if head[:2] == b"PK":
        return "zip"
    return "other"


def string_hits(path: str) -> tuple[list[bytes], list[bytes], int]:
    total = 0
    flags: list[bytes] = []
    interesting: list[bytes] = []
    try:
        raw = subprocess.run(["strings", "-a", "-n", "6", path], capture_output=True, timeout=120).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return [], [], 0
    for line in raw.splitlines():
        total += 1
        if len(flags) < 50 and FLAG.search(line):
            flags.append(line)
        if len(interesting) < 120 and INTERESTING.search(line):
            interesting.append(line)
    return flags, interesting, total


def packer(path: str, info: str) -> str:
    notes = []
    if "upx" in info.lower():
        notes.append("rabin2 segnala UPX")
    if have("upx"):
        out = run(["upx", "-t", path], timeout=30)
        if "packed" in out.lower() and "not packed" not in out.lower():
            notes.append("upx -t: " + out.strip().splitlines()[-1] if out.strip() else "upx -t: packed")
    return "; ".join(notes) if notes else "nessun packer noto"


def parse_kv(text: str) -> dict:
    """rabin2 -I prints 'key<pad>value' lines; keep the ones we summarise."""
    out = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            out[parts[0]] = parts[1].strip()
    return out


def build(path: str, fast: bool) -> tuple[str, dict]:
    k = kind(path)
    name = os.path.basename(path)
    size = os.path.getsize(path)
    hs = hashes(path)
    ftype = run(["file", "-b", path]).strip()

    s: list[str] = []
    s.append(f"# rev report — `{name}`\n")
    s.append(f"- **file**: `{path}`")
    s.append(f"- **tipo**: `{ftype}`")
    s.append(f"- **dimensione**: {size} byte")
    s.append(f"- **md5**: `{hs['md5']}`")
    s.append(f"- **sha1**: `{hs['sha1']}`")
    s.append(f"- **sha256**: `{hs['sha256']}`")
    s.append(f"- **generato**: {datetime.datetime.now().isoformat(timespec='seconds')}\n")

    info, dang = "", []
    if have("rabin2"):
        info = run(["rabin2", "-I", path])
        s.append("## info (rabin2 -I)\n\n```\n" + cap(info.strip()) + "\n```\n")
        s.append("## sections (rabin2 -S)\n\n```\n" + cap(run(["rabin2", "-S", path]).strip()) + "\n```\n")
        imports = run(["rabin2", "-i", path])
        s.append("## imports (rabin2 -i)\n\n```\n" + cap(imports.strip()) + "\n```\n")
        dang = sorted({w for w in DANGEROUS if re.search(rf"\b{w}\b", imports)})
        s.append("## funzioni pericolose\n\n" + (", ".join(f"`{d}`" for d in dang) if dang else "_nessuna delle solite_") + "\n")

    if k == "elf":
        s.append("## hardening (checksec)\n\n```\n" + cap(run(["checksec", "--file=" + path]).strip()) + "\n```\n")
        s.append("## header / dynamic (readelf)\n\n```\n" + cap(run(["readelf", "-W", "-h", "-d", path]).strip()) + "\n```\n")
        s.append("## note\n\n" + ("_profondità locale_: metti i file in `./data/rev`.\n"))
    elif k == "pe":
        s.append("## hardening (checksec)\n\n```\n" + cap(run(["checksec", "--file=" + path]).strip()) + "\n```\n")
        s.append("## headers (objdump -x -h)\n\n```\n" + cap(run(["objdump", "-x", "-h", path]).strip()) + "\n```\n")
    elif k == "zip":
        lst = run(["unzip", "-l", path])
        s.append("## archivio (unzip -l)\n\n```\n" + cap(lst.strip()) + "\n```\n")
        if "AndroidManifest.xml" in lst:
            s.append("## APK\n\n_Android package._ Nel terminale: `apk FILE` (apktool) e `jd FILE` (jadx).\n")

    pack = packer(path, info)
    s.append("## packer\n\n" + pack + "\n")

    flags, interesting, total = string_hits(path)
    s.append(f"## strings (di interesse)\n\n_{total} stringhe totali; {len(flags)} candidati flag._\n")
    if flags:
        s.append("### possibili flag\n\n```\n" + "\n".join(f.decode("latin1", "replace") for f in flags) + "\n```\n")
    if interesting:
        s.append("### interessanti (url/secret/path…)\n\n```\n" +
                 "\n".join(i.decode("latin1", "replace") for i in interesting) + "\n```\n")

    if not fast and have("ghidra-decompile"):
        s.append("## decompilato (Ghidra headless)\n\n_Headless: da qualche secondo a qualche minuto._\n\n```c\n" +
                 cap(run(["ghidra-decompile", path], timeout=1800).strip(), 1200) + "\n```\n")
    elif not fast:
        s.append("## decompilato\n\n`ghidra-decompile` non disponibile.\n")
    else:
        s.append("## decompilato\n\n_saltato (--fast). Rilancia senza `--fast` per decompilare._\n")

    kv = parse_kv(info)
    summary = {
        "binary": name, "path": path, "type": ftype, "size": size, "hashes": hs,
        "arch": kv.get("arch"), "bits": kv.get("bits"), "bintype": kv.get("bintype"),
        "canary": kv.get("canary"), "nx": kv.get("nx"), "pic": kv.get("pic"),
        "relro": kv.get("relro"), "stripped": kv.get("stripped"),
        "packer": pack,
        "dangerous": dang,
        "flags": [f.decode("latin1", "replace") for f in flags],
        "interesting_total": total,
        "interesting": [i.decode("latin1", "replace") for i in interesting[:40]],
    }
    return "\n".join(s), summary


def main(argv) -> int:
    ap = argparse.ArgumentParser(prog="rev-report",
                                 description="First-pass reversing report for a binary.")
    ap.add_argument("binary")
    ap.add_argument("--out", default="reports", help="directory for the Markdown (default ./reports)")
    ap.add_argument("--fast", action="store_true", help="skip the Ghidra decompile")
    ap.add_argument("--print", dest="show", action="store_true", help="also print the report to stdout")
    ap.add_argument("--no-write", action="store_true",
                    help="do not write the Markdown file (use with --print for a one-shot view)")
    ap.add_argument("--json", action="store_true",
                    help="print a JSON object (summary + markdown) instead of the report")
    a = ap.parse_args(argv)

    if not os.path.isfile(a.binary):
        sys.exit(f"rev-report: no such file: {a.binary}")
    report, summary = build(a.binary, a.fast)
    if a.json:
        print(json.dumps({**summary, "markdown": report}))
    elif a.show:
        print(report)
    if not a.no_write:
        try:
            os.makedirs(a.out, exist_ok=True)
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            dest = os.path.join(a.out, f"{os.path.basename(a.binary)}-{stamp}.md")
            with open(dest, "w") as fh:
                fh.write(report)
            print(f"rev-report: scritto {dest}", file=sys.stderr)
        except OSError as exc:
            print(f"rev-report: impossibile scrivere il report ({exc})", file=sys.stderr)
            if not (a.json or a.show):
                print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
