#!/usr/bin/env python3
"""CTF Triage - deep, parallel recursive analysis with flag hunt + wordlist attacks.

Usable both as a CLI and as a library (see webapp.py).

Behaviour:
  * does every analysis automatically and recurses as deep as files allow
    (7z, binwalk -e, foremost, strings, exiftool, zsteg, steghide, flag hunt)
  * when it hits something that BLOCKS it (password-protected archive / PDF, or
    a JPEG/BMP/WAV that may hide a steghide payload) it asks which wordlist to
    use, smallest -> largest by default
  * `-w <file>`  : use only that wordlist (no prompt)
  * `--yes`      : no prompt, try every wordlist smallest -> largest
  * `--no-crack` : never attack passwords
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

# Patterns searched everywhere (binary included).
STRICT_PATTERNS = [
    r"ITS\{[^}]{1,200}\}",
    r"flag\{[^}]{1,200}\}",
    r"FLAG\{[^}]{1,200}\}",
    r"CTF\{[^}]{1,200}\}",
    r"ctf\{[^}]{1,200}\}",
    r"HTB\{[^}]{1,200}\}",
    r"picoCTF\{[^}]{1,200}\}",
]
# Generic pattern: only on printable text (strings/exiftool/zsteg/text files).
GENERIC_PATTERNS = [r"[0-9A-Za-z_]{2,32}\{[ -~]{1,200}\}"]
PATTERNS_FILE = "/usr/local/share/triage/patterns.txt"

LOCK = threading.Lock()
FLAGS: list[dict] = []
PASSWORDS: list[dict] = []
PER_FILE: list[dict] = []
COMMANDS: list[str] = []
EXTRACTED: list[tuple[str, int]] = []
WARNINGS: list[str] = []
KNOWN_PWS: list[str] = []
LOCKED: list[dict] = []
_seen: set[str] = set()
WORDLISTS: list[Path] = []
_LOG_FN = print


def set_logger(fn) -> None:
    global _LOG_FN
    _LOG_FN = fn or print


def log(msg: str) -> None:
    try:
        _LOG_FN(f"[*] {msg}")
    except Exception:
        print(f"[*] {msg}", flush=True)


def run(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    with LOCK:
        COMMANDS.append(" ".join(cmd))
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        with LOCK:
            WARNINGS.append(f"timeout: {' '.join(cmd)}")
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", "not found")


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def sha1(path: Path) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def human(n: int) -> str:
    f = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if f < 1024:
            return f"{f:.0f}{u}" if u == "B" else f"{f:.1f}{u}"
        f /= 1024
    return f"{f:.1f}TB"


def line_count(p: Path) -> int:
    try:
        with open(p, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


# ------------------------------------------------------------------ wordlists
def _expand(path: Path) -> Path:
    if path.suffix == ".gz":
        plain = Path("/tmp") / path.stem
        if not plain.exists():
            with gzip.open(path, "rb") as src, open(plain, "wb") as out:
                shutil.copyfileobj(src, out)
        return plain
    return path


def resolve_wordlists(arg: str | None = None) -> list[Path]:
    """All available lists, ordered smallest -> largest (small repo lists first).

    Wordlists come from the mounted /wordlists (the repo directory) and the
    wordlists baked into the image at /opt/wordlists (rockyou). Same name ->
    the mounted one wins.
    """
    if arg:
        return [Path(arg)]
    found: dict[str, Path] = {}
    for d in (Path("/wordlists"), Path("/opt/wordlists")):
        if not d.is_dir():
            continue
        for p in d.iterdir():
            if p.is_file() and p.suffix in (".txt", ".lst", ".gz"):
                found[p.name] = p
    return [_expand(p) for p in sorted(found.values(), key=lambda x: x.stat().st_size)]


# ------------------------------------------------------------------- patterns
def _compile(pats: list[str]) -> list[re.Pattern]:
    out = []
    for p in dict.fromkeys(pats):
        try:
            out.append(re.compile(p.encode(), re.IGNORECASE))
        except re.error as exc:
            with LOCK:
                WARNINGS.append(f"bad pattern {p!r}: {exc}")
    return out


def load_patterns(extra: list[str] | None) -> tuple[list[re.Pattern], list[re.Pattern]]:
    raw = list(STRICT_PATTERNS)
    if os.path.exists(PATTERNS_FILE):
        for line in Path(PATTERNS_FILE).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                raw.append(line)
    raw.extend(extra or [])
    return _compile(raw), _compile(GENERIC_PATTERNS)


def hunt(label: str, data: bytes, patterns: tuple[list[re.Pattern], list[re.Pattern]],
         generic: bool = False) -> None:
    strict, gen = patterns
    for pat in strict + (gen if generic else []):
        for m in pat.findall(data):
            value = m.decode("latin-1", "replace")
            if not all(32 <= ord(c) <= 126 for c in value):
                continue
            with LOCK:
                hit = next((f for f in FLAGS if f["value"] == value), None)
                if hit:
                    if label not in hit["where"]:
                        hit["where"].append(label)
                else:
                    FLAGS.append({"value": value, "where": [label]})


# ------------------------------------------------------------------ extraction
ARCHIVE_KEYS = ("archive", "compressed", "zip", "7-zip", "gzip", "bzip2", "xz",
                "tar ", "rar", "cpio", "cab", "iso 9660", "filesystem")


def is_archive(path: Path, ftype: str | None = None) -> bool:
    t = (ftype or run(["file", "-b", str(path)], timeout=30).stdout).lower()
    return any(k in t for k in ARCHIVE_KEYS)


def extract_7z(path: Path, outdir: Path, password: str | None) -> tuple[bool, bool]:
    outdir.mkdir(parents=True, exist_ok=True)
    r = run(["7z", "x", "-y", f"-p{password or ''}", f"-o{outdir}", str(path)], timeout=600)
    blob = (r.stdout + r.stderr).lower()
    needs = ("password" in blob or "encrypted" in blob or "wrong" in blob) and r.returncode != 0
    if r.returncode != 0:
        shutil.rmtree(outdir, ignore_errors=True)
    return r.returncode == 0, needs


def binwalk_extract(path: Path, outdir: Path) -> Path | None:
    run(["binwalk", "--matryoshka", "--depth=2", "--count=100",
         "--size=10485760", "-e", str(path), "--run-as=root"], timeout=600)
    produced = path.parent / f"_{path.name}.extracted"
    if produced.exists():
        target = outdir / f"{path.name}.binwalk"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(produced), str(target))
        return target
    return None


def foremost_extract(path: Path, outdir: Path) -> Path | None:
    if not have("foremost"):
        return None
    outdir.mkdir(parents=True, exist_ok=True)
    run(["foremost", "-q", "-i", str(path), "-o", str(outdir)], timeout=600)
    return outdir if any(outdir.iterdir()) else None


def try_steghide(path: Path, outdir: Path, password: str | None) -> Path | None:
    if not have("steghide"):
        return None
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / (path.name + ".steghide")
    r = run(["steghide", "extract", "-sf", str(path), "-p", password or "", "-xf", str(outfile), "-f"], timeout=120)
    return outfile if r.returncode == 0 and outfile.exists() else None


# --------------------------------------------------------------- analysis pass
def analyze_file(path: Path, work: Path, patterns) -> list[Path]:
    found: list[Path] = []
    try:
        size = path.stat().st_size
    except OSError:
        return found
    if size == 0:
        return found

    rel = str(path.relative_to(work))
    ftype = run(["file", "-b", str(path)], timeout=30).stdout.strip()
    low = ftype.lower()
    is_text = ("text" in low) or ("ascii" in low) or ("unicode" in low)
    entry: dict = {"path": rel, "size": size, "type": ftype, "notes": []}

    if size <= 50 * 1024 * 1024:
        hunt(rel, path.read_bytes(), patterns, generic=is_text)

    (work / "strings").mkdir(parents=True, exist_ok=True)
    r = run(["strings", "-n", "6", str(path)], timeout=120)
    if r.stdout:
        (work / "strings" / (path.name + ".strings")).write_text(r.stdout, errors="replace")
        hunt(f"strings:{rel}", r.stdout.encode("latin-1", "replace"), patterns, generic=True)

    if have("exiftool") and size <= 100 * 1024 * 1024:
        ex = run(["exiftool", str(path)], timeout=60).stdout
        (work / "exiftool").mkdir(parents=True, exist_ok=True)
        (work / "exiftool" / (path.name + ".txt")).write_text(ex, errors="replace")
        hunt(f"exiftool:{rel}", ex.encode("latin-1", "replace"), patterns, generic=True)

    if ("png" in low or "bmp" in low or "bitmap" in low) and have("zsteg"):
        z = run(["zsteg", "-a", str(path)], timeout=180)
        (work / "zsteg").mkdir(parents=True, exist_ok=True)
        (work / "zsteg" / (path.name + ".txt")).write_text(z.stdout + z.stderr, errors="replace")
        hunt(f"zsteg:{rel}", (z.stdout + z.stderr).encode("latin-1", "replace"), patterns, generic=True)
        entry["notes"].append("zsteg")

    is_img_audio = any(x in low for x in ("jpeg", "jpg", "bitmap", "bmp", "wave", "wav", "au"))
    arch = is_archive(path, low)

    if is_img_audio:
        out = try_steghide(path, work / "steghide", None)
        if out:
            entry["notes"].append("steghide:password vuota")
            found.append(out)
        else:
            with LOCK:
                LOCKED.append({"path": path, "rel": rel, "kind": "image"})

    if arch:
        outdir = work / "extracted" / f"{path.name}.7z"
        ok, needs = extract_7z(path, outdir, None)
        if needs:
            with LOCK:
                LOCKED.append({"path": path, "rel": rel, "kind": "archive"})
        elif ok:
            found += [p for p in outdir.rglob("*") if p.is_file()]
    elif "pdf" in low:
        info = run(["pdfinfo", str(path)], timeout=60).stdout
        if re.search(r"^Encrypted:\s*yes", info, re.M | re.I):
            with LOCK:
                LOCKED.append({"path": path, "rel": rel, "kind": "pdf"})

    if 64 <= size <= 100 * 1024 * 1024 and not is_text and not arch:
        carved = foremost_extract(path, work / "foremost" / path.name)
        if carved:
            found += [p for p in carved.rglob("*") if p.is_file()]
            entry["notes"].append("foremost")
        bw = binwalk_extract(path, work / "binwalk")
        if bw:
            found += [p for p in bw.rglob("*") if p.is_file()]
            entry["notes"].append("binwalk -e")

    with LOCK:
        PER_FILE.append(entry)
    return found


# -------------------------------------------------------------- cracking phase
def crack_archive(path: Path, wls: list[Path]) -> str | None:
    for wl in wls:
        if have("fcrackzip"):
            r = run(["fcrackzip", "-u", "-D", "-p", str(wl), str(path)], timeout=3600)
            m = re.search(r"pw\s*==\s*(\S+)", r.stdout)
            if m:
                return m.group(1)
        if not have("fcrackzip") or wl.stat().st_size < 200_000:
            for pw in wl.read_text(errors="replace").splitlines():
                pw = pw.strip()
                if pw and extract_7z(path, Path("/tmp/probe"), pw)[0]:
                    return pw
    return None


def crack_pdf(path: Path, wls: list[Path]) -> str | None:
    if not have("pdfcrack"):
        return None
    for wl in wls:
        r = run(["pdfcrack", "-f", str(path), "-w", str(wl)], timeout=3600)
        m = re.search(r"found (?:user|owner)-password:\s*'([^']+)'", r.stdout)
        if m:
            return m.group(1)
    return None


def crack_image(path: Path, wls: list[Path]) -> tuple[str | None, Path | None]:
    if not have("stegseek"):
        return None, None
    outfile = path.with_suffix(path.suffix + ".stegseek.out")
    for wl in wls:
        r = run(["stegseek", "-sf", str(path), "-wl", str(wl), "-xf", str(outfile), "-f"], timeout=3600)
        m = re.search(r'passphrase:\s*"?([^"\n]+?)"?\s*$', r.stdout + r.stderr, re.I | re.M)
        if m:
            return m.group(1).strip(), (outfile if outfile.exists() else None)
    return None, None


def crack_selected(work: Path, entries: list[dict], decisions: dict, paths_by_index: dict) -> list[Path]:
    """Crack the entries the user selected (decisions: index -> list[Path])."""
    unlocked: list[Path] = []
    for e in entries:
        wls = decisions.get(e["index"])
        if not wls:
            continue
        path = paths_by_index[e["index"]]
        kind = e["kind"]
        if kind == "archive":
            pw = crack_archive(path, wls)
        elif kind == "pdf":
            pw = crack_pdf(path, wls)
        else:
            pw, out = crack_image(path, wls)
            if pw:
                with LOCK:
                    if pw not in KNOWN_PWS:
                        KNOWN_PWS.append(pw)
                    PASSWORDS.append({"file": e["rel"], "tool": "stegseek", "password": pw})
                if out and out.exists():
                    unlocked.append(out)
            continue
        if not pw:
            continue
        with LOCK:
            if pw not in KNOWN_PWS:
                KNOWN_PWS.append(pw)
            PASSWORDS.append({"file": e["rel"], "tool": kind, "password": pw})
        if kind == "archive":
            outdir = work / "extracted" / (path.name + ".cracked")
            ok, _ = extract_7z(path, outdir, pw)
            if ok:
                unlocked += [p for p in outdir.rglob("*") if p.is_file()]
        elif kind == "pdf" and have("pdftotext"):
            pout = work / "pdf" / (path.name + ".txt")
            pout.parent.mkdir(parents=True, exist_ok=True)
            run(["pdftotext", "-upw", pw, str(path), str(pout)], timeout=120)
            if pout.exists():
                unlocked.append(pout)
    return unlocked


def process(seeds: list[Path], work: Path, patterns, jobs: int, depth: int) -> int:
    current = seeds
    count = 0
    for level in range(depth):
        batch = []
        for p in current:
            try:
                key = sha1(p)
            except OSError:
                continue
            with LOCK:
                if key in _seen:
                    continue
                _seen.add(key)
            batch.append(p)
        if not batch:
            break
        log(f"livello {level}: {len(batch)} file ({jobs} job)")
        nxt: list[Path] = []
        with cf.ThreadPoolExecutor(max_workers=jobs) as pool:
            futs = {pool.submit(analyze_file, p, work, patterns): p for p in batch}
            for fut in cf.as_completed(futs):
                p = futs[fut]
                count += 1
                try:
                    new = fut.result()
                except Exception as exc:
                    with LOCK:
                        WARNINGS.append(f"errore su {p.name}: {exc}")
                    continue
                for nf in new:
                    try:
                        with LOCK:
                            EXTRACTED.append((str(nf.relative_to(work)), nf.stat().st_size))
                    except (OSError, ValueError):
                        pass
                    nxt.append(nf)
        current = nxt
    return count


# --------------------------------------------------------------------- report
def write_report(work: Path, inputs: list[str], elapsed: float, count: int) -> None:
    ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# CTF Triage report", "",
        f"- **Data:** {ts}",
        f"- **Input:** {', '.join(inputs)}",
        f"- **File analizzati:** {count}",
        f"- **File estratti:** {len(EXTRACTED)}",
        f"- **Tempo:** {elapsed:.1f}s",
        f"- **Wordlist (piccola → grande):** {', '.join(w.name for w in WORDLISTS) or 'nessuna'}",
        "", "## 🚩 Flag trovate", "",
    ]
    lines += [f"- `{f['value']}`  \n  _trovata in: {', '.join(f['where'])}_" for f in FLAGS] or \
             ["_Nessuna flag trovata con i pattern attuali._"]
    lines += ["", "## 🔑 Password trovate", ""]
    lines += [f"- `{p['password']}` ({p['tool']}) su `{p['file']}`" for p in PASSWORDS] or \
             ["_Nessuna password trovata._"]
    lines += ["", "## 📦 File estratti", ""]
    lines += [f"- `{rel}` ({size} bytes)" for rel, size in EXTRACTED] or ["_Nessun file estratto._"]
    lines += ["", "## 🔎 Dettaglio per file", ""]
    for e in PER_FILE:
        notes = f" — {', '.join(e['notes'])}" if e["notes"] else ""
        lines.append(f"- `{e['path']}` ({e['size']} bytes) — {e['type']}{notes}")
    if WARNINGS:
        lines += ["", "## ⚠️ Avvisi", ""] + [f"- {w}" for w in WARNINGS]
    lines += ["", "## 🧰 Comandi eseguiti", "", "```", *COMMANDS, "```", ""]
    (work / "report.md").write_text("\n".join(lines), errors="replace")
    (work / "report.json").write_text(json.dumps({
        "generated": ts, "input": inputs, "elapsed_seconds": round(elapsed, 2),
        "wordlists": [w.name for w in WORDLISTS], "flags": FLAGS, "passwords": PASSWORDS,
        "files": PER_FILE, "extracted": [{"path": p, "size": s} for p, s in EXTRACTED],
        "warnings": WARNINGS, "commands": COMMANDS,
    }, indent=2, ensure_ascii=False), errors="replace")


def chown_outputs(work: Path) -> None:
    uid, gid = os.environ.get("HOST_UID"), os.environ.get("HOST_GID")
    if not uid or not gid:
        return
    for root, dirs, files in os.walk(work):
        for name in [root] + [os.path.join(root, x) for x in files + dirs]:
            try:
                os.chown(name, int(uid), int(gid))
            except OSError:
                pass


# --------------------------------------------------------------------- engine
def reset_state(wordlists, explicit):
    global FLAGS, PASSWORDS, PER_FILE, COMMANDS, EXTRACTED, WARNINGS, KNOWN_PWS, LOCKED, _seen, WORDLISTS, EXPLICIT_WL
    with LOCK:
        FLAGS, PASSWORDS, PER_FILE, COMMANDS, EXTRACTED, WARNINGS, KNOWN_PWS, LOCKED = [], [], [], [], [], [], [], []
        _seen = set()
        WORDLISTS = wordlists
        EXPLICIT_WL = explicit


EXPLICIT_WL: Path | None = None


def execute(paths, work, *, crack=True, wordlists_list=None, explicit_wl=None,
            patterns_extra=None, jobs=4, depth=3, asker=None, make_latest=True) -> dict:
    """Run the whole pipeline. `asker(entries, candidates) -> {index: [wordlists]}`."""
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    patterns = load_patterns(patterns_extra)
    if not crack:
        wls: list[Path] = []
    elif wordlists_list is not None:
        wls = [Path(w) for w in wordlists_list]
    else:
        wls = resolve_wordlists()
    reset_state(wls, Path(explicit_wl) if explicit_wl else None)
    if crack and not wls:
        WARNINGS.append("nessuna wordlist in /wordlists")
    if wls:
        log("wordlist (piccola → grande): " + ", ".join(w.name for w in wls))

    start = time.time()
    (work / "input").mkdir(parents=True, exist_ok=True)
    staged: list[Path] = []
    for p in paths:
        src = Path(p).resolve()
        if not src.exists():
            WARNINGS.append(f"input inesistente: {p}")
            continue
        dst = work / "input" / src.name
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
            staged += [x for x in sorted(dst.rglob("*")) if x.is_file()]
        else:
            shutil.copy2(src, dst)
            staged.append(dst)
    log(f"work dir: {work}")

    count = process(staged, work, patterns, jobs, depth)

    while LOCKED and crack:
        with LOCK:
            items, LOCKED[:] = list(LOCKED), []
        entries = [{"index": i, "rel": it["rel"], "kind": it["kind"]} for i, it in enumerate(items)]
        paths_by_index = {i: it["path"] for i, it in enumerate(items)}
        decisions = asker(entries, wls) if asker else {e["index"]: wls for e in entries}
        new = crack_selected(work, entries, decisions, paths_by_index)
        if not new:
            # nothing unlocked: stop to avoid looping forever
            if not LOCKED:
                break
            continue
        count += process(new, work, patterns, jobs, depth)

    elapsed = time.time() - start
    write_report(work, [str(p) for p in paths], elapsed, count)
    if make_latest:
        latest = Path("/data/latest")
        try:
            if latest.is_symlink() or latest.exists():
                latest.unlink()
            latest.symlink_to(work.relative_to("/data"))
        except (OSError, ValueError):
            pass
    chown_outputs(work)
    log(f"report: {work}/report.md")
    log(f"flag trovate: {len(FLAGS)} | password: {len(PASSWORDS)} | file: {count} | tempo: {elapsed:.1f}s")
    return {
        "work": str(work),
        "report": str(work / "report.md"),
        "flags": FLAGS,
        "passwords": PASSWORDS,
        "extracted": [{"path": p, "size": s} for p, s in EXTRACTED],
        "files": PER_FILE,
        "warnings": WARNINGS,
        "count": count,
        "elapsed": round(elapsed, 2),
    }


# ------------------------------------------------------------------- CLI asker
def choose_wordlist(label: str, candidates: list[Path]) -> list[Path]:
    if EXPLICIT_WL:
        return [EXPLICIT_WL]
    if not candidates:
        print(f"  {label}: nessuna wordlist in /wordlists — salto")
        return []
    print(f"\n  🔒 {label}")
    print("     Wordlist disponibili (piccola → grande):")
    for i, w in enumerate(candidates, 1):
        print(f"       {i}) {w.name:<26} {line_count(w):>10} voci  {human(w.stat().st_size)}")
    print("       a) prova tutte in ordine\n       s) salta\n       c) percorso custom")
    try:
        ans = input("     scelta [s]: ").strip().lower()
    except EOFError:
        return []
    if ans in ("", "s"):
        return []
    if ans == "a":
        return candidates
    if ans == "c":
        try:
            p = Path(input("     percorso wordlist: ").strip())
        except EOFError:
            return []
        return [p] if p.is_file() else []
    if ans.isdigit() and 1 <= int(ans) <= len(candidates):
        return [candidates[int(ans) - 1]]
    print("     scelta non valida → salto")
    return []


def cli_asker(entries, candidates):
    decisions: dict[int, list[Path]] = {}
    others = [e for e in entries if e["kind"] != "image"]
    images = [e for e in entries if e["kind"] == "image"]
    for e in others:
        wls = choose_wordlist(f"{e['rel']}  ({e['kind']})", candidates)
        if wls:
            decisions[e["index"]] = wls
    if images:
        wls = choose_wordlist(f"{len(images)} immagini potenzialmente stego (steghide)", candidates)
        if wls:
            for e in images:
                decisions[e["index"]] = wls
    return decisions


def main() -> int:
    ap = argparse.ArgumentParser(description="Deep recursive CTF/steg triage with flag hunt.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("-o", "--output")
    ap.add_argument("-w", "--wordlist", help="usa SOLO questa wordlist (nessun prompt)")
    ap.add_argument("--yes", action="store_true", help="nessun prompt, prova tutte da piccola a grande")
    ap.add_argument("--no-crack", action="store_true")
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 2))
    ap.add_argument("--pattern", action="append", default=[])
    args = ap.parse_args()

    explicit = Path(args.wordlist) if args.wordlist else None
    if args.no_crack:
        asker = None
        wls = []
    elif args.yes:
        asker = lambda entries, cands: {e["index"]: cands for e in entries}
        wls = None
    elif explicit:
        asker = lambda entries, cands: {e["index"]: [explicit] for e in entries}
        wls = [explicit]
    else:
        asker = cli_asker
        wls = None

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    work = Path(args.output) if args.output else Path("/data/triage") / f"{stamp}_{Path(args.paths[0]).name or 'target'}"
    execute(args.paths, work, crack=not args.no_crack, wordlists_list=wls,
            explicit_wl=explicit, patterns_extra=args.pattern, jobs=args.jobs,
            depth=args.depth, asker=asker)
    return 0


if __name__ == "__main__":
    sys.exit(main())
