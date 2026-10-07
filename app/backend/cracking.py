"""Password cracking for locked artifacts.

Tools per format:
  * ZIP (ZipCrypto)      -> fcrackzip
  * ZIP (AES)            -> hashcat (mode 13600) via the vendored zip2hashcat
  * PDF                  -> pdfcrack
  * steghide (img/audio) -> stegseek

Wordlists are tried smallest -> largest; the first success wins.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import BinaryIO, Callable, Optional

from .config import DATA_DIR

# user-uploaded lists live under /data (persisted); the rest come from the image
USER_WORDLIST_DIR = DATA_DIR / "wordlists"
WORDLIST_DIRS = [USER_WORDLIST_DIR, Path("/wordlists"), Path("/opt/wordlists")]
MAX_WORDLIST_BYTES = int(float(os.environ.get("MAX_WORDLIST_MB", "512")) * 1024 * 1024)
# hashcat rules/mask support (opt-in) and a CPU budget for cracking
RULES_DIR = Path("/usr/share/hashcat/rules")
HASHCAT_RULES = os.environ.get("HASHCAT_RULES", "best64").strip()   # "" disables the rules pass
CRACK_BUDGET_S = int(float(os.environ.get("CRACK_BUDGET_S", "0") or 0))  # 0 = no limit
Z2H = "/opt/third_party/zip2hashcat.py"
ARCHIVE_EXT = (".zip", ".7z", ".rar", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".cab")
PDF_EXT = (".pdf",)
IMG_EXT = (".jpg", ".jpeg", ".bmp", ".wav", ".au")


def _log(log: Optional[Callable[[str], None]], msg: str) -> None:
    if log:
        log(msg)


def _expand(p: Path) -> Path:
    if p.suffix == ".gz":
        plain = Path("/tmp") / p.stem
        if not plain.exists():
            with gzip.open(p, "rb") as src, open(plain, "wb") as out:
                shutil.copyfileobj(src, out)
        return plain
    return p


def _lines(p: Path) -> int:
    try:
        with open(p, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def list_wordlists() -> list[dict]:
    """Available lists, ordered smallest -> largest."""
    found: dict[str, Path] = {}
    for d in WORDLIST_DIRS:
        if not d.is_dir():
            continue
        for p in d.iterdir():
            if p.is_file() and p.suffix in (".txt", ".lst", ".gz"):
                found.setdefault(p.name, p)
    return [{"name": p.name, "size": p.stat().st_size, "lines": _lines(p)}
            for p in sorted(found.values(), key=lambda x: x.stat().st_size)]


def resolve_wordlists(names: Optional[list[str]] = None) -> list[Path]:
    found: dict[str, Path] = {}
    wanted = set(names) if names else None
    for d in WORDLIST_DIRS:
        if not d.is_dir():
            continue
        for p in d.iterdir():
            if not p.is_file() or p.suffix not in (".txt", ".lst", ".gz"):
                continue
            if wanted and p.name not in wanted:
                continue
            found.setdefault(p.name, p)
    return [_expand(p) for p in sorted(found.values(), key=lambda x: x.stat().st_size)]


def save_wordlist(filename: str, src: BinaryIO) -> dict:
    """Store an uploaded wordlist under ``/data/wordlists`` (persisted) and
    return its metadata. Rejects oversized uploads and sanitises the name."""
    USER_WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(filename or "wordlist.txt").name) or "wordlist.txt"
    if not name.lower().endswith((".txt", ".lst", ".gz")):
        name += ".txt"
    dest = USER_WORDLIST_DIR / name
    n = 1
    while dest.exists():
        dest = USER_WORDLIST_DIR / f"{Path(name).stem}_{n}{Path(name).suffix}"
        n += 1
    size = 0
    try:
        with open(dest, "wb") as out:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_WORDLIST_BYTES:
                    raise ValueError(
                        f"wordlist too large (max {MAX_WORDLIST_BYTES // (1024 * 1024)} MB)")
                out.write(chunk)
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    return {"name": dest.name, "size": size, "lines": _lines(dest)}


def _run(cmd: list[str], timeout: int = 3600, cwd: str | None = None,
         log: Optional[Callable[[str], None]] = None) -> subprocess.CompletedProcess:
    _log(log, "$ " + " ".join(map(str, cmd)))
    try:
        return subprocess.run([str(c) for c in cmd], capture_output=True, text=True,
                              errors="replace", timeout=timeout, stdin=subprocess.DEVNULL, cwd=cwd)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))


def _kind(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in ARCHIVE_EXT:
        return "archive"
    if ext in PDF_EXT:
        return "pdf"
    if ext in IMG_EXT:
        return "image"
    return "unknown"


# --------------------------------------------------- hashcat args / rules / budget
def _rules_path(name: Optional[str]) -> Optional[Path]:
    """Resolve a rules name ("best64") or path to an existing .rule file."""
    if not name:
        return None
    p = Path(name)
    if p.is_file():
        return p
    cand = RULES_DIR / (name if name.endswith(".rule") else name + ".rule")
    return cand if cand.is_file() else None


def _remaining(deadline: Optional[float]) -> Optional[int]:
    if deadline is None:
        return None
    return max(1, int(deadline - time.time()))


def hashcat_args(mode: int, hashfile: str, *, wordlist: Optional[str] = None,
                 rules_file: Optional[Path] = None, mask: Optional[str] = None,
                 runtime: Optional[int] = None, potfile: Optional[str] = None) -> list[str]:
    """Build a hashcat command line (wordlist±rules, or a mask brute-force)."""
    args = ["hashcat", "-m", str(mode)]
    if mask is not None:
        args += ["-a", "3", hashfile, mask]
    else:
        args += ["-a", "0", hashfile, str(wordlist)]
        if rules_file:
            args += ["--rules-file", str(rules_file)]
    if runtime:
        args += ["--runtime", str(int(runtime))]
    if potfile:
        args += ["--potfile-path", str(potfile)]
    args += ["--force", "--quiet"]
    return args


# ------------------------------------------------------------------- crackers
def _zip_hash(path: Path, log) -> Optional[tuple[int, str]]:
    r = _run(["python3", Z2H, "--json", str(path)], timeout=120, log=log)
    try:
        info = json.loads(r.stdout)[0]
        return int(info["hashcat_mode"]), info["hash"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None


def _crack_zip_hashcat(path: Path, log, *, wl: Optional[Path] = None,
                       rules_file: Optional[Path] = None, mask: Optional[str] = None,
                       runtime: Optional[int] = None) -> Optional[str]:
    """Crack a zip (ZipCrypto or AES) with hashcat.

    Exactly one of ``wl`` (wordlist, optionally with ``rules_file``) or ``mask``
    (brute-force) is used. hashcat stops at the first match, so running it once
    per wordlist is what lets us attribute the crack to the exact list.
    """
    if not shutil.which("hashcat"):
        return None
    got = _zip_hash(path, log)
    if not got or not got[1]:
        return None
    mode, h = got
    hf, wf, pf = "/tmp/hc.hash", "/tmp/hc.wordlist", "/tmp/hc.pot"
    Path(hf).write_text(h + "\n")
    if wl is not None:
        try:
            with open(wf, "wb") as out:
                with open(wl, "rb") as src:
                    shutil.copyfileobj(src, out)
                out.write(b"\n")
        except OSError:
            return None
    try:
        Path(pf).unlink()
    except OSError:
        pass
    args = hashcat_args(mode, hf, wordlist=wf if wl is not None else None,
                        rules_file=rules_file, mask=mask, runtime=runtime, potfile=pf)
    _run(args, timeout=(runtime + 120 if runtime else 7200), log=log)
    show = _run(["hashcat", "-m", str(mode), hf, "--potfile-path", pf, "--show", "--quiet"],
                timeout=120, log=log).stdout
    for line in show.splitlines():
        if ":" in line:
            return line.rsplit(":", 1)[1].strip()
    return None


def _crack_zip(path: Path, wls: list[Path], log, rules_file: Optional[Path] = None,
               mask: Optional[str] = None,
               deadline: Optional[float] = None) -> tuple[Optional[str], Optional[str]]:
    # hashcat first: the vendored zip2hashcat handles BOTH ZipCrypto and AES.
    # Plain wordlists smallest -> largest, then an optional rules pass, then an
    # optional mask brute-force; a CPU deadline bounds the whole thing.
    if shutil.which("hashcat"):
        for wl in wls:
            if deadline and time.time() > deadline:
                break
            pw = _crack_zip_hashcat(path, log, wl=wl, runtime=_remaining(deadline))
            if pw:
                return pw, wl.name
        if rules_file:
            for wl in wls:
                if deadline and time.time() > deadline:
                    break
                pw = _crack_zip_hashcat(path, log, wl=wl, rules_file=rules_file,
                                        runtime=_remaining(deadline))
                if pw:
                    return pw, f"{wl.name} (rules)"
        if mask:
            pw = _crack_zip_hashcat(path, log, mask=mask, runtime=_remaining(deadline))
            if pw:
                return pw, "mask"
    if shutil.which("fcrackzip"):
        for wl in wls:
            if deadline and time.time() > deadline:
                break
            r = _run(["fcrackzip", "-u", "-D", "-p", str(wl), str(path)], timeout=3600, log=log)
            m = re.search(r"pw\s*==\s*(\S+)", r.stdout)
            if m:
                return m.group(1), wl.name
    return None, None


_BK_KEYS_RE = re.compile(r"Keys:\s*([0-9a-fA-F]{8}\s+[0-9a-fA-F]{8}\s+[0-9a-fA-F]{8})")


def _parse_bkcrack_keys(text: str) -> Optional[str]:
    m = _BK_KEYS_RE.search(text or "")
    return m.group(1) if m else None


def bkcrack_attack(path: Path, known_name: str, plaintext, log=None) -> dict:
    """ZipCrypto known-plaintext attack.

    Needs the plaintext (>= 12 bytes) of one *stored* entry; recovers the zip
    keys and writes an unencrypted copy, which is then extracted.
    """
    kind = _kind(path)
    miss = {"password": None, "kind": kind, "extracted": [],
            "wordlist_hit": None, "wordlists": []}
    if kind != "archive" or not shutil.which("bkcrack"):
        return miss
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("latin-1", "replace")
    pf = Path("/tmp") / "bkcrack_plain.bin"
    pf.write_bytes(plaintext or b"")
    r = _run(["bkcrack", "-C", str(path), "-c", str(known_name), "-p", str(pf)],
             timeout=600, log=log)
    keys = _parse_bkcrack_keys((r.stdout or "") + "\n" + (r.stderr or ""))
    if not keys:
        return miss
    out = Path("/tmp") / f"bkcrack-{int(time.time())}.zip"
    # `-k` takes the three keys as separate arguments
    _run(["bkcrack", "-C", str(path), "-k", *keys.split(), "-D", str(out)],
         timeout=600, log=log)
    extracted: list[str] = []
    if out.is_file():
        dest = Path("/tmp") / f"bkcrack-out-{int(time.time())}"
        _run(["7z", "x", "-y", f"-o{dest}", str(out)], timeout=600, log=log)
        if dest.exists():
            extracted = [str(p) for p in dest.rglob("*") if p.is_file()]
    return {"password": "(known-plaintext)", "kind": kind, "extracted": extracted,
            "wordlist_hit": "bkcrack", "wordlists": []}


def _crack_pdf(path: Path, wls: list[Path], log) -> tuple[Optional[str], Optional[str]]:
    if not shutil.which("pdfcrack"):
        return None, None
    for wl in wls:
        r = _run(["pdfcrack", "-f", str(path), "-w", str(wl)], timeout=3600, log=log)
        m = re.search(r"found (?:user|owner)-password:\s*'([^']+)'", r.stdout)
        if m:
            return m.group(1), wl.name
    return None, None


def _crack_image(path: Path, wls: list[Path], log) -> tuple[Optional[str], Optional[str]]:
    if not shutil.which("stegseek"):
        return None, None
    outfile = Path("/tmp") / (path.name + ".stegseek.out")
    for wl in wls:
        r = _run(["stegseek", "-sf", str(path), "-wl", str(wl), "-xf", str(outfile), "-f"],
                 timeout=3600, log=log)
        m = re.search(r'passphrase:\s*"?([^"\n]+?)"?\s*$', r.stdout + r.stderr, re.I | re.M)
        if m:
            return m.group(1).strip(), wl.name
    return None, None


def _extract_with(path: Path, kind: str, password: str, outdir: Path, log) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    if kind == "archive":
        _run(["7z", "x", "-y", f"-p{password}", f"-o{outdir}", str(path)], timeout=600, log=log)
    elif kind == "image":
        dest = outdir / (path.name + ".steghide.out")
        _run(["steghide", "extract", "-sf", str(path), "-p", password, "-xf", str(dest), "-f"],
             timeout=120, log=log)
    elif kind == "pdf":
        dest = outdir / (path.name + ".txt")
        _run(["pdftotext", "-upw", password, str(path), str(dest)], timeout=120, log=log)
    return [p for p in outdir.rglob("*") if p.is_file()] if outdir.exists() else []


def crack_file(path: Path, wordlist_names: Optional[list[str]] = None,
               log: Optional[Callable[[str], None]] = None, *,
               rules: Optional[str] = None, mask: Optional[str] = None,
               budget_s: Optional[int] = None) -> dict:
    wls = resolve_wordlists(wordlist_names)
    kind = _kind(path)
    no_hit = {"password": None, "kind": kind, "extracted": [],
              "wordlist_hit": None, "wordlists": [w.name for w in wls]}
    if kind == "unknown" or (not wls and not mask):
        return no_hit
    rules_name = HASHCAT_RULES if rules is None else rules
    rules_file = _rules_path(rules_name)
    budget = CRACK_BUDGET_S if budget_s is None else int(budget_s)
    deadline = (time.time() + budget) if budget and budget > 0 else None
    _log(log, f"cracking {path.name} ({kind}) with {len(wls)} wordlists"
              + (f", rules {rules_file.name}" if rules_file else "")
              + (", mask" if mask else ""))
    if kind == "archive":
        pw, wl_hit = _crack_zip(path, wls, log, rules_file=rules_file, mask=mask,
                                deadline=deadline)
    elif kind == "pdf":
        pw, wl_hit = _crack_pdf(path, wls, log)
    else:
        pw, wl_hit = _crack_image(path, wls, log)
    if not pw:
        return no_hit
    outdir = Path("/tmp") / f"cracked-{int(time.time())}"
    extracted = _extract_with(path, kind, pw, outdir, log)
    return {"password": pw, "kind": kind, "extracted": [str(p) for p in extracted],
            "wordlist_hit": wl_hit, "wordlists": [w.name for w in wls]}
