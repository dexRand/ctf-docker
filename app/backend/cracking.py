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
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import BinaryIO, Callable, Optional

from .analyzers.base import run_cmd
from .analyzers.util import ARCHIVE_EXT
from . import storage
from .config import DATA_DIR

# user-uploaded lists live under /data (persisted); the rest come from the image
USER_WORDLIST_DIR = DATA_DIR / "wordlists"
WORDLIST_DIRS = [USER_WORDLIST_DIR, Path("/wordlists"), Path("/opt/wordlists")]
MAX_WORDLIST_BYTES = int(float(os.environ.get("MAX_WORDLIST_MB", "512")) * 1024 * 1024)
# hashcat rules/mask support (opt-in) and a CPU budget for cracking
RULES_DIR = Path("/usr/share/hashcat/rules")
HASHCAT_RULES = os.environ.get("HASHCAT_RULES", "best64").strip()   # "" disables the rules pass
CRACK_BUDGET_S = int(float(os.environ.get("CRACK_BUDGET_S", "0") or 0))  # 0 = no limit
# Auto mode must not churn through huge lists (e.g. rockyou, 140 MB): it only
# tries wordlists up to this size, under a per-project time budget.
AUTO_CRACK_MAX_BYTES = int(float(os.environ.get("AUTO_CRACK_MAX_MB", "1")) * 1024 * 1024)
AUTO_CRACK_BUDGET_S = int(float(os.environ.get("AUTO_CRACK_BUDGET_S", "120") or 0))
Z2H = "/opt/third_party/zip2hashcat.py"
PDF_EXT = (".pdf",)
IMG_EXT = (".jpg", ".jpeg", ".bmp", ".wav", ".au")


def _log(log: Optional[Callable[[str], None]], msg: str) -> None:
    if log:
        log(msg)


def _scratch(prefix: str) -> Path:
    """A private temp dir per crack: concurrent cracks never share files."""
    return Path(tempfile.mkdtemp(prefix=f"stegsuite-{prefix}-"))


def _expand(p: Path) -> Path:
    if p.suffix == ".gz":
        # cache keyed by source path + mtime; written to a temp name and renamed
        # so a crash mid-gunzip never leaves a truncated list behind
        st = p.stat()
        key = hashlib.sha1(f"{p}:{st.st_mtime_ns}".encode()).hexdigest()[:12]
        plain = Path(tempfile.gettempdir()) / f"stegsuite-wl-{key}-{p.stem}"
        if not plain.exists():
            tmp = plain.with_suffix(plain.suffix + ".part")
            with gzip.open(p, "rb") as src, open(tmp, "wb") as out:
                shutil.copyfileobj(src, out)
            tmp.replace(plain)
        return plain
    return p


WORDLIST_SUFFIXES = (".txt", ".lst", ".gz")
_LINES_CACHE: dict[tuple[str, int, int], int] = {}


def _lines(p: Path) -> int:
    """Line count, cached by (path, size, mtime): rockyou is 14M lines and the
    wordlist endpoint is polled by the UI."""
    try:
        st = p.stat()
        key = (str(p), st.st_size, st.st_mtime_ns)
        if key not in _LINES_CACHE:
            with open(p, "rb") as fh:
                _LINES_CACHE[key] = sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(1 << 20), b""))
        return _LINES_CACHE[key]
    except OSError:
        return 0


def _available() -> list[Path]:
    """Every wordlist (first directory wins on a name clash), smallest first."""
    found: dict[str, Path] = {}
    for d in WORDLIST_DIRS:
        if not d.is_dir():
            continue
        for p in d.iterdir():
            if p.is_file() and p.suffix in WORDLIST_SUFFIXES:
                found.setdefault(p.name, p)
    return sorted(found.values(), key=lambda x: x.stat().st_size)


def list_wordlists() -> list[dict]:
    """Available lists, ordered smallest -> largest."""
    return [{"name": p.name, "size": p.stat().st_size, "lines": _lines(p)} for p in _available()]


def resolve_wordlists(names: Optional[list[str]] = None,
                      max_bytes: Optional[int] = None) -> list[Path]:
    wanted = set(names) if names else None
    return [_expand(p) for p in _available()
            if (not wanted or p.name in wanted)
            and (max_bytes is None or p.stat().st_size <= max_bytes)]


def save_wordlist(filename: str, src: BinaryIO) -> dict:
    """Store an uploaded wordlist under ``/data/wordlists`` (persisted) and
    return its metadata. Rejects oversized uploads and sanitises the name."""
    USER_WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    name = storage.sanitize_name(filename or "wordlist.txt")
    if not name.lower().endswith(WORDLIST_SUFFIXES):
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
    return run_cmd(cmd, timeout=timeout, cwd=cwd)


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


def _tool_timeout(deadline: Optional[float], default: int = 3600) -> int:
    """Per-process timeout: the default, capped by what is left of the budget."""
    left = _remaining(deadline)
    return default if left is None else min(default, left)


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
    tmp = _scratch("hashcat")
    hf, wf, pf = tmp / "hash", tmp / "wordlist", tmp / "pot"
    try:
        hf.write_text(h + "\n")
        if wl is not None:
            try:
                with open(wf, "wb") as out:
                    with open(wl, "rb") as src:
                        shutil.copyfileobj(src, out)
                    out.write(b"\n")   # a last line without newline is skipped by hashcat
            except OSError:
                return None
        args = hashcat_args(mode, str(hf), wordlist=str(wf) if wl is not None else None,
                            rules_file=rules_file, mask=mask, runtime=runtime, potfile=str(pf))
        _run(args, timeout=(runtime + 120 if runtime else 7200), log=log)
        show = _run(["hashcat", "-m", str(mode), str(hf), "--potfile-path", str(pf),
                     "--show", "--quiet"], timeout=120, log=log).stdout
        return _pot_password(show, h)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _pot_password(show: str, hash_line: str) -> Optional[str]:
    """Password from `hashcat --show` (`<hash>:<password>`; the password may hold `:`)."""
    # only a line that *is* our hash counts: hashcat also prints warnings and
    # errors ("Hashfile …: Hash contains unsupported compression type") that
    # contain ':' and used to be taken as the password
    kind = hash_line.split("*", 1)[0]          # e.g. "$pkzip2$1", "$zip2$"
    for line in show.splitlines():
        if line.startswith(hash_line + ":"):
            return line[len(hash_line) + 1:]
        if kind.startswith("$") and line.startswith(kind) and ":" in line:
            return line.rsplit(":", 1)[1]      # hashcat may print the hash normalised
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
            r = _run(["fcrackzip", "-u", "-D", "-p", str(wl), str(path)],
                     timeout=_tool_timeout(deadline), log=log)
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
    tmp = _scratch("bkcrack")
    try:
        pf = tmp / "plain.bin"
        pf.write_bytes(plaintext or b"")
        r = _run(["bkcrack", "-C", str(path), "-c", str(known_name), "-p", str(pf)],
                 timeout=600, log=log)
        keys = _parse_bkcrack_keys((r.stdout or "") + "\n" + (r.stderr or ""))
        if not keys:
            return miss
        out = tmp / "decrypted.zip"
        # `-k` takes the three keys as separate arguments
        _run(["bkcrack", "-C", str(path), "-k", *keys.split(), "-D", str(out)],
             timeout=600, log=log)
        extracted: list[str] = []
        if out.is_file():
            # the caller moves these into the project, so they live outside `tmp`
            dest = _scratch("bkcrack-out")
            _run(["7z", "x", "-y", f"-o{dest}", str(out)], timeout=600, log=log)
            extracted = [str(p) for p in dest.rglob("*") if p.is_file()]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {"password": "(known-plaintext)", "kind": kind, "extracted": extracted,
            "wordlist_hit": "bkcrack", "wordlists": []}


def _crack_pdf(path: Path, wls: list[Path], log,
               deadline: Optional[float] = None) -> tuple[Optional[str], Optional[str]]:
    if not shutil.which("pdfcrack"):
        return None, None
    for wl in wls:
        if deadline and time.time() > deadline:
            break
        r = _run(["pdfcrack", "-f", str(path), "-w", str(wl)],
                 timeout=_tool_timeout(deadline), log=log)
        m = re.search(r"found (?:user|owner)-password:\s*'([^']+)'", r.stdout)
        if m:
            return m.group(1), wl.name
    return None, None


def _crack_image(path: Path, wls: list[Path], log,
                 deadline: Optional[float] = None) -> tuple[Optional[str], Optional[str]]:
    if not shutil.which("stegseek"):
        return None, None
    tmp = _scratch("stegseek")
    try:
        outfile = tmp / "out"
        for wl in wls:
            if deadline and time.time() > deadline:
                break
            r = _run(["stegseek", "-sf", str(path), "-wl", str(wl), "-xf", str(outfile), "-f"],
                     timeout=_tool_timeout(deadline), log=log)
            m = re.search(r'passphrase:\s*"?([^"\n]+?)"?\s*$', r.stdout + r.stderr, re.I | re.M)
            if m:
                return m.group(1).strip(), wl.name
        return None, None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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
               budget_s: Optional[int] = None,
               extra_wordlists: Optional[list[Path]] = None) -> dict:
    """`extra_wordlists` (e.g. passwords suggested by the challenge's own
    metadata) are tried before the regular lists."""
    wls = [p for p in (extra_wordlists or []) if p.is_file()] + resolve_wordlists(wordlist_names)
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
        pw, wl_hit = _crack_pdf(path, wls, log, deadline=deadline)
    else:
        pw, wl_hit = _crack_image(path, wls, log, deadline=deadline)
    if not pw:
        return no_hit
    outdir = _scratch("cracked")   # the caller moves these files into the project
    extracted = _extract_with(path, kind, pw, outdir, log)
    return {"password": pw, "kind": kind, "extracted": [str(p) for p in extracted],
            "wordlist_hit": wl_hit, "wordlists": [w.name for w in wls]}
