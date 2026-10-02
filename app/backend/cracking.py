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
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

WORDLIST_DIRS = [Path("/wordlists"), Path("/opt/wordlists")]
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


# ------------------------------------------------------------------- crackers
def _crack_zip_hashcat(path: Path, wls: list[Path], log) -> Optional[str]:
    """ZipCrypto/AES via hashcat; the hash comes from the vendored zip2hashcat."""
    if not (shutil.which("hashcat") and Path(Z2H).exists()):
        return None
    r = _run(["python3", Z2H, "--json", str(path)], timeout=120, log=log)
    try:
        info = json.loads(r.stdout)[0]
        mode, h = int(info["hashcat_mode"]), info["hash"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None
    if not h:
        return None
    hf, wf, pf = "/tmp/hc.hash", "/tmp/hc.wordlist", "/tmp/hc.pot"
    Path(hf).write_text(h + "\n")
    with open(wf, "wb") as out:  # concatenate the chosen lists, small -> large
        for wl in wls:
            try:
                with open(wl, "rb") as src:
                    shutil.copyfileobj(src, out)
            except OSError:
                continue
            out.write(b"\n")
    try:
        Path(pf).unlink()
    except OSError:
        pass
    _run(["hashcat", "-m", str(mode), "-a", "0", hf, wf,
          "--potfile-path", pf, "--force", "--quiet"], timeout=7200, log=log)
    show = _run(["hashcat", "-m", str(mode), hf, "--potfile-path", pf, "--show", "--quiet"],
                timeout=120, log=log).stdout
    for line in show.splitlines():
        if ":" in line:
            return line.rsplit(":", 1)[1].strip()
    return None


def _crack_zip(path: Path, wls: list[Path], log) -> Optional[str]:
    # hashcat first: the vendored zip2hashcat handles BOTH ZipCrypto and AES, and
    # hashcat stops at the first match. fcrackzip is only a fallback (it would
    # uselessly churn through huge wordlists on AES archives).
    pw = _crack_zip_hashcat(path, wls, log)
    if pw:
        return pw
    if shutil.which("fcrackzip"):
        for wl in wls:
            r = _run(["fcrackzip", "-u", "-D", "-p", str(wl), str(path)], timeout=3600, log=log)
            m = re.search(r"pw\s*==\s*(\S+)", r.stdout)
            if m:
                return m.group(1)
    return None


def _crack_pdf(path: Path, wls: list[Path], log) -> Optional[str]:
    if not shutil.which("pdfcrack"):
        return None
    for wl in wls:
        r = _run(["pdfcrack", "-f", str(path), "-w", str(wl)], timeout=3600, log=log)
        m = re.search(r"found (?:user|owner)-password:\s*'([^']+)'", r.stdout)
        if m:
            return m.group(1)
    return None


def _crack_image(path: Path, wls: list[Path], log) -> Optional[str]:
    if not shutil.which("stegseek"):
        return None
    outfile = Path("/tmp") / (path.name + ".stegseek.out")
    for wl in wls:
        r = _run(["stegseek", "-sf", str(path), "-wl", str(wl), "-xf", str(outfile), "-f"],
                 timeout=3600, log=log)
        m = re.search(r'passphrase:\s*"?([^"\n]+?)"?\s*$', r.stdout + r.stderr, re.I | re.M)
        if m:
            return m.group(1).strip()
    return None


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
               log: Optional[Callable[[str], None]] = None) -> dict:
    wls = resolve_wordlists(wordlist_names)
    kind = _kind(path)
    if not wls or kind == "unknown":
        return {"password": None, "kind": kind, "extracted": [], "wordlists": [w.name for w in wls]}
    _log(log, f"cracking {path.name} ({kind}) with {len(wls)} wordlists")
    if kind == "archive":
        pw = _crack_zip(path, wls, log)
    elif kind == "pdf":
        pw = _crack_pdf(path, wls, log)
    else:
        pw = _crack_image(path, wls, log)
    if not pw:
        return {"password": None, "kind": kind, "extracted": [], "wordlists": [w.name for w in wls]}
    outdir = Path("/tmp") / f"cracked-{int(time.time())}"
    extracted = _extract_with(path, kind, pw, outdir, log)
    return {"password": pw, "kind": kind, "extracted": [str(p) for p in extracted],
            "wordlists": [w.name for w in wls]}
