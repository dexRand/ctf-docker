"""Filesystem layout for projects.

/data/projects/<id>/
    uploads/     original uploaded files
    files/       extracted files, as NNNN__name (discovery order)
    work/        tool outputs, one dir per file node
"""
from __future__ import annotations

import hashlib
import mimetypes
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from .config import PROJECTS_DIR


def new_project_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


_MAX_NAME = 120          # filesystem limit is 255 bytes; HTTP object names are URLs


def sanitize_name(name: str) -> str:
    name = (name or "file").replace("\\", "/").split("/")[-1].strip()
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    if len(name) > _MAX_NAME:
        stem, dot, ext = name.rpartition(".")
        if dot and 1 <= len(ext) <= 10:
            name = stem[:_MAX_NAME - len(ext) - 1] + "." + ext
        else:
            name = name[:_MAX_NAME]
    return name or "file"


# project / tool-job ids: `new_project_id()` output (and legacy hand-made ids);
# never a path component like "..", so ids can't escape their base directory
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class InvalidId(ValueError):
    """An id that is not a plain project/job identifier (answered as 404)."""


def check_id(value: str) -> str:
    if not _ID_RE.match(value or ""):
        raise InvalidId(value)
    return value


def project_dir(pid: str) -> Path:
    return PROJECTS_DIR / check_id(pid)


def init_project(pid: str) -> None:
    for sub in ("uploads", "files", "work"):
        (project_dir(pid) / sub).mkdir(parents=True, exist_ok=True)


def delete_project(pid: str) -> None:
    shutil.rmtree(project_dir(pid), ignore_errors=True)


def hashes_of(path: Path) -> tuple[str, str, int]:
    """(sha256, md5, size) of a file, read in 1 MB chunks."""
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            size += len(chunk)
            md5.update(chunk)
            sha.update(chunk)
    return sha.hexdigest(), md5.hexdigest(), size


def save_upload(pid: str, filename: str, src: BinaryIO) -> dict:
    """Save an uploaded stream into uploads/ and return file metadata."""
    name = sanitize_name(filename)
    dest = project_dir(pid) / "uploads" / name
    n = 1
    while dest.exists():
        dest = project_dir(pid) / "uploads" / f"{Path(name).stem}_{n}{Path(name).suffix}"
        n += 1
    with open(dest, "wb") as out:
        shutil.copyfileobj(src, out)
    sha, md5, size = hashes_of(dest)
    return {"name": dest.name, "path": dest, "sha256": sha, "md5": md5,
            "size": size, "mime": sniff_mime(dest)}


# magic bytes -> media type. Content beats the file name: an extracted file
# often has no (or a lying) extension, and the UI needs the real type to pick a
# preview instead of falling back to "download".
_MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
    (b"II*\x00", "image/tiff"),
    (b"MM\x00*", "image/tiff"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"PK\x05\x06", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "application/vnd.rar"),
    (b"\x7fELF", "application/x-elf"),
    (b"MZ", "application/x-dosexec"),
    (b"OggS", "audio/ogg"),
    (b"fLaC", "audio/flac"),
    (b"ID3", "audio/mpeg"),
    (b"\xff\xfb", "audio/mpeg"),
    (b"SQLite format 3\x00", "application/vnd.sqlite3"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
]


def sniff_mime(path: Path) -> str | None:
    """Detect a file's media type from its bytes, falling back to its name."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except OSError:
        return mimetypes.guess_type(str(path))[0]
    for sig, mime in _MAGIC:
        if head.startswith(sig):
            return mime
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "audio/wav"
    if head[:4] == b"RIFF" and head[8:12] == b"AVI ":
        return "video/x-msvideo"
    if head[4:8] == b"ftyp":
        return "video/mp4"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "application/x-tar"
    # no NUL and valid UTF-8 in the sample -> plain text (covers extensionless
    # text files such as `flag.txt` renamed or carved dumps)
    if b"\x00" not in head:
        try:
            head.decode("utf-8")
            return "text/plain"
        except UnicodeDecodeError:
            pass
    return mimetypes.guess_type(str(path))[0]


