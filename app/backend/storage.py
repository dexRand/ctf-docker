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
from .magic import mime_of


def sniff_mime(path: Path) -> str | None:
    """Detect a file's media type from its bytes, falling back to its name."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except OSError:
        return mimetypes.guess_type(str(path))[0]
    mime = mime_of(head)
    if mime:
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


