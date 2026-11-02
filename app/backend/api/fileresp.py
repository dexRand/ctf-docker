"""One way to serve project files: inline only what the browser cannot script.

Anything else (HTML, SVG, XML, JSON, PDF…) is a download: a challenge's
.html/.svg would otherwise run scripts on localhost:19014 and could call the API
(same origin). `nosniff` + a CSP sandbox are the second layer on every response.
PDFs are downloads too: browsers' PDF viewers render a blank page under a
sandbox CSP, and the SPA has no inline PDF preview.
"""
from __future__ import annotations

from pathlib import Path

from fastapi.responses import FileResponse, Response

INLINE_MIME = {"image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp",
               "image/tiff", "image/avif", "text/plain"}
FILE_HEADERS = {"X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "sandbox"}


def inline_ok(mime: str | None) -> bool:
    m = (mime or "").split(";")[0].strip().lower()
    return m in INLINE_MIME or m.startswith(("audio/", "video/"))


def file_response(path: Path, mime: str | None, name: str | None = None) -> FileResponse:
    """Inline for safe media, otherwise an `application/octet-stream` download."""
    if inline_ok(mime):
        return FileResponse(path, media_type=mime, headers=FILE_HEADERS)
    return FileResponse(path, media_type="application/octet-stream",
                        filename=name or path.name or "download", headers=FILE_HEADERS)


def text_response(text: str) -> Response:
    return Response(text, media_type="text/plain; charset=utf-8", headers=FILE_HEADERS)
