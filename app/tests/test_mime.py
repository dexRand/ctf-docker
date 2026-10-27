"""Content-based MIME detection, so extensionless files get a real preview."""
from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

from backend.storage import sniff_mime

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


@pytest.mark.parametrize("data,expected", [
    (PNG, "image/png"),
    (b"\xff\xd8\xff\xe0" + b"\x00" * 16, "image/jpeg"),
    (b"GIF89a" + b"\x00" * 16, "image/gif"),
    (b"BM" + b"\x00" * 16, "image/bmp"),
    (b"%PDF-1.7\n", "application/pdf"),
    (b"PK\x03\x04" + b"\x00" * 16, "application/zip"),
    (b"RIFF\x00\x00\x00\x00WAVE" + b"\x00" * 8, "audio/wav"),
    (b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 8, "image/webp"),
    (b"\x7fELF" + b"\x00" * 16, "application/x-elf"),
    (b"SQLite format 3\x00" + b"\x00" * 16, "application/vnd.sqlite3"),
])
def test_sniff_from_bytes_ignores_the_name(tmp_path, data, expected):
    assert sniff_mime(_write(tmp_path, "no-extension-here", data)) == expected


def test_plain_text_is_detected(tmp_path):
    assert sniff_mime(_write(tmp_path, "mystery", b"hello\npicoCTF{x}\n")) == "text/plain"


def test_binary_with_nul_is_not_text(tmp_path):
    # no magic match, NUL present, no extension -> not mislabelled as text
    assert sniff_mime(_write(tmp_path, "blob", b"\x01\x02\x00\x03\x04\x05")) is None


@pytest.fixture(scope="module")
def client():
    with TestClient(importlib.import_module("backend.main").app) as c:
        yield c


def test_extensionless_png_upload_is_served_as_an_image(client):
    r = client.post("/api/v1/projects",
                    files=[("files", ("mystery", PNG, "application/octet-stream"))],
                    data={"mode": "check", "name": "mime-preview"})
    assert r.status_code in (200, 201), r.text
    pid = r.json()["id"]
    node = client.get(f"/api/v1/projects/{pid}").json()["tree"][0]
    assert node["mime"] == "image/png"            # detected from the bytes
    content = client.get(f"/api/v1/projects/{pid}/files/{node['id']}/content")
    assert content.status_code == 200
    assert content.headers["content-type"].startswith("image/png")
    # inline preview: no attachment disposition
    assert "attachment" not in content.headers.get("content-disposition", "")


def _upload(client, name, data, mime="application/octet-stream"):
    r = client.post("/api/v1/projects", files=[("files", (name, data, mime))],
                    data={"mode": "check", "name": f"xss-{name}"})
    assert r.status_code in (200, 201), r.text
    pid = r.json()["id"]
    node = client.get(f"/api/v1/projects/{pid}").json()["tree"][0]
    return pid, node


def test_html_with_binary_prefix_is_never_inline(client):
    # a NUL in the first 8 KiB makes sniff_mime fall back to the extension
    evil = b"<html><script>alert(1)</script>\x00</html>"
    pid, node = _upload(client, "evil.html", evil, "text/html")
    assert node["mime"] == "text/html"
    r = client.get(f"/api/v1/projects/{pid}/files/{node['id']}/content")
    assert "attachment" in r.headers.get("content-disposition", "")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in r.headers.get("content-security-policy", "")


def test_svg_with_binary_prefix_is_never_inline(client):
    evil = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script>\x00</svg>'
    pid, node = _upload(client, "evil.svg", evil, "image/svg+xml")
    assert node["mime"] == "image/svg+xml"
    r = client.get(f"/api/v1/projects/{pid}/files/{node['id']}/content")
    assert "attachment" in r.headers.get("content-disposition", "")
    assert r.headers["x-content-type-options"] == "nosniff"


def test_png_preview_is_still_inline_but_hardened(client):
    pid, node = _upload(client, "pic.png", PNG)
    r = client.get(f"/api/v1/projects/{pid}/files/{node['id']}/content")
    assert r.headers["content-type"].startswith("image/png")
    assert "attachment" not in r.headers.get("content-disposition", "")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in r.headers.get("content-security-policy", "")
