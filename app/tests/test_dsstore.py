"""ds-store analyzer (issue #13): names, Iloc order, base64 pieces -> flag."""
from __future__ import annotations

import base64
import struct
from types import SimpleNamespace

from backend.analyzers.dsstore import MAGIC, DsStoreAnalyzer, rebuild_flag


def _record(name: str, x: int, y: int) -> bytes:
    raw = name.encode("utf-16-be")
    return struct.pack(">I", len(name)) + raw + b"Iloc" + b"blob" \
        + struct.pack(">IIII", 16, x, y, 0xFFFFFFFF) + b"\xff\xff\x00\x00"


def test_flag_split_across_base64_file_names(tmp_path):
    a = base64.urlsafe_b64encode(b"tjctf{ds_").decode().rstrip("=")
    b = base64.urlsafe_b64encode(b"store}").decode().rstrip("=")
    noise = base64.urlsafe_b64encode(bytes(range(200, 216))).decode().rstrip("=")
    data = MAGIC + b"\x00" * 24 + _record(b, 10, 10) + _record(noise, 20, 20) + _record(a, 30, 30)
    path = tmp_path / ".DS_Store"
    path.write_bytes(data)
    r = DsStoreAnalyzer().run(SimpleNamespace(input=path))
    assert r.status == "done"
    assert "tjctf{ds_store}" in r.output
    assert noise in r.output                       # every name is listed


def test_rebuild_flag_wraps_around():
    # starts at the prefix piece, wraps to the first piece, stops at the brace
    assert rebuild_flag(["b}", "x", "flag{a"]) == "flag{ab}"
    assert rebuild_flag(["no", "prefix"]) is None


def test_not_a_ds_store(tmp_path):
    path = tmp_path / "x.DS_Store"
    path.write_bytes(b"hello")
    assert DsStoreAnalyzer().run(SimpleNamespace(input=path)).status == "skipped"
