"""png-chunks: text chunks are decoded, including compressed zTXt."""
import struct
import zlib

from backend.analyzers.base import ToolContext
from backend.analyzers.png import PNG_SIG, PngChunksAnalyzer


def _chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data))


def _run(tmp_path, *chunks: bytes):
    p = tmp_path / "x.png"
    p.write_bytes(PNG_SIG + b"".join(chunks) + _chunk(b"IEND", b""))
    return PngChunksAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))


def test_ztxt_is_decompressed(tmp_path):
    body = b"Comment\x00\x00" + zlib.compress(b"flag{ztxt_ok}")
    res = _run(tmp_path, _chunk(b"zTXt", body))
    assert "flag{ztxt_ok}" in res.output


def test_ztxt_without_nul_does_not_crash(tmp_path):
    res = _run(tmp_path, _chunk(b"zTXt", b"garbage-no-nul"))
    assert res.status != "error"
