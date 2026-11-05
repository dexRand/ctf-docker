"""tar-chain: chains of nested tar archives (picoCTF "like1000")."""
from __future__ import annotations

import io
import tarfile

from backend.analyzers.base import ToolContext
from backend.analyzers.tarchain import TarChainAnalyzer


def _tar(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _chain(depth: int, leaf_name: str, leaf: bytes) -> bytes:
    blob = _tar({leaf_name: leaf, "filler.txt": b"filler\n"})
    for i in range(depth, 0, -1):
        blob = _tar({f"{i}.tar": blob, "filler.txt": b"filler\n"})
    return blob


def test_gating_skips_a_plain_tar(tmp_path):
    p = tmp_path / "plain.tar"
    p.write_bytes(_tar({"note.txt": b"hello"}))
    r = TarChainAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and "no nested tar chain" in r.summary


def test_gating_skips_a_non_tar(tmp_path):
    p = tmp_path / "x.tar"
    p.write_bytes(b"not a tar at all" * 40)
    r = TarChainAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "skipped" and "not a tar" in r.summary


def test_chain_is_walked_to_the_bottom(tmp_path):
    p = tmp_path / "chain.tar"
    p.write_bytes(_chain(12, "flag.txt", b"picoCTF{l0t5_0f_TAR5}\n"))
    r = TarChainAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert r.status == "done", r.summary
    assert "12 nested layer(s)" in r.summary
    assert len(r.extracted) == 2
    names = {p_.rsplit("__", 1)[-1] for p_ in r.extracted}
    assert names == {"flag.txt", "filler.txt"}
    leaf = next(p_ for p_ in r.extracted if p_.endswith("flag.txt"))
    assert open(leaf, "rb").read().startswith(b"picoCTF{l0t5_0f_TAR5}")
    assert "layers: 12" in (r.output or "")
