"""Unit tests for the deep nested-archive unwrapper (like1000-style chains).

Pure/stdlib: builds archive chains in a tmp dir and checks ``peel`` follows
them to the payload without relying on any external binary.
"""
import io
import tarfile
import zipfile
from pathlib import Path

from backend.analyzers import nested_archive as na


def _tar_bytes(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _chain(tmp_path: Path, levels: int, flag: bytes) -> Path:
    """levels tars, each `<n>.tar` + `filler.txt`, innermost has `flag.txt`."""
    cur = flag
    for i in range(1, levels + 1):
        inner = ("flag.txt", flag) if i == 1 else (f"{i - 1}.tar", cur)
        cur = _tar_bytes([inner, ("filler.txt", b"alkfdslkjf")])
    p = tmp_path / f"{levels}.tar"
    p.write_bytes(cur)
    return p


def test_plain_file_is_untouched(tmp_path):
    p = tmp_path / "note.txt"
    p.write_text("hello")
    layers, finals = na.peel(p, tmp_path / "work")
    assert layers == []
    assert finals == [p]


def test_single_archive_is_not_a_chain(tmp_path):
    p = tmp_path / "one.tar"
    p.write_bytes(_tar_bytes([("a.txt", b"hi")]))
    layers, finals = na.peel(p, tmp_path / "work")
    # peel may extract the member, but reports no followed layers
    assert layers == []


def test_deep_tar_chain_reaches_the_flag(tmp_path):
    flag = b"ITS{nested_archive_19}"
    p = _chain(tmp_path, 40, flag)
    layers, finals = na.peel(p, tmp_path / "work")
    assert len(layers) == 39           # 40 -> 1
    contents = {f.name: f.read_bytes() for f in finals}
    assert flag in contents.values()
    assert any("flag.txt" in n for n in contents)


def test_chain_ignores_filler_and_follows_the_archive(tmp_path):
    flag = b"ITS{solo}"
    p = _chain(tmp_path, 3, flag)
    layers, finals = na.peel(p, tmp_path / "work")
    assert len(layers) == 2
    assert any(b"ITS{solo}" in f.read_bytes() for f in finals)


def test_zip_chain(tmp_path):
    flag = b"ITS{zip_chain}"
    inner = tmp_path / "inner.txt"
    inner.write_bytes(flag)
    cur = inner.read_bytes()
    name = "flag.txt"
    for _ in range(6):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr(name, cur)
        cur = buf.getvalue()
        name = "next.zip"
    p = tmp_path / "chain.zip"
    p.write_bytes(cur)
    layers, finals = na.peel(p, tmp_path / "work")
    assert len(layers) == 5
    assert any(flag in f.read_bytes() for f in finals)


def test_encrypted_zip_is_left_to_the_cracker(tmp_path, monkeypatch):
    # simulate an encrypted member: the listing is visible, extraction raises
    p = tmp_path / "locked.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("flag.txt", "secret")
    real = zipfile.ZipFile
    orig = real.infolist

    def patched(self):  # noqa: ANN001
        for zi in orig(self):
            zi.flag_bits |= 0x1
        return orig(self)

    monkeypatch.setattr(zipfile.ZipFile, "infolist", patched)
    layers, finals = na.peel(p, tmp_path / "work")
    assert layers == []
    assert finals == [p]
