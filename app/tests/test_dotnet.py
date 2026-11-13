"""dotnet analyzer (issue #16): CLR managed resources become child files.

Building a real .NET assembly is awkward, so the unit tests mock the pieces of
``dnfile.dnPE`` that the analyzer reads (CLR header, ManifestResource rows,
``get_data``). The MZ/PE/CLI gating is exercised on bytes generated here, so the
test also passes without dnfile installed.
"""
from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace

from backend.analyzers import dotnet


def _pe(*, rva: int = 0x400, size: int = 0x80, plus: bool = True) -> bytes:
    """Minimal MZ + PE + optional header with data directory 14 filled."""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)          # e_lfanew
    data[0x80:0x84] = b"PE\x00\x00"
    opt = 0x80 + 24                                   # PE sig + COFF header
    struct.pack_into("<H", data, opt, 0x20B if plus else 0x10B)
    num_off = opt + (108 if plus else 92)
    dirs_off = opt + (112 if plus else 96)
    struct.pack_into("<I", data, num_off, 16)         # NumberOfRvaAndSizes
    struct.pack_into("<II", data, dirs_off + 14 * 8, rva, size)   # CLR directory
    return bytes(data)


class _Ctx:
    """The subset of ToolContext the analyzer uses."""

    def __init__(self, path: Path):
        self.input = path
        self.workdir = path.parent

    def sub(self, name: str) -> Path:
        d = self.workdir / name
        d.mkdir(parents=True, exist_ok=True)
        return d


class _Row:
    def __init__(self, name: str, offset: int, external: bool = False):
        self.Name = SimpleNamespace(value=name)
        self.Offset = offset
        self.Implementation = SimpleNamespace() if external else None


class _FakePE:
    """Resource area of a dnPE: rows + the blobs ``get_data`` returns."""

    def __init__(self, resources: list[tuple[str, bytes]], rva: int = 0x400):
        self._blobs = b""
        self._rva = rva
        rows = []
        for name, blob in resources:
            rows.append(_Row(name, len(self._blobs)))
            self._blobs += struct.pack("<I", len(blob)) + blob
        self.net = SimpleNamespace(
            struct=SimpleNamespace(ResourcesRva=rva, ResourcesSize=len(self._blobs)),
            mdtables=SimpleNamespace(ManifestResource=SimpleNamespace(rows=rows)),
        )

    def get_data(self, rva: int, size: int) -> bytes:
        off = rva - self._rva
        if off < 0 or off >= len(self._blobs):
            raise ValueError("rva outside the resource area")
        return self._blobs[off:off + size]


def _run(tmp_path: Path, monkeypatch, pe: _FakePE) -> object:
    path = tmp_path / "sample.dll"
    path.write_bytes(_pe())
    monkeypatch.setattr(dotnet, "_load", lambda _path: pe)
    return dotnet.DotNetAnalyzer().run(_Ctx(path))


def test_cli_directory_pe32_and_pe32plus():
    assert dotnet.cli_directory(_pe(plus=True)) == (0x400, 0x80)
    assert dotnet.cli_directory(_pe(plus=False)) == (0x400, 0x80)
    assert dotnet.cli_directory(b"hello") is None
    assert dotnet.cli_directory(b"MZ" + b"\x00" * 100) is None


def test_pe_without_cli_directory_is_skipped(tmp_path, monkeypatch):
    path = tmp_path / "plain.exe"
    path.write_bytes(_pe(rva=0, size=0))

    def _boom(_path):
        raise AssertionError("dnfile must not parse a non-.NET PE")

    monkeypatch.setattr(dotnet, "_load", _boom)
    r = dotnet.DotNetAnalyzer().run(_Ctx(path))
    assert r.status == "skipped"
    assert r.extracted == []


def test_non_pe_is_skipped_without_parsing(tmp_path, monkeypatch):
    path = tmp_path / "flag.txt"
    path.write_bytes(b"this is not a PE file")

    def _boom(_path):
        raise AssertionError("dnfile must not parse a non-PE file")

    monkeypatch.setattr(dotnet, "_load", _boom)
    r = dotnet.DotNetAnalyzer().run(_Ctx(path))
    assert r.status == "skipped"
    assert r.extracted == []


def test_resources_become_named_children(tmp_path, monkeypatch):
    pe = _FakePE([
        ("App.Strings.resources", b"first resource"),
        ("logo/evil name.bin", b"\x89PNG\r\n\x1a\npayload"),
        ("empty.dat", b""),
    ])
    r = _run(tmp_path, monkeypatch, pe)
    assert r.status == "done"
    files = sorted(Path(p).name for p in r.extracted)
    assert files == ["App.Strings.resources", "evil_name.bin"]
    written = {Path(p).name: Path(p).read_bytes() for p in r.extracted}
    assert written["App.Strings.resources"] == b"first resource"
    assert written["evil_name.bin"].startswith(b"\x89PNG")
    assert "logo/evil name.bin" in r.output


def test_at_most_100_resources(tmp_path, monkeypatch):
    assert dotnet._MAX_RESOURCES == 100
    pe = _FakePE([(f"r{i:03d}.bin", b"x") for i in range(130)])
    r = _run(tmp_path, monkeypatch, pe)
    assert r.status == "done"
    assert len(r.extracted) == 100


def test_total_byte_cap_skips_resources_that_do_not_fit(tmp_path, monkeypatch):
    assert dotnet._MAX_BYTES == 50 << 20
    monkeypatch.setattr(dotnet, "_MAX_BYTES", 10)
    pe = _FakePE([("a.bin", b"12345678"), ("b.bin", b"12345678")])
    r = _run(tmp_path, monkeypatch, pe)
    assert [Path(p).name for p in r.extracted] == ["a.bin"]


def test_resource_over_the_cap_is_not_written(tmp_path, monkeypatch):
    monkeypatch.setattr(dotnet, "_MAX_BYTES", 10)
    pe = _FakePE([("big.bin", b"x" * 11)])
    r = _run(tmp_path, monkeypatch, pe)
    assert r.status == "skipped"
    assert r.extracted == []


def test_external_resources_are_ignored(tmp_path, monkeypatch):
    pe = _FakePE([])
    pe.net.mdtables.ManifestResource.rows.append(_Row("linked.resources", 0, external=True))
    r = _run(tmp_path, monkeypatch, pe)
    assert r.status == "skipped"
    assert r.extracted == []
