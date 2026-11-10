"""pcap: extra `--export-objects` protocols, gated by the hierarchy already parsed.

The commands are recorded with a fake context: no tshark run, no network.
"""
from __future__ import annotations

import subprocess

from backend.analyzers import pcap


class _Ctx:
    def __init__(self, root):
        self.input = root / "capture.pcap"
        self.input.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        self.workdir = root
        self.calls: list[list[str]] = []

    def sub(self, name):
        d = self.workdir / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def run(self, cmd, timeout=300, **_kw):
        self.calls.append([str(c) for c in cmd])
        return subprocess.CompletedProcess([str(c) for c in cmd], 0, "", "")


def _exports(ctx) -> list[str]:
    return [c[c.index("--export-objects") + 1] for c in ctx.calls
            if "--export-objects" in c]


PHS_HTTP = """\
Protocol Hierarchy Statistics
Filter:

eth                     frames:10 bytes:900
  ip                    frames:10 bytes:900
    tcp                 frames:10 bytes:900
      http              frames:4 bytes:400
      ftp               frames:3 bytes:300
"""


def test_http_only_capture_does_not_run_the_extra_exports(tmp_path):
    ctx = _Ctx(tmp_path)
    pcap.export_objects(ctx, ctx.input, [], PHS_HTTP, ctx.sub("pcap"))
    targets = _exports(ctx)
    assert len(targets) == 1 and targets[0].endswith("pcap")
    assert not any(t.split(",")[0] in ("smb", "tftp", "imf", "ftp-data") for t in targets)


def test_smb_in_the_hierarchy_triggers_its_export(tmp_path):
    phs = PHS_HTTP + "      smb2              frames:2 bytes:200\n"
    ctx = _Ctx(tmp_path)
    pcap.export_objects(ctx, ctx.input, [], phs, ctx.sub("pcap"))
    targets = _exports(ctx)
    smb = [t for t in targets if t.startswith("smb,")]
    assert len(smb) == 1
    assert smb[0].endswith(str(tmp_path / "pcap" / "smb"))


def test_each_extra_protocol_is_exported_in_its_own_folder(tmp_path):
    phs = PHS_HTTP + (
        "      tftp              frames:1 bytes:90\n"
        "      smb               frames:1 bytes:90\n"
        "      imf               frames:1 bytes:90\n"
        "      ftp-data          frames:1 bytes:90\n")
    ctx = _Ctx(tmp_path)
    pcap.export_objects(ctx, ctx.input, [], phs, ctx.sub("pcap"))
    targets = _exports(ctx)
    for proto in ("smb", "tftp", "imf", "ftp-data"):
        match = [t for t in targets if t.startswith(proto + ",")]
        assert len(match) == 1, proto
        assert match[0].endswith(str(tmp_path / "pcap" / proto))


def test_ftp_control_alone_does_not_export_ftp_data(tmp_path):
    ctx = _Ctx(tmp_path)
    pcap.export_objects(ctx, ctx.input, [], PHS_HTTP, ctx.sub("pcap"))
    assert not any(t.startswith("ftp-data,") for t in _exports(ctx))


def test_protocol_names_must_match_a_whole_layer(tmp_path):
    # "smb_direct" is a different layer text and must not be read as "smb"
    phs = PHS_HTTP + "      smb2xyz           frames:1 bytes:90\n"
    ctx = _Ctx(tmp_path)
    pcap.export_objects(ctx, ctx.input, [], phs, ctx.sub("pcap"))
    assert not any(t.startswith("smb,") for t in _exports(ctx))


def test_exported_folders_are_listed_as_files(tmp_path, monkeypatch):
    def fake_run(cmd, timeout=300, **_kw):
        target = cmd[cmd.index("--export-objects") + 1]
        proto, _, folder = target.partition(",")
        if proto in ("smb", "tftp"):
            (tmp_path / "pcap" / proto / "object.bin").write_bytes(b"data")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    ctx = _Ctx(tmp_path)
    monkeypatch.setattr(ctx, "run", fake_run)
    phs = PHS_HTTP + "      smb              frames:1 bytes:90\n"
    files = pcap.export_objects(ctx, ctx.input, [], phs, ctx.sub("pcap"))
    assert (tmp_path / "pcap" / "smb" / "object.bin") in files
