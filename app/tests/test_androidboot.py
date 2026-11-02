"""android-boot analyzer (issue #13): header v0, gzip ramdisk, cpio newc."""
from __future__ import annotations

import gzip
import struct
from pathlib import Path
from types import SimpleNamespace

from backend.analyzers.androidboot import AndroidBootAnalyzer, cpio_files


def _cpio(files: dict[str, bytes]) -> bytes:
    out = b""
    for i, (name, data) in enumerate(list(files.items()) + [("TRAILER!!!", b"")]):
        mode = 0o100644 if name != "TRAILER!!!" else 0
        nm = name.encode() + b"\x00"
        hdr = b"070701" + b"".join(b"%08X" % v for v in
                                    (i, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0))
        rec = hdr + nm
        rec += b"\x00" * (-len(rec) % 4) + data
        rec += b"\x00" * (-len(rec) % 4)
        out += rec
    return out


def _bootimg(kernel: bytes, ramdisk: bytes, page: int = 2048) -> bytes:
    hdr = b"ANDROID!" + struct.pack("<10I", len(kernel), 0, len(ramdisk), 0, 0, 0, 0, page, 0, 0)
    pad = lambda b: b + b"\x00" * (-len(b) % page)          # noqa: E731
    return pad(hdr) + pad(kernel) + pad(ramdisk)


def test_cpio_newc_regular_files():
    raw = _cpio({"init.rc": b"on boot", "res/flag.txt": b"flag{x}"})
    assert dict(cpio_files(raw)) == {"init.rc": b"on boot", "res/flag.txt": b"flag{x}"}


def test_boot_image_unpacks_kernel_and_ramdisk_files(tmp_path):
    ramdisk = gzip.compress(_cpio({"res/images/charger/battery_fail.png": b"\x89PNG fake"}))
    img = tmp_path / "boot.img"
    img.write_bytes(_bootimg(b"KERNEL" * 10, ramdisk))
    ctx = SimpleNamespace(input=img, sub=lambda n: tmp_path / n)
    r = AndroidBootAnalyzer().run(ctx)
    assert r.status == "done"
    names = [Path(p).name for p in r.extracted]
    assert "kernel" in names
    assert any(n.endswith("battery_fail.png") for n in names)
    png = next(p for p in r.extracted if p.endswith("battery_fail.png"))
    assert Path(png).read_bytes() == b"\x89PNG fake"


def test_other_img_files_are_skipped(tmp_path):
    img = tmp_path / "disk.img"
    img.write_bytes(b"\x00" * 1024)
    assert AndroidBootAnalyzer().run(SimpleNamespace(input=img, sub=lambda n: tmp_path / n)).status \
        == "skipped"
