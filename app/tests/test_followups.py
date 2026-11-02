"""Follow-ups of the 02/11 verification: issues #17–#22."""
from __future__ import annotations

import pathlib
import struct
from types import SimpleNamespace

from backend.magic import by_ext, has_embedded
from backend.planner import CARVERS, _plan_for, carving_useless
from backend.storage import sniff_mime

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
ZIP = b"PK\x03\x04" + b"\x00" * 26


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


# --- #17: carving on files extracted from archives --------------------------

def test_unknown_leaf_with_an_embedded_file_is_carved(tmp_path):
    blob = _write(tmp_path, "mystery", b"\x13\x37" * 32 + PNG + b"\x00" * 64)
    assert has_embedded(blob)
    plan = _plan_for("mystery", None, False, "7z", size=200, depth=1,
                     embedded=has_embedded(blob))
    assert {"binwalk-extract", "foremost"} <= set(plan)
    assert "binwalk-scan" not in plan                   # folded into binwalk -e


def test_unknown_leaf_without_signatures_is_not_carved(tmp_path):
    blob = _write(tmp_path, "settings.dat", b"\x13\x37\x00\x01" * 64)
    assert not has_embedded(blob)
    assert carving_useless(1, None, False)
    plan = _plan_for("settings.dat", None, False, "7z", size=256, depth=1, embedded=False)
    assert not CARVERS & set(plan)


def test_audio_video_and_captures_from_archives_are_always_carved():
    for name, mime in (("song.mp3", "audio/mpeg"), ("clip.mp4", "video/mp4"),
                       ("cap.pcap", "application/vnd.tcpdump.pcap")):
        assert not carving_useless(1, mime, False), name


def test_uploads_are_always_carved():
    assert not carving_useless(0, None, False)


def test_pcap_and_registry_are_recognised(tmp_path):
    assert sniff_mime(_write(tmp_path, "x", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)) \
        == "application/vnd.tcpdump.pcap"
    assert sniff_mime(_write(tmp_path, "y", b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)) \
        == "application/x-pcapng"
    assert sniff_mime(_write(tmp_path, "z", b"regf" + b"\x00" * 20)) == "application/x-ms-registry"


# --- #18: node budget order --------------------------------------------------

def test_node_budget_order_shallow_then_known_then_small():
    from backend.pipeline import _priority
    deep_txt = SimpleNamespace(name="a.txt", depth=3, size=10)
    shallow_unknown = SimpleNamespace(name="b.lnk", depth=1, size=10)
    shallow_zip = SimpleNamespace(name="c.zip", depth=1, size=9_000_000)
    shallow_txt = SimpleNamespace(name="d.txt", depth=1, size=50)
    ordered = sorted([deep_txt, shallow_unknown, shallow_zip, shallow_txt], key=_priority)
    assert ordered == [shallow_txt, shallow_zip, shallow_unknown, deep_txt]


# --- #19: pdf-images keeps every image visible -------------------------------
# (exercised end-to-end by the real challenges; here only the listing format)

def test_pdf_images_listing_mentions_skipped_images():
    import inspect
    from backend.analyzers import pdf
    src = inspect.getsource(pdf.PdfImagesAnalyzer.run)
    assert "not analysed" in src and "for p in imgs]" in src


# --- #20: usb-hid only on USB captures ---------------------------------------

def _pcap(linktype: int) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)


def _pcapng(linktype: int) -> bytes:
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body \
        + struct.pack("<I", 12 + len(shb_body))
    idb_body = struct.pack("<HHI", linktype, 0, 65535)
    idb = struct.pack("<II", 1, 12 + len(idb_body)) + idb_body + struct.pack("<I", 12 + len(idb_body))
    return shb + idb


def test_link_types_from_pcap_and_pcapng(tmp_path):
    from backend.analyzers.usbhid import USB_LINKTYPES, link_types
    assert link_types(_write(tmp_path, "eth.pcap", _pcap(1))) == {1}
    assert link_types(_write(tmp_path, "usb.pcap", _pcap(189))) & USB_LINKTYPES
    assert link_types(_write(tmp_path, "usb.pcapng", _pcapng(249))) == {249}
    assert link_types(_write(tmp_path, "junk.pcap", b"not a capture")) is None


def test_usb_hid_skips_non_usb_capture_without_tshark(tmp_path, monkeypatch):
    from backend.analyzers import usbhid
    calls = []
    ctx = SimpleNamespace(input=_write(tmp_path, "eth.pcap", _pcap(1)),
                          run=lambda *a, **k: calls.append(a))
    monkeypatch.setattr(usbhid, "which", lambda _t: "/usr/bin/tshark")
    r = usbhid.UsbHidAnalyzer().run(ctx)
    assert r.status == "skipped" and "not a USB capture" in r.summary
    assert not calls                     # no tshark pass at all


# --- #21: msb-bits on palette / grayscale images ------------------------------

def test_rgba_head_converts_palette_and_gray_on_request(tmp_path):
    from PIL import Image
    from backend.analyzers.lsb import _rgba_head
    for mode in ("P", "L"):
        path = tmp_path / f"img-{mode}.png"
        Image.new(mode, (8, 4)).save(path)
        assert _rgba_head(path) is None                       # default: RGB/RGBA only
        arr = _rgba_head(path, any_mode=True)
        assert arr is not None and arr.shape == (4, 8, 4)


# --- #22: leftovers ------------------------------------------------------------

def test_every_file_endpoint_is_hardened():
    from backend.api.fileresp import file_response, inline_ok
    assert inline_ok("image/png") and inline_ok("audio/wav") and inline_ok("text/plain")
    for bad in ("text/html", "image/svg+xml", "application/xml", "application/pdf", None):
        assert not inline_ok(bad)
    r = file_response(pathlib.Path(__file__), "text/html", "x.html")
    assert r.media_type == "application/octet-stream"
    assert "attachment" in r.headers["content-disposition"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in r.headers["content-security-policy"]


def test_no_endpoint_builds_its_own_file_response():
    api = pathlib.Path(__file__).resolve().parents[1] / "backend" / "api"
    for f in api.glob("*.py"):
        if f.name != "fileresp.py":
            assert "FileResponse(" not in f.read_text(), f.name


def test_shared_magic_subsets_drop_short_signatures():
    sigs = dict(by_ext(".bmp", ".png", ".exe"))
    assert b"\x89PNG\r\n\x1a\n" in sigs
    assert b"BM" not in sigs and b"MZ" not in sigs
    assert b"BM" in dict(by_ext(".bmp", min_len=2))


def test_chef_uses_the_shared_prefixes():
    from backend.analyzers import chef
    from backend.flagpatterns import FLAG_PREFIXES
    assert "hxp" in FLAG_PREFIXES and "bctf" in FLAG_PREFIXES
    assert not hasattr(chef, "_PREFIXES")


def test_sniff_mime_empty_file_and_cut_utf8(tmp_path):
    assert sniff_mime(_write(tmp_path, "empty", b"")) is None
    cut = ("a" * 8191 + "é").encode()            # "é" straddles the 8 KiB sample
    assert sniff_mime(_write(tmp_path, "text", cut)) == "text/plain"


def test_ztxt_decompression_is_capped():
    import inspect
    from backend.analyzers import png
    assert "_ZTXT_MAX" in inspect.getsource(png)


def test_disk_images_unpacked_by_the_disk_analyzer_are_not_carved_again():
    for made_by in ("disk", "7z", "binwalk-extract"):
        plan = _plan_for("disk.flag.img", None, False, made_by, size=400 << 20, depth=1,
                         embedded=True)
        assert not CARVERS & set(plan), made_by
    # an uploaded image is still carved (deleted files, slack space)
    assert CARVERS - {"binwalk-scan"} <= set(_plan_for("disk.img", None, False, "", size=400 << 20, depth=0))
