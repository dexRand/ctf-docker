"""Gap-closing helpers: IPv4 evil bit, zstd IDAT, OCR confusion fixes."""
import io
import shutil
import struct
import subprocess
import zlib

import pytest
from PIL import Image

from backend.analyzers.pcap import evil_bit_streams, repaired_pcap
from backend.analyzers.png import PNG_SIG, rebuild_zstd_png
from backend.analyzers.vision import _confusable_variants


def test_evil_bit_streams_reads_one_byte_payloads():
    rows = "\n".join([f"False\t{ord(c):02x}" for c in "lactf{ab"]
                     + [f"True\t{ord(c):02x}" for c in "n0is3abc"])
    got = dict(evil_bit_streams(rows))
    assert got["without the evil bit"] == "lactf{ab"
    assert got["with the evil bit"] == "n0is3abc"


def test_evil_bit_streams_ignores_short_or_binary_sides():
    assert evil_bit_streams("False\t6c\nFalse\t61") == []          # too few
    # eight one-byte payloads that are not text
    assert evil_bit_streams("\n".join("False\t00" for _ in range(8))) == []


def test_ocr_confusions_are_fixed_inside_flags_only():
    assert _confusable_variants("see picoCTF{cOrrupt10n_\n1847995} here") == \
        "picoCTF{c0rrupt10n_1847995}"
    # nothing to fix in a clean body
    assert _confusable_variants("its{clean_body}") == ""


def test_ocr_leet_bodies_try_one_for_i():
    assert "picoCTF{qu1t3_a_v13w_2020}" in _confusable_variants("picoCTF{quit3_a_v13w_2020}")


def test_rebuild_zstd_png_leaves_a_normal_png_alone(tmp_path):
    buf = io.BytesIO()
    Image.new("RGB", (3, 3), (1, 2, 3)).save(buf, format="PNG")
    log: list[str] = []
    assert rebuild_zstd_png(buf.getvalue(), log) is None
    assert log == []


@pytest.mark.skipif(not shutil.which("zstd"), reason="zstd not installed")
def test_rebuild_zstd_png_from_lying_ihdr():
    # 4x4 RGB scanlines (filter byte 0 + pixels), compressed with zstd and put
    # into a PNG whose IHDR claims 1x1 (the picoCTF "miniscule" trick)
    raw = b"".join(b"\x00" + b"\x10\x20\x30" * 4 for _ in range(4))
    zst = subprocess.run(["zstd", "-q", "-c"], input=raw, capture_output=True, check=True).stdout

    def chunk(ctype: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + ctype + payload
                + struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF))

    png = (PNG_SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zst) + chunk(b"IEND", b""))
    log: list[str] = []
    out = rebuild_zstd_png(png, log)
    assert out and out.startswith(PNG_SIG)
    im = Image.open(io.BytesIO(out))
    assert im.size == (4, 4)
    assert im.getpixel((0, 0)) == (0x10, 0x20, 0x30)
    assert any("zstd IDAT" in line for line in log)


def test_repaired_pcap_fixes_magic_and_record_lengths():
    payload = b"\x00" * 14          # a short ethernet frame
    global_hdr = b"\xde\xad\xbe\xef" + struct.pack("<HHiiii", 2, 4, 0, 0, 262144, 1)
    rec = struct.pack("<IIII", 1, 2, 999999, len(payload)) + payload
    out = repaired_pcap(global_hdr + rec)
    assert out and out[:4] == b"\xd4\xc3\xb2\xa1"
    assert struct.unpack_from("<I", out, 24 + 8)[0] == len(payload)
    # a valid capture is left alone
    good = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiiii", 2, 4, 0, 0, 262144, 1) + rec
    assert repaired_pcap(good) is None


def test_chef_recipe_with_two_unknown_quantities():
    from backend.analyzers.chef import decode_chef
    text = """Ingredients.
1 cup water
5 kg salt
Method.
Put water into 1st mixing bowl.
Add salt to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Add salt to 1st mixing bowl.
"""
    # group 1: x + 5 + y = 65; group 2: 2x + 5 + y = 66 -> x=1, y=59
    assert (1, 59, "AB") in decode_chef(text)


def test_long_http_object_names_are_truncated():
    from backend.storage import sanitize_name
    name = sanitize_name("videoplayback?" + "a" * 400 + ".webm")
    assert len(name) <= 120 and name.endswith(".webm")


def test_sam_hashes_are_parsed_and_blank_ones_skipped():
    from backend.analyzers.sam import parse_hashes
    text = ("Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
            "476b4dddbbffde29e739b618580adb1e:::\n"
            "Guest:501:aad3b435b51404eeaad3b435b51404ee:"
            "31d6cfe0d16ae931b73c59d7e0c089c0:::")
    assert parse_hashes(text) == {"Administrator": "476b4dddbbffde29e739b618580adb1e"}
