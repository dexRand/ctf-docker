"""disk: NTFS alternate data streams and numbered pieces (TCP1P 2023 hide and split)."""
from __future__ import annotations

from backend.analyzers.disk import _FLS_RE, join_numbered


def test_fls_keeps_the_ntfs_attribute_of_streams():
    m = _FLS_RE.match("r/r 64-128-4:\tflag00.txt:flag0")
    assert m and m.group(3) == "64-128-4" and m.group(4) == "flag00.txt:flag0"
    m = _FLS_RE.match("r/r 12:\tetc/passwd")
    assert m and m.group(3) == "12"


def test_streams_joined_in_numeric_order_and_hex_decoded():
    png = b"\x89PNG\r\n\x1a\n" + b"IHDR-and-the-rest-of-the-picture"
    hexed = png.hex().encode()
    chunks = [hexed[i:i + 10] for i in range(0, len(hexed), 10)]
    pieces = [(f"flag{i:02d}.txt:flag{i}", c) for i, c in enumerate(chunks)][::-1]
    pieces += [(f"flag{i:02d}.txt", b"Unfortunately this is not the flag") for i in range(len(chunks))]
    joined = dict(join_numbered(pieces))
    assert joined["joined_streams_flag.png"] == png       # streams apart from the files


def test_unnumbered_or_too_few_pieces_are_left_alone():
    assert join_numbered([("a.txt", b"x"), ("part1", b"y"), ("part2", b"z")]) == []
