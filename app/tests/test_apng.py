"""gif-frames on animated PNGs: only APNGs are accepted, plain PNGs skip."""
from __future__ import annotations

from PIL import Image

from backend.analyzers.base import ToolContext
from backend.analyzers.gif import GifFramesAnalyzer


def _apng(path, colors, durations=(100, 200, 300)) -> Image.Image:
    frames = [Image.new("RGB", (16, 12), c) for c in colors]
    frames[0].save(path, save_all=True, append_images=frames[1:],
                   duration=list(durations), loop=0)
    return frames[0]


def _run(tmp_path, p):
    return GifFramesAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))


def test_png_extension_is_matched_for_apng():
    a = GifFramesAnalyzer()
    assert a.matches("image/png", "anim.png")
    assert a.matches("image/gif", "anim.gif")


def test_plain_png_is_skipped_before_opening_it(tmp_path):
    p = tmp_path / "still.png"
    Image.new("RGB", (16, 12), "red").save(p)
    r = _run(tmp_path, p)
    assert r.status == "skipped"
    assert "animated PNG" in r.summary


def test_apng_frames_are_all_split(tmp_path):
    p = tmp_path / "anim.png"
    _apng(p, ["red", "green", "blue"])
    r = _run(tmp_path, p)
    assert r.status == "done"
    assert "frames: 3" in r.output
    assert "durations(ms): [100, 200, 300]" in r.output
    frames = sorted((tmp_path / "w" / "gif-frames").glob("frame_*.png"))
    assert len(frames) == 3
    assert len(r.extracted) == 3


def test_actl_outside_the_first_64k_is_ignored(tmp_path):
    p = tmp_path / "late.png"
    _apng(p, ["red", "green"])
    raw = p.read_bytes()
    # push the acTL chunk past the 64 KiB the gate reads: pad with a private
    # ancillary chunk right after the signature
    pos = 8
    length = int.from_bytes(raw[pos:pos + 4], "big")
    insert_at = pos + 12 + length          # after IHDR
    payload = b"\x00" * 0x4000
    filler = (len(payload).to_bytes(4, "big") + b"prVt" + payload
              + b"\x00\x00\x00\x00")
    p.write_bytes(raw[:insert_at] + filler * 7 + raw[insert_at:])
    assert b"acTL" not in p.read_bytes()[:65536]
    r = _run(tmp_path, p)
    assert r.status == "skipped"
