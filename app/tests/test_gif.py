"""gif-frames: distinct frames become children; the others are OCR'd once."""
from PIL import Image

from backend.analyzers import gif


def _frames(tmp_path, colors):
    out = []
    for i, c in enumerate(colors):
        p = tmp_path / f"frame_{i:04d}.png"
        Image.new("RGB", (8, 8), c).save(p)
        out.append(p)
    return out


def test_identical_frames_are_exported_once(tmp_path):
    frames = _frames(tmp_path, ["red", "red", "blue", "red", "blue"])
    picked = gif.GifFramesAnalyzer._pick_exported(frames, [])
    assert [p.name for p in picked] == ["frame_0000.png", "frame_0002.png"]


def test_many_distinct_frames_are_sampled_with_the_most_changed(tmp_path, monkeypatch):
    monkeypatch.setattr(gif, "MAX_NODES", 4)
    frames = _frames(tmp_path, [(i, i, i) for i in range(20)])
    picked = gif.GifFramesAnalyzer._pick_exported(frames, [(99.0, 17)])
    names = {p.name for p in picked}
    assert len(picked) <= 5 and "frame_0017.png" in names
