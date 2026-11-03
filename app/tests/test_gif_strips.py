"""gif-frames: QR codes cut into strips across frames (DUCTF 2021 how-to-pronounce-gif)."""
from __future__ import annotations

import base64
import shutil
import subprocess

import pytest

from backend.analyzers.gif import stacked_qr, strip_strides


def test_strides_only_for_strip_frames():
    assert 10 in strip_strides(120, 300, 22)
    assert strip_strides(10, 300, 300) == []          # full frames, not strips


@pytest.mark.skipif(not shutil.which("qrencode") or not shutil.which("zbarimg"),
                    reason="qrencode/zbarimg not installed")
def test_two_qr_codes_in_strips_with_base64_halves(tmp_path):
    from PIL import Image
    halves = [base64.b64encode(b"DUCTF{strips_ok}").decode()[:8],
              base64.b64encode(b"DUCTF{strips_ok}").decode()[8:]]
    codes = []
    for i, text in enumerate(halves):
        png = tmp_path / f"q{i}.png"
        subprocess.run(["qrencode", "-s", "6", "-m", "2", "-o", str(png), text], check=True)
        codes.append(Image.open(png).convert("L"))
    w = max(c.width for c in codes)
    codes = [c.resize((w, w)) for c in codes]
    strip, k = 12, len(codes)
    frames = []
    for r in range(w // strip):                         # frame order: q0 s0, q1 s0, q0 s1 ...
        for c in codes:
            f = tmp_path / f"f{len(frames):03d}.png"
            c.crop((0, r * strip, w, (r + 1) * strip)).save(f)
            frames.append(f)
    out = stacked_qr(frames, tmp_path)
    assert any(f"every {k}th frame" in ln and "DUCTF{strips_ok}" in ln for ln in out)
