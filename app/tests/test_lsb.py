"""lsb-carve: the numpy bit streams must be byte-identical to `zsteg -e`."""
import shutil
import subprocess

import numpy as np
import pytest
from PIL import Image

from backend.analyzers.base import ToolContext
from backend.analyzers.lsb import _SPECS, LsbCarveAnalyzer, lsb_stream


@pytest.mark.skipif(not shutil.which("zsteg"), reason="zsteg not installed")
@pytest.mark.parametrize("mode,fmt", [("RGB", "png"), ("RGBA", "png"), ("RGB", "bmp")])
def test_numpy_stream_equals_zsteg(tmp_path, mode, fmt):
    rng = np.random.default_rng(7)
    img = Image.fromarray(rng.integers(0, 256, (23, 37, len(mode)), dtype=np.uint8), mode)
    p = tmp_path / f"x.{fmt}"
    img.save(p)
    arr = np.asarray(Image.open(p).convert("RGBA"))
    for spec in _SPECS:
        z = subprocess.run(["zsteg", "-e", spec, str(p)], capture_output=True).stdout
        assert z and lsb_stream(arr, spec)[:len(z)] == z, spec


def test_carves_a_zip_hidden_in_the_lsb(tmp_path):
    payload = b"PK\x03\x04" + bytes(range(256)) * 2
    bits = np.unpackbits(np.frombuffer(b"\x00\x01\x02" + payload, dtype=np.uint8))
    h, w = 40, 40
    px = np.random.default_rng(1).integers(0, 256, (h, w, 3), dtype=np.uint8)
    flat = px.reshape(-1, 3)[:, ::-1].reshape(-1)          # b1,bgr: channel order b,g,r
    flat[: len(bits)] = (flat[: len(bits)] & 0xFE) | bits
    px = flat.reshape(-1, 3)[:, ::-1].reshape(h, w, 3)
    p = tmp_path / "hide.png"
    Image.fromarray(px, "RGB").save(p)
    res = LsbCarveAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    carved = [f for f in res.extracted if f.endswith(".zip")]
    assert carved and open(carved[0], "rb").read().startswith(payload[:64])


def _stepic_encode(img: Image.Image, data: bytes) -> Image.Image:
    """Reference stepic encoder (3 pixels per byte, last LSB = end marker)."""
    px = np.asarray(img.convert("RGB")).copy().reshape(-1, 3)
    for i, byte in enumerate(data):
        vals = px[i * 3:i * 3 + 3].reshape(-1)
        bits = [(byte >> (7 - k)) & 1 for k in range(8)] + [1 if i == len(data) - 1 else 0]
        vals[:] = (vals & 0xFE) | np.array(bits, dtype=np.uint8)
        px[i * 3:i * 3 + 3] = vals.reshape(3, 3)
    return Image.fromarray(px.reshape(np.asarray(img).shape[0], -1, 3), "RGB")


def test_stepic_decodes(tmp_path):
    from backend.analyzers.lsb import StepicAnalyzer
    base = Image.fromarray(np.random.default_rng(3).integers(0, 256, (40, 60, 3), dtype=np.uint8), "RGB")
    p = tmp_path / "s.png"
    _stepic_encode(base, b"picoCTF{fl4g_st3pic}").save(p)
    res = StepicAnalyzer().run(ToolContext(input=p, workdir=tmp_path / "w"))
    assert res.output == "picoCTF{fl4g_st3pic}"
