"""qr.py: generic de-masking of the data modules of a structural QR.

The matrix is a version-1 QR for `flag{test_mask}` (generated once, so the
unit test does not need qrencode; zbarimg still does the real decode).
"""
from __future__ import annotations

import shutil
import subprocess

import numpy as np
import pytest
from PIL import Image

from backend.analyzers import qr
from backend.analyzers.base import ToolContext
from backend.analyzers.qr import QrAnalyzer

QR_ROWS = (
    "#######___#_#_#######",
    "#_____#_###_#_#_____#",
    "#_###_#___###_#_###_#",
    "#_###_#_##_#__#_###_#",
    "#_###_#__#_#__#_###_#",
    "#_____#_#__##_#_____#",
    "#######_#_#_#_#######",
    "_________#_#_________",
    "#####_###____#_#_#_#_",
    "####_#___##_____##__#",
    "#__#__##_#_####___##_",
    "#_#_____####_#___##_#",
    "###_####__#_###____#_",
    "________#_##_#_##_#_#",
    "#######_#####____###_",
    "#_____#___####_#_####",
    "#_###_#_#___##_____##",
    "#_###_#_#_#__##_###__",
    "#_###_#_##_####__#___",
    "#_____#_######__###__",
    "#######_####__####_#_",
)


def _matrix() -> np.ndarray:
    return np.array([[c == "#" for c in row] for row in QR_ROWS], dtype=bool)


def _render(matrix: np.ndarray, path, module: int = 6, quiet: int = 2) -> None:
    size = matrix.shape[0]
    full = size + 2 * quiet
    arr = np.full((full * module, full * module), 255, dtype=np.uint8)
    for row, col in np.argwhere(matrix):
        y = (int(row) + quiet) * module
        x = (int(col) + quiet) * module
        arr[y:y + module, x:x + module] = 0
    Image.fromarray(arr, "L").save(path)


def _masked_all(matrix: np.ndarray) -> np.ndarray:
    """Apply the XOR of all eight QR masks to the data modules only."""
    functional = qr.functional_modules(matrix.shape[0])
    all_masks = qr.mask_patterns(matrix.shape[0])[-1]
    return qr.apply_mask(matrix, all_masks, functional)


def test_functional_regions_are_version_generic():
    size = 29
    fm = qr.functional_modules(size)
    assert fm.shape == (size, size)
    # finder + separator + format bits at the three corners
    assert fm[0, 0] and fm[8, 8]
    assert fm[0, size - 1] and fm[8, size - 8]
    assert fm[size - 1, 0] and fm[size - 8, 8]
    # timing patterns away from the corner boxes
    assert fm[6, 10] and fm[10, 6]
    # alignment pattern and dark module
    assert fm[22, 22] and fm[size - 8, 8]
    # a few modules that are data, not functional
    for x, y in ((9, 9), (12, 12), (20, 9), (9, 20)):
        assert not fm[y, x]

    # version information exists only from version 7 on
    size = 45
    fm = qr.functional_modules(size)
    assert fm[0, size - 10] and fm[size - 10, 0]
    assert not fm[10, 10]


def test_masks_come_in_nine_candidates():
    assert len(qr.mask_patterns(21)) == 9


@pytest.mark.skipif(shutil.which("zbarimg") is None, reason="zbarimg not installed")
def test_masked_qr_is_recovered_by_unmasking(tmp_path):
    plain = _matrix()
    masked = _masked_all(plain)
    assert not np.array_equal(masked, plain)
    path = tmp_path / "masked.png"
    _render(masked, path)

    direct = subprocess.run(["zbarimg", "--quiet", "--raw", str(path)],
                            capture_output=True, text=True)
    assert "flag{test_mask}" not in (direct.stdout + direct.stderr)

    r = QrAnalyzer().run(ToolContext(input=path, workdir=tmp_path / "work"))
    assert r.status == "done", r.summary
    assert "flag{test_mask}" in r.output


@pytest.mark.skipif(shutil.which("zbarimg") is None, reason="zbarimg not installed")
def test_plain_qr_is_decoded_without_unmasking(tmp_path, monkeypatch):
    path = tmp_path / "plain.png"
    _render(_matrix(), path)
    called: list[int] = []

    def fake_unmasked(*_args, **_kwargs):
        called.append(1)
        return iter(())

    monkeypatch.setattr(qr, "_unmasked", fake_unmasked)
    r = QrAnalyzer().run(ToolContext(input=path, workdir=tmp_path / "work"))
    assert r.status == "done", r.summary
    assert "flag{test_mask}" in r.output
    assert called == []


def test_image_without_qr_runs_no_extra_zbar(tmp_path, monkeypatch):
    rng = np.random.default_rng(0)
    path = tmp_path / "noise.png"
    Image.fromarray(rng.integers(0, 256, (160, 160), dtype=np.uint8), "L").save(path)
    assert list(qr._unmasked(path, tmp_path / "out")) == []

    monkeypatch.setattr(qr, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(qr, "_deblurred", lambda *_args, **_kwargs: iter(()))
    calls: list[list] = []

    class Ctx:
        input = path
        workdir = tmp_path / "work"

        def sub(self, name):
            d = self.workdir / name
            d.mkdir(parents=True, exist_ok=True)
            return d

        def run(self, cmd, timeout=300, cwd=None, env=None):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 4, "", "")

        def log(self, _message):
            pass

    r = QrAnalyzer().run(Ctx())
    assert r.status == "skipped"
    assert len(calls) == 1                     # only the direct zbarimg attempt


def test_too_large_image_is_rejected(tmp_path):
    path = tmp_path / "huge.png"
    Image.new("L", (3000, 3000), 255).save(path)     # 9 MPix > cap
    assert list(qr._unmasked(path, tmp_path / "out")) == []
