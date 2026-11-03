"""7z: data hidden under a directory entry of a zip (TJCTF 2022 sneaker-zipper)."""
from __future__ import annotations

import zipfile

from backend.analyzers.extract import zip_dir_payloads


def test_directory_entry_with_a_body_is_recovered(tmp_path):
    z = tmp_path / "chall.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("flag/", "tjctf{hidden_in_a_folder}")
        zf.writestr("flag/decoy.txt", "your flag is in another castle")
    out = zip_dir_payloads(z, tmp_path)
    assert [p.read_text() for p in out] == ["tjctf{hidden_in_a_folder}"]


def test_normal_zip_gives_nothing(tmp_path):
    z = tmp_path / "ok.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a/", "")
        zf.writestr("a/b.txt", "x")
    assert zip_dir_payloads(z, tmp_path) == []
