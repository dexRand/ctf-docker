"""VNC passwords stored in registry hives (DES-ECB with the universal key).

RealVNC/TightVNC/UltraVNC obfuscate the password with one DES key that is the
same in every product (`e84ad660c4721ae0`): it is protocol data, not a value
taken from a challenge. The published example `d7a514d8c556aade` -> "Secure!"
comes from the TightVNC/Frizb password-decrypt notes (DES-CBC with a zero IV:
the first block is plain DES-ECB).
"""
from __future__ import annotations

import sys
import types

import pytest

pytest.importorskip("Cryptodome.Cipher.DES")

from backend.analyzers.base import ToolContext  # noqa: E402
from backend.analyzers.winreg import WinregAnalyzer, vnc_plaintext  # noqa: E402

# published protocol example ("Secure!\x00"), not a challenge value
VECTOR = "d7a514d8c556aade"
# same key, plaintext b"\x00" * 8 -> empty after stripping the padding NULs
VECTOR_NULS = "5ab2cdc0badcaf13"
# same key, plaintext b"\x01\x02\x03\x04\x05\x06\x07\x08" -> not printable
VECTOR_CONTROL = "8a74f13c9ea4b02b"


def test_known_vnc_vector_comes_back_as_text():
    assert vnc_plaintext(r"\Software\TightVNC\Server", "Password", VECTOR) == "Secure!"


def test_bytes_other_products_and_uppercase_hex():
    raw = bytes.fromhex(VECTOR)
    assert vnc_plaintext(r"\Software\RealVNC\WinVNC4", "password", raw) == "Secure!"
    assert vnc_plaintext(r"\Software\UltraVNC", "passwd", VECTOR.upper()) == "Secure!"
    assert vnc_plaintext(r"\Software\TightVNC\Server", "ControlPassword", VECTOR) == "Secure!"


def test_a_password_outside_a_vnc_key_is_not_decrypted():
    assert vnc_plaintext(r"\Software\Windows\CurrentVersion", "Password", VECTOR) is None


def test_other_values_of_a_vnc_key_are_not_decrypted():
    assert vnc_plaintext(r"\Software\TightVNC\Server", "RfbPort", VECTOR) is None
    assert vnc_plaintext(r"\Software\TightVNC\Server", "(default)", VECTOR) is None


@pytest.mark.parametrize("blob", ["", "00", VECTOR + "00", "zz" * 4, None, 123,
                                  bytes.fromhex(VECTOR) + b"\x00"])
def test_malformed_values_are_refused(blob):
    assert vnc_plaintext(r"\Software\TightVNC\Server", "Password", blob) is None


def test_non_printable_plaintext_is_refused():
    assert vnc_plaintext(r"\Software\TightVNC\Server", "Password", VECTOR_NULS) is None
    assert vnc_plaintext(r"\Software\TightVNC\Server", "Password", VECTOR_CONTROL) is None


class _Value:
    def __init__(self, name, value):
        self.name, self.value = name, value


class _Entry:
    def __init__(self, path, values):
        self.path = self.subkey_name = path
        self.values = values


def _fake_regipy(monkeypatch, entries):
    """regipy is an external parser: a fake hive keeps the unit test offline."""
    module = types.ModuleType("regipy.registry")
    module.RegistryHive = lambda _path: types.SimpleNamespace(
        recurse_subkeys=lambda: iter(entries))
    package = types.ModuleType("regipy")
    package.registry = module
    monkeypatch.setitem(sys.modules, "regipy", package)
    monkeypatch.setitem(sys.modules, "regipy.registry", module)


def test_analyzer_output_contains_the_decrypted_password(tmp_path, monkeypatch):
    _fake_regipy(monkeypatch, [
        _Entry(r"\Software\TightVNC\Server",
               [_Value("Password", VECTOR), _Value("RfbPort", 5900)]),
        # same blob under a key without "VNC" must stay undecrypted
        _Entry(r"\Software\Windows\CurrentVersion", [_Value("Password", VECTOR)]),
    ])
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"regf" + b"\x00" * 4096)
    r = WinregAnalyzer().run(ToolContext(input=hive, workdir=tmp_path / "w"))
    assert r.status == "done", r.summary
    out = r.output or ""
    assert out.count("Secure!") == 1
    assert r"\Software\TightVNC\Server" in out
    assert "1 VNC password(s)" in r.summary


def test_a_hive_without_vnc_keys_has_no_vnc_section(tmp_path, monkeypatch):
    _fake_regipy(monkeypatch, [
        _Entry(r"\Software\Windows\CurrentVersion", [_Value("Password", VECTOR)]),
    ])
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"regf" + b"\x00" * 4096)
    r = WinregAnalyzer().run(ToolContext(input=hive, workdir=tmp_path / "w"))
    assert r.status == "done", r.summary
    assert "VNC" not in (r.output or "")
    assert "VNC" not in r.summary
