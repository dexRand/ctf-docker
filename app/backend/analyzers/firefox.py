"""Firefox saved logins: decrypt them with NSS (libnss3), like firefed.

`logins.json` keeps the username/password as base64 SDR blobs; the keys live in
`key4.db`. Calling `PK11SDR_Decrypt` through libnss3 is the same path Firefox
uses, so an empty master password (or one NSS can unlock) is enough — no need to
reimplement PBES2/3DES.
"""
from __future__ import annotations

import ctypes
import json
import shutil
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

_DB_FILES = ("key4.db", "cert9.db", "pkcs11.txt")


class _SecItem(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint), ("data", ctypes.c_void_p), ("len", ctypes.c_uint)]


def _libnss():
    for name in ("libnss3.so", "libnss3.dylib", "nss3.dll"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    return None


def _sdr_decrypt(nss, value: str) -> str | None:
    """Plaintext of one base64 SDR blob, or None."""
    raw = value.encode("ascii", "ignore")
    item = _SecItem(0, None, 0)
    if not nss.NSSBase64_DecodeBuffer(None, ctypes.byref(item), raw, len(raw)):
        return None
    out = _SecItem(0, None, 0)
    if nss.PK11SDR_Decrypt(ctypes.byref(item), ctypes.byref(out), None) != 0:
        return None
    return ctypes.string_at(out.data, out.len).decode("utf-8", "replace")


class FirefoxLoginsAnalyzer(Analyzer):
    name = "firefox-logins"
    category = "windows"
    description = "Decrypt Firefox saved logins (logins.json + key4.db) with libnss3."
    accepts = (".json",)
    display_order = 265

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            data = ctx.input.read_bytes()[:4_000_000]
        except OSError:
            return ToolResult(self.name, status="skipped", summary="unreadable")
        if b'"encryptedPassword"' not in data:
            return ToolResult(self.name, status="skipped", summary="not a Firefox logins file")
        try:
            logins = json.loads(data).get("logins") or []
        except ValueError:
            return ToolResult(self.name, status="skipped", summary="invalid logins.json")
        nss = _libnss()
        if not nss:
            return ToolResult(self.name, status="skipped", summary="libnss3 not installed")
        # NSS wants a directory with the DB files: rebuild a minimal profile
        prof = ctx.sub(self.name) / "profile"
        prof.mkdir(parents=True, exist_ok=True)
        for src, head, _size in ctx.siblings(1 << 20):
            # on disk the children are stored as `0034__logins.json`
            low = src.name.lower()
            db = next((d for d in _DB_FILES if low.endswith(d)), None)
            if not db:
                continue
            try:
                shutil.copy2(src, prof / db)
            except OSError:
                continue
        if not (prof / "key4.db").is_file():
            return ToolResult(self.name, status="skipped",
                              summary="key4.db missing (cannot unlock the logins)")
        shutil.copy2(ctx.input, prof / "logins.json")
        nss.NSS_Init.argtypes = [ctypes.c_char_p]
        nss.NSS_Init.restype = ctypes.c_int
        nss.PK11_GetInternalKeySlot.restype = ctypes.c_void_p
        nss.PK11_Authenticate.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_void_p]
        nss.PK11_Authenticate.restype = ctypes.c_int
        nss.NSSBase64_DecodeBuffer.restype = ctypes.c_void_p
        nss.PK11SDR_Decrypt.argtypes = [ctypes.POINTER(_SecItem), ctypes.POINTER(_SecItem),
                                        ctypes.c_void_p]
        nss.PK11SDR_Decrypt.restype = ctypes.c_int
        if nss.NSS_Init(str(prof).encode()) != 0:
            return ToolResult(self.name, status="skipped", summary="NSS_Init failed")
        lines: list[str] = []
        try:
            slot = nss.PK11_GetInternalKeySlot()
            if slot:
                nss.PK11_Authenticate(slot, True, None)
            for entry in logins:
                host = entry.get("hostname") or "?"
                user = _sdr_decrypt(nss, entry.get("encryptedUsername") or "")
                pw = _sdr_decrypt(nss, entry.get("encryptedPassword") or "")
                if user or pw:
                    lines.append(f"{host}\n  user: {user or ''}\n  password: {pw or ''}")
        finally:
            nss.NSS_Shutdown()
        if not lines:
            return ToolResult(self.name, status="skipped",
                              summary="logins present but not decryptable")
        return ToolResult(self.name, status="done",
                          summary=f"{len(lines)} login(s) decrypted",
                          output="== Firefox logins ==\n" + "\n".join(lines))


register(FirefoxLoginsAnalyzer())
