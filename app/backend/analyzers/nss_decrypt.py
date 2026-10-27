"""Subprocess helper: decrypt Firefox saved logins with libnss3.

Run as `python -m backend.analyzers.nss_decrypt <profile_dir> <logins.json>`;
prints a JSON list of {hostname, user, password}. It lives in its own process
because NSS_Init/NSS_Shutdown are process-global and the analyzers run in a
ThreadPoolExecutor: two projects decrypting at the same time would tear each
other's NSS state down and crash the backend.
"""
from __future__ import annotations

import ctypes
import json
import sys


class _SecItem(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint), ("data", ctypes.c_void_p), ("len", ctypes.c_uint)]


def _libnss():
    for name in ("libnss3.so", "libnss3.dylib", "nss3.dll"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    return None


def _decrypt(nss, value: str) -> str | None:
    raw = (value or "").encode("ascii", "ignore")
    if not raw:
        return None
    item = _SecItem(0, None, 0)
    if not nss.NSSBase64_DecodeBuffer(None, ctypes.byref(item), raw, len(raw)):
        return None
    out = _SecItem(0, None, 0)
    if nss.PK11SDR_Decrypt(ctypes.byref(item), ctypes.byref(out), None) != 0:
        return None
    return ctypes.string_at(out.data, out.len).decode("utf-8", "replace")


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: nss_decrypt <profile_dir> <logins.json>", file=sys.stderr)
        return 2
    prof, logins_path = argv[1], argv[2]
    try:
        with open(logins_path, encoding="utf-8") as fh:
            logins = json.load(fh).get("logins") or []
    except (OSError, ValueError) as exc:
        print(f"cannot read logins: {exc}", file=sys.stderr)
        return 2
    nss = _libnss()
    if not nss:
        print("libnss3 not installed", file=sys.stderr)
        return 3
    nss.NSS_Init.argtypes = [ctypes.c_char_p]
    nss.NSS_Init.restype = ctypes.c_int
    nss.PK11_GetInternalKeySlot.restype = ctypes.c_void_p
    nss.PK11_Authenticate.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_void_p]
    nss.PK11_Authenticate.restype = ctypes.c_int
    nss.NSSBase64_DecodeBuffer.restype = ctypes.c_void_p
    nss.PK11SDR_Decrypt.argtypes = [ctypes.POINTER(_SecItem), ctypes.POINTER(_SecItem),
                                    ctypes.c_void_p]
    nss.PK11SDR_Decrypt.restype = ctypes.c_int
    nss.NSS_Shutdown.restype = ctypes.c_int
    if nss.NSS_Init(prof.encode()) != 0:
        print("NSS_Init failed", file=sys.stderr)
        return 4
    rows: list[dict] = []
    try:
        slot = nss.PK11_GetInternalKeySlot()
        if slot:
            nss.PK11_Authenticate(slot, True, None)
        for entry in logins:
            user = _decrypt(nss, entry.get("encryptedUsername") or "")
            password = _decrypt(nss, entry.get("encryptedPassword") or "")
            if user or password:
                rows.append({"hostname": entry.get("hostname") or "?",
                             "user": user or "", "password": password or ""})
    finally:
        nss.NSS_Shutdown()
    print(json.dumps(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
