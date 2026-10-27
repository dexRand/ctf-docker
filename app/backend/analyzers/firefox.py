"""Firefox saved logins: decrypt them with NSS (libnss3), like firefed.

`logins.json` keeps the username/password as base64 SDR blobs; the keys live in
`key4.db`. The decryption happens in a **subprocess** (`nss_decrypt`) because
NSS_Init/NSS_Shutdown are process-global and the analyzers run in a thread pool.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult
from .registry import register

_DB_FILES = ("key4.db", "cert9.db", "pkcs11.txt")


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
            if not json.loads(data).get("logins"):
                return ToolResult(self.name, status="skipped", summary="no saved logins")
        except ValueError:
            return ToolResult(self.name, status="skipped", summary="invalid logins.json")
        # NSS wants a directory with the DB files: rebuild a minimal profile
        prof = ctx.sub(self.name) / "profile"
        prof.mkdir(parents=True, exist_ok=True)
        for src, _head, _size in ctx.siblings(1 << 20):
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
        try:
            shutil.copy2(ctx.input, prof / "logins.json")
        except OSError as exc:
            return ToolResult(self.name, status="skipped", summary=f"cannot stage logins: {exc}")
        app_dir = Path(__file__).resolve().parents[2]
        proc = ctx.run([sys.executable, "-m", "backend.analyzers.nss_decrypt",
                        str(prof), str(prof / "logins.json")],
                       timeout=60, cwd=app_dir, env={"PYTHONPATH": str(app_dir)})
        if proc.returncode != 0:
            detail = (proc.stderr or "").strip().splitlines()[-1:] or ["decryption failed"]
            return ToolResult(self.name, status="skipped",
                              summary=f"NSS: {detail[0][:120]}")
        try:
            rows = json.loads(proc.stdout or "[]")
        except ValueError:
            return ToolResult(self.name, status="skipped", summary="unexpected NSS output")
        if not rows:
            return ToolResult(self.name, status="skipped",
                              summary="logins present but not decryptable")
        lines = [f"{r['hostname']}\n  user: {r['user']}\n  password: {r['password']}"
                 for r in rows]
        return ToolResult(self.name, status="done",
                          summary=f"{len(rows)} login(s) decrypted",
                          output="== Firefox logins ==\n" + "\n".join(lines))


register(FirefoxLoginsAnalyzer())
