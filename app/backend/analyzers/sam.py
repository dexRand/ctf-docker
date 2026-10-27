"""Windows SAM hive: local account hashes (with the SYSTEM hive BootKey).

Offline dump with impacket's `secretsdump` when the SYSTEM hive is next to the
SAM (the usual `sam.bak` + `system.bak` pair), then a hashcat pass on the
built-in wordlists so the recovered password shows up in the report.
"""
from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, which
from .. import cracking
from .registry import register

_REGF = b"regf"
_SAM_MARK = b"Domains"      # key names are stored separately, not as a full path
_SYSTEM_MARK = b"CurrentControlSet"
_LINE = re.compile(r"^(?P<user>[^:]+):(?P<rid>\d+):(?P<lm>[0-9a-fA-F]*):(?P<nt>[0-9a-fA-F]*):::$")
_EMPTY_NT = {"31d6cfe0d16ae931b73c59d7e0c089c0"}      # blank Windows password


def parse_hashes(text: str) -> dict[str, str]:
    """{user: nt_hash} from secretsdump LOCAL output (blank hashes skipped)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        nt = m.group("nt").lower()
        if len(nt) == 32 and nt not in _EMPTY_NT:
            out[m.group("user")] = nt
    return out


class SamAnalyzer(Analyzer):
    name = "sam"
    category = "windows"
    description = "Windows SAM hive: dump the local hashes (SYSTEM BootKey) and crack them."
    accepts = ()
    display_order = 264

    def _find_system(self, ctx: ToolContext) -> Path | None:
        """The SYSTEM hive is the other `regf` file of the project."""
        for path, head, _size in ctx.siblings(65536):
            if head[:4] != _REGF or (b"Domains" in head and b"Account" in head):
                continue
            name = path.name.lower()
            if "system" in name or "sys" in name:
                return path
            try:
                with path.open("rb") as fh:
                    if _SYSTEM_MARK in fh.read(1 << 20):
                        return path
            except OSError:
                continue
        return None

    def _secretsdump(self) -> str | None:
        for cand in (Path("/opt/stegsuite/venv/bin/secretsdump.py"),
                     Path(shutil.which("secretsdump.py") or "")):
            if cand.is_file():
                return str(cand)
        return None

    def run(self, ctx: ToolContext) -> ToolResult:
        try:
            with ctx.input.open("rb") as fh:
                head = fh.read(1 << 20)
        except OSError:
            return ToolResult(self.name, status="skipped", summary="unreadable")
        if head[:4] != _REGF or _SAM_MARK not in head or b"Account" not in head:
            return ToolResult(self.name, status="skipped", summary="not a SAM hive")
        system = self._find_system(ctx)
        if not system:
            return ToolResult(self.name, status="skipped",
                              summary="SYSTEM hive missing (needed for the BootKey)")
        sd = self._secretsdump()
        if not sd:
            return ToolResult(self.name, status="skipped", summary="impacket not installed")
        proc = ctx.run([sd, "-sam", str(ctx.input), "-system", str(system), "LOCAL"], timeout=240)
        hashes = parse_hashes(proc.stdout or "")
        if not hashes:
            return ToolResult(self.name, status="skipped", summary="no local hash in the hive",
                              output=(proc.stdout or "")[-2000:])
        lines = ["== hashes =="] + [f"{u}:{h}" for u, h in hashes.items()]
        cracked: dict[str, str] = {}
        if which("hashcat"):
            cracked = self._crack(hashes, ctx)
        if cracked:
            lines.append("== cracked ==")
            lines += [f"{u}: {pw}" for u, pw in cracked.items()]
        return ToolResult(self.name, status="done",
                          summary=f"{len(hashes)} hash(es), {len(cracked)} cracked",
                          output="\n".join(lines))

    def _crack(self, hashes: dict[str, str], ctx: ToolContext) -> dict[str, str]:
        # the shared resolver also sees the wordlists uploaded by the user
        wordlists = [p for p in cracking.resolve_wordlists() if p.is_file()]
        if not wordlists:
            return {}
        tmp = Path(ctx.sub(self.name))
        hf = tmp / "sam-nt.txt"
        hf.write_text("\n".join(hashes.values()) + "\n", encoding="utf-8")
        pot = tmp / "sam-nt.pot"
        found: dict[str, str] = {}
        deadline = time.time() + 240          # a miss must not stall the analysis
        for wl in sorted(wordlists, key=lambda p: p.stat().st_size):
            left = int(deadline - time.time())
            if left <= 5:
                break
            ctx.run(cracking.hashcat_args(1000, str(hf), wordlist=str(wl),
                                          potfile=str(pot), runtime=min(90, left)),
                    timeout=min(150, left + 30))
            found = self._show(hf, pot, hashes)
            if len(found) == len(hashes):
                break
        return found

    @staticmethod
    def _show(hf: Path, pot: Path, hashes: dict[str, str]) -> dict[str, str]:
        from .base import run_cmd
        show = run_cmd(["hashcat", "-m", "1000", str(hf), "--show",
                        "--potfile-path", str(pot)], timeout=60)
        found: dict[str, str] = {}
        for user, h in hashes.items():
            pw = cracking._pot_password(show.stdout or "", h)
            if pw:
                found[user] = pw
        return found


register(SamAnalyzer())
