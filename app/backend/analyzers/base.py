"""Analyzer framework: ToolResult, ToolContext, Analyzer base + factory."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


@dataclass
class ToolResult:
    tool: str
    status: str = "done"          # done|error|skipped|needs_password
    summary: str = ""
    output: str = ""
    exit_code: Optional[int] = None
    needs_password: bool = False
    artifacts: list[dict] = field(default_factory=list)   # {name, path, size}
    extracted: list[str] = field(default_factory=list)    # new files (abs paths)
    consumed: bool = False        # tool fully handled the input: skip remaining analyzers

    def as_dict(self, *, include_output: bool = True) -> dict:
        d = {
            "tool": self.tool, "status": self.status, "summary": self.summary,
            "exit_code": self.exit_code, "needs_password": self.needs_password,
            "artifacts": self.artifacts,
        }
        if include_output:
            d["output"] = self.output
        return d


@dataclass
class ToolContext:
    input: Path
    workdir: Path
    password: Optional[str] = None
    log: Callable[[str], None] = lambda _m: None

    def sub(self, tool: str) -> Path:
        d = self.workdir / tool
        d.mkdir(parents=True, exist_ok=True)
        return d

    def run(self, cmd: list, timeout: int = 300, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
        self.log("$ " + " ".join(str(c) for c in cmd))
        try:
            return subprocess.run(
                [str(c) for c in cmd], capture_output=True, text=True, errors="replace",
                timeout=timeout, stdin=subprocess.DEVNULL,
                cwd=str(cwd) if cwd else None,
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(cmd, 124, "", "timeout")
        except FileNotFoundError as exc:
            return subprocess.CompletedProcess(cmd, 127, "", f"not found: {exc}")


def which(tool: str) -> Optional[str]:
    return shutil.which(tool)


def list_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return [p for p in sorted(root.rglob("*")) if p.is_file()]


def out_of(proc: subprocess.CompletedProcess) -> str:
    return ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()


class Analyzer:
    name: str = "?"
    category: str = "misc"
    description: str = ""
    needs_password: bool = False
    has_archive: bool = False
    accepts: tuple = ()          # mime substrings or file extensions; () = all
    display_order: int = 100

    def matches(self, mime: Optional[str], name: str) -> bool:
        if not self.accepts:
            return True
        low = (name or "").lower()
        mime = mime or ""
        return any(a in mime or low.endswith(a) for a in self.accepts)

    def run(self, ctx: ToolContext) -> ToolResult:  # pragma: no cover
        raise NotImplementedError


class SubprocessAnalyzer(Analyzer):
    cmd: list = []
    soft_errors: bool = False  # tools whose non-zero exit is informational, not a failure

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.cmd:
            return ToolResult(self.name, status="skipped", summary="no command configured")
        if not which(str(self.cmd[0])):
            return ToolResult(self.name, status="skipped", summary=f"{self.cmd[0]} not installed")
        cmd = [str(ctx.input) if str(c) == "{input}" else str(c) for c in self.cmd]
        proc = ctx.run(cmd)
        ok = proc.returncode == 0 or self.soft_errors
        return ToolResult(
            self.name,
            status="done" if ok else "error",
            output=out_of(proc),
            exit_code=proc.returncode,
        )
