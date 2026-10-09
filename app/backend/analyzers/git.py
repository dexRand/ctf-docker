"""Git repository analyzer.

A repo zipped and shipped as a challenge can hide a flag in an old commit, a
side branch, the reflog, a stash or a dangling object. This unzips the archive,
finds the ``.git`` directory and dumps everything git can see (history with
patches, all refs, reflog, stashes and every object including unreachable ones).
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, which, out_of
from .registry import register

ARCHIVE_EXT = (".zip",)
_MAX_FILES = 5000
_MAX_BYTES = 256 * 1024 * 1024


class GitAnalyzer(Analyzer):
    name = "git"
    category = "extract"
    description = "Inspect an archived git repo: history/patches, refs, reflog, stashes, all objects."
    accepts = ARCHIVE_EXT
    display_order = 216

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("git"):
            return ToolResult(self.name, status="skipped", summary="git not installed")
        if not zipfile.is_zipfile(ctx.input):
            return ToolResult(self.name, status="skipped", summary="not a zip")
        dest = ctx.sub(self.name)
        total = 0
        try:
            with zipfile.ZipFile(ctx.input) as z:
                for info in z.infolist()[:_MAX_FILES]:
                    if info.is_dir() or info.file_size == 0:
                        continue
                    name = info.filename
                    if ".." in name or name.startswith("/"):
                        continue
                    total += info.file_size
                    if total > _MAX_BYTES:
                        break
                    out = dest / name
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(z.read(info))
        except (OSError, zipfile.BadZipFile) as exc:
            return ToolResult(self.name, status="error", summary=f"cannot unzip: {exc}")

        gitdir = next((p for p in dest.rglob(".git") if p.is_dir()), None)
        if gitdir is None:
            return ToolResult(self.name, status="skipped", summary="no git repo")
        repo = gitdir.parent
        base = ["git", "--git-dir", str(gitdir), "--work-tree", str(repo)]
        logs: list[str] = []
        for c in (["branch", "-a"], ["tag", "-n"], ["log", "--all", "--oneline", "--decorate"],
                  ["reflog", "--all"], ["stash", "list"], ["log", "--all", "-p"],
                  ["fsck", "--unreachable", "--lost-found"]):
            proc = ctx.run(base + c, timeout=120, cwd=repo)
            out = out_of(proc)
            if out:
                logs.append(f"$ git {' '.join(c)}\n{out}")
        # every object (blobs/commits/trees), including unreachable ones
        proc = ctx.run(base + ["cat-file", "--batch-all-objects", "--batch"], timeout=180, cwd=repo)
        dump = out_of(proc)
        if dump:
            logs.append("$ git cat-file --batch-all-objects --batch\n" + dump)
        text = "\n\n".join(logs)
        if len(text) > 120000:
            text = text[:120000] + f"\n… [truncated {len(text) - 120000} chars]"
        return ToolResult(self.name, status="done", summary="git repo dumped",
                          output=text, consumed=True)


register(GitAnalyzer())
