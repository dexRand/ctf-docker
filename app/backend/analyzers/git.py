"""Git repository analyzer.

A repo zipped or tarred and shipped as a challenge can hide a flag in an old
commit, a side branch, the reflog, a stash or a dangling object. This unpacks the
archive, finds the ``.git`` directory and dumps everything git can see (history
with patches, all refs, reflog, stashes and every object including unreachable
ones).
"""
from __future__ import annotations

import tarfile
import zipfile

from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, which, out_of
from .registry import register

ARCHIVE_EXT = (".zip", ".tar", ".tar.gz", ".tgz", ".gz")
_MAX_FILES = 5000
_MAX_BYTES = 256 * 1024 * 1024

# The repo comes from an untrusted archive: its .git/config could point
# fsmonitor/hooks/pager/diff drivers at arbitrary commands. Override every
# config key git would execute and ignore system/global config entirely.
_SAFE_CFG = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
             "-c", "core.pager=cat", "-c", "core.sshCommand=false",
             "-c", "diff.external=", "-c", "uploadpack.packObjectsHook="]
_SAFE_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_PAGER": "cat", "GIT_EXTERNAL_DIFF": "", "GIT_TERMINAL_PROMPT": "0"}


def _safe_member(name: str) -> bool:
    return bool(name) and ".." not in name and not name.startswith("/")


def _in_git(name: str) -> bool:
    """Only the `.git` tree is needed: the rest of the worktree stays unpacked."""
    return ".git" in name.split("/")


def _extract_zip(archive: Path, dest: Path) -> str:
    """Unpack the `.git` of a zipped repo. Returns an error or ""."""
    total = 0
    try:
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist()[:_MAX_FILES]:
                if (info.is_dir() or info.file_size == 0
                        or not _safe_member(info.filename) or not _in_git(info.filename)):
                    continue
                total += info.file_size
                if total > _MAX_BYTES:
                    break
                out = dest / info.filename
                out.parent.mkdir(parents=True, exist_ok=True)
                try:
                    out.write_bytes(z.read(info))
                except (OSError, RuntimeError):
                    continue            # encrypted (AES) member: skip it
    except (OSError, zipfile.BadZipFile) as exc:
        return f"cannot unzip: {exc}"
    return ""


def _extract_tar(archive: Path, dest: Path) -> str:
    """Unpack the `.git` of a tarred repo (symlinks, devices, odd paths skipped)."""
    total = 0
    try:
        with tarfile.open(archive, "r:*") as t:
            for member in t.getmembers()[:_MAX_FILES]:
                if (not member.isfile() or member.size == 0
                        or not _safe_member(member.name) or not _in_git(member.name)):
                    continue
                total += member.size
                if total > _MAX_BYTES:
                    break
                src = t.extractfile(member)
                if src is None:
                    continue
                out = dest / member.name
                out.parent.mkdir(parents=True, exist_ok=True)
                try:
                    out.write_bytes(src.read())
                except OSError:
                    continue
    except (OSError, tarfile.TarError) as exc:
        return f"cannot untar: {exc}"
    return ""


class GitAnalyzer(Analyzer):
    name = "git"
    category = "extract"
    description = "Inspect an archived git repo: history/patches, refs, reflog, stashes, all objects."
    accepts = ARCHIVE_EXT
    display_order = 216

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("git"):
            return ToolResult(self.name, status="skipped", summary="git not installed")
        dest = ctx.sub(self.name)
        if zipfile.is_zipfile(ctx.input):
            err = _extract_zip(ctx.input, dest)
        elif tarfile.is_tarfile(ctx.input):
            err = _extract_tar(ctx.input, dest)     # utflag{gitR3fl0g}: a .tar.gz repo
        else:
            return ToolResult(self.name, status="skipped", summary="not a zip/tar archive")
        if err:
            return ToolResult(self.name, status="skipped", summary=err)

        gitdir = next((p for p in dest.rglob(".git") if p.is_dir()), None)
        if gitdir is None:
            return ToolResult(self.name, status="skipped", summary="no git repo")
        repo = gitdir.parent
        base = ["git", *_SAFE_CFG, "--git-dir", str(gitdir), "--work-tree", str(repo)]
        logs: list[str] = []
        cfg = gitdir / "config"
        if cfg.is_file():  # remotes/user info can hold the flag: show it as text
            logs.append("$ cat .git/config\n" + cfg.read_text("utf-8", "replace")[:8000])
        for c in (["branch", "-a"], ["tag", "-n"], ["log", "--all", "--oneline", "--decorate"],
                  ["reflog", "--all"], ["stash", "list"],
                  ["log", "--all", "-p", "--no-ext-diff", "--no-textconv"],
                  ["fsck", "--unreachable", "--lost-found"]):
            proc = ctx.run(base + c, timeout=120, cwd=repo, env=_SAFE_ENV)
            out = out_of(proc)
            if out:
                logs.append(f"$ git {' '.join(c)}\n{out}")
        # every object (blobs/commits/trees), including unreachable ones
        proc = ctx.run(base + ["cat-file", "--batch-all-objects", "--batch"], timeout=180,
                       cwd=repo, env=_SAFE_ENV)
        dump = out_of(proc)
        if dump:
            logs.append("$ git cat-file --batch-all-objects --batch\n" + dump)
        text = "\n\n".join(logs)
        if len(text) > 120000:
            text = text[:120000] + f"\n… [truncated {len(text) - 120000} chars]"
        return ToolResult(self.name, status="done", summary="git repo dumped",
                          output=text, consumed=True)


register(GitAnalyzer())
