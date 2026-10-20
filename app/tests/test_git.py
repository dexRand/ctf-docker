"""git analyzer: dumps history from a zipped repo without running repo config."""
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from backend.analyzers.base import ToolContext
from backend.analyzers.git import GitAnalyzer

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="git not installed")

ENV = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
       "GIT_COMMITTER_EMAIL": "t@t"}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, env=ENV, check=True, capture_output=True)


def _zip_repo(tmp_path: Path, extra_config: str = "") -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "notes.txt").write_text("flag{old_commit}\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "first")
    (repo / "notes.txt").write_text("nothing here\n")
    _git(repo, "commit", "-qam", "scrub")
    if extra_config:
        with open(repo / ".git" / "config", "a") as fh:
            fh.write(extra_config)
    out = tmp_path / "repo.zip"
    with zipfile.ZipFile(out, "w") as z:
        for p in repo.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(tmp_path))
    return out


def _run(tmp_path: Path, archive: Path):
    work = tmp_path / "work"
    work.mkdir()
    return GitAnalyzer().run(ToolContext(input=archive, workdir=work))


def test_old_commit_content_is_dumped(tmp_path):
    res = _run(tmp_path, _zip_repo(tmp_path))
    assert res.status == "done"
    assert "flag{old_commit}" in res.output


def test_hostile_repo_config_is_not_executed(tmp_path):
    marker = tmp_path / "pwned"
    hostile = (f"[core]\n\tfsmonitor = touch {marker}\n\tpager = touch {marker}\n"
               f"[diff]\n\texternal = touch {marker}\n")
    res = _run(tmp_path, _zip_repo(tmp_path, hostile))
    assert "flag{old_commit}" in res.output
    assert "fsmonitor" in res.output          # config shown as text
    assert not marker.exists()
