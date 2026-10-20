"""Analysis orchestrator: public entry points used by the API.

The implementation is split by concern:
  jobs.py          start/stop/pause a project's background job
  pipeline.py      the job itself (walk the tree, run analyzers, record runs)
  planner.py       which analyzers run on a file, in which order
  flagpatterns.py  what a flag looks like (regexes, normalisation)
  flaghunt.py      scan text for flags and store findings
  tree.py          store extracted files as child nodes
  crackflow.py     crack runs and auto-crack inside the flow
  maintenance.py   startup cleanup (orphans, duplicate findings)
"""
from __future__ import annotations

from .crackflow import mark_unlocked, record_crack_run  # noqa: F401
from .flaghunt import _hunt, custom_flag_matches  # noqa: F401
from .jobs import JOBS, analyze_new, control, is_running, start, stop  # noqa: F401
from .maintenance import dedupe_findings, reconcile_orphans  # noqa: F401
from .tree import import_children  # noqa: F401
