"""Analyzer package: importing it registers every tool."""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult  # noqa: F401
from .registry import REGISTRY, catalog, get, register, run_tool, subprocess_analyzer  # noqa: F401

# register all tools (import side effects)
from . import metadata, text, extract, steg, image, audio  # noqa: E402,F401
