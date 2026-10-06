"""Analyzer package: importing it registers every tool."""
from __future__ import annotations

from .base import Analyzer, ToolContext, ToolResult  # noqa: F401
from .registry import REGISTRY, catalog, get, register, run_tool, subprocess_analyzer  # noqa: F401

# register all tools (import side effects)
from . import metadata, text, hex, decode, extract, nested_archive, steg, png, image, gif, vision, morse, audio, sstv, qr, pcap, repair  # noqa: E402,F401
