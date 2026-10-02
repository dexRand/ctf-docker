"""Analyzer registry."""
from __future__ import annotations

from typing import Optional

from .base import Analyzer, SubprocessAnalyzer, ToolContext, ToolResult

REGISTRY: dict[str, Analyzer] = {}


def register(analyzer: Analyzer) -> Analyzer:
    REGISTRY[analyzer.name] = analyzer
    return analyzer


def subprocess_analyzer(name, cmd, category, description, *, accepts=(), order=100,
                        needs_password=False, has_archive=False, soft=False) -> type:
    """Factory for simple command wrappers."""
    cls = type(
        f"Analyzer_{name}",
        (SubprocessAnalyzer,),
        {
            "name": name, "cmd": list(cmd), "category": category,
            "description": description, "accepts": tuple(accepts),
            "display_order": order, "needs_password": needs_password,
            "has_archive": has_archive, "soft_errors": soft,
        },
    )
    register(cls())
    return cls


def get(name: str) -> Optional[Analyzer]:
    return REGISTRY.get(name)


def catalog() -> list[dict]:
    items = sorted(REGISTRY.values(), key=lambda a: (a.display_order, a.name))
    return [
        {
            "name": a.name, "category": a.category, "description": a.description,
            "needs_password": a.needs_password, "has_archive": a.has_archive,
            "accepts": list(a.accepts), "display_order": a.display_order,
        }
        for a in items
    ]


def run_tool(name: str, input_path, workdir, password: Optional[str] = None,
             log=lambda _m: None) -> ToolResult:
    analyzer = REGISTRY.get(name)
    if not analyzer:
        return ToolResult(name, status="error", summary=f"unknown tool: {name}")
    ctx = ToolContext(input=input_path, workdir=workdir, password=password, log=log)
    try:
        return analyzer.run(ctx)
    except Exception as exc:  # keep the API resilient to a broken analyzer
        return ToolResult(name, status="error", summary=f"exception: {exc}")
