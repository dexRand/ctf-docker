"""API routers (kept small and independent for easy maintenance)."""
from __future__ import annotations

from . import analysis, cracking_api, ctfs, mcp, projects, reports, system, tools, ws

routers = [
    system.router,
    projects.router,
    ctfs.router,
    analysis.router,
    reports.router,
    tools.router,
    cracking_api.router,
    mcp.router,
    ws.router,
]
