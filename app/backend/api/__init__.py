"""API routers (kept small and independent for easy maintenance)."""
from __future__ import annotations

from . import analysis, cracking_api, projects, system, tools, ws

routers = [
    system.router,
    projects.router,
    analysis.router,
    tools.router,
    cracking_api.router,
    ws.router,
]
