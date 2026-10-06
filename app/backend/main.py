"""StegSuite backend — FastAPI app factory.

Routes live in `backend/api/` (one module per area); analyzers in
`backend/analyzers/` (one file per tool, auto-registered). See
`docs/ADDING-A-TOOL.md` and `docs/API.md`.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import routers
from .config import API_KEY, VERSION, rate_limit
from .db import init_db
from .ratelimit import client_ip, get_bucket
from .retention import purge_old_projects
from . import orchestrator

app = FastAPI(
    title="StegSuite",
    version=VERSION,
    description="Self-hosted steganography/forensics workbench.",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

STATIC_DIR = Path(__file__).parent / "static"


@app.on_event("startup")
def _startup() -> None:
    init_db()
    orchestrator.reconcile_orphans()
    orchestrator.dedupe_findings()
    purge_old_projects()


HEALTH_PATH = "/api/v1/health"
# endpoints that answer immediately; throttling them breaks liveness checks and
# would turn a full bucket into a hard-down signal
NEVER_THROTTLE = {HEALTH_PATH}


@app.middleware("http")
async def api_key_guard(request: Request, call_next):
    if API_KEY and request.url.path.startswith("/api") and request.url.path != HEALTH_PATH:
        if request.headers.get("x-api-key") != API_KEY:
            return JSONResponse({"detail": "invalid or missing X-API-Key"}, status_code=401)
    return await call_next(request)


@app.middleware("http")
async def rate_limit_guard(request: Request, call_next):
    capacity, refill = rate_limit()
    if not capacity or request.url.path in NEVER_THROTTLE:
        return await call_next(request)
    if not get_bucket(client_ip(request), capacity=capacity, refill_per_sec=refill).take():
        return JSONResponse(
            {"detail": "rate limit exceeded: too many requests, slow down"},
            status_code=429,
            headers={"Retry-After": str(max(1, round(1 / refill))) if refill else "60"},
        )
    return await call_next(request)


for _router in routers:
    app.include_router(_router)

# served last: the built SPA catches everything else
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="spa")
