"""MCP endpoint (Streamable HTTP, stateless, JSON responses)."""
from __future__ import annotations

import os
from urllib.parse import urlparse

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from .. import mcp_server

router = APIRouter(tags=["mcp"])


def _origin_ok(request: Request) -> bool:
    """MCP spec: refuse browser requests from other sites (DNS rebinding).

    Agents send no Origin; a browser page may only call us from our own host
    or from localhost. More origins: STEGSUITE_MCP_ORIGINS (comma separated).
    """
    origin = request.headers.get("origin")
    if not origin:
        return True
    host = (urlparse(origin).hostname or "").lower()
    extra = {o.strip().lower() for o in os.environ.get("STEGSUITE_MCP_ORIGINS", "").split(",") if o.strip()}
    return (host in ("localhost", "127.0.0.1", "::1")
            or host == (request.url.hostname or "").lower() or origin.lower() in extra)


@router.post("/api/v1/mcp")
async def mcp_post(request: Request):
    """JSON-RPC 2.0 message or batch from an MCP client."""
    import anyio
    if not _origin_ok(request):
        return JSONResponse(mcp_server._error(None, -32600, "origin not allowed"), status_code=403)
    try:
        msg = await request.json()
    except ValueError:
        return JSONResponse(mcp_server._error(None, -32700, "parse error"), status_code=400)
    batch = msg if isinstance(msg, list) else [msg]
    if not batch or not all(isinstance(m, dict) for m in batch):
        return JSONResponse(mcp_server._error(None, -32600, "invalid request"), status_code=400)
    # tools call the REST API over HTTP: run them off the event loop
    out = [r for r in [await anyio.to_thread.run_sync(mcp_server.handle, m) for m in batch] if r]
    if not out:
        return Response(status_code=202)            # only notifications
    return JSONResponse(out if isinstance(msg, list) else out[0])


@router.get("/api/v1/mcp")
def mcp_get():
    """No server-initiated stream (stateless server)."""
    return Response(status_code=405, headers={"Allow": "POST"})
