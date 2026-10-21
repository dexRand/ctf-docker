"""MCP endpoint (Streamable HTTP, stateless, JSON responses)."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from .. import mcp_server

router = APIRouter(tags=["mcp"])


@router.post("/api/v1/mcp")
async def mcp_post(request: Request):
    """JSON-RPC 2.0 message or batch from an MCP client."""
    import anyio
    try:
        msg = await request.json()
    except ValueError:
        return JSONResponse(mcp_server._error(None, -32700, "parse error"), status_code=400)
    batch = msg if isinstance(msg, list) else [msg]
    # tools call the REST API over HTTP: run them off the event loop
    out = [r for r in [await anyio.to_thread.run_sync(mcp_server.handle, m) for m in batch] if r]
    if not out:
        return Response(status_code=202)            # only notifications
    return JSONResponse(out if isinstance(msg, list) else out[0])


@router.get("/api/v1/mcp")
def mcp_get():
    """No server-initiated stream (stateless server)."""
    return Response(status_code=405, headers={"Allow": "POST"})
