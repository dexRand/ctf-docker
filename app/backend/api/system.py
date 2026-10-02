"""System endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from ..config import VERSION

router = APIRouter()


@router.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok", "version": VERSION}
