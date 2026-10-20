"""System endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from .. import services
from ..config import VERSION

router = APIRouter()


@router.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok", "version": VERSION}


@router.get("/api/v1/services")
def toolbox_services(check: bool = True) -> list[dict]:
    """The toolbox's web tools: name, purpose, profile, URL, and whether it is up."""
    return services.catalog(check)
