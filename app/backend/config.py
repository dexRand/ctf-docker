"""Configuration for StegSuite (env-driven)."""
from __future__ import annotations

import os
from pathlib import Path

VERSION = "0.1.0"

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
PROJECTS_DIR = DATA_DIR / "projects"
TOOLJOBS_DIR = DATA_DIR / "tooljobs"
DB_PATH = DATA_DIR / "stegsuite.db"

# optional API key for non-localhost access (empty = no auth)
API_KEY = os.environ.get("API_KEY", "").strip()

# upload cap (bytes)
MAX_UPLOAD = int(float(os.environ.get("MAX_UPLOAD_MB", "1024")) * 1024 * 1024)

# recursion depth for extracted children (nested archives)
MAX_DEPTH = int(os.environ.get("MAX_DEPTH", "6"))

# auto-delete projects older than N days (0 = never); read per call so tests
# and a future reload can change it at runtime
def retention_days() -> int:
    return int(os.environ.get("RETENTION_DAYS", "0") or 0)


def rate_limit() -> tuple[int, float]:
    """Per-IP budget as (capacity, refill_per_sec). (0, 0) = disabled.

    Read per request rather than at import so the env stays authoritative for
    tests and for a future reload endpoint.
    """
    rpm = int(os.environ.get("RATE_LIMIT_RPM", "0") or 0)
    if rpm <= 0:
        return 0, 0.0
    burst = int(os.environ.get("RATE_LIMIT_BURST", "0") or 0)
    capacity = burst if burst > 0 else max(1, rpm)
    return capacity, rpm / 60.0
