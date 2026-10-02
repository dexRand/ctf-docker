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
