"""API key check shared by the HTTP middleware and the WebSockets.

The key is accepted from the `X-API-Key` header (scripts, other containers),
the `stegsuite_key` cookie (browser loads of <img>/<audio>/downloads, which
can't send headers) or a `?key=` query parameter (WebSockets, quick links).
"""
from __future__ import annotations

import hmac
from typing import Mapping

from . import config

COOKIE = "stegsuite_key"


def authorized(headers: Mapping[str, str], query: Mapping[str, str],
               cookies: Mapping[str, str]) -> bool:
    key = config.API_KEY  # read per call: tests reload config with a new key
    if not key:
        return True
    for given in (headers.get("x-api-key"), cookies.get(COOKIE), query.get("key")):
        if given and hmac.compare_digest(given.encode(), key.encode()):
            return True
    return False
