"""Middleware behaviour: API key guard + per-IP rate limiting (HTTP surface)."""
import importlib

import pytest
from fastapi.testclient import TestClient

from backend import ratelimit
from backend.config import rate_limit


@pytest.fixture
def env(monkeypatch):
    """Set env vars for the duration of a test and restore module state after."""
    for key in ("API_KEY", "RATE_LIMIT_RPM", "RATE_LIMIT_BURST"):
        monkeypatch.delenv(key, raising=False)
    ratelimit.reset()
    yield monkeypatch
    ratelimit.reset()


def _reload_main():
    """Rebuild the app so module-level config (API_KEY) is re-read."""
    import backend.config as cfg
    import backend.main as m
    importlib.reload(cfg)
    importlib.reload(m)
    return m


# --- API key -----------------------------------------------------------------

def test_health_is_reachable_without_a_key(env):
    env.setenv("API_KEY", "secret")
    m = _reload_main()
    with TestClient(m.app) as c:
        assert c.get("/api/v1/health").status_code == 200


def test_api_requires_the_configured_key(env):
    env.setenv("API_KEY", "secret")
    m = _reload_main()
    with TestClient(m.app) as c:
        assert c.get("/api/v1/tools").status_code == 401
        assert c.get("/api/v1/tools", headers={"X-API-Key": "wrong"}).status_code == 401
        assert c.get("/api/v1/tools", headers={"X-API-Key": "secret"}).status_code == 200


def test_no_key_configured_means_no_auth(env):
    m = _reload_main()
    with TestClient(m.app) as c:
        assert c.get("/api/v1/tools").status_code == 200


# --- rate limit configuration ------------------------------------------------

def test_rate_limit_is_disabled_by_default(env):
    assert rate_limit() == (0, 0.0)


def test_rate_limit_burst_defaults_to_the_per_minute_budget(env):
    env.setenv("RATE_LIMIT_RPM", "60")
    capacity, refill = rate_limit()
    assert (capacity, refill) == (60, 1.0)


def test_rate_limit_honours_an_explicit_burst(env):
    env.setenv("RATE_LIMIT_RPM", "60")
    env.setenv("RATE_LIMIT_BURST", "5")
    assert rate_limit() == (5, 1.0)


def test_a_negative_budget_disables_the_limiter(env):
    env.setenv("RATE_LIMIT_RPM", "-1")
    assert rate_limit() == (0, 0.0)


# --- rate limit enforcement --------------------------------------------------

def test_requests_are_unthrottled_when_rpm_is_zero(env):
    with TestClient(_reload_main().app) as c:
        assert [c.get("/api/v1/tools").status_code for _ in range(50)] == [200] * 50


def test_exceeding_the_budget_returns_429(env):
    env.setenv("RATE_LIMIT_RPM", "60")
    env.setenv("RATE_LIMIT_BURST", "2")
    with TestClient(_reload_main().app) as c:
        codes = [c.get("/api/v1/tools").status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429]


def test_429_body_explains_the_limit_and_says_when_to_retry(env):
    env.setenv("RATE_LIMIT_RPM", "60")
    env.setenv("RATE_LIMIT_BURST", "1")
    with TestClient(_reload_main().app) as c:
        c.get("/api/v1/tools")
        r = c.get("/api/v1/tools")
    assert r.status_code == 429
    assert "rate limit" in r.json()["detail"].lower()
    assert int(r.headers["Retry-After"]) >= 1


def test_health_stays_reachable_while_over_budget(env):
    env.setenv("RATE_LIMIT_RPM", "60")
    env.setenv("RATE_LIMIT_BURST", "1")
    with TestClient(_reload_main().app) as c:
        assert c.get("/api/v1/tools").status_code == 200
        assert c.get("/api/v1/tools").status_code == 429
        assert c.get("/api/v1/health").status_code == 200


def test_the_budget_is_per_client_ip(env):
    env.setenv("RATE_LIMIT_RPM", "60")
    env.setenv("RATE_LIMIT_BURST", "1")
    with TestClient(_reload_main().app) as c:
        assert c.get("/api/v1/tools", headers={"X-Forwarded-For": "203.0.113.7"}).status_code == 200
        assert c.get("/api/v1/tools", headers={"X-Forwarded-For": "203.0.113.7"}).status_code == 429
        assert c.get("/api/v1/tools", headers={"X-Forwarded-For": "198.51.100.9"}).status_code == 200