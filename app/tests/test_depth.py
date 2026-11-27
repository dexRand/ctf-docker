"""Analysis-depth tiers (normal/deep/full): planner filtering + API `depth`.

The API parameter is `depth`; the planner names it `tier` because it already
uses `depth` for archive recursion. An analyzer runs when its own tier is at or
below the requested one.
"""
from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from backend import planner
from backend.analyzers import REGISTRY
from backend.analyzers.base import Analyzer
from backend.db import engine, init_db
from backend.models import Project
from backend.planner import TIERS, _plan_for


def test_tiers_are_ordered():
    assert TIERS == ("normal", "deep", "full")
    assert planner._TIER_RANK == {"normal": 0, "deep": 1, "full": 2}


def test_normal_excludes_deep_analyzers():
    # sstv (audio) and wpa (captures) are slow and solve no real challenge:
    # they only run from `deep` upwards.
    for name, mime, tool in (("song.wav", "audio/wav", "sstv"),
                             ("handshake.pcap", "application/vnd.tcpdump.pcap", "wpa")):
        assert tool not in _plan_for(name, mime, False, tier="normal")
        assert tool in _plan_for(name, mime, False, tier="deep")
        assert tool in _plan_for(name, mime, False, tier="full")
        # the default is `normal`
        assert tool not in _plan_for(name, mime, False)


@pytest.mark.parametrize("tier", TIERS)
def test_normal_analyzer_runs_at_every_tier(tier):
    plan = _plan_for("photo.jpg", "image/jpeg", False, tier=tier)
    assert "exiftool" in plan and "strings" in plan


def test_tier_filter_ordering_and_unknown_tier_fallback(monkeypatch):
    class Fake(Analyzer):
        accepts = ()

    names = (("fake-normal", "normal"), ("fake-deep", "deep"), ("fake-full", "full"))
    for name, tier in names:
        a = Fake()
        a.name, a.tier = name, tier
        monkeypatch.setitem(REGISTRY, name, a)
    monkeypatch.setattr(planner, "DEFAULT_PLAN", [n for n, _ in names])

    normal = _plan_for("x.bin", None, False, tier="normal")
    deep = _plan_for("x.bin", None, False, tier="deep")
    full = _plan_for("x.bin", None, False, tier="full")
    assert normal == ["fake-normal"]
    assert deep == ["fake-normal", "fake-deep"]
    assert full == ["fake-normal", "fake-deep", "fake-full"]
    # an unknown tier is clamped to normal, never to full
    assert _plan_for("x.bin", None, False, tier="bogus") == normal


@pytest.fixture(scope="module")
def client():
    from backend.main import app
    with TestClient(app) as c:
        yield c


def _upload(client, **data):
    return client.post("/api/v1/projects", data=data,
                       files={"files": ("note.txt", io.BytesIO(b"hello\n"), "text/plain")})


def test_api_depth_is_stored_and_validated(client):
    r = _upload(client, depth="deep")
    assert r.status_code == 201, r.text
    assert r.json()["depth"] == "deep"
    # no depth = the default tier
    assert _upload(client).json()["depth"] == "normal"
    # an unknown depth is rejected, not silently mapped
    assert _upload(client, depth="bogus").status_code == 422


def test_api_depth_is_editable(client):
    pid = _upload(client).json()["id"]
    assert client.patch(f"/api/v1/projects/{pid}",
                        json={"depth": "full"}).json()["depth"] == "full"
    assert client.patch(f"/api/v1/projects/{pid}",
                        json={"depth": "ultra"}).status_code == 422


def test_ctf_challenge_accepts_depth(client):
    cid = client.post("/api/v1/ctfs", json={"name": "depth"}).json()["id"]
    r = client.post(f"/api/v1/ctfs/{cid}/challenges", data={"name": "c", "depth": "full"},
                    files={"files": ("note.txt", io.BytesIO(b"hi\n"), "text/plain")})
    assert r.status_code == 201, r.text
    assert r.json()["depth"] == "full"


def test_project_depth_defaults_to_normal():
    assert Project(id="p").depth == "normal"


def test_project_depth_column_exists():
    init_db()
    cols = {c["name"] for c in inspect(engine).get_columns("project")}
    assert "depth" in cols
