"""Rate limiting: token bucket per IP, opt-in via RATE_LIMIT_RPM.

Single worker process (see Dockerfile CMD), so an in-process counter is the
correct scope. See tasks/remaining.md item B7.
"""
import threading

import pytest

from backend import ratelimit
from backend.ratelimit import TokenBucket, client_ip


@pytest.fixture(autouse=True)
def _clean_registry():
    """The bucket registry is process-global; isolate every test from the last."""
    ratelimit.reset()
    yield
    ratelimit.reset()


# --- bucket arithmetic -------------------------------------------------------

def test_bucket_allows_burst_then_refuses():
    b = TokenBucket(capacity=3, refill_per_sec=1000.0, clock=lambda: 0.0)
    assert [b.take() for _ in range(3)] == [True, True, True]
    assert b.take() is False


def test_bucket_refills_at_the_configured_rate():
    now = [0.0]
    b = TokenBucket(capacity=2, refill_per_sec=2.0, clock=lambda: now[0])
    assert b.take() and b.take()
    assert b.take() is False            # bucket empty
    now[0] += 0.5                      # +1 token at 2 tokens/s
    assert b.take() is True
    assert b.take() is False


def test_bucket_refill_is_capped_at_capacity():
    now = [0.0]
    b = TokenBucket(capacity=2, refill_per_sec=10.0, clock=lambda: now[0])
    b.take()
    b.take()
    now[0] += 3600                     # long idle: never more than `capacity`
    assert b.take() and b.take()
    assert b.take() is False


def test_bucket_grants_the_sustained_rate_over_a_long_window():
    now = [0.0]
    b = TokenBucket(capacity=3, refill_per_sec=2.0, clock=lambda: now[0])
    granted = 0
    for _ in range(1000):                   # 100s at 2 tokens/s -> 200 refilled
        now[0] += 0.1
        granted += b.take()
    # 200 sustained + 3 initial, minus the sub-token remainders the 0.1s sampling
    # never reaches: the long-run rate is what matters, not the exact instant.
    assert 200 <= granted <= 203


def test_bucket_admits_exactly_capacity_requests_under_concurrency():
    b = TokenBucket(capacity=50, refill_per_sec=0.0, clock=lambda: 0.0)
    granted: list[bool] = []
    lock = threading.Lock()

    def worker():
        ok = b.take()
        with lock:
            granted.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(200)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(granted) == 50


# --- registry ----------------------------------------------------------------

def test_get_bucket_returns_the_same_bucket_for_the_same_key():
    first = ratelimit.get_bucket("1.2.3.4", capacity=5, refill_per_sec=1.0)
    second = ratelimit.get_bucket("1.2.3.4", capacity=5, refill_per_sec=1.0)
    assert first is second


def test_get_bucket_isolates_different_keys():
    a = ratelimit.get_bucket("1.2.3.4", capacity=1, refill_per_sec=0.0)
    b = ratelimit.get_bucket("5.6.7.8", capacity=1, refill_per_sec=0.0)
    assert a.take() is True
    assert a.take() is False
    assert b.take() is True


def test_idle_buckets_are_evicted_to_bound_memory():
    now = [0.0]
    with _frozen_clock(now):
        ratelimit.get_bucket("1.2.3.4", capacity=5, refill_per_sec=1.0, ttl=60.0)
        assert len(ratelimit._BUCKETS) == 1
        now[0] += 3600
        ratelimit.get_bucket("5.6.7.8", capacity=5, refill_per_sec=1.0, ttl=60.0)
        assert "1.2.3.4" not in ratelimit._BUCKETS
        assert "5.6.7.8" in ratelimit._BUCKETS


# --- client identification ---------------------------------------------------

@pytest.mark.parametrize("forwarded, peer, expected", [
    ("203.0.113.7, 10.0.0.1", "198.51.100.9", "203.0.113.7"),   # first hop wins
    ("", "198.51.100.9", "198.51.100.9"),                        # blank -> peer
    ("   ", "198.51.100.9", "198.51.100.9"),                     # whitespace -> peer
    (None, "198.51.100.9:5555", "198.51.100.9"),                 # strip port
    (None, "198.51.100.9", "198.51.100.9"),
])
def test_client_ip_resolution(forwarded, peer, expected):
    headers = {} if forwarded is None else {"x-forwarded-for": forwarded}
    assert client_ip(_FakeRequest(headers, peer)) == expected


class _FakeRequest:
    def __init__(self, headers, peer):
        self.headers = headers
        self.client = type("Peer", (), {"host": peer})()


class _frozen_clock:
    """Swap ratelimit's clock so eviction/refill is deterministic."""

    def __init__(self, now):
        self.now = now

    def __enter__(self):
        self._saved = ratelimit._clock
        ratelimit._clock = lambda: self.now[0]
        ratelimit._BUCKETS.clear()
        return self

    def __exit__(self, *_exc):
        ratelimit._clock = self._saved
        ratelimit._BUCKETS.clear()
        return False