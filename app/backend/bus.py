"""Tiny thread-safe in-process pub/sub for live updates (WebSocket fan-out)."""
from __future__ import annotations

import queue
import threading
import time
from collections import defaultdict

Queue = queue.Queue


class Bus:
    def __init__(self) -> None:
        self._subs: dict[str, set[Queue]] = defaultdict(set)
        self._lock = threading.Lock()

    def subscribe(self, topic: str) -> Queue:
        q: Queue = Queue(maxsize=1000)
        with self._lock:
            self._subs[topic].add(q)
        return q

    def unsubscribe(self, topic: str, q: Queue) -> None:
        with self._lock:
            self._subs[topic].discard(q)

    def publish(self, topic: str, event: dict) -> None:
        event = {"topic": topic, "ts": time.time(), **event}
        with self._lock:
            targets = list(self._subs[topic]) + list(self._subs["*"])
        for q in targets:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass


bus = Bus()
