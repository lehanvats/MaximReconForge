"""In-memory pub/sub bus for live engagement events (localhost mode).

A single process runs both the graph and the WebSocket endpoint, so a plain
in-process bus is all we need. Each engagement keeps a bounded event history so
a WebSocket that connects (or reconnects) slightly after the run started still
replays everything that already happened.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)

# Cap replayed history so a very chatty engagement can't grow unbounded.
_MAX_HISTORY = 2000


class EngagementBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._finished: set[str] = set()

    def subscribe(self, engagement_id: str) -> asyncio.Queue:
        """Register a subscriber, replaying any events already emitted."""
        queue: asyncio.Queue = asyncio.Queue()
        for event in self._history.get(engagement_id, []):
            queue.put_nowait(event)
        if engagement_id in self._finished:
            queue.put_nowait({"type": "end"})
        self._subscribers[engagement_id].add(queue)
        return queue

    def unsubscribe(self, engagement_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(engagement_id)
        if subs:
            subs.discard(queue)

    def publish(self, engagement_id: str, event: dict[str, Any]) -> None:
        """Record an event and fan it out to every current subscriber."""
        history = self._history[engagement_id]
        history.append(event)
        if len(history) > _MAX_HISTORY:
            # Keep the newest events; older log spam is expendable.
            del history[: len(history) - _MAX_HISTORY]
        for queue in list(self._subscribers.get(engagement_id, ())):
            queue.put_nowait(event)

    def finish(self, engagement_id: str) -> None:
        """Mark an engagement complete so late subscribers get a terminal event."""
        self._finished.add(engagement_id)
        self.publish(engagement_id, {"type": "end"})

    def is_finished(self, engagement_id: str) -> bool:
        return engagement_id in self._finished


# Module-level singleton shared by the runner and the WebSocket endpoint.
bus = EngagementBus()
