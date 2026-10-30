"""Bounded Asynchronous Persistence Worker for XRL-IDARS (Phase B).

Preserves the non-blocking detection pipeline contract:
- Non-blocking event submission via bounded FIFO queue (O(1)).
- Queue saturation handling: drops with observable metrics under extreme burst/outage,
  never blocking the live packet capture or flow engine.
- Batch database writes with connection recycling and error handling.
- Graceful shutdown with flush timeout.
- Real-time observable telemetry counters.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any, Sequence

from xrlids.events.schema import SecurityEvent
from xrlids.storage.postgres import PostgresEventStore
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


class PostgresAsyncPersistenceWorker:
    """Thread-safe bounded asynchronous batch persistence queue for SecurityEvents."""

    def __init__(
        self,
        event_store: PostgresEventStore,
        max_queue_size: int = 10000,
        batch_size: int = 100,
        flush_interval_s: float = 0.5,
        auto_start: bool = True,
    ) -> None:
        self.event_store = event_store
        self.max_queue_size = max(1, int(max_queue_size))
        self.batch_size = max(1, int(batch_size))
        self.flush_interval_s = max(0.05, float(flush_interval_s))

        self._queue: queue.Queue[SecurityEvent] = queue.Queue(maxsize=self.max_queue_size)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        # Telemetry metrics
        self.total_enqueued: int = 0
        self.total_persisted: int = 0
        self.total_dropped_queue_full: int = 0
        self.total_db_write_errors: int = 0
        self.last_error: str | None = None
        self.last_error_time: float = 0.0
        self._last_warn_time: float = 0.0

        if auto_start:
            self.start()

    @property
    def is_alive(self) -> bool:
        """Evaluate if the background worker thread is running."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def current_queue_size(self) -> int:
        """Current count of items waiting in the persistence queue."""
        return self._queue.qsize()

    def start(self) -> None:
        """Start the background ingestion daemon thread."""
        with self._lock:
            if self.is_alive:
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._worker_loop,
                name="xrlids-pg-worker",
                daemon=True,
            )
            self._thread.start()
            logger.info(
                "Started PostgresAsyncPersistenceWorker (max_queue=%d, batch=%d, flush=%.2fs)",
                self.max_queue_size,
                self.batch_size,
                self.flush_interval_s,
            )

    def enqueue(self, event: SecurityEvent) -> bool:
        """Submit an event to the persistence queue without blocking the detection pipeline.

        Returns
        -------
        bool
            True if queued successfully; False if queue is full (dropped to protect pipeline).
        """
        try:
            self._queue.put_nowait(event)
            self.total_enqueued += 1
            return True
        except queue.Full:
            self.total_dropped_queue_full += 1
            now = time.time()
            if now - self._last_warn_time > 5.0:
                logger.warning(
                    "Async persistence queue saturated (size=%d, dropped=%d). Dropping event %s to preserve pipeline non-blocking invariant.",
                    self.max_queue_size,
                    self.total_dropped_queue_full,
                    event.event_id,
                )
                self._last_warn_time = now
            return False

    def _worker_loop(self) -> None:
        """Main batch consumer loop running in dedicated daemon thread."""
        backoff_s = 0.5
        while not self._stop_event.is_set():
            batch = self._drain_batch(timeout=self.flush_interval_s)
            if not batch:
                continue

            success, err_count = self._persist_batch(batch)
            if success:
                backoff_s = 0.5
            else:
                # Transient backoff on database error
                time.sleep(min(3.0, backoff_s))
                backoff_s = min(3.0, backoff_s * 1.5)

        # Final drain on shutdown
        final_batch = self._drain_all()
        if final_batch:
            self._persist_batch(final_batch)

    def _drain_batch(self, timeout: float) -> list[SecurityEvent]:
        """Collect up to batch_size items or wait up to timeout seconds."""
        batch: list[SecurityEvent] = []
        try:
            item = self._queue.get(timeout=timeout)
            batch.append(item)
            self._queue.task_done()
        except queue.Empty:
            return batch

        # Non-blocking collection of remaining available items up to batch_size
        while len(batch) < self.batch_size:
            try:
                item = self._queue.get_nowait()
                batch.append(item)
                self._queue.task_done()
            except queue.Empty:
                break

        return batch

    def _drain_all(self) -> list[SecurityEvent]:
        """Drain all remaining items currently queued."""
        items: list[SecurityEvent] = []
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
                items.append(item)
                self._queue.task_done()
            except queue.Empty:
                break
        return items

    def _persist_batch(self, batch: Sequence[SecurityEvent]) -> tuple[bool, int]:
        """Attempt writing batch to PostgreSQL store."""
        if not batch:
            return True, 0

        inserted, errors = self.event_store.insert_events_batch(batch)
        if errors == 0:
            self.total_persisted += inserted
            return True, 0
        else:
            self.total_db_write_errors += errors
            self.last_error = f"Failed to persist batch of {len(batch)} events"
            self.last_error_time = time.time()
            return False, errors

    def flush_and_stop(self, timeout: float = 5.0) -> None:
        """Signal worker to finish in-flight events, drain queue to database, and terminate."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info(
            "Stopped PostgresAsyncPersistenceWorker (persisted=%d, dropped=%d, errors=%d)",
            self.total_persisted,
            self.total_dropped_queue_full,
            self.total_db_write_errors,
        )

    def get_metrics(self) -> dict[str, Any]:
        """Return real-time operational status and queue metrics."""
        return {
            "worker_alive": self.is_alive,
            "current_queue_size": self.current_queue_size,
            "max_queue_size": self.max_queue_size,
            "total_enqueued": self.total_enqueued,
            "total_persisted": self.total_persisted,
            "total_dropped_queue_full": self.total_dropped_queue_full,
            "total_db_write_errors": self.total_db_write_errors,
            "last_error": self.last_error,
            "last_error_time": self.last_error_time,
        }
