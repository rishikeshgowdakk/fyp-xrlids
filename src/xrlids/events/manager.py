"""Event Manager and Audit Bus for XRL-IDARS.

Provides:
- Thread-safe event publishing and subscription callbacks
- In-memory ring-buffer caching for immediate UI reactivity
- Persistent append-only JSONL audit logging for independent offline inspection
- PostgreSQL persistent storage via bounded asynchronous persistence queue
- Backward-compatible retrieval API supporting historical and filtered queries
- Fault isolation: database outages or queue saturation never crash the detection pipeline
"""

from __future__ import annotations

from collections import deque
import json
import logging
from pathlib import Path
import threading
import time
from typing import Any, Callable

from xrlids.config.database import DatabaseConfig, load_database_config_from_env
from xrlids.events.schema import SecurityEvent
from xrlids.storage.postgres import PostgresEventStore
from xrlids.storage.worker import PostgresAsyncPersistenceWorker
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_AUDIT_LOG = REPO_ROOT / "results" / "audits" / "security_events.jsonl"


class EventManager:
    """Thread-safe event dispatcher, ring buffer, JSONL auditor, and PostgreSQL persistence coordinator."""

    def __init__(
        self,
        max_buffer_size: int = 5000,
        audit_log_path: Path | str | None = None,
        persist_to_disk: bool = True,
        db_config: DatabaseConfig | None = None,
        postgres_store: PostgresEventStore | None = None,
        enable_async_worker: bool = True,
    ) -> None:
        self.max_buffer_size = max_buffer_size
        self.persist_to_disk = persist_to_disk
        self.audit_log_path = Path(audit_log_path or DEFAULT_AUDIT_LOG)
        if self.persist_to_disk:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._buffer: deque[SecurityEvent] = deque(maxlen=max_buffer_size)
        self._subscribers: list[Callable[[SecurityEvent], None]] = []

        # In-memory session counters
        self.total_events: int = 0
        self.threat_events: int = 0
        self.rule_matches_count: int = 0
        self.escalated_events_count: int = 0

        # PostgreSQL Storage Initialization
        self.db_config = db_config or load_database_config_from_env()
        self.postgres_store: PostgresEventStore | None = postgres_store
        self.async_worker: PostgresAsyncPersistenceWorker | None = None
        self.storage_mode: str = "memory_jsonl"
        self._db_initialized: bool = False

        self._initialize_storage(enable_async_worker=enable_async_worker)

    def _initialize_storage(self, enable_async_worker: bool = True) -> None:
        """Establish PostgreSQL connection and persistence worker if configured."""
        if not self.db_config.is_postgres_enabled and self.postgres_store is None:
            self.storage_mode = "memory_jsonl" if self.persist_to_disk else "disabled"
            return

        try:
            if self.postgres_store is None:
                self.postgres_store = PostgresEventStore(self.db_config)

            is_healthy, msg, _ = self.postgres_store.health_check()
            if is_healthy:
                self.postgres_store.init_schema()
                if enable_async_worker:
                    self.async_worker = PostgresAsyncPersistenceWorker(
                        event_store=self.postgres_store,
                        max_queue_size=self.db_config.async_queue_size,
                        batch_size=self.db_config.async_batch_size,
                        flush_interval_s=self.db_config.async_flush_interval_s,
                        auto_start=True,
                    )
                self.storage_mode = "postgres"
                self._db_initialized = True
                logger.info("EventManager connected to PostgreSQL event store (%s).", msg)
            else:
                if self.db_config.is_postgres_strictly_required:
                    raise ConnectionError(f"PostgreSQL strictly required by configuration but unreachable: {msg}")
                self.storage_mode = "memory_jsonl"
                logger.info("PostgreSQL unreachable (%s); EventManager running in memory_jsonl mode.", msg)
        except Exception as exc:
            if self.db_config.is_postgres_strictly_required:
                raise
            self.storage_mode = "memory_jsonl"
            logger.warning("PostgreSQL initialization bypassed: %s. Using memory_jsonl fallback.", exc)

    def subscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a subscriber callback for real-time event notifications."""
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Unregister a subscriber callback."""
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def publish(self, event: SecurityEvent) -> None:
        """Publish a new security event to the buffer, disk, PostgreSQL, and subscribers.

        Guarantees non-blocking pipeline execution:
        - In-memory ring buffer append is immediate (O(1)).
        - Submissions to PostgreSQL are dispatched via a bounded asynchronous queue.
        - Queue saturation or database outages drop/log without blocking caller.
        """
        with self._lock:
            # 1. In-memory ring buffer
            self._buffer.append(event)
            self.total_events += 1

            if event.hybrid_verdict in ("RF", "RULE", "HYBRID", "ATTACK"):
                self.threat_events += 1
            if event.rule_matches:
                self.rule_matches_count += len(event.rule_matches)
            if event.source_escalated:
                self.escalated_events_count += 1

            # 2. Append to secondary JSONL audit log
            if self.persist_to_disk:
                try:
                    with open(self.audit_log_path, "a", encoding="utf-8") as f:
                        f.write(event.to_json() + "\n")
                except Exception as e:
                    logger.warning("Could not append event to %s: %s", self.audit_log_path, e)

            # 3. Asynchronous PostgreSQL Persistence
            if self.async_worker is not None:
                self.async_worker.enqueue(event)
            elif self.postgres_store is not None and self.storage_mode == "postgres":
                # Fallback synchronous write when worker disabled
                try:
                    self.postgres_store.insert_event(event)
                except Exception as e:
                    logger.error("Synchronous PostgreSQL insert failed for %s: %s", event.event_id, e)

            subscribers_copy = list(self._subscribers)

        # 4. Notify subscribers outside critical lock
        for sub in subscribers_copy:
            try:
                sub(event)
            except Exception as e:
                logger.error("Error executing event subscriber callback: %s", e)

    def get_recent_events(
        self,
        limit: int = 50,
        severity_filter: str | None = None,
        verdict_filter: str | None = None,
        source_ip: str | None = None,
        source_mode: str | None = None,
        fetch_from_db: bool | None = None,
    ) -> list[SecurityEvent]:
        """Retrieve recent events with optional filtering.

        If fetch_from_db is True (or if the in-memory buffer is empty after an application restart
        and PostgreSQL is active), queries the persistent database. Otherwise serves from ring buffer.
        """
        # Determine whether to query database
        should_query_db = fetch_from_db
        if should_query_db is None:
            # Auto-retrieve from DB if memory buffer is empty but DB has events (e.g. after restart)
            with self._lock:
                buf_len = len(self._buffer)
            should_query_db = (buf_len == 0 and self.postgres_store is not None and self.storage_mode == "postgres")

        if should_query_db and self.postgres_store is not None:
            try:
                db_events = self.postgres_store.query_events(
                    limit=limit,
                    severity=severity_filter,
                    verdict=verdict_filter,
                    source_ip=source_ip,
                    source_mode=source_mode,
                )
                if db_events:
                    return db_events
            except Exception as exc:
                logger.warning("Failed to query events from PostgreSQL: %s. Falling back to ring buffer.", exc)

        # In-memory buffer retrieval
        with self._lock:
            events = list(self._buffer)

        if severity_filter and severity_filter.upper() != "ALL":
            sev_upper = severity_filter.upper().strip()
            events = [e for e in events if e.severity == sev_upper]

        if verdict_filter and verdict_filter.upper() != "ALL":
            verd_upper = verdict_filter.upper().strip()
            events = [e for e in events if e.hybrid_verdict == verd_upper]

        if source_ip and source_ip.strip():
            sip = source_ip.strip()
            events = [e for e in events if e.source_ip == sip]

        if source_mode and source_mode.upper() != "ALL":
            smode = source_mode.upper().strip()
            events = [e for e in events if getattr(e, "source_mode", "LIVE") == smode]

        return events[-limit:]

    def get_historical_events(
        self,
        limit: int = 50,
        offset: int = 0,
        source_ip: str | None = None,
        severity: str | None = None,
        verdict: str | None = None,
        source_mode: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list[SecurityEvent]:
        """Retrieve paginated historical events from PostgreSQL with fallback to ring buffer."""
        if self.postgres_store is not None:
            try:
                return self.postgres_store.query_events(
                    limit=limit,
                    offset=offset,
                    source_ip=source_ip,
                    severity=severity,
                    verdict=verdict,
                    source_mode=source_mode,
                    start_time=start_time,
                    end_time=end_time,
                )
            except Exception as exc:
                logger.error("Historical event query to PostgreSQL failed: %s", exc)

        return self.get_recent_events(
            limit=limit,
            severity_filter=severity,
            verdict_filter=verdict,
            source_ip=source_ip,
            source_mode=source_mode,
            fetch_from_db=False,
        )

    def get_all_events(self) -> list[SecurityEvent]:
        """Retrieve all events currently held in the in-memory ring buffer."""
        with self._lock:
            return list(self._buffer)

    def get_stats(self) -> dict[str, Any]:
        """Return operational counters and PostgreSQL persistence telemetry."""
        with self._lock:
            stats: dict[str, Any] = {
                "total_events": self.total_events,
                "threat_events": self.threat_events,
                "rule_matches_count": self.rule_matches_count,
                "escalated_events_count": self.escalated_events_count,
                "buffer_size": len(self._buffer),
                "storage_mode": self.storage_mode,
                "postgres_active": (self.storage_mode == "postgres" and self.postgres_store is not None),
                "postgres_persisted_events": 0,
                "postgres_queue_size": 0,
                "postgres_dropped_events": 0,
                "postgres_errors": 0,
            }

            if self.async_worker is not None:
                worker_metrics = self.async_worker.get_metrics()
                stats["postgres_persisted_events"] = worker_metrics["total_persisted"]
                stats["postgres_queue_size"] = worker_metrics["current_queue_size"]
                stats["postgres_dropped_events"] = worker_metrics["total_dropped_queue_full"]
                stats["postgres_errors"] = worker_metrics["total_db_write_errors"]
            elif self.postgres_store is not None and self.storage_mode == "postgres":
                stats["postgres_persisted_events"] = self.total_events

            return stats

    def clear(self) -> None:
        """Clear memory buffer and reset counters."""
        with self._lock:
            self._buffer.clear()
            self.total_events = 0
            self.threat_events = 0
            self.rule_matches_count = 0
            self.escalated_events_count = 0

    def close(self, timeout: float = 5.0) -> None:
        """Gracefully terminate background workers and flush queued events."""
        if self.async_worker is not None:
            self.async_worker.flush_and_stop(timeout=timeout)
