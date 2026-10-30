"""PostgreSQL Persistent Storage for XRL-IDARS Security Events.

Provides:
- Schema initialization (tables and performance indexes)
- Parameterized inserts (single and batch)
- Rich multi-attribute indexed filtering
- Complete JSONB round-trip preservation (TreeSHAP, DQN, rule matches, detection)
- Health check and connection lifecycle management
- Safe non-crashing failure modes
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Generator, Sequence

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from xrlids.config.database import DatabaseConfig, load_database_config_from_env
from xrlids.events.schema import SecurityEvent
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS security_events (
    event_id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    flow_id VARCHAR(128) NOT NULL,
    source_mode VARCHAR(32) NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    dest_ip VARCHAR(64) NOT NULL,
    source_port INTEGER NOT NULL,
    dest_port INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    hybrid_verdict VARCHAR(32) NOT NULL,
    hybrid_risk_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    severity VARCHAR(32) NOT NULL,
    source_escalated BOOLEAN NOT NULL DEFAULT FALSE,
    features JSONB NOT NULL DEFAULT '{}'::jsonb,
    detection JSONB NOT NULL DEFAULT '{}'::jsonb,
    rule_matches JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    explanation JSONB,
    response JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events (timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events (source_ip);",
    "CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events (severity);",
    "CREATE INDEX IF NOT EXISTS idx_security_events_hybrid_verdict ON security_events (hybrid_verdict);",
    "CREATE INDEX IF NOT EXISTS idx_security_events_source_mode ON security_events (source_mode);",
    "CREATE INDEX IF NOT EXISTS idx_security_events_source_time ON security_events (source_ip, timestamp DESC);",
]

INSERT_EVENT_SQL = """
INSERT INTO security_events (
    event_id, timestamp, flow_id, source_mode, source_ip, dest_ip,
    source_port, dest_port, protocol, hybrid_verdict, hybrid_risk_score,
    severity, source_escalated, features, detection, rule_matches,
    source_status, explanation, response, metadata
) VALUES (
    %(event_id)s, %(timestamp)s, %(flow_id)s, %(source_mode)s, %(source_ip)s, %(dest_ip)s,
    %(source_port)s, %(dest_port)s, %(protocol)s, %(hybrid_verdict)s, %(hybrid_risk_score)s,
    %(severity)s, %(source_escalated)s, %(features)s, %(detection)s, %(rule_matches)s,
    %(source_status)s, %(explanation)s, %(response)s, %(metadata)s
)
ON CONFLICT (event_id) DO NOTHING;
"""


class PostgresEventStore:
    """Manages connection, schema, persistence, and queries for SecurityEvent entities."""

    def __init__(self, config: DatabaseConfig | None = None) -> None:
        self.config = config or load_database_config_from_env()
        self._schema_initialized = False

    @contextmanager
    def get_connection(self) -> Generator[psycopg.Connection, None, None]:
        """Context manager yielding an active psycopg connection with row_factory dict_row."""
        params = self.config.to_connection_params()
        conn = psycopg.connect(**params, row_factory=dict_row)
        try:
            yield conn
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def health_check(self) -> tuple[bool, str, dict[str, Any]]:
        """Verify database connectivity, query response, and schema state.

        Returns
        -------
        tuple[bool, str, dict[str, Any]]
            (is_healthy, status_message, details_dictionary)
        """
        details: dict[str, Any] = {
            "config": self.config.to_safe_dict(),
            "connected": False,
            "latency_ms": None,
            "table_exists": False,
            "row_count": 0,
        }

        t0 = time.perf_counter()
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1;")
                    cur.fetchone()
                    latency_ms = (time.perf_counter() - t0) * 1000.0
                    details["connected"] = True
                    details["latency_ms"] = round(latency_ms, 2)

                    # Check table existence
                    cur.execute(
                        """
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_schema = 'public' 
                            AND table_name = 'security_events'
                        );
                        """
                    )
                    row = cur.fetchone()
                    table_exists = bool(row and (row.get("exists") or list(row.values())[0]))
                    details["table_exists"] = table_exists

                    if table_exists:
                        cur.execute("SELECT COUNT(*) AS cnt FROM security_events;")
                        cnt_row = cur.fetchone()
                        cnt = int(cnt_row.get("cnt") if cnt_row else 0)
                        details["row_count"] = cnt

            return True, f"Connected to PostgreSQL (latency: {details['latency_ms']:.1f}ms)", details
        except Exception as exc:
            msg = f"PostgreSQL connection failed: {exc}"
            logger.warning(msg)
            return False, msg, details

    def init_schema(self) -> bool:
        """Create the security_events table and required indexes if they do not exist."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(CREATE_TABLE_SQL)
                    for idx_sql in CREATE_INDEXES_SQL:
                        cur.execute(idx_sql)
                conn.commit()
            self._schema_initialized = True
            logger.info("PostgreSQL security_events schema initialized successfully.")
            return True
        except Exception as exc:
            logger.error("Failed to initialize PostgreSQL schema: %s", exc)
            return False

    def _format_event_params(self, event: SecurityEvent) -> dict[str, Any]:
        """Convert a SecurityEvent into parameters with JSONB type adaptation."""
        # Convert timestamp to ISO8601 string or datetime
        ts_val = event.timestamp
        if not ts_val:
            ts_val = datetime.now(timezone.utc).isoformat()

        return {
            "event_id": str(event.event_id),
            "timestamp": ts_val,
            "flow_id": str(event.flow_id),
            "source_mode": str(getattr(event, "source_mode", "LIVE")),
            "source_ip": str(event.source_ip),
            "dest_ip": str(event.dest_ip),
            "source_port": int(event.source_port or 0),
            "dest_port": int(event.dest_port or 0),
            "protocol": int(event.protocol or 6),
            "hybrid_verdict": str(event.hybrid_verdict or "BENIGN"),
            "hybrid_risk_score": float(getattr(event, "hybrid_risk_score", 0.0)),
            "severity": str(event.severity or "NONE"),
            "source_escalated": bool(event.source_escalated),
            "features": Jsonb(event.features or {}),
            "detection": Jsonb(event.detection or {}),
            "rule_matches": Jsonb(event.rule_matches or []),
            "source_status": Jsonb(event.source_status or {}),
            "explanation": Jsonb(event.explanation) if event.explanation is not None else None,
            "response": Jsonb(event.response or {}),
            "metadata": Jsonb(event.metadata or {}),
        }

    def insert_event(self, event: SecurityEvent) -> bool:
        """Insert a single SecurityEvent into PostgreSQL with duplicate prevention.

        Returns
        -------
        bool
            True if inserted or safely ignored on duplicate conflict; False on error.
        """
        params = self._format_event_params(event)
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(INSERT_EVENT_SQL, params)
                conn.commit()
            return True
        except Exception as exc:
            logger.error("Failed to insert SecurityEvent %s to PostgreSQL: %s", event.event_id, exc)
            return False

    def insert_events_batch(self, events: Sequence[SecurityEvent]) -> tuple[int, int]:
        """Insert a batch of SecurityEvents in a single database transaction.

        Returns
        -------
        tuple[int, int]
            (inserted_count, error_count)
        """
        if not events:
            return 0, 0

        param_list = [self._format_event_params(e) for e in events]
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.executemany(INSERT_EVENT_SQL, param_list)
                conn.commit()
            return len(events), 0
        except Exception as exc:
            logger.error("Failed to insert batch of %d SecurityEvents: %s", len(events), exc)
            return 0, len(events)

    def _row_to_event(self, row: dict[str, Any]) -> SecurityEvent:
        """Construct a strongly typed SecurityEvent from a PostgreSQL result row."""
        ts = row["timestamp"]
        if isinstance(ts, datetime):
            ts_str = ts.isoformat()
        else:
            ts_str = str(ts)

        return SecurityEvent(
            event_id=str(row["event_id"]),
            timestamp=ts_str,
            flow_id=str(row["flow_id"]),
            source_mode=str(row["source_mode"]),
            source_ip=str(row["source_ip"]),
            dest_ip=str(row["dest_ip"]),
            source_port=int(row["source_port"]),
            dest_port=int(row["dest_port"]),
            protocol=int(row["protocol"]),
            hybrid_verdict=str(row["hybrid_verdict"]),
            hybrid_risk_score=float(row["hybrid_risk_score"]),
            severity=str(row["severity"]),
            source_escalated=bool(row["source_escalated"]),
            features=row["features"] if isinstance(row["features"], dict) else json.loads(row["features"] or "{}"),
            detection=row["detection"] if isinstance(row["detection"], dict) else json.loads(row["detection"] or "{}"),
            rule_matches=row["rule_matches"] if isinstance(row["rule_matches"], list) else json.loads(row["rule_matches"] or "[]"),
            source_status=row["source_status"] if isinstance(row["source_status"], dict) else json.loads(row["source_status"] or "{}"),
            explanation=row["explanation"] if isinstance(row["explanation"], dict) or row["explanation"] is None else json.loads(row["explanation"]),
            response=row["response"] if isinstance(row["response"], dict) else json.loads(row["response"] or "{}"),
            metadata=row["metadata"] if isinstance(row["metadata"], dict) else json.loads(row["metadata"] or "{}"),
        )

    def query_events(
        self,
        limit: int = 50,
        offset: int = 0,
        source_ip: str | None = None,
        severity: str | None = None,
        verdict: str | None = None,
        source_mode: str | None = None,
        start_time: str | datetime | None = None,
        end_time: str | datetime | None = None,
    ) -> list[SecurityEvent]:
        """Query historical security events with parameterized filtering and index utilization."""
        clauses = ["1=1"]
        params: dict[str, Any] = {
            "limit": max(1, min(1000, int(limit))),
            "offset": max(0, int(offset)),
        }

        if source_ip and source_ip.strip():
            clauses.append("source_ip = %(source_ip)s")
            params["source_ip"] = source_ip.strip()

        if severity and severity.upper() != "ALL":
            clauses.append("severity = %(severity)s")
            params["severity"] = severity.upper().strip()

        if verdict and verdict.upper() != "ALL":
            clauses.append("hybrid_verdict = %(verdict)s")
            params["verdict"] = verdict.upper().strip()

        if source_mode and source_mode.upper() != "ALL":
            clauses.append("source_mode = %(source_mode)s")
            params["source_mode"] = source_mode.upper().strip()

        if start_time:
            clauses.append("timestamp >= %(start_time)s")
            params["start_time"] = start_time

        if end_time:
            clauses.append("timestamp <= %(end_time)s")
            params["end_time"] = end_time

        where_sql = " AND ".join(clauses)
        sql = f"""
        SELECT
            event_id, timestamp, flow_id, source_mode, source_ip, dest_ip,
            source_port, dest_port, protocol, hybrid_verdict, hybrid_risk_score,
            severity, source_escalated, features, detection, rule_matches,
            source_status, explanation, response, metadata
        FROM security_events
        WHERE {where_sql}
        ORDER BY timestamp DESC
        LIMIT %(limit)s OFFSET %(offset)s;
        """

        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                    rows = cur.fetchall()
            return [self._row_to_event(r) for r in rows]
        except Exception as exc:
            logger.error("Failed to query security events: %s", exc)
            return []

    def get_event_by_id(self, event_id: str) -> SecurityEvent | None:
        """Fetch a single SecurityEvent by its primary key ID."""
        sql = """
        SELECT
            event_id, timestamp, flow_id, source_mode, source_ip, dest_ip,
            source_port, dest_port, protocol, hybrid_verdict, hybrid_risk_score,
            severity, source_escalated, features, detection, rule_matches,
            source_status, explanation, response, metadata
        FROM security_events
        WHERE event_id = %(event_id)s;
        """
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, {"event_id": event_id})
                    row = cur.fetchone()
            if row:
                return self._row_to_event(row)
            return None
        except Exception as exc:
            logger.error("Failed to fetch SecurityEvent by id %s: %s", event_id, exc)
            return None

    def count_events(
        self,
        source_ip: str | None = None,
        severity: str | None = None,
        verdict: str | None = None,
        source_mode: str | None = None,
    ) -> int:
        """Count security events matching criteria."""
        clauses = ["1=1"]
        params: dict[str, Any] = {}

        if source_ip and source_ip.strip():
            clauses.append("source_ip = %(source_ip)s")
            params["source_ip"] = source_ip.strip()

        if severity and severity.upper() != "ALL":
            clauses.append("severity = %(severity)s")
            params["severity"] = severity.upper().strip()

        if verdict and verdict.upper() != "ALL":
            clauses.append("hybrid_verdict = %(verdict)s")
            params["verdict"] = verdict.upper().strip()

        if source_mode and source_mode.upper() != "ALL":
            clauses.append("source_mode = %(source_mode)s")
            params["source_mode"] = source_mode.upper().strip()

        where_sql = " AND ".join(clauses)
        sql = f"SELECT COUNT(*) AS cnt FROM security_events WHERE {where_sql};"
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                    row = cur.fetchone()
            return int(row["cnt"]) if row else 0
        except Exception as exc:
            logger.error("Failed to count security events: %s", exc)
            return 0
