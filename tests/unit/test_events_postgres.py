"""Unit tests for XRL-IDARS PostgreSQL Database Configuration and Event Persistence."""

from __future__ import annotations

import json
from pathlib import Path
import time
import pytest

from xrlids.config.database import DatabaseConfig, load_database_config_from_env
from xrlids.events.manager import EventManager
from xrlids.events.schema import SecurityEvent
from xrlids.storage.worker import PostgresAsyncPersistenceWorker


def test_database_config_env_loading_and_masking(monkeypatch):
    """Verify database configuration loads from environment and masks passwords."""
    monkeypatch.setenv("POSTGRES_HOST", "db.internal")
    monkeypatch.setenv("POSTGRES_PORT", "5432")
    monkeypatch.setenv("POSTGRES_DB", "custom_idars")
    monkeypatch.setenv("POSTGRES_USER", "secops")
    monkeypatch.setenv("POSTGRES_PASSWORD", "super_secret_pw")
    monkeypatch.setenv("XRLIDS_STORAGE_MODE", "postgres")

    cfg = load_database_config_from_env()
    assert cfg.host == "db.internal"
    assert cfg.port == 5432
    assert cfg.database == "custom_idars"
    assert cfg.user == "secops"
    assert cfg.password == "super_secret_pw"
    assert cfg.storage_mode == "postgres"
    assert cfg.is_postgres_enabled is True
    assert cfg.is_postgres_strictly_required is True

    # Password masking in safe representations
    safe_dict = cfg.to_safe_dict()
    assert safe_dict["password"] == "******"
    assert "super_secret_pw" not in str(safe_dict)

    dsn_masked = cfg.get_dsn(mask_password=True)
    assert "******" in dsn_masked
    assert "super_secret_pw" not in dsn_masked


def test_security_event_full_payload_roundtrip():
    """Verify complete security event payload roundtrips without flattening or truncation."""
    event = SecurityEvent(
        event_id="evt-test-12345",
        timestamp="2026-10-31T01:30:00.000000+00:00",
        flow_id="flow-999-1",
        source_mode="PCAP",
        source_ip="192.168.10.150",
        dest_ip="10.0.0.5",
        source_port=54321,
        dest_port=80,
        protocol=6,
        hybrid_verdict="HYBRID",
        hybrid_risk_score=0.85,
        severity="HIGH",
        source_escalated=True,
        features={
            "flow_duration_ms": 120.5,
            "flow_packets_per_s": 450.0,
            "syn_count": 25.0,
            "ack_count": 0.0,
        },
        detection={
            "model_name": "Random Forest",
            "attack_score": 0.885,
            "prediction_label": "ATTACK",
            "attack_family": "DoS/DDoS",
            "family_probabilities": {"BENIGN": 0.115, "DoS/DDoS": 0.885},
        },
        rule_matches=[
            {
                "rule_id": "RULE-SYN-FLOOD",
                "severity": "HIGH",
                "description": "Unanswered SYN flood",
            }
        ],
        source_status={"flow_count": 14, "threat_count": 10},
        explanation={
            "base_value": 0.50,
            "top_attributions": {
                "syn_count": 0.35,
                "flow_packets_per_s": 0.12,
            },
        },
        response={
            "proposed_action": "ISOLATE",
            "enforced_action": "ALERT",
            "safety_override": True,
            "override_reason": "CRITICAL_INFRASTRUCTURE_EXEMPTION",
            "q_values": {"ALLOW": -10.0, "ALERT": -2.0, "RATE_LIMIT": -5.0, "ISOLATE": -1.0},
            "state_vector": [0.85, 0.2, 0.5, 0.333, 0.0, 0.6],
        },
        metadata={"capture_node": "sensor-01"},
    )

    # Test dictionary serialization and deserialization
    d = event.to_dict()
    assert d["event_id"] == "evt-test-12345"
    assert d["features"]["syn_count"] == 25.0
    assert d["detection"]["attack_family"] == "DoS/DDoS"
    assert d["response"]["enforced_action"] == "ALERT"

    # Test JSON string conversion
    json_str = event.to_json()
    parsed = json.loads(json_str)
    assert parsed["hybrid_verdict"] == "HYBRID"

    # Reconstruct from dict
    restored = SecurityEvent.from_dict(d)
    assert restored.event_id == event.event_id
    assert restored.features == event.features
    assert restored.detection == event.detection
    assert restored.rule_matches == event.rule_matches
    assert restored.explanation == event.explanation
    assert restored.response == event.response


def test_event_manager_offline_memory_and_jsonl_default(tmp_path):
    """Verify EventManager functions completely offline with in-memory ring buffer and JSONL."""
    jsonl_file = tmp_path / "test_audit.jsonl"
    cfg = DatabaseConfig(storage_mode="memory_jsonl")

    mgr = EventManager(
        max_buffer_size=10,
        audit_log_path=jsonl_file,
        persist_to_disk=True,
        db_config=cfg,
        enable_async_worker=False,
    )
    assert mgr.storage_mode == "memory_jsonl"
    assert mgr.postgres_store is None

    # Publish events
    for i in range(5):
        ev = SecurityEvent(
            event_id=f"evt-{i}",
            source_ip=f"10.0.0.{i}",
            hybrid_verdict="ATTACK" if i % 2 == 0 else "BENIGN",
            severity="HIGH" if i % 2 == 0 else "NONE",
        )
        mgr.publish(ev)

    stats = mgr.get_stats()
    assert stats["total_events"] == 5
    assert stats["threat_events"] == 3
    assert stats["buffer_size"] == 5
    assert stats["postgres_active"] is False

    # Verify JSONL log on disk
    assert jsonl_file.is_file()
    lines = jsonl_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 5

    # Verify ring buffer filtering
    high_events = mgr.get_recent_events(limit=10, severity_filter="HIGH")
    assert len(high_events) == 3
    assert all(e.severity == "HIGH" for e in high_events)


def test_event_manager_subscribers():
    """Verify subscriber callbacks receive published events."""
    mgr = EventManager(db_config=DatabaseConfig(storage_mode="memory_jsonl"), persist_to_disk=False)
    received = []

    def callback(ev: SecurityEvent):
        received.append(ev.event_id)

    mgr.subscribe(callback)

    mgr.publish(SecurityEvent(event_id="sub-1"))
    mgr.publish(SecurityEvent(event_id="sub-2"))
    assert received == ["sub-1", "sub-2"]

    mgr.unsubscribe(callback)
    mgr.publish(SecurityEvent(event_id="sub-3"))
    assert received == ["sub-1", "sub-2"]  # Unsubscribed, no longer called


def test_async_persistence_worker_bounded_queue_saturation():
    """Verify worker queue drops excess events when saturated without blocking caller."""
    # Mock event store that does not drain immediately
    class MockStore:
        def insert_events_batch(self, batch):
            return len(batch), 0

    worker = PostgresAsyncPersistenceWorker(
        event_store=MockStore(),
        max_queue_size=5,  # Tiny queue to test saturation
        batch_size=10,
        flush_interval_s=60.0,  # Do not flush automatically during test
        auto_start=False,
    )

    # Enqueue 5 items to fill queue to capacity
    for i in range(5):
        ok = worker.enqueue(SecurityEvent(event_id=f"q-{i}"))
        assert ok is True

    assert worker.current_queue_size == 5

    # 6th and 7th items MUST return False and increment dropped count (non-blocking)
    dropped1 = worker.enqueue(SecurityEvent(event_id="overflow-1"))
    dropped2 = worker.enqueue(SecurityEvent(event_id="overflow-2"))
    assert dropped1 is False
    assert dropped2 is False
    assert worker.total_dropped_queue_full == 2
    assert worker.current_queue_size == 5  # Still at max


def test_async_persistence_worker_error_tracking():
    """Verify database write failures update metrics without raising exceptions."""
    class FailingStore:
        def insert_events_batch(self, batch):
            return 0, len(batch)  # Simulated write failure

    worker = PostgresAsyncPersistenceWorker(
        event_store=FailingStore(),
        max_queue_size=100,
        batch_size=10,
        flush_interval_s=0.05,
        auto_start=False,
    )

    batch = [SecurityEvent(event_id=f"fail-{i}") for i in range(3)]
    success, errors = worker._persist_batch(batch)
    assert success is False
    assert errors == 3
    assert worker.total_db_write_errors == 3
    assert worker.last_error is not None
    assert "Failed to persist batch" in worker.last_error


def test_event_manager_get_stats_backward_compatibility():
    """Verify get_stats preserves all original keys while exposing postgres metadata."""
    mgr = EventManager(db_config=DatabaseConfig(storage_mode="memory_jsonl"), persist_to_disk=False)
    stats = mgr.get_stats()

    # Original keys
    assert "total_events" in stats
    assert "threat_events" in stats
    assert "rule_matches_count" in stats
    assert "escalated_events_count" in stats
    assert "buffer_size" in stats

    # New storage keys
    assert "storage_mode" in stats
    assert "postgres_active" in stats
    assert "postgres_persisted_events" in stats
    assert "postgres_queue_size" in stats
    assert "postgres_dropped_events" in stats
    assert "postgres_errors" in stats
