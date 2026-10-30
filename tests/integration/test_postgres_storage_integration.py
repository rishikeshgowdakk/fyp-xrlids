"""Real PostgreSQL Integration Tests for XRL-IDARS Event Persistence.

Executes against an authentic local PostgreSQL instance (port 5433 / xrlids).
Verifies:
1. Schema initialization and health checks.
2. Complete SecurityEvent JSONB round-trip preservation (TreeSHAP, DQN, rules, detection).
3. Parameterized indexed query filtering (source_ip, severity, verdict, source_mode).
4. Duplicate event_id idempotence (ON CONFLICT DO NOTHING).
5. Data persistence across application/process restart (new EventManager instance retrieves historical events).
6. Database outage failure handling and fault isolation.
"""

from __future__ import annotations

import time
import pytest

from xrlids.config.database import DatabaseConfig
from xrlids.events.manager import EventManager
from xrlids.events.schema import SecurityEvent
from xrlids.storage.postgres import PostgresEventStore


@pytest.fixture(scope="module")
def pg_config() -> DatabaseConfig:
    """Fixture providing configuration targeting the active local test PostgreSQL instance."""
    return DatabaseConfig(
        host="localhost",
        port=5433,
        database="xrlids",
        user="xrlids_user",
        password="",
        sslmode="disable",
        connect_timeout=3,
        storage_mode="postgres",
        jsonl_export=False,
    )


@pytest.fixture(scope="module")
def pg_store(pg_config) -> PostgresEventStore:
    """Fixture providing an initialized PostgresEventStore."""
    store = PostgresEventStore(pg_config)
    is_healthy, msg, _ = store.health_check()
    if not is_healthy:
        pytest.skip(f"PostgreSQL integration test skipped: {msg}")
    store.init_schema()
    return store


def test_postgres_schema_initialization_and_health_check(pg_store):
    """Verify database connection, schema initialization, and health check details."""
    is_healthy, msg, details = pg_store.health_check()
    assert is_healthy is True
    assert "Connected to PostgreSQL" in msg
    assert details["connected"] is True
    assert details["table_exists"] is True
    assert isinstance(details["latency_ms"], float)
    assert details["latency_ms"] >= 0.0


def test_postgres_full_security_event_insertion_and_jsonb_roundtrip(pg_store):
    """Verify complete security event payload roundtrips through PostgreSQL without truncation."""
    event_id = f"evt-full-{int(time.time() * 1000)}"
    event = SecurityEvent(
        event_id=event_id,
        timestamp="2026-10-31T01:45:00.123456+00:00",
        flow_id="flow-pcap-full-1",
        source_mode="PCAP",
        source_ip="10.200.1.55",
        dest_ip="192.168.10.10",
        source_port=49152,
        dest_port=443,
        protocol=6,
        hybrid_verdict="HYBRID",
        hybrid_risk_score=0.9250,
        severity="HIGH",
        source_escalated=True,
        features={
            "flow_duration_ms": 500.0,
            "flow_packets_per_s": 1200.0,
            "flow_bytes_per_s": 850000.0,
            "packet_length_mean": 708.3,
            "packet_length_std": 124.5,
            "syn_count": 50.0,
            "ack_count": 0.0,
            "rst_count": 0.0,
            "fin_count": 0.0,
            "syn_ack_ratio": 50.0,
        },
        detection={
            "model_name": "Random Forest (Sole Operational Detector)",
            "model_type": "rf",
            "attack_score": 0.9250,
            "prediction_label": "ATTACK",
            "attack_family": "DoS/DDoS",
            "attack_family_confidence": 0.94,
            "family_probabilities": {"BENIGN": 0.06, "DoS/DDoS": 0.94},
        },
        rule_matches=[
            {
                "rule_id": "RULE-SYN-FLOOD",
                "name": "TCP SYN Flood Detection",
                "severity": "HIGH",
                "description": "Unanswered SYN flood: 50 SYNs with 0 ACKs.",
            }
        ],
        source_status={"flow_count": 12, "threat_count": 8, "status": "ESCALATED"},
        explanation={
            "base_value": 0.5000,
            "top_attributions": {
                "syn_count": 0.2850,
                "packet_length_std": 0.1420,
                "flow_packets_per_s": -0.0520,
            },
        },
        response={
            "proposed_action": "ISOLATE",
            "enforced_action": "ISOLATE",
            "safety_override": False,
            "override_reason": "OK",
            "q_values": {"ALLOW": -95.2, "ALERT": -15.4, "RATE_LIMIT": -22.1, "ISOLATE": -8.5},
            "best_q_value": -8.5,
            "state_vector": [0.925, 0.15, 0.75, 0.667, 0.0, 0.738],
            "execution_report": {"execution_id": "exec-99", "final_lifecycle_state": "VERIFIED"},
        },
        metadata={"capture_interface": "eth0", "operator": "secops"},
    )

    # 1. Insert into PostgreSQL
    ok = pg_store.insert_event(event)
    assert ok is True

    # 2. Retrieve from PostgreSQL
    retrieved = pg_store.get_event_by_id(event_id)
    assert retrieved is not None
    assert retrieved.event_id == event.event_id
    assert retrieved.flow_id == event.flow_id
    assert retrieved.source_mode == "PCAP"
    assert retrieved.source_ip == "10.200.1.55"
    assert retrieved.dest_ip == "192.168.10.10"
    assert retrieved.protocol == 6
    assert retrieved.hybrid_verdict == "HYBRID"
    assert retrieved.hybrid_risk_score == pytest.approx(0.9250)
    assert retrieved.severity == "HIGH"
    assert retrieved.source_escalated is True

    # 3. Verify JSONB fields preserved exactly
    assert retrieved.features["syn_count"] == 50.0
    assert retrieved.features["flow_bytes_per_s"] == 850000.0
    assert retrieved.detection["attack_family"] == "DoS/DDoS"
    assert retrieved.rule_matches[0]["rule_id"] == "RULE-SYN-FLOOD"
    assert retrieved.explanation["top_attributions"]["syn_count"] == 0.2850
    assert retrieved.response["enforced_action"] == "ISOLATE"
    assert retrieved.response["q_values"]["ISOLATE"] == -8.5
    assert retrieved.metadata["capture_interface"] == "eth0"


def test_postgres_indexed_queries_and_filtering(pg_store):
    """Verify indexed queries filter accurately by source_ip, severity, verdict, and source_mode."""
    base_ts = time.time()
    batch_events = [
        SecurityEvent(
            event_id=f"evt-filter-1-{int(base_ts * 1000)}",
            source_ip="192.168.99.1",
            dest_ip="10.0.0.1",
            source_mode="PCAP",
            hybrid_verdict="HYBRID",
            severity="HIGH",
        ),
        SecurityEvent(
            event_id=f"evt-filter-2-{int(base_ts * 1000)}",
            source_ip="192.168.99.1",
            dest_ip="10.0.0.2",
            source_mode="SAMPLE",
            hybrid_verdict="RULE",
            severity="MEDIUM",
        ),
        SecurityEvent(
            event_id=f"evt-filter-3-{int(base_ts * 1000)}",
            source_ip="192.168.99.2",
            dest_ip="10.0.0.3",
            source_mode="PCAP",
            hybrid_verdict="BENIGN",
            severity="NONE",
        ),
    ]

    inserted, errs = pg_store.insert_events_batch(batch_events)
    assert inserted == 3
    assert errs == 0

    # 1. Filter by source_ip
    res_ip = pg_store.query_events(source_ip="192.168.99.1")
    assert len(res_ip) >= 2
    assert all(e.source_ip == "192.168.99.1" for e in res_ip)

    # 2. Filter by severity
    res_sev = pg_store.query_events(source_ip="192.168.99.1", severity="HIGH")
    assert len(res_sev) >= 1
    assert all(e.severity == "HIGH" for e in res_sev)

    # 3. Filter by hybrid_verdict
    res_verd = pg_store.query_events(source_ip="192.168.99.2", verdict="BENIGN")
    assert len(res_verd) >= 1
    assert all(e.hybrid_verdict == "BENIGN" for e in res_verd)

    # 4. Filter by source_mode
    res_mode = pg_store.query_events(source_mode="SAMPLE")
    assert len(res_mode) >= 1
    assert all(e.source_mode == "SAMPLE" for e in res_mode)


def test_postgres_duplicate_event_id_idempotence(pg_store):
    """Verify duplicate event_id insertion is safely ignored without raising errors."""
    dup_id = f"evt-dup-{int(time.time() * 1000)}"
    ev1 = SecurityEvent(event_id=dup_id, source_ip="10.10.10.10", severity="LOW")
    ev2 = SecurityEvent(event_id=dup_id, source_ip="10.10.10.10", severity="CRITICAL")

    # First insert
    ok1 = pg_store.insert_event(ev1)
    assert ok1 is True

    # Second insert with same event_id
    ok2 = pg_store.insert_event(ev2)
    assert ok2 is True  # ON CONFLICT DO NOTHING returns True safely

    # Verify original record retained
    stored = pg_store.get_event_by_id(dup_id)
    assert stored is not None
    assert stored.severity == "LOW"  # First record preserved


def test_postgres_event_manager_integration_and_restart_persistence(pg_config, tmp_path):
    """Verify EventManager persists events to PostgreSQL and retrieves them across application restart."""
    audit_file = tmp_path / "restart_audit.jsonl"
    unique_prefix = f"restart-{int(time.time())}"

    # 1. First Session: Instantiate EventManager and publish events
    mgr1 = EventManager(
        audit_log_path=audit_file,
        persist_to_disk=True,
        db_config=pg_config,
        enable_async_worker=True,
    )
    assert mgr1.storage_mode == "postgres"

    published_ids = []
    for i in range(3):
        eid = f"evt-{unique_prefix}-{i}"
        published_ids.append(eid)
        mgr1.publish(
            SecurityEvent(
                event_id=eid,
                source_ip=f"172.16.0.{i+10}",
                hybrid_verdict="HYBRID",
                severity="HIGH",
            )
        )

    # Allow async persistence worker to flush queue to DB
    mgr1.close(timeout=3.0)

    # 2. Simulate Application Restart: Instantiate new EventManager instance with empty ring buffer
    mgr2 = EventManager(
        audit_log_path=audit_file,
        persist_to_disk=True,
        db_config=pg_config,
        enable_async_worker=False,
    )
    assert mgr2.storage_mode == "postgres"
    # Ring buffer is currently empty (simulating process cold-start)
    assert len(mgr2._buffer) == 0

    # 3. Retrieve events: Query PostgreSQL for persisted historical events
    historical_events = mgr2.get_historical_events(limit=50)
    retrieved_ids = {e.event_id for e in historical_events}

    for eid in published_ids:
        assert eid in retrieved_ids, f"Event {eid} failed to survive application restart!"

    # 4. Also verify get_recent_events auto-retrieves from DB when buffer is empty
    recent_events = mgr2.get_recent_events(limit=50)
    recent_ids = {e.event_id for e in recent_events}
    for eid in published_ids:
        assert eid in recent_ids


def test_postgres_database_outage_resilience():
    """Verify store and EventManager handle database outage gracefully without crashing."""
    # Point to an unreachable closed port
    bad_cfg = DatabaseConfig(
        host="localhost",
        port=5499,  # Non-existent port
        database="xrlids",
        user="xrlids_user",
        password="",
        connect_timeout=1,
        storage_mode="auto",
    )
    bad_store = PostgresEventStore(bad_cfg)

    # 1. Health check returns False without raising
    is_healthy, msg, details = bad_store.health_check()
    assert is_healthy is False
    assert details["connected"] is False

    # 2. Insert event returns False without unhandled crash
    ev = SecurityEvent(event_id="evt-outage-1")
    ok = bad_store.insert_event(ev)
    assert ok is False

    # 3. EventManager with auto mode falls back to memory mode
    mgr = EventManager(db_config=bad_cfg, persist_to_disk=False)
    assert mgr.storage_mode == "memory"
    # Pipeline publish still succeeds into ring buffer
    mgr.publish(ev)
    assert len(mgr._buffer) == 1
    assert mgr.total_events == 1
