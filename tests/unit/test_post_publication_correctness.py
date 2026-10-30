"""Unit tests verifying post-publication correctness fixes and invariants."""

from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pytest

from xrlids.events.manager import EventManager
from xrlids.events.schema import SecurityEvent
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline, PipelineResult
from xrlids.response.state import StateBuilder
from xrlids.response.service import DQNResponseService
from xrlids.response.types import Action
from xrlids.response.executor import ResponseExecutor
from xrlids.response.transaction import SimulatedActuatorBackend
from xrlids.capture.live_manager import LiveCaptureManager
from dashboard.session_init import ensure_session_state


def test_no_automatic_traffic_seeding_on_startup():
    """Verify that dashboard initialization starts with 0 events and an idle live daemon."""
    event_mgr, pipeline, live_mgr = ensure_session_state()

    assert len(event_mgr.get_all_events()) == 0, "Initial event manager must be completely empty"
    assert live_mgr.status == "IDLE", "Live capture manager must be IDLE on startup"
    assert not live_mgr.is_running, "Live capture must not run automatically on startup"
    assert len(live_mgr.completed_flows) == 0, "No completed flows should be pre-seeded"


def test_source_mode_provenance_pipeline_and_events():
    """Verify that source_mode is faithfully preserved in PipelineResult and SecurityEvent."""
    event_mgr = EventManager()
    pipeline = ActiveInferencePipeline(event_manager=event_mgr, explain_all=True)

    r10_benign = {
        "flow_duration_ms": 1000.0,
        "flow_packets_per_s": 50.0,
        "flow_bytes_per_s": 10000.0,
        "packet_length_mean": 200.0,
        "packet_length_std": 50.0,
        "syn_count": 2.0,
        "ack_count": 4.0,
        "rst_count": 0.0,
        "fin_count": 1.0,
        "syn_ack_ratio": 0.5,
    }

    # Test PCAP mode
    res_pcap = pipeline.process_flow(
        r10_benign,
        source_ip="192.168.1.10",
        dest_ip="192.168.1.1",
        flow_id="test-pcap-001",
        source_mode="PCAP",
    )
    assert res_pcap.source_mode == "PCAP"
    assert res_pcap.security_event.source_mode == "PCAP"

    # Test SAMPLE mode
    res_sample = pipeline.process_flow(
        r10_benign,
        source_ip="192.168.1.20",
        dest_ip="192.168.1.1",
        flow_id="test-sample-001",
        source_mode="SAMPLE",
    )
    assert res_sample.source_mode == "SAMPLE"
    assert res_sample.security_event.source_mode == "SAMPLE"

    # Test LIVE mode
    res_live = pipeline.process_flow(
        r10_benign,
        source_ip="192.168.1.30",
        dest_ip="192.168.1.1",
        flow_id="test-live-001",
        source_mode="LIVE",
    )
    assert res_live.source_mode == "LIVE"
    assert res_live.security_event.source_mode == "LIVE"

    # Verify filtering in event manager
    pcap_events = [e for e in event_mgr.get_all_events() if e.source_mode == "PCAP"]
    sample_events = [e for e in event_mgr.get_all_events() if e.source_mode == "SAMPLE"]
    live_events = [e for e in event_mgr.get_all_events() if e.source_mode == "LIVE"]

    assert len(pcap_events) == 1
    assert len(sample_events) == 1
    assert len(live_events) == 1


def test_dqn_state_contract_6d_exact_semantics():
    """Verify that StateBuilder strictly produces 6 causal dimensions and service infers correctly."""
    builder = StateBuilder(cooldown_max_steps=30)
    service = DQNResponseService(action_dim=4)

    # Step 1: Benign flow
    s1 = builder.build_state(attack_score=0.10, flow_bytes_per_s=500.0)
    assert s1.shape == (6,)
    assert np.isclose(s1[0], 0.10)  # S_t
    assert np.isclose(s1[1], 0.0)   # Delta S_t (first step)
    assert np.isclose(s1[2], 0.0)   # Alert density (0.10 < 0.50)
    assert np.isclose(s1[3], 0.0)   # Previous action (ALLOW = 0)
    assert np.isclose(s1[4], 0.0)   # Cooldown fraction (0)
    assert 0.0 <= s1[5] <= 1.0      # Normalized log volumetric scale

    q_vals1 = service.get_q_values(s1)
    assert q_vals1.shape == (4,)

    # Step 2: Advance history and check state update
    builder.update_history(attack_score=0.10, enforced_action=Action.RATE_LIMIT, cooldown_remaining=15)
    s2 = builder.build_state(attack_score=0.90, flow_bytes_per_s=1_000_000.0)
    assert np.isclose(s2[0], 0.90)                    # S_t
    assert np.isclose(s2[1], 0.80)                    # Delta S_t (0.90 - 0.10)
    assert s2[2] > 0.0                               # Alert density increased
    assert np.isclose(s2[3], Action.RATE_LIMIT.value / 3.0)  # 2 / 3 = 0.6667
    assert np.isclose(s2[4], 15.0 / 30.0)             # 0.50 cooldown fraction
    assert s2[5] > s1[5]                             # higher volume

    q_vals2 = service.get_q_values(s2)
    assert q_vals2.shape == (4,)


def test_live_capture_permission_failure(monkeypatch):
    """Verify unprivileged capture attempt transitions cleanly to BLOCKED without thread leaks."""
    mgr = LiveCaptureManager()

    # Simulate unprivileged state
    monkeypatch.setattr(mgr, "check_permissions", lambda: (False, "Insufficient privileges: CAP_NET_RAW missing"))

    success, msg = mgr.start(interface="lo")
    assert not success, "start must return False when unprivileged"
    assert mgr.status == "BLOCKED", f"Status must be BLOCKED, got {mgr.status}"
    assert "CAP_NET_RAW missing" in msg
    assert not mgr.is_running, "Manager must not be marked as running"
    assert mgr.service is None, "Capture service thread must not be initialized"


def test_one_event_linked_response_lifecycle():
    """Verify that a single processed event records all 13 linked attributes."""
    event_mgr = EventManager()
    pipeline = ActiveInferencePipeline(event_manager=event_mgr, explain_all=True)

    r10_syn_flood = {
        "flow_duration_ms": 500.0,
        "flow_packets_per_s": 5000.0,
        "flow_bytes_per_s": 300000.0,
        "packet_length_mean": 60.0,
        "packet_length_std": 0.0,
        "syn_count": 100.0,
        "ack_count": 0.0,
        "rst_count": 0.0,
        "fin_count": 0.0,
        "syn_ack_ratio": 100.0,
    }

    result = pipeline.process_flow(
        r10_syn_flood,
        source_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        flow_id="evt-verification-001",
        source_mode="PCAP",
    )

    event = result.security_event
    assert event is not None, "Pipeline must generate an event for high attack flow"

    # Verify all 13 required attributes
    # 1. Event ID
    assert isinstance(event.event_id, str) and len(event.event_id) > 0
    # 2. Flow ID
    assert event.flow_id == "evt-verification-001"
    # 3. Source mode
    assert event.source_mode == "PCAP"
    # 4. RF score
    assert isinstance(event.detection["attack_score"], float)
    assert 0.0 <= event.detection["attack_score"] <= 1.0
    # 5. Rule matches
    assert isinstance(event.rule_matches, list)
    # 6. TreeSHAP output
    assert isinstance(event.explanation, dict)
    assert "feature_attributions" in event.explanation or "top_features" in event.explanation
    # 7. DQN state (6D)
    assert isinstance(event.response["state_vector"], (list, np.ndarray))
    assert len(event.response["state_vector"]) == 6
    # 8. Q-values
    assert isinstance(event.response["q_values"], (dict, list, np.ndarray))
    assert len(event.response["q_values"]) == 4
    # 9. Proposed action
    assert event.response["proposed_action"] in ("ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE")
    # 10. Safety-enforced action
    assert event.response["enforced_action"] in ("ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE")
    # 11. Override reason
    assert "override_reason" in event.response
    # 12. Lifecycle state
    assert event.response["execution_report"]["final_lifecycle_state"] in ("EXECUTED", "VERIFIED", "AUTHORIZED", "REJECTED")
    # 13. Advisory / dry-run status
    assert event.response["execution_report"]["is_advisory"] is True


def test_zero_kernel_mutations_advisory_mode():
    """Verify that dry-run/advisory execution performs 0 kernel iptables mutations."""
    backend = SimulatedActuatorBackend()
    executor = ResponseExecutor(actuator_backend=backend, advisory_mode=True)

    assert backend.zero_network_mutation is True
    assert backend.network_mutations_count == 0

    report = executor.execute_action(
        proposed_action=Action.ISOLATE,
        target_host="192.168.1.200",
        state_before=np.zeros(6, dtype=np.float32),
        metadata={"reason": "SYN Flood Detected"},
    )

    assert report.authorized_action == Action.ISOLATE
    assert report.is_advisory is True
    assert backend.network_mutations_count == 0, "No kernel network mutations allowed in advisory/simulated mode"
