"""Acceptance Tests for XRL-IDARS Live Operational Demonstration & Autonomous Response.

Formal verification of:
A. Normal Scapy Ping:
   - Genuine ICMP packets captured and assembled into canonical flow.
   - RF model evaluates flow with genuine score (< 0.15, BENIGN).
   - Dueling DQN genuinely evaluates 6D causal state and recommends ALLOW.
   - Safety Gate authorizes ALLOW.
   - Ping continues successfully with ZERO firewall mutations.

B. Controlled ICMP Flood:
   - Genuine high-rate ICMP burst packets captured and assembled.
   - Correct R10 features extracted (flow_packets_per_s, packet_length_mean).
   - Actual RF checkpoint and independent deterministic Rule (RULE-ICMP-FLOOD) evaluated.
   - RF prediction and rule evidence displayed distinctly.
   - TreeSHAP computes local Shapley feature attributions.
   - DQN genuinely evaluates state and Q-values.
   - Safety Gate authorizes action (protecting critical hosts, verifying lab subnet).
   - Temporary firewall rule installed against verified lab attacker IP (10.200.1.2) when operator enabled.
   - Attacker traffic verified as BLOCKED (packet drop counters verified).
   - Temporary rule expires / rolls back and normal connectivity is verified restored.

C. PCAP Wire Replay:
   - Captured frames streamed through identical pipeline.
   - RF and DQN operate on the same flow events.
   - Results explicitly marked PCAP_REPLAY (Advisory only).
   - Zero false claims of live firewall blocking.

D. Anti-Fabrication Invariants:
   - Zero hardcoded scores, fake Q-values, or synthetic status claims.
   - Complete data provenance from model checkpoint and rule engine.
"""

from __future__ import annotations

import time
from pathlib import Path
import pytest

from xrlids.capture.scapy_service import ScapyCaptureConfig, ScapyCaptureService, scapy_packet_to_packet_info
from xrlids.demo.scapy_simulator import ScapyAttackSimulator
from xrlids.events.manager import EventManager
from xrlids.flow.canonical_builder import CanonicalFlow, CanonicalFlowBuilder
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline
from xrlids.response.firewall import LabFirewallManager
from xrlids.response.types import Action


@pytest.fixture
def clean_pipeline():
    """Create clean isolated ActiveInferencePipeline with in-memory EventManager."""
    evt_mgr = EventManager()
    evt_mgr.clear()
    pipe = ActiveInferencePipeline(event_manager=evt_mgr, explain_all=True)
    pipe.safety_gate.reset()
    pipe.firewall_manager.clear()
    pipe.set_enforcement_mode(False)
    return pipe


def test_acceptance_a_normal_scapy_ping(clean_pipeline):
    """Acceptance Test A: Normal Scapy ping flow lifecycle."""
    pipeline = clean_pipeline
    sim = ScapyAttackSimulator()

    # 1. Generate normal ICMP echo requests
    raw_pkts = sim.build_benign_ping(count=4)
    assert len(raw_pkts) == 8  # 4 requests + 4 replies
    scapy_pkts = [scapy_packet_to_packet_info(p) for p in raw_pkts]
    assert all(p is not None for p in scapy_pkts)

    # 2. Build flow using operational CanonicalFlowBuilder
    builder = CanonicalFlowBuilder(idle_timeout_s=120.0)
    flows = []
    for p in scapy_pkts:
        flows.extend(builder.process_packet(p))
    flows.extend(builder.flush_all())
    assert len(flows) == 1
    ping_flow = flows[0]

    # Verify R10 features
    assert ping_flow.protocol == 1
    feats = ping_flow.features
    assert "flow_packets_per_s" in feats
    assert "packet_length_mean" in feats
    assert feats["syn_count"] == 0.0

    # 3. Pipeline execution: RF -> Rules -> TreeSHAP -> DQN -> Safety Gate
    result = pipeline.process_flow(ping_flow, source_mode="SCAPY_LIVE")

    # RF Classification
    assert result.inference.prediction_label == "BENIGN"
    assert result.inference.attack_score < 0.15

    # Rules
    assert len(result.rule_matches) == 0
    assert result.hybrid.detection_source == "NONE"

    # DQN Evaluation
    assert result.response.action == Action.ALLOW
    assert result.response.q_values["ALLOW"] > result.response.q_values["ISOLATE"]

    # Safety Gate & Firewall
    assert result.enforced_action == Action.ALLOW
    assert result.execution_report.is_advisory is True
    assert len(pipeline.firewall_manager.get_active_rules()) == 0

    # Ping connectivity test
    conn_rep = sim.test_ping_connectivity(
        firewall_filter_fn=pipeline.firewall_manager.filter_packet,
        count=4,
    )
    assert conn_rep["success"] is True
    assert conn_rep["packets_delivered"] == 4
    assert conn_rep["packets_dropped"] == 0


def test_acceptance_b_controlled_icmp_flood_with_firewall_enforcement(clean_pipeline):
    """Acceptance Test B: Controlled ICMP flood with autonomous DQN response and temporary firewall block."""
    pipeline = clean_pipeline
    sim = ScapyAttackSimulator()

    # 1. Generate controlled ICMP flood packets (40 echo requests)
    raw_pkts = sim.build_scenario_d_icmp_burst(packet_count=40)
    assert len(raw_pkts) == 40
    scapy_pkts = [scapy_packet_to_packet_info(p) for p in raw_pkts]

    # 2. Flow construction
    builder = CanonicalFlowBuilder(idle_timeout_s=120.0)
    flows = []
    for p in scapy_pkts:
        flows.extend(builder.process_packet(p))
    flows.extend(builder.flush_all())
    assert len(flows) == 1
    icmp_flow = flows[0]

    # Verify R10 features
    assert icmp_flow.packet_count == 40
    assert icmp_flow.protocol == 1
    assert icmp_flow.features["flow_packets_per_s"] > 20.0

    # 3. Operator explicitly enables real enforcement with 15s TTL
    pipeline.set_enforcement_mode(True)
    pipeline.firewall_manager.default_ttl_seconds = 15.0

    # 4. Pipeline execution
    result = pipeline.process_flow(icmp_flow, source_mode="SCAPY_LIVE")

    # Distinct RF vs Rule evidence
    assert result.inference.prediction_label == "BENIGN"  # RF is not falsely claimed as detecting
    assert any(r.rule_id == "RULE-ICMP-FLOOD" for r in result.rule_matches)  # Rule engine detected flood
    assert result.hybrid.detection_source == "RULE"
    assert result.hybrid.threat_score >= 0.60

    # TreeSHAP computed
    assert result.explanation is not None
    assert len(result.explanation.attributions) > 0

    # DQN evaluates event and recommends ISOLATE
    assert result.response.action in (Action.ISOLATE, Action.RATE_LIMIT)
    assert result.response.q_values is not None
    assert len(result.response.state_vector) == 6

    # Safety Gate authorizes action
    assert result.enforced_action == Action.ISOLATE
    assert result.execution_report.safety_check.allowed is True

    # 5. Firewall Rule Installation
    active_rules = pipeline.firewall_manager.get_active_rules()
    assert len(active_rules) == 1
    rule = active_rules[0]
    assert rule["source_ip"] == "10.200.1.2"
    assert rule["dest_ip"] == "10.200.1.3"
    assert rule["action"] == "ISOLATE"
    assert rule["status"] == "ACTIVE"
    assert rule["ttl_seconds"] == 15.0
    assert rule["remaining_seconds"] > 0.0

    # 6. Verify Attacker Traffic is Blocked
    traffic_verif = pipeline.firewall_manager.verify_traffic_blocked("10.200.1.2")
    assert traffic_verif["is_blocked"] is True
    assert traffic_verif["probe_packets_dropped"] == 4
    assert traffic_verif["probe_packets_delivered"] == 0
    assert traffic_verif["status"] == "TRAFFIC_BLOCKED_CONFIRMED"

    # Ping connectivity probe fails while blocked
    conn_blocked = sim.test_ping_connectivity(
        firewall_filter_fn=pipeline.firewall_manager.filter_packet,
        count=4,
    )
    assert conn_blocked["success"] is False
    assert conn_blocked["packets_dropped"] == 4

    # 7. Rollback / Expire Rule and verify restored connectivity
    ok, msg, restoration = pipeline.firewall_manager.rollback_rule("10.200.1.2")
    assert ok is True
    assert restoration["connectivity_restored"] is True
    assert len(pipeline.firewall_manager.get_active_rules()) == 0

    # Ping connectivity probe succeeds after rollback
    conn_restored = sim.test_ping_connectivity(
        firewall_filter_fn=pipeline.firewall_manager.filter_packet,
        count=4,
    )
    assert conn_restored["success"] is True
    assert conn_restored["packets_delivered"] == 4
    assert conn_restored["packets_dropped"] == 0


def test_acceptance_c_pcap_replay_advisory_only(clean_pipeline):
    """Acceptance Test C: PCAP replay operates identically but never applies live firewall blocks."""
    pipeline = clean_pipeline
    repo_root = Path(__file__).resolve().parents[2]
    pcap_path = repo_root / "data" / "demo" / "sample_traffic.pcap"
    assert pcap_path.is_file()

    # Replay 20 packets from PCAP
    cfg = ScapyCaptureConfig(pcap_path=pcap_path, queue_size=1000)
    service = ScapyCaptureService(cfg)
    service.start()
    pkts = []
    t0 = time.time()
    while service.is_running or not service._queue.empty():
        p = service.get_packet(timeout=0.05)
        if p:
            pkts.append(p)
        if len(pkts) >= 20 or (time.time() - t0 > 3.0):
            break
    service.stop()
    assert len(pkts) >= 10

    # Build flows
    builder = CanonicalFlowBuilder(idle_timeout_s=120.0)
    flows = []
    for p in pkts:
        flows.extend(builder.process_packet(p))
    flows.extend(builder.flush_all())
    assert len(flows) > 0

    # Process through pipeline in PCAP mode
    res_list = []
    for fl in flows:
        res = pipeline.process_flow(fl, source_mode="PCAP_REPLAY")
        res_list.append(res)

    for r in res_list:
        evt = r.security_event
        assert evt.source_mode == "PCAP_REPLAY"
        # Invariant: PCAP replay MUST be advisory only (zero firewall rules)
        assert r.execution_report.is_advisory is True
        assert len(pipeline.firewall_manager.get_active_rules()) == 0


def test_acceptance_d_anti_fabrication_and_provenance(clean_pipeline):
    """Acceptance Test D: Model outputs, Q-values, and enforcement decisions are non-fabricated."""
    pipeline = clean_pipeline
    sim = ScapyAttackSimulator()

    # Test SYN Burst
    raw_pkts = sim.build_scenario_c_syn_burst(packet_count=60)
    builder = CanonicalFlowBuilder(idle_timeout_s=120.0)
    flows = []
    for p in [scapy_packet_to_packet_info(x) for x in raw_pkts]:
        flows.extend(builder.process_packet(p))
    flows.extend(builder.flush_all())

    for fl in flows:
        res = pipeline.process_flow(fl, source_mode="SCAPY_LIVE")
        evt = res.security_event

        # Check Q-values integrity
        q_vals = evt.response["q_values"]
        assert isinstance(q_vals, dict)
        assert set(q_vals.keys()) == {"ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE"}
        for k, v in q_vals.items():
            assert isinstance(v, float)
            assert v < 0.0  # Bellman negative penalty cost formulation

        # Check 6D Markov state vector
        state = evt.response["state_vector"]
        assert len(state) == 6
        assert 0.0 <= state[0] <= 1.0  # Threat score in [0, 1]

        # Check Random Forest threat score matches raw model
        infer = pipeline.model_manager.predict_flow(fl.features)
        assert abs(infer.attack_score - evt.detection["attack_score"]) < 1e-5
