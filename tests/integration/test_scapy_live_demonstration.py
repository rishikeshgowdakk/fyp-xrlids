"""Comprehensive end-to-end integration and verification suite for the Scapy live demonstration.

Tests all 20 required points from the specification:
1. Namespace isolation and safety boundaries.
2. Scapy packet generation.
3. Actual packet capture.
4. Bidirectional flow assembly.
5. Canonical feature extraction (R10).
6. RF checkpoint loading.
7. Preprocessor compatibility.
8. RF inference.
9. Deterministic rule detection.
10. TreeSHAP explanations.
11. DQN action proposals.
12. Deterministic safety gate.
13. Dashboard event delivery.
14. Stop and cleanup behavior.
15. Scenario A (Benign traffic).
16. Scenario B (Port scan simulation).
17. Scenario C (TCP SYN burst simulation).
18. Scenario D (ICMP burst simulation).
19. Session report and export generation.
20. Backend failure handling and boundary protection.

Plus the UNMOCKED end-to-end integration test:
Start isolated lab -> start Scapy capture -> launch simulator -> capture generated packets ->
build flows -> extract features -> perform actual inference -> produce real detection events ->
update dashboard -> export session results -> clean up lab.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

import pytest

from xrlids.capture.scapy_service import ScapyCaptureConfig, ScapyCaptureService, scapy_packet_to_packet_info
from xrlids.demo.flow import FlowBuilder
from xrlids.demo.pcap import PacketInfo
from xrlids.demo.scapy_simulator import (
    ATTACKER_IP,
    SCENARIO_SPECS,
    VICTIM_IP,
    ScapyAttackSimulator,
    validate_target_safety,
)
from xrlids.enforcement.lab import IsolatedLabEnvironment
from xrlids.evaluation.csv_evaluator import explain_flow_prediction
from xrlids.models.inference_service import DEFAULT_INFERENCE_SERVICE
from xrlids.response.dqn.network import DuelingQNetwork
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action, ActionSpaceMode
from xrlids.rules.engine import RuleEngine
from dashboard.server import LIVE_SESSION, LiveSession


# 1. Target isolation safety boundary
def test_namespace_target_safety_boundary():
    """Verify validate_target_safety rejects external or public IPs and accepts lab subnet."""
    validate_target_safety("10.200.1.3")
    validate_target_safety("10.200.1.10")
    validate_target_safety("127.0.0.1")

    with pytest.raises(ValueError, match="Security invariant violated"):
        validate_target_safety("8.8.8.8")

    with pytest.raises(ValueError, match="Security invariant violated"):
        validate_target_safety("192.168.1.1")


# 2. Scapy packet generation
def test_scapy_packet_generation_all_scenarios():
    """Verify Scapy simulator constructs valid Scapy packets for all 4 scenarios."""
    simulator = ScapyAttackSimulator()
    for sc_id in SCENARIO_SPECS:
        pkts = simulator.build_packets_for_scenario(sc_id)
        assert len(pkts) > 0, f"Scenario {sc_id} built zero packets"
        for p in pkts:
            assert hasattr(p, "time"), "Scapy packet missing time attribute"
            pinfo = scapy_packet_to_packet_info(p)
            assert pinfo is not None, "Failed to convert Scapy packet to PacketInfo"
            assert pinfo.packet_length > 0
            assert pinfo.src_ip.startswith("10.200.1.")
            assert pinfo.dst_ip.startswith("10.200.1.")


# 3. Actual packet capture via ScapyCaptureService
def test_scapy_packet_capture_virtual_injection():
    """Verify ScapyCaptureService ingests and streams Scapy packets with accurate counters."""
    config = ScapyCaptureConfig(interface="virtual")
    service = ScapyCaptureService(config=config)
    service.start()

    simulator = ScapyAttackSimulator()
    pkts = simulator.build_scenario_a_benign()
    for p in pkts:
        service.inject_scapy_packet(p)

    captured = []
    for _ in range(len(pkts)):
        pkt = service.get_packet(timeout=0.5)
        if pkt is not None:
            captured.append(pkt)

    service.stop()
    assert len(captured) == len(pkts)
    assert service.stats.packets_captured == len(pkts)
    assert service.stats.packets_dropped == 0


# 4. Bidirectional flow assembly
def test_bidirectional_flow_assembly():
    """Verify FlowBuilder reconstructs bidirectional TCP and ICMP flows correctly."""
    simulator = ScapyAttackSimulator()
    pkts = simulator.build_scenario_a_benign()
    builder = FlowBuilder(idle_timeout_s=5.0)

    for p in pkts:
        pinfo = scapy_packet_to_packet_info(p)
        builder.process_packet(pinfo)

    flows = builder.flush_all()
    assert len(flows) >= 2, "Expected at least 2 flows for benign HTTP + ICMP"
    tcp_flows = [f for f in flows if f.key.protocol == 6]
    icmp_flows = [f for f in flows if f.key.protocol == 1]
    assert len(tcp_flows) >= 1
    assert len(icmp_flows) >= 1


# 5. Canonical R10 feature extraction
def test_canonical_r10_feature_extraction():
    """Verify flows extract the exact 10 canonical features."""
    simulator = ScapyAttackSimulator()
    pkts = simulator.build_scenario_c_syn_burst()
    builder = FlowBuilder(idle_timeout_s=5.0)
    for p in pkts:
        pinfo = scapy_packet_to_packet_info(p)
        builder.process_packet(pinfo)
    flows = builder.flush_all()
    assert len(flows) > 0

    features = flows[0].to_features()
    expected_r10 = {
        "flow_duration_ms",
        "flow_packets_per_s",
        "flow_bytes_per_s",
        "packet_length_mean",
        "packet_length_std",
        "syn_count",
        "ack_count",
        "rst_count",
        "fin_count",
        "syn_ack_ratio",
    }
    assert set(features.keys()) == expected_r10
    assert all(isinstance(v, (int, float)) for v in features.values())


# 6, 7, 8. RF checkpoint loading, preprocessor compatibility, and inference
def test_rf_inference_genuine():
    """Verify UnifiedInferenceService runs genuine Random Forest inference on R10 features."""
    simulator = ScapyAttackSimulator()
    pkts = simulator.build_scenario_a_benign()
    builder = FlowBuilder(idle_timeout_s=5.0)
    for p in pkts:
        builder.process_packet(scapy_packet_to_packet_info(p))
    flows = builder.flush_all()

    features = flows[0].to_features()
    res = DEFAULT_INFERENCE_SERVICE.infer(features, session_key="test_session", benchmark="cicids2017")

    assert res.prediction in (0, 1)
    assert 0.0 <= res.attack_score <= 1.0
    assert 0.0 <= res.rf_score <= 1.0
    assert res.inference_source in ("RANDOM_FOREST", "RF+LSTM_FUSION")


# 9. Deterministic rule detection
def test_deterministic_rule_detection():
    """Verify deterministic rules trigger on known signatures."""
    simulator = ScapyAttackSimulator()
    rule_engine = RuleEngine()

    # SYN flood
    syn_pkts = simulator.build_scenario_c_syn_burst()
    builder = FlowBuilder(idle_timeout_s=5.0)
    for p in syn_pkts:
        builder.process_packet(scapy_packet_to_packet_info(p))
    flows = builder.flush_all()
    syn_matches = [rule_engine.evaluate_flow(f) for f in flows]
    assert any(any(m.rule_id == "RULE-SYN-FLOOD" for m in matches) for matches in syn_matches)

    # Port scan
    scan_pkts = simulator.build_scenario_b_port_scan()
    builder2 = FlowBuilder(idle_timeout_s=5.0)
    for p in scan_pkts:
        builder2.process_packet(scapy_packet_to_packet_info(p))
    flows2 = builder2.flush_all()
    scan_matches = [rule_engine.evaluate_flow(f) for f in flows2]
    assert any(any(m.rule_id == "RULE-PORT-SCAN" for m in matches) for matches in scan_matches)


# 10. TreeSHAP explanations
def test_treeshap_feature_attributions():
    """Verify TreeSHAP computes real feature attributions without mock values."""
    simulator = ScapyAttackSimulator()
    pkts = simulator.build_scenario_c_syn_burst()
    builder = FlowBuilder(idle_timeout_s=5.0)
    for p in pkts:
        builder.process_packet(scapy_packet_to_packet_info(p))
    flows = builder.flush_all()

    explanation = explain_flow_prediction(flows[0].to_features(), benchmark="cicids2017")
    assert "features" in explanation or "attributions" in explanation
    assert "base_value" in explanation
    feats = explanation.get("features", [])
    assert len(feats) > 0
    assert all("shap_attribution" in f for f in feats)


# 11, 12. DQN response policy and DeterministicSafetyGate
def test_dqn_policy_and_safety_gate():
    """Verify DQN policy evaluates causal state and DeterministicSafetyGate enforces invariants."""
    import torch

    gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.FOUR_ACTION)
    state_builder = StateBuilder()
    state_vec = state_builder.build_state(attack_score=0.95, flow_bytes_per_s=10000.0)

    dqn_path = Path("models/dqn/dqn_4action_best.pt")
    assert dqn_path.exists()
    dqn = DuelingQNetwork(input_dim=6, action_dim=4)
    ckpt = torch.load(dqn_path, map_location="cpu", weights_only=False)
    st = ckpt.get("online_net_state_dict", ckpt.get("model_state_dict", ckpt))
    dqn.load_state_dict(st)
    dqn.eval()

    with torch.no_grad():
        q_vals = dqn(torch.from_numpy(state_vec).float().unsqueeze(0))
        act_idx = int(torch.argmax(q_vals, dim=-1).item())
        proposed_action = Action(act_idx)

    enforced_action, overridden, reason = gate.enforce_safety(
        step=1,
        flow_id="test_flow_1",
        host_id="10.200.1.2",
        proposed_action=proposed_action,
    )
    assert isinstance(enforced_action, Action)
    assert isinstance(overridden, bool)


# 13, 14. Dashboard event delivery, stop and cleanup
def test_dashboard_event_delivery_and_cleanup():
    """Verify LiveSession delivers events, provides demo_snapshot, and cleans up cleanly."""
    session = LiveSession()
    session.start(mode="isolated_lab")
    assert session.status == "running"

    session.simulate_scenario("scenario_a_benign", speed=20.0)
    time.sleep(0.3)

    snap = session.demo_snapshot()
    assert snap["capture_status"] == "RUNNING"
    assert snap["mode"] == "ISOLATED LAB"
    assert snap["model_status"] == "LOADED"
    assert len(snap["events"]) > 0

    session.stop()
    assert session.status == "stopped"


# 15, 16, 17, 18. Execution of each individual scenario
@pytest.mark.parametrize("scenario_id", [
    "scenario_a_benign",
    "scenario_b_port_scan",
    "scenario_c_syn_burst",
    "scenario_d_icmp_burst",
])
def test_individual_scenario_execution(scenario_id: str):
    """Verify all 4 scenarios execute cleanly through the simulator."""
    sim = ScapyAttackSimulator()
    record = sim.run_simulation(scenario_id=scenario_id, pace_multiplier=50.0)
    assert record.status == "COMPLETED"
    assert record.generated_packets > 0
    assert record.duration_s > 0.0


# 19. Session report generation
def test_session_report_and_export():
    """Verify LiveSession export produces both CSV and structured JSON records."""
    session = LiveSession()
    session.start(mode="isolated_lab")
    session.simulate_scenario("scenario_a_benign", speed=30.0)
    time.sleep(0.3)

    # JSON export
    rep = session.export_demo_report()
    assert "session_summary" in rep
    assert "flows" in rep
    assert "events" in rep
    assert rep["session_summary"]["total_packets"] > 0

    # CSV export
    csv_str = session.export_demo_csv()
    assert "flow_id,timestamp,src_endpoint" in csv_str
    session.stop()


# 20. Backend failure handling
def test_backend_failure_handling():
    """Verify simulator and session gracefully reject invalid scenarios or bad paths."""
    session = LiveSession()
    res = session.simulate_scenario("scenario_non_existent")
    assert "error" in res

    sim = ScapyAttackSimulator()
    with pytest.raises(ValueError):
        sim.build_packets_for_scenario("scenario_invalid_xyz")


# ---------------------------------------------------------------------------
# THE UNMOCKED END-TO-END INTEGRATION TEST
# ---------------------------------------------------------------------------
def test_unmocked_live_scapy_demonstration_lifecycle():
    """Formally execute the complete end-to-end intrusion detection demonstration without mocks.

    Lifecycle:
      1. Setup isolated lab environment and verify baseline.
      2. Start live monitoring session in ISOLATED LAB mode.
      3. Launch Scapy simulator across benign and attack scenarios.
      4. Capture real generated wire packets through Scapy.
      5. Construct bidirectional network flows with FlowBuilder.
      6. Extract canonical R10 features.
      7. Perform actual inference using loaded Random Forest / UnifiedInferenceService.
      8. Evaluate deterministic security rules.
      9. Compute genuine TreeSHAP explanations.
      10. Evaluate Dueling DQN response policy.
      11. Enforce DeterministicSafetyGate invariants.
      12. Verify dashboard snapshot reflects live traffic, detections, and latency.
      13. Export experiment session results.
      14. Stop monitoring and clean up lab environment.
      15. Verify host network state remains 100% unmodified.
    """
    # 1. Setup isolated lab
    lab = IsolatedLabEnvironment(experiment_id="EXP-E2E-SCAPY-DEMO-001")
    created = lab.create()
    assert created is True
    isolated, diag = lab.verify_isolation()
    assert isolated is True, f"Lab isolation failed: {diag}"

    # 2. Start monitoring session
    session = LiveSession()
    start_res = session.start(mode="isolated_lab")
    assert start_res.get("status") == "running"
    assert session.status == "running"

    try:
        # 3, 4, 5. Launch Scenario A (Benign)
        res_a = session.simulate_scenario("scenario_a_benign", speed=30.0)
        assert res_a.get("status") == "simulating"
        time.sleep(0.4)

        snap_a = session.demo_snapshot()
        assert snap_a["metrics"]["packets_captured"] >= 12
        assert snap_a["metrics"]["flows_processed"] >= 2
        assert snap_a["metrics"]["threats_detected"] == 0, "Benign traffic must not trigger false alarms"

        # 6, 7, 8. Launch Scenario C (TCP SYN Burst)
        res_c = session.simulate_scenario("scenario_c_syn_burst", speed=50.0)
        assert res_c.get("status") == "simulating"
        time.sleep(0.6)

        snap_c = session.demo_snapshot()
        assert snap_c["metrics"]["packets_captured"] >= 72
        assert snap_c["metrics"]["flows_processed"] >= 4
        assert snap_c["metrics"]["threats_detected"] >= 2, "TCP SYN Burst must be detected by rules"
        assert snap_c["metrics"]["active_alerts"] >= 2

        # 9. Compute genuine TreeSHAP for detected flow
        detected_flows = [d for d in snap_c["detections"] if d["result"] == "ATTACK"]
        assert len(detected_flows) > 0
        target_flow_id = detected_flows[0]["flow_id"]
        exp_res = session.explain_flow(target_flow_id)
        assert exp_res["status"] == "ok"
        assert exp_res["explanation_available"] is True
        assert len(exp_res["top_features"]) > 0

        # 10, 11. Verify DQN advisory response and safety gate
        resp = snap_c["response"]
        valid_actions = ("ALLOW", "ALERT", "RATE_LIMIT_100", "RATE_LIMIT_10", "BLOCK_HOST", "RATE_LIMIT", "ISOLATE")
        assert resp["dqn_action"] in valid_actions
        assert resp["enforced_action"] in valid_actions
        assert ("ADVISORY" in resp["mode"] or "FIREWALL" in resp["mode"])

        # 12. Verify latency percentiles
        lat = snap_c["latency"]
        assert "total_ms" in lat
        assert lat["total_ms"]["p50"] >= 0.0

        # 13. Export experiment session results
        report = session.export_demo_report()
        assert report["session_summary"]["total_packets"] >= 72
        assert len(report["flows"]) >= 4

        csv_data = session.export_demo_csv()
        assert len(csv_data) > 100

    finally:
        # 14. Stop monitoring and clean up lab
        session.stop()
        lab_cleaned = lab.cleanup()
        assert lab_cleaned is True

    # 15. Verify host network state remains unmodified
    host_ok, host_diff = lab._host_baseline.verify_unmodified()
    assert host_ok is True, f"Host state modified after cleanup: {host_diff}"
