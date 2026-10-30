"""End-to-End Pipeline Integration Test for XRL-IDARS.

Tests the full causal pipeline:
ScapyCaptureService (PCAP)
    -> LiveFlowBuilder (bidirectional 5-tuple aggregation, R10 features)
    -> UnifiedInferenceService (RF + LSTM T=5 sequence buffer + Fusion)
    -> TreeSHAP (feature attributions on Random Forest)
    -> StateBuilder (6D causal state vector s_t in R^6)
    -> DuelingQNetwork (advisory Q-values & action proposal)
    -> DeterministicSafetyGate (cooldown, critical host allowlist, blast radius circuit breaker)
"""

from __future__ import annotations

import time
from pathlib import Path

import numpy as np
import pytest
import torch

from xrlids.capture.scapy_service import ScapyCaptureConfig, ScapyCaptureService
from xrlids.evaluation.csv_evaluator import explain_flow_prediction
from xrlids.features.definitions import R10_FEATURES
from xrlids.live.flow_builder import LiveFlowBuilder
from xrlids.models.inference_service import UnifiedInferenceService
from xrlids.response.dqn.network import DuelingQNetwork
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action, ActionSpaceMode


SAMPLE_PCAP_PATH = Path("data/demo/sample_traffic.pcap")
DQN_CHECKPOINT_PATH = Path("models/dqn/dqn_4action_best.pt")


@pytest.mark.integration
def test_end_to_end_scapy_pcap_to_safety_pipeline():
    """Verify complete Scapy PCAP -> Flow -> RF/LSTM -> TreeSHAP -> DQN -> Safety Gate pipeline."""
    assert SAMPLE_PCAP_PATH.exists(), f"Sample PCAP missing at {SAMPLE_PCAP_PATH}"
    assert DQN_CHECKPOINT_PATH.exists(), f"DQN checkpoint missing at {DQN_CHECKPOINT_PATH}"

    # 1. Capture subsystem
    cfg = ScapyCaptureConfig(pcap_path=SAMPLE_PCAP_PATH, queue_size=1000)
    service = ScapyCaptureService(cfg)
    flow_builder = LiveFlowBuilder(idle_timeout_s=1.0, clock_mode="packet")

    service.start()
    completed_flows = []
    start_t = time.time()
    while service.is_running or not service._queue.empty():
        pkt = service.get_packet(timeout=0.1)
        if pkt is not None:
            flows = flow_builder.process_packet(pkt)
            completed_flows.extend(flows)
        if time.time() - start_t > 5.0:
            break
    service.stop()

    # Flush remaining active flows
    for flow in flow_builder.active_flows.values():
        completed_flows.append(flow)

    assert service.stats.packets_captured == 42, f"Expected 42 packets, got {service.stats.packets_captured}"
    assert len(completed_flows) >= 5, f"Expected at least 5 flows, got {len(completed_flows)}"

    # 2. Unified Inference subsystem
    inf_service = UnifiedInferenceService()

    # 3. DQN Agent
    dqn = DuelingQNetwork(input_dim=6, action_dim=4)
    ckpt = torch.load(DQN_CHECKPOINT_PATH, map_location="cpu", weights_only=False)
    state_dict = ckpt.get("online_net_state_dict", ckpt.get("model_state_dict", ckpt))
    dqn.load_state_dict(state_dict)
    dqn.eval()

    # 4. State & Safety Gate
    state_builder = StateBuilder(alert_threshold=0.50)
    safety_gate = DeterministicSafetyGate(
        action_mode=ActionSpaceMode.FOUR_ACTION,
        cooldown_steps=30,
        blast_radius_threshold=0.05,
    )

    eval_records = []
    for step_idx, flow in enumerate(completed_flows):
        features = flow.to_features()
        for f in R10_FEATURES:
            assert f in features, f"Missing feature {f}"

        host_ip = flow.key.endpoint_a

        # Model Inference
        res = inf_service.infer(features, session_key=host_ip, benchmark="cicids2017")
        assert 0.0 <= res.attack_score <= 1.0
        assert res.inference_source in ("RANDOM_FOREST", "RF+LSTM_FUSION")

        # TreeSHAP Explanation on Random Forest
        shap_res = explain_flow_prediction(features, benchmark="cicids2017")
        assert "features" in shap_res
        assert len(shap_res["features"]) == len(R10_FEATURES)
        assert "attributions" in shap_res

        # 6D Causal State Vector
        state = state_builder.build_state(
            attack_score=res.attack_score,
            flow_bytes_per_s=features["flow_bytes_per_s"],
        )
        assert state.shape == (6,)
        assert state.dtype == np.float32

        # DQN Advisory Action Proposal
        with torch.no_grad():
            s_tensor = torch.from_numpy(state).float().unsqueeze(0)
            q_vals = dqn(s_tensor)
            proposed_action_idx = int(torch.argmax(q_vals, dim=-1).item())
            proposed_action = Action(proposed_action_idx)

        # Deterministic Safety Gate Enforcement
        enforced_action, overridden, reason = safety_gate.enforce_safety(
            step=step_idx,
            flow_id=f"flow_{step_idx}",
            host_id=host_ip,
            proposed_action=proposed_action,
        )

        rem_cool = safety_gate.get_remaining_cooldown(host_ip, step_idx)
        state_builder.update_history(
            attack_score=res.attack_score,
            enforced_action=enforced_action,
            cooldown_remaining=rem_cool,
        )

        eval_records.append({
            "step": step_idx,
            "host": host_ip,
            "score": res.attack_score,
            "source": res.inference_source,
            "proposed": proposed_action,
            "enforced": enforced_action,
            "overridden": overridden,
            "reason": reason,
        })

    assert len(eval_records) == len(completed_flows)
    # Check that safety gate cooldown was exercised when high risk flow triggered ISOLATE
    isolated_steps = [r for r in eval_records if r["enforced"] == Action.ISOLATE]
    if isolated_steps:
        # Verify subsequent step for same host within cooldown preserves ISOLATE or overrides
        iso_host = isolated_steps[0]["host"]
        later_steps = [r for r in eval_records if r["host"] == iso_host and r["step"] > isolated_steps[0]["step"]]
        if later_steps:
            assert later_steps[0]["enforced"] == Action.ISOLATE, "Expected cooldown to maintain isolation"


def test_lstm_sequence_buffer_triggers_fusion_on_fifth_flow():
    """Verify that when 5 consecutive flows arrive for the same session, LSTM fusion activates."""
    inf_service = UnifiedInferenceService()
    session_key = "192.168.10.99:5000"
    base_features = {
        "flow_duration_ms": 1500.0,
        "flow_packets_per_s": 12.0,
        "flow_bytes_per_s": 850.0,
        "packet_length_mean": 70.8,
        "packet_length_std": 25.4,
        "syn_count": 1.0,
        "ack_count": 2.0,
        "rst_count": 0.0,
        "fin_count": 1.0,
        "syn_ack_ratio": 0.5,
    }

    # First 4 flows -> RF only
    for i in range(4):
        res = inf_service.infer(base_features, session_key=session_key, benchmark="cicids2017")
        assert res.inference_source == "RANDOM_FOREST"
        assert res.lstm_score is None
        assert res.fusion_score is None
        assert res.sequence_length_available == i + 1

    # 5th flow -> RF+LSTM_FUSION
    res5 = inf_service.infer(base_features, session_key=session_key, benchmark="cicids2017")
    assert res5.inference_source == "RF+LSTM_FUSION"
    assert res5.lstm_score is not None
    assert res5.fusion_score is not None
    assert res5.sequence_length_available == 5
    assert 0.0 <= res5.lstm_score <= 1.0
    assert 0.0 <= res5.fusion_score <= 1.0

