"""Unit tests for the ActiveInferencePipeline end-to-end integration."""

from pathlib import Path
import pytest

from xrlids.events.manager import EventManager
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline, PipelineResult
from xrlids.response.types import Action


@pytest.fixture
def benign_r10():
    return {
        "flow_duration_ms": 1250.0,
        "flow_packets_per_s": 80.5,
        "flow_bytes_per_s": 15400.0,
        "packet_length_mean": 191.3,
        "packet_length_std": 84.2,
        "syn_count": 2.0,
        "ack_count": 4.0,
        "rst_count": 0.0,
        "fin_count": 1.0,
        "syn_ack_ratio": 0.5,
    }


@pytest.fixture
def syn_flood_r10():
    return {
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


def test_pipeline_benign_flow(benign_r10, tmp_path):
    audit_file = tmp_path / "events.jsonl"
    event_mgr = EventManager(audit_log_path=audit_file)
    pipeline = ActiveInferencePipeline(event_manager=event_mgr)

    res = pipeline.process_flow(
        benign_r10,
        source_ip="192.168.1.55",
        dest_ip="10.0.0.1",
        flow_id="test-benign-1",
    )

    assert isinstance(res, PipelineResult)
    assert res.flow_id == "test-benign-1"
    assert res.inference.attack_score < 0.50
    assert res.hybrid.verdict == "BENIGN"
    assert res.enforced_action == Action.ALLOW
    assert len(event_mgr.get_recent_events()) == 1


def test_pipeline_attack_flow_and_explanation(syn_flood_r10, tmp_path):
    audit_file = tmp_path / "events.jsonl"
    event_mgr = EventManager(audit_log_path=audit_file)
    pipeline = ActiveInferencePipeline(event_manager=event_mgr, explain_all=True)

    res = pipeline.process_flow(
        syn_flood_r10,
        source_ip="10.200.1.99",
        dest_ip="10.0.0.1",
        flow_id="test-attack-1",
    )

    assert isinstance(res, PipelineResult)
    assert res.hybrid.verdict == "ATTACK"
    assert res.hybrid.detection_source in ("RULE", "RF", "HYBRID")
    assert res.hybrid.severity in ("HIGH", "CRITICAL", "MEDIUM")
    assert res.explanation is not None
    assert len(res.explanation.top_features) == 10
    assert res.enforced_action in (Action.ALERT, Action.RATE_LIMIT, Action.ISOLATE)


def test_pipeline_critical_host_safety(tmp_path):
    audit_file = tmp_path / "events.jsonl"
    event_mgr = EventManager(audit_log_path=audit_file)
    pipeline = ActiveInferencePipeline(event_manager=event_mgr)

    # If critical host triggers an attack detection, safety gate must never allow ISOLATE
    critical_ip = "192.168.10.1"  # Default Gateway
    dummy_attack = {
        "flow_duration_ms": 100.0,
        "flow_packets_per_s": 10000.0,
        "flow_bytes_per_s": 600000.0,
        "packet_length_mean": 60.0,
        "packet_length_std": 0.0,
        "syn_count": 50.0,
        "ack_count": 0.0,
        "rst_count": 0.0,
        "fin_count": 0.0,
        "syn_ack_ratio": 50.0,
    }

    res = pipeline.process_flow(dummy_attack, source_ip=critical_ip)
    assert res.enforced_action != Action.ISOLATE
    if res.response.action == Action.ISOLATE:
        assert res.safety_override is True
        assert res.enforced_action == Action.ALERT


def test_pipeline_safety_gate_agreement_and_single_evaluation(syn_flood_r10, tmp_path):
    """Regression test ensuring pipeline, executor report, and event all agree on enforced action,
    and safety gate is evaluated exactly once per flow."""
    audit_file = tmp_path / "events.jsonl"
    event_mgr = EventManager(audit_log_path=audit_file)
    pipeline = ActiveInferencePipeline(event_manager=event_mgr)

    eval_count_before = pipeline.safety_gate._total_evaluations

    res = pipeline.process_flow(
        syn_flood_r10,
        source_ip="10.200.1.77",
        dest_ip="10.0.0.1",
        flow_id="test-agreement-1",
    )

    eval_count_after = pipeline.safety_gate._total_evaluations
    # Safety gate must be evaluated exactly once per flow
    assert eval_count_after == eval_count_before + 1

    # PipelineResult, ExecutionReport, and SecurityEvent must all agree on enforced action
    assert res.enforced_action == res.execution_report.authorized_action
    assert res.security_event.response["enforced_action"] == res.enforced_action.name
    assert res.security_event.response["proposed_action"] == res.response.action.name
    assert res.security_event.response["safety_override"] == res.safety_override
    assert res.execution_report.is_advisory is True

