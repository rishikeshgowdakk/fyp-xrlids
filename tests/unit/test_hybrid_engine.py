"""Unit tests for the HybridDecisionEngine.

Validates:
1. RF-only detections (RF probability >= tau, no rule matches).
2. Rule-only detections (deterministic rule fires, RF probability < tau).
3. Combined HYBRID detections (both RF and Rule trigger).
4. Conflicting decisions and deterministic rule priority.
5. Handling of unavailable rule features without silent zero-filling.
6. Configurable thresholds and severity floor enforcement.
7. Output contract and serializability.
"""

from __future__ import annotations

import pytest

from xrlids.rules.engine import RuleMatch
from xrlids.rules.hybrid import HybridDecision, HybridDecisionEngine


@pytest.fixture
def engine() -> HybridDecisionEngine:
    return HybridDecisionEngine(
        rf_threshold=0.50,
        high_severity_rf_threshold=0.85,
        medium_severity_rf_threshold=0.65,
        high_severity_rule_floor=0.85,
        medium_severity_rule_floor=0.65,
        low_severity_rule_floor=0.50,
    )


def test_benign_flow_neither_triggers(engine: HybridDecisionEngine):
    """Flow with low RF probability and zero rule matches is BENIGN with source NONE."""
    decision = engine.evaluate(rf_probability=0.12, rule_matches=[])
    assert decision.verdict == "BENIGN"
    assert not decision.is_attack
    assert decision.detection_source == "NONE"
    assert decision.threat_score == 0.12
    assert decision.severity == "INFORMATIONAL"
    assert not decision.rule_triggered
    assert len(decision.matched_rules) == 0


def test_rf_only_detection(engine: HybridDecisionEngine):
    """Flow with high RF probability and no rule matches is classified as RF detection."""
    decision = engine.evaluate(rf_probability=0.72, rule_matches=[])
    assert decision.verdict == "ATTACK"
    assert decision.is_attack
    assert decision.detection_source == "RF"
    assert decision.threat_score == 0.72
    assert decision.severity == "MEDIUM"
    assert not decision.rule_triggered
    assert decision.rf_prediction == "ATTACK"


def test_rule_only_detection_priority(engine: HybridDecisionEngine):
    """Flow with low RF probability (e.g. 0.05) but high-severity rule match declares ATTACK."""
    rule_match = RuleMatch(
        rule_id="RULE-SYN-FLOOD",
        name="TCP SYN Flood (Zero ACK)",
        severity="HIGH",
        description="SYN flood violation",
        matched_value="syn_count=30, ack_count=0",
    )
    decision = engine.evaluate(rf_probability=0.05, rule_matches=[rule_match])
    assert decision.verdict == "ATTACK"
    assert decision.is_attack
    assert decision.detection_source == "RULE"
    # Threat score is floored to high severity floor (0.85) despite low RF score
    assert decision.threat_score >= 0.85
    assert decision.severity == "HIGH"
    assert decision.rule_triggered
    assert decision.rule_ids == ["RULE-SYN-FLOOD"]
    assert decision.rf_prediction == "BENIGN"


def test_combined_hybrid_detection(engine: HybridDecisionEngine):
    """Flow where both RF and deterministic rules trigger declares HYBRID detection."""
    rule_match = RuleMatch(
        rule_id="RULE-HIGH-RATE-BURST",
        name="High Volumetric Packet Rate Burst",
        severity="HIGH",
        description="High rate",
        matched_value="flow_packets_per_s=60000",
    )
    decision = engine.evaluate(rf_probability=0.92, rule_matches=[rule_match])
    assert decision.verdict == "ATTACK"
    assert decision.is_attack
    assert decision.detection_source == "HYBRID"
    assert decision.threat_score == 0.92
    assert decision.severity == "HIGH"
    assert decision.rule_triggered
    assert decision.rf_prediction == "ATTACK"


def test_severity_levels(engine: HybridDecisionEngine):
    """Test severity resolution across various RF probabilities and rule severities."""
    # Low severity RF attack (between 0.50 and 0.65) with no rules
    d_low = engine.evaluate(rf_probability=0.55, rule_matches=[])
    assert d_low.severity == "LOW"

    # Medium severity RF attack (between 0.65 and 0.85)
    d_med = engine.evaluate(rf_probability=0.75, rule_matches=[])
    assert d_med.severity == "MEDIUM"

    # High severity RF attack (>= 0.85)
    d_high = engine.evaluate(rf_probability=0.88, rule_matches=[])
    assert d_high.severity == "HIGH"

    # Medium rule match elevates severity to MEDIUM even with low RF
    med_rule = RuleMatch(
        rule_id="RULE-PORT-SCAN",
        name="Port Scan",
        severity="MEDIUM",
        description="Scan probe",
        matched_value="syn_count=5",
    )
    d_rule_med = engine.evaluate(rf_probability=0.10, rule_matches=[med_rule])
    assert d_rule_med.severity == "MEDIUM"
    assert d_rule_med.threat_score >= 0.65


def test_unavailable_features_handling_in_evaluate_features(engine: HybridDecisionEngine):
    """Verify that evaluate_features detects missing rule features and does not fake values."""
    # Degraded sensor features missing TCP flags (e.g. UNSW-NB15 R4)
    degraded_features = {
        "flow_duration_ms": 150.0,
        "flow_packets_per_s": 20.0,
        "flow_bytes_per_s": 1500.0,
        "packet_length_mean": 75.0,
    }
    decision = engine.evaluate_features(features=degraded_features, rf_probability=0.20)
    assert "syn_count" in decision.unavailable_features
    assert "ack_count" in decision.unavailable_features
    assert "RULE-SYN-FLOOD" in decision.unavailable_rules
    assert "RULE-PORT-SCAN" in decision.unavailable_rules
    assert decision.verdict == "BENIGN"
    assert decision.detection_source == "NONE"


def test_volumetric_burst_rule_evaluates_when_rates_present(engine: HybridDecisionEngine):
    """Verify that rules whose features ARE present evaluate correctly."""
    features = {
        "flow_packets_per_s": 75000.0,  # exceeds 50k threshold
        "flow_bytes_per_s": 1000.0,
    }
    decision = engine.evaluate_features(features=features, rf_probability=0.10)
    assert decision.verdict == "ATTACK"
    assert decision.detection_source == "RULE"
    assert "RULE-HIGH-RATE-BURST" in decision.rule_ids
    assert decision.threat_score >= 0.85


def test_serialization_to_dict(engine: HybridDecisionEngine):
    """Verify that to_dict returns JSON-serializable structured data."""
    decision = engine.evaluate(rf_probability=0.77777, rule_matches=[])
    d = decision.to_dict()
    assert d["verdict"] == "ATTACK"
    assert d["threat_score"] == 0.7778
    assert d["detection_source"] == "RF"
    assert isinstance(d["rule_ids"], list)
    assert isinstance(d["unavailable_features"], list)
