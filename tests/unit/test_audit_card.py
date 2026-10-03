"""Unit tests for Phase 2E explainability and Action Decision Audit Card generation."""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from xrlids.response.dqn.agent import DqnAgent
from xrlids.response.explainability.audit_card import (
    ActionAuditCard,
    PerceptionLayerAttribution,
    PolicyLayerExplainability,
    SafetyGateAudit,
    audit_card_to_markdown,
    explain_state_factors,
)
from xrlids.response.explainability.auditor import AutonomousResponseAuditor
from xrlids.response.types import Action, ActionSpaceMode, StepRecord


def test_explain_state_factors():
    # Test state with high threat, acceleration, critical host
    state = np.array([0.82, 0.65, 0.25, 0.40, 1.0, 0.5])
    factors = explain_state_factors(state, enforced_action="RATE_LIMIT")

    assert any("Instantaneous attack risk is severe" in f for f in factors)
    assert any("Exponentially smoothed threat density is elevated" in f for f in factors)
    assert any("Threat velocity accelerating rapidly" in f for f in factors)
    assert any("critical infrastructure" in f for f in factors)
    assert any("cooldown" in f for f in factors)


def test_audit_card_to_markdown():
    card = ActionAuditCard(
        timestamp="2026-10-04T12:00:00Z",
        flow_id="flow-9999",
        host_id="192.168.10.50",
        proposed_action="ISOLATE",
        enforced_action="ALERT",
        perception_layer=PerceptionLayerAttribution(
            detector_score=0.7891,
            top_contributing_features=[
                {"feature": "flow_packets_per_s", "shap_value": 0.1234, "feature_value": 450.0},
                {"feature": "packet_length_std", "shap_value": 0.0567, "feature_value": 85.2},
            ],
        ),
        policy_layer=PolicyLayerExplainability(
            q_values={"ALLOW": -30.0, "ALERT": -15.0, "RATE_LIMIT": -8.0, "ISOLATE": -4.0},
            decision_margin=4.0,
            driving_state_factors=["Instantaneous attack risk is severe"],
        ),
        safety_gate=SafetyGateAudit(
            invariants_checked=["CRITICAL_INFRASTRUCTURE_EXEMPTION", "MANDATORY_ACTION_COOLDOWN"],
            action_overruled=True,
            override_reason="CRITICAL_INFRASTRUCTURE_EXEMPTION",
        ),
    )

    md = audit_card_to_markdown(card)
    assert "### Action Decision Audit Card: `flow-9999`" in md
    assert "flow_packets_per_s" in md
    assert "CRITICAL_INFRASTRUCTURE_EXEMPTION" in md
    assert "Decision Margin" in md
    assert "Action Overruled" in md


def test_auditor_with_toy_model():
    # Train tiny RF classifier
    X = np.random.randn(50, 4)
    y = (X[:, 0] > 0).astype(int)
    rf = RandomForestClassifier(n_estimators=5, random_state=42)
    rf.fit(X, y)

    agent = DqnAgent(input_dim=6, action_mode=ActionSpaceMode.FOUR_ACTION)
    feature_names = ["feat_0", "feat_1", "feat_2", "feat_3"]

    auditor = AutonomousResponseAuditor(
        detector_rf_model=rf,
        feature_names=feature_names,
        agent=agent,
        top_k_features=2,
    )

    # Explain single perception
    perception = auditor.explain_perception(X[0], detector_score=0.85)
    assert len(perception.top_contributing_features) == 2
    assert perception.detector_score == 0.85

    # Explain policy
    dummy_state = np.array([0.85, 0.70, 0.10, 0.3, 0.0, 0.0])
    policy_exp = auditor.explain_policy(dummy_state, enforced_action="ISOLATE")
    assert "ISOLATE" in policy_exp.q_values
    assert policy_exp.decision_margin >= 0.0

    # Audit simulation run
    steps = [
        StepRecord(
            step=0,
            flow_id="f1",
            host_id="h1",
            true_label=0,
            attack_score=0.1,
            state=np.zeros(6),
            proposed_action=Action.ALLOW,
            enforced_action=Action.ALLOW,
            overridden=False,
            override_reason=None,
            base_cost=0.0,
            chattering_penalty=0.0,
            fatigue_penalty=0.0,
            total_cost=0.0,
            reward=0.0,
        ),
        StepRecord(
            step=1,
            flow_id="f2",
            host_id="h2",
            true_label=1,
            attack_score=0.9,
            state=dummy_state,
            proposed_action=Action.ISOLATE,
            enforced_action=Action.ISOLATE,
            overridden=False,
            override_reason=None,
            base_cost=0.0,
            chattering_penalty=0.0,
            fatigue_penalty=0.0,
            total_cost=0.0,
            reward=0.0,
        ),
    ]

    cards, summary = auditor.audit_simulation_run(
        step_records=steps,
        flow_features=np.tile(X[0], (2, 1)),
        audit_only_interventions=True,
    )

    assert len(cards) == 1
    assert summary["audit_coverage_pct"] == 100.0
    assert summary["rq7_3_pass"] is True
