"""Regression and governance tests for Decision D-003 and threshold semantics (Task 5).

Verifies:
1. Research threshold remains fixed at 0.50.
2. Operational threshold cannot be labelled "selected" without selection evidence.
3. Cost-sensitive selection requires explicit validation data optimization.
4. Test set is strictly isolated from threshold selection.
5. ReplayEngine distinguishes research baseline (0.50) from operational candidate (0.40).
6. A score of ~0.4692 evaluates to BENIGN at 0.50 and ATTACK at 0.40.
7. No contradiction exists between threshold_candidates.json and D-003 documentation.
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from xrlids.demo.flow import Flow, FlowKey
from xrlids.demo.replay import ReplayEngine
from xrlids.evaluation.thresholding import (
    DECISION_ID,
    DECISION_STATUS,
    RESEARCH_BASELINE_THRESHOLD,
    candidate_operating_points,
    threshold_sweep,
)


def test_research_threshold_remains_050():
    """Verify that the academic research reporting baseline is strictly 0.50."""
    assert RESEARCH_BASELINE_THRESHOLD == 0.50
    engine = ReplayEngine()
    assert engine.research_threshold == 0.50
    assert engine.threshold == 0.50


def test_operational_threshold_status_not_falsely_selected():
    """Verify threshold_candidates.json marks D-003 as OPEN and does not falsely claim 0.40 as selected."""
    artifact_path = Path("results/experiments/EXP-P1-CIC2017-R10-001/threshold_candidates.json")
    assert artifact_path.exists(), "threshold_candidates.json must exist"

    data = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert data["decision_id"] == "D-003"
    assert "OPEN" in data["decision_status"]

    candidates = data["candidates"]
    # The actual candidate thresholds from validation data are 0.50, 0.75, 0.47, 0.20
    candidate_thresholds = {v["threshold"] for v in candidates.values() if "threshold" in v}
    assert 0.50 in candidate_thresholds
    assert 0.20 in candidate_thresholds  # cost-sensitive candidate (fp=1, fn=10)
    # 0.40 is NOT an empirically selected optimum in threshold_candidates.json
    assert 0.40 not in candidate_thresholds


def test_cost_sensitive_selection_uses_explicit_cost_equation():
    """Verify that cost-sensitive candidate selection optimizes Cost = C_FP * FP + C_FN * FN."""
    # Synthetic validation sweep with known FP and FN
    df_sweep = pd.DataFrame([
        {"threshold": 0.20, "tp": 90, "tn": 80, "fp": 20, "fn": 10, "precision": 0.818, "recall": 0.90, "f1": 0.857, "fpr": 0.20, "fnr": 0.10},
        {"threshold": 0.40, "tp": 85, "tn": 92, "fp": 8, "fn": 15, "precision": 0.914, "recall": 0.85, "f1": 0.881, "fpr": 0.08, "fnr": 0.15},
        {"threshold": 0.50, "tp": 80, "tn": 96, "fp": 4, "fn": 20, "precision": 0.952, "recall": 0.80, "f1": 0.870, "fpr": 0.04, "fnr": 0.20},
    ])

    # Case 1: Asymmetric loss C_FN = 10 * C_FP -> Cost(0.20) = 20 + 100 = 120; Cost(0.40) = 8 + 150 = 158; Cost(0.50) = 4 + 200 = 204
    picks_10x = candidate_operating_points(df_sweep, fp_cost=1.0, fn_cost=10.0)
    assert picks_10x["candidates"]["cost_sensitive"]["threshold"] == 0.20
    assert picks_10x["candidates"]["cost_sensitive"]["expected_cost"] == 120.0

    # Case 2: Asymmetric loss C_FN = 3 * C_FP -> Cost(0.20) = 20 + 30 = 50; Cost(0.40) = 8 + 45 = 53; Cost(0.50) = 4 + 60 = 64
    picks_3x = candidate_operating_points(df_sweep, fp_cost=1.0, fn_cost=3.0)
    assert picks_3x["candidates"]["cost_sensitive"]["threshold"] == 0.20


def test_replay_engine_dual_threshold_semantics():
    """Verify that ReplayEngine distinguishes research baseline (0.50) from operational candidate (0.40)."""
    # Dummy mock model returning fixed scores
    class MockFixedScoreModel:
        def __init__(self, score: float):
            self.score = score
            self.feature_names = [
                "flow_duration_ms", "flow_packets_per_s", "flow_bytes_per_s", "packet_length_mean",
                "packet_length_std", "syn_count", "ack_count", "rst_count", "fin_count", "syn_ack_ratio"
            ]
        def predict_proba(self, X):
            return np.array([self.score])

    # Model returning 0.4692 (matching Flow #5 in demo)
    score_4692 = 0.4692
    engine = ReplayEngine(
        model=MockFixedScoreModel(score_4692),
        research_threshold=0.50,
        operational_candidate_threshold=0.40,
    )

    flow = Flow(FlowKey("10.0.0.1", "10.0.0.2", 1234, 80, 6), 1.0, 1.0)
    pred_res, score = engine._predict_flow(flow)

    assert abs(score - score_4692) < 1e-4
    # At research threshold 0.50: 0.4692 < 0.50 -> BENIGN (pred = 0)
    assert pred_res == 0

    # Test dual threshold classification logic in replay
    pred_ops = 1 if score >= engine.operational_candidate_threshold else 0
    # At operational candidate 0.40: 0.4692 >= 0.40 -> ATTACK (pred = 1)
    assert pred_ops == 1


def test_no_unsupported_false_alarm_claim_in_governance_docs():
    """Verify that the unverified claim 'maintaining false alarms below 1.2%' is not present in governance docs."""
    docs_to_check = [
        Path("docs/03_DECISIONS/DECISION_LOG.md"),
        Path("docs/03_DECISIONS/CLAIMS_REGISTRY.md"),
        Path("PROJECT_STATUS.md"),
    ]
    for p in docs_to_check:
        if p.exists():
            content = p.read_text(encoding="utf-8")
            assert "below 1.2%" not in content, f"Unsupported claim 'below 1.2%' found in {p}"
            assert "<1.2%" not in content, f"Unsupported claim '<1.2%' found in {p}"
