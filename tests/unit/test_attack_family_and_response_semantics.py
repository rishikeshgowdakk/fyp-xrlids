"""Unit tests for Attack-Family Capability Audit and Autonomous Response Semantics (Addendum).

Verifies:
1. All RF artifacts are strictly binary (classes_ = [0, 1]) and output P(ATTACK).
2. FlagshipDecision carries transparent semantics:
   - detection_type == "binary"
   - attack_family_prediction is None (no multiclass model exists)
   - response_mode == "advisory"
3. Workbench API endpoints cleanly separate detection, ground-truth family evaluation,
   and advisory response semantics.
4. LiveSession.snapshot() declares binary detection and advisory response semantics.
5. DQN state vector is verified as 6D causal with no attack-family feature leakage.
"""

from __future__ import annotations

from pathlib import Path
import sys

import joblib
import numpy as np
import pytest
import torch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dashboard.server import LIVE_SESSION
from dashboard.workbench_data import (
    get_evaluation_data,
    get_explainability_data,
    get_limitations_data,
    get_overview_data,
    get_response_benchmark_data,
)
from xrlids.flagship import FlagshipDecision, FlagshipXRLIDS
from xrlids.response.types import Action


def test_rf_artifacts_are_strictly_binary():
    """Verify all saved RF detector artifacts are strictly binary classifiers."""
    for model_path in [
        "models/rf/random_forest_cicids2017.joblib",
        "models/rf/random_forest_cse2018.joblib",
        "models/rf/random_forest_unswnb15.joblib",
    ]:
        detector = joblib.load(model_path)
        # Check underlying sklearn classifier
        clf = detector.model
        assert clf is not None
        assert hasattr(clf, "classes_")
        assert list(clf.classes_) == [0, 1]
        assert clf.n_classes_ == 2


def test_flagship_decision_semantics():
    """Verify FlagshipDecision dataclass fields and to_dict serialization."""
    decision = FlagshipDecision(
        threat_score=0.88,
        is_attack=True,
        confidence=0.76,
        recommended_action=Action.ISOLATE,
        enforced_action=Action.ISOLATE,
        safety_override=False,
        override_reason=None,
        rf_score=0.85,
        lstm_score=0.91,
        state_vector=[0.88, 0.1, 0.4, 0.667, 0.0, 0.5],
        detection_type="binary",
        attack_family_prediction=None,
        response_mode="advisory",
    )
    d = decision.to_dict()
    assert d["detection_type"] == "binary"
    assert d["attack_family_prediction"] is None
    assert d["response_mode"] == "advisory"
    assert d["is_attack"] is True
    assert d["recommended_action"] == "ISOLATE"


def test_flagship_engine_outputs_binary_semantics():
    """Verify FlagshipXRLIDS.process_flow outputs binary detection and advisory response."""
    engine = FlagshipXRLIDS(dataset="cicids2017")
    mock_features = {
        "flow_duration_ms": 120.0,
        "flow_packets_per_s": 500.0,
        "flow_bytes_per_s": 15000.0,
        "packet_length_mean": 60.0,
        "packet_length_std": 10.0,
        "syn_count": 5.0,
        "ack_count": 0.0,
        "rst_count": 0.0,
        "fin_count": 0.0,
        "syn_ack_ratio": 5.0,
    }
    decision = engine.process_flow(mock_features)
    assert decision.detection_type == "binary"
    assert decision.attack_family_prediction is None
    assert decision.response_mode == "advisory"
    assert isinstance(decision.threat_score, float)
    assert isinstance(decision.recommended_action, Action)
    assert isinstance(decision.enforced_action, Action)


def test_workbench_overview_semantic_contract():
    """Verify get_overview_data includes the semantic contract distinguishing all concepts."""
    overview = get_overview_data()
    assert "semantic_contract" in overview
    contract = overview["semantic_contract"]
    assert "detection_model" in contract
    assert "Binary" in contract["detection_model"]
    assert "attack_family_prediction" in contract
    assert "NOT AVAILABLE" in contract["attack_family_prediction"]
    assert "dqn_response" in contract
    assert "advisory/dry-run" in contract["dqn_response"]

    # Check component status for DQN
    dqn_status = next(c for c in overview["component_statuses"] if "DQN" in c["component"])
    assert dqn_status["response_mode"] == "advisory_dry_run"
    assert "advisory" in dqn_status["response_note"].lower()


def test_workbench_evaluation_detection_semantics():
    """Verify get_evaluation_data includes detection semantics."""
    eval_data = get_evaluation_data("cicids2017")
    assert "detection_semantics" in eval_data
    sem = eval_data["detection_semantics"]
    assert "Binary" in sem["model_output"]
    assert "ground-truth" in sem["per_family_note"].lower()


def test_workbench_explainability_semantics():
    """Verify get_explainability_data clarifies TreeSHAP scope."""
    xai = get_explainability_data("cicids2017")
    assert "explanation_semantics" in xai
    sem = xai["explanation_semantics"]
    assert "binary" in sem["scope"].lower()
    assert "limitation" in sem


def test_workbench_response_benchmark_semantics():
    """Verify get_response_benchmark_data confirms advisory dry-run status."""
    resp = get_response_benchmark_data()
    assert "response_semantics" in resp
    sem = resp["response_semantics"]
    assert sem["execution_status"] == "advisory_dry_run"
    assert "offline_replay" in sem["mode"]
    assert "6D causal state" in sem["dqn_state_contract"]


def test_workbench_limitations_autonomous_response_status():
    """Verify get_limitations_data confirms production enforcement is strictly NO-GO."""
    lim = get_limitations_data()
    assert "autonomous_response_status" in lim
    status = lim["autonomous_response_status"]
    assert "Advisory" in status["current_capability"]
    assert "strictly NO-GO" in status["safety_assessment"]
    assert any("Live network intervention" in s for s in status["not_implemented"])


def test_live_session_snapshot_semantics():
    """Verify LiveSession.snapshot carries detection and response semantics."""
    snap = LIVE_SESSION.snapshot()
    assert "detection_semantics" in snap
    assert snap["detection_semantics"]["model_type"] == "binary"
    assert snap["detection_semantics"]["attack_family_prediction"] is None
    assert "response_semantics" in snap
    assert snap["response_semantics"]["mode"] == "advisory"


def test_dqn_checkpoints_state_dimension():
    """Verify DQN checkpoints use 6D causal state with no multiclass dimension."""
    for cp_path, expected_actions in [
        ("models/dqn/dqn_3action_best.pt", 3),
        ("models/dqn/dqn_4action_best.pt", 4),
    ]:
        cp = torch.load(cp_path, map_location="cpu", weights_only=False)
        sd = cp["online_net_state_dict"]
        # Input layer weight shape: [hidden_dim, input_dim]
        assert sd["fc1.weight"].shape[1] == 6
        # Advantage stream output shape: [action_dim, 32]
        assert sd["adv_out.weight"].shape[0] == expected_actions
