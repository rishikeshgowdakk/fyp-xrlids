"""Unit tests verifying Phase 2 deterministic baseline policies (Task 7 & 12)."""

import numpy as np
import pytest

from xrlids.response.baselines import (
    AlwaysAllowPolicy,
    HeuristicStateMachinePolicy,
    SingleThresholdPolicy,
    TwoTierThresholdPolicy,
)
from xrlids.response.types import Action, ActionSpaceMode


dummy_state = np.zeros(6, dtype=np.float32)


def test_baseline_0_always_allow():
    """Verify Baseline 0 always returns Action.ALLOW regardless of score."""
    p = AlwaysAllowPolicy()
    assert p.predict_action(dummy_state, attack_score=0.99) == Action.ALLOW
    assert p.predict_action(dummy_state, attack_score=0.01) == Action.ALLOW


def test_baseline_1_single_threshold_4_action():
    """Verify Baseline 1 in 4-action mode: ISOLATE if >= 0.50 else ALLOW."""
    p = SingleThresholdPolicy(threshold=0.50, action_mode=ActionSpaceMode.FOUR_ACTION)
    assert p.predict_action(dummy_state, 0.49) == Action.ALLOW
    assert p.predict_action(dummy_state, 0.50) == Action.ISOLATE
    assert p.predict_action(dummy_state, 0.95) == Action.ISOLATE


def test_baseline_1_single_threshold_3_action():
    """Verify Baseline 1 in 3-action mode: RATE_LIMIT if >= 0.50 else ALLOW."""
    p = SingleThresholdPolicy(threshold=0.50, action_mode=ActionSpaceMode.THREE_ACTION)
    assert p.predict_action(dummy_state, 0.49) == Action.ALLOW
    assert p.predict_action(dummy_state, 0.50) == Action.RATE_LIMIT
    assert p.predict_action(dummy_state, 0.95) == Action.RATE_LIMIT


def test_baseline_2_two_tier_threshold_4_action():
    """Verify Baseline 2 in 4-action mode: ALLOW (<0.40), RATE_LIMIT ([0.40, 0.75)), ISOLATE (>=0.75)."""
    p = TwoTierThresholdPolicy(tau_suspect=0.40, tau_isolate=0.75, action_mode=ActionSpaceMode.FOUR_ACTION)
    assert p.predict_action(dummy_state, 0.35) == Action.ALLOW
    assert p.predict_action(dummy_state, 0.40) == Action.RATE_LIMIT
    assert p.predict_action(dummy_state, 0.74) == Action.RATE_LIMIT
    assert p.predict_action(dummy_state, 0.75) == Action.ISOLATE
    assert p.predict_action(dummy_state, 0.99) == Action.ISOLATE


def test_baseline_2_two_tier_threshold_3_action():
    """Verify Baseline 2 in 3-action mode: ALLOW (<0.40), ALERT ([0.40, 0.75)), RATE_LIMIT (>=0.75)."""
    p = TwoTierThresholdPolicy(tau_suspect=0.40, tau_isolate=0.75, action_mode=ActionSpaceMode.THREE_ACTION)
    assert p.predict_action(dummy_state, 0.35) == Action.ALLOW
    assert p.predict_action(dummy_state, 0.45) == Action.ALERT
    assert p.predict_action(dummy_state, 0.85) == Action.RATE_LIMIT


def test_baseline_4_cost_optimal_threshold_standard_enterprise():
    """Verify Baseline 4 chooses actions minimizing expected loss in Standard Enterprise."""
    from xrlids.response.baselines import CostOptimalThresholdPolicy
    from xrlids.response.costs import CostRegime

    # 4-action mode:
    # tau_1 = 1/89 ≈ 0.011236, tau_2 = 14/20 = 0.700000, tau_3 = 45/49 ≈ 0.918367
    p4 = CostOptimalThresholdPolicy(
        action_mode=ActionSpaceMode.FOUR_ACTION,
        cost_regime=CostRegime.STANDARD_ENTERPRISE,
    )
    # Below tau_1 -> ALLOW
    assert p4.predict_action(dummy_state, 0.005) == Action.ALLOW
    # Between tau_1 and tau_2 -> ALERT
    assert p4.predict_action(dummy_state, 0.02) == Action.ALERT
    assert p4.predict_action(dummy_state, 0.69) == Action.ALERT
    # Between tau_2 and tau_3 -> RATE_LIMIT
    assert p4.predict_action(dummy_state, 0.71) == Action.RATE_LIMIT
    assert p4.predict_action(dummy_state, 0.90) == Action.RATE_LIMIT
    # Above tau_3 -> ISOLATE
    assert p4.predict_action(dummy_state, 0.95) == Action.ISOLATE
    assert p4.predict_action(dummy_state, 0.999) == Action.ISOLATE

    # Verify dynamically derived boundaries
    b4 = p4.derive_threshold_boundaries()
    assert len(b4) == 4
    assert b4[0]["action"] == Action.ALLOW
    assert abs(b4[0]["upper"] - 1.0 / 89.0) < 1e-5
    assert b4[1]["action"] == Action.ALERT
    assert abs(b4[1]["upper"] - 0.70) < 1e-5
    assert b4[2]["action"] == Action.RATE_LIMIT
    assert abs(b4[2]["upper"] - 45.0 / 49.0) < 1e-5
    assert b4[3]["action"] == Action.ISOLATE
    assert b4[3]["upper"] == 1.0

    # 3-action mode: ISOLATE disabled, RATE_LIMIT extends to 1.0
    p3 = CostOptimalThresholdPolicy(
        action_mode=ActionSpaceMode.THREE_ACTION,
        cost_regime=CostRegime.STANDARD_ENTERPRISE,
    )
    assert p3.predict_action(dummy_state, 0.005) == Action.ALLOW
    assert p3.predict_action(dummy_state, 0.30) == Action.ALERT
    assert p3.predict_action(dummy_state, 0.80) == Action.RATE_LIMIT
    assert p3.predict_action(dummy_state, 0.99) == Action.RATE_LIMIT
    b3 = p3.derive_threshold_boundaries()
    assert len(b3) == 3
    assert b3[2]["action"] == Action.RATE_LIMIT
    assert b3[2]["upper"] == 1.0


def test_baseline_4_cost_optimal_other_regimes():
    """Verify Baseline 4 analytical boundaries in High Availability and High Security Enclave."""
    from xrlids.response.baselines import CostOptimalThresholdPolicy
    from xrlids.response.costs import CostRegime

    # High Availability (4-action):
    # tau_1 = 1/39 ≈ 0.025641, tau_2 = 29/35 ≈ 0.828571, tau_3 = 90/94 ≈ 0.957447
    p_ha = CostOptimalThresholdPolicy(
        action_mode=ActionSpaceMode.FOUR_ACTION,
        cost_regime=CostRegime.HIGH_AVAILABILITY,
    )
    assert p_ha.predict_action(dummy_state, 0.01) == Action.ALLOW
    assert p_ha.predict_action(dummy_state, 0.50) == Action.ALERT
    assert p_ha.predict_action(dummy_state, 0.90) == Action.RATE_LIMIT
    assert p_ha.predict_action(dummy_state, 0.98) == Action.ISOLATE

    b_ha = p_ha.derive_threshold_boundaries()
    assert abs(b_ha[0]["upper"] - 1.0 / 39.0) < 1e-5
    assert abs(b_ha[1]["upper"] - 29.0 / 35.0) < 1e-5
    assert abs(b_ha[2]["upper"] - 90.0 / 94.0) < 1e-5

    # High Security Enclave (4-action):
    # tau_1 = 1/481 ≈ 0.002079, tau_2 = 4/14 = 2/7 ≈ 0.285714, tau_3 = 20/28 = 5/7 ≈ 0.714286
    p_hse = CostOptimalThresholdPolicy(
        action_mode=ActionSpaceMode.FOUR_ACTION,
        cost_regime=CostRegime.HIGH_SECURITY_ENCLAVE,
    )
    assert p_hse.predict_action(dummy_state, 0.001) == Action.ALLOW
    assert p_hse.predict_action(dummy_state, 0.10) == Action.ALERT
    assert p_hse.predict_action(dummy_state, 0.50) == Action.RATE_LIMIT
    assert p_hse.predict_action(dummy_state, 0.85) == Action.ISOLATE

    b_hse = p_hse.derive_threshold_boundaries()
    assert abs(b_hse[0]["upper"] - 1.0 / 481.0) < 1e-5
    assert abs(b_hse[1]["upper"] - 2.0 / 7.0) < 1e-5
    assert abs(b_hse[2]["upper"] - 5.0 / 7.0) < 1e-5


def test_baseline_4_tie_breaking():
    """Verify tie breaking at exact boundary points under conservative vs aggressive policies."""
    from xrlids.response.baselines import CostOptimalThresholdPolicy
    from xrlids.response.costs import CostRegime

    # In Standard Enterprise at p = 14/20 = 0.70: Cost(ALERT) == Cost(RATE_LIMIT) == 8.7
    p_tie_070 = 0.70

    p_cons = CostOptimalThresholdPolicy(
        action_mode=ActionSpaceMode.FOUR_ACTION,
        cost_regime=CostRegime.STANDARD_ENTERPRISE,
        tie_breaker="conservative",
    )
    assert p_cons.predict_action(dummy_state, p_tie_070) == Action.ALERT

    p_aggr = CostOptimalThresholdPolicy(
        action_mode=ActionSpaceMode.FOUR_ACTION,
        cost_regime=CostRegime.STANDARD_ENTERPRISE,
        tie_breaker="aggressive",
    )
    assert p_aggr.predict_action(dummy_state, p_tie_070) == Action.RATE_LIMIT


def test_baseline_4_invalid_inputs_and_clipping():
    """Verify input validation, NaN handling, and out-of-bounds clipping."""
    import math
    from xrlids.response.baselines import CostOptimalThresholdPolicy

    p = CostOptimalThresholdPolicy(clip_out_of_bounds=True)

    # Valid score clipping
    assert p.predict_action(dummy_state, -0.25) == Action.ALLOW
    assert p.predict_action(dummy_state, 1.50) == Action.ISOLATE

    # NaN must raise ValueError
    with pytest.raises(ValueError, match="NaN"):
        p.predict_action(dummy_state, float("nan"))

    # Inf must raise ValueError
    with pytest.raises(ValueError, match="infinite"):
        p.predict_action(dummy_state, float("inf"))

    # When clip_out_of_bounds is False, out-of-range must raise ValueError
    p_strict = CostOptimalThresholdPolicy(clip_out_of_bounds=False)
    with pytest.raises(ValueError, match="must be in \\[0.0, 1.0\\]"):
        p_strict.predict_action(dummy_state, -0.01)
    with pytest.raises(ValueError, match="must be in \\[0.0, 1.0\\]"):
        p_strict.predict_action(dummy_state, 1.01)


def test_baseline_4_unconstrained_vs_safety_gate():
    """Verify unconstrained cost-optimal decision vs constrained enforcement through safety gate."""
    from xrlids.response.baselines import CostOptimalThresholdPolicy
    from xrlids.response.safety import DeterministicSafetyGate

    pol = CostOptimalThresholdPolicy(action_mode=ActionSpaceMode.FOUR_ACTION)
    sg = DeterministicSafetyGate(action_mode=ActionSpaceMode.FOUR_ACTION)

    # Critical host: policy proposes ISOLATE at p=0.95, safety gate downgrades to ALERT
    crit_host = "192.168.10.1"
    proposed = pol.predict_action(dummy_state, 0.95, host_id=crit_host)
    assert proposed == Action.ISOLATE

    enforced, overridden, reason = sg.enforce_safety(
        step=0,
        flow_id=1,
        host_id=crit_host,
        proposed_action=proposed,
    )
    assert enforced == Action.ALERT
    assert overridden is True
    assert reason == "CRITICAL_INFRASTRUCTURE_EXEMPTION"


def test_baseline_3_heuristic_state_machine_escalation():
    """Verify Baseline 3 escalates from ALLOW -> ALERT -> RATE_LIMIT -> ISOLATE."""
    p = HeuristicStateMachinePolicy(
        action_mode=ActionSpaceMode.FOUR_ACTION,
        tau_suspect=0.40,
        tau_high_risk=0.85,
        alert_density_threshold=3,
        cooldown_steps=10,
    )
    host = "test-host-1"

    # Step 1: Normal score -> ALLOW
    assert p.predict_action(dummy_state, 0.10, host_id=host) == Action.ALLOW

    # Step 2: Suspect score 0.45 -> escalates to ALERT
    assert p.predict_action(dummy_state, 0.45, host_id=host) == Action.ALERT

    # Step 3 & 4: More alerts -> when reaches 3 alerts in past 10, escalates to RATE_LIMIT
    p.predict_action(dummy_state, 0.45, host_id=host)
    act = p.predict_action(dummy_state, 0.45, host_id=host)
    assert act == Action.RATE_LIMIT

    # Step 5: Critical high risk 0.90 -> escalates to ISOLATE
    assert p.predict_action(dummy_state, 0.90, host_id=host) == Action.ISOLATE
