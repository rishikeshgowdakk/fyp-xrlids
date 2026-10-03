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
