"""Unit tests verifying Phase 2 illustrative research cost engine (Task 6 & 12)."""

import pytest

from xrlids.response.costs import CostRegime, ResearchCostEngine
from xrlids.response.types import Action


def test_standard_enterprise_cost_matrix():
    """Verify research assumption baseline cost values for Standard Enterprise regime."""
    engine = ResearchCostEngine(regime=CostRegime.STANDARD_ENTERPRISE)

    # Benign traffic
    assert engine.compute_base_cost(Action.ALLOW, y_true=0) == 0.0
    assert engine.compute_base_cost(Action.ALERT, y_true=0) == 1.0
    assert engine.compute_base_cost(Action.RATE_LIMIT, y_true=0) == 15.0
    assert engine.compute_base_cost(Action.ISOLATE, y_true=0) == 60.0

    # Malicious traffic
    assert engine.compute_base_cost(Action.ALLOW, y_true=1) == 100.0
    assert engine.compute_base_cost(Action.ALERT, y_true=1) == 12.0
    assert engine.compute_base_cost(Action.RATE_LIMIT, y_true=1) == 6.0
    assert engine.compute_base_cost(Action.ISOLATE, y_true=1) == 2.0


def test_high_availability_regime():
    """Verify High Availability regime prioritizes service uptime (high penalty for false isolation)."""
    engine = ResearchCostEngine(regime=CostRegime.HIGH_AVAILABILITY)

    # False outage cost is 120.0 (double standard)
    assert engine.compute_base_cost(Action.ISOLATE, y_true=0) == 120.0
    # Missed attack penalty is lower (50.0)
    assert engine.compute_base_cost(Action.ALLOW, y_true=1) == 50.0


def test_high_security_enclave_regime():
    """Verify High Security Enclave prioritizes breach containment (catastrophic missed attack penalty)."""
    engine = ResearchCostEngine(regime=CostRegime.HIGH_SECURITY_ENCLAVE)

    # Missed attack is 500.0
    assert engine.compute_base_cost(Action.ALLOW, y_true=1) == 500.0
    # False outage is lower priority (25.0)
    assert engine.compute_base_cost(Action.ISOLATE, y_true=0) == 25.0


def test_action_chattering_penalty():
    """Verify chattering penalty applies only when |a_t - a_(t-1)| >= 2 during active cooldown."""
    engine = ResearchCostEngine(chattering_penalty_cost=10.0, chattering_action_delta_threshold=2)

    # Violent jump from ALLOW (0) to RATE_LIMIT (2) during cooldown -> 10.0 penalty
    assert engine.compute_chattering_penalty(Action.RATE_LIMIT, Action.ALLOW, in_cooldown=True) == 10.0

    # Violent jump when NOT in cooldown -> 0.0 penalty
    assert engine.compute_chattering_penalty(Action.RATE_LIMIT, Action.ALLOW, in_cooldown=False) == 0.0

    # Mild jump |ALERT - ALLOW| = 1 during cooldown -> 0.0 penalty
    assert engine.compute_chattering_penalty(Action.ALERT, Action.ALLOW, in_cooldown=True) == 0.0


def test_alert_fatigue_penalty():
    """Verify fatigue penalty scales linearly after exceeding 5 consecutive alerts."""
    engine = ResearchCostEngine(fatigue_threshold=5, fatigue_penalty_slope=0.5)

    assert engine.compute_fatigue_penalty(consecutive_alerts=3) == 0.0
    assert engine.compute_fatigue_penalty(consecutive_alerts=5) == 0.0
    # 7 consecutive alerts: (7 - 5) * 0.5 = 1.0
    assert engine.compute_fatigue_penalty(consecutive_alerts=7) == 1.0


def test_evaluate_step_composite_reward():
    """Verify step evaluation returns (base, chatter, fatigue, total_cost, reward) with reward = -total_cost."""
    engine = ResearchCostEngine()

    base, chatter, fatigue, total, reward = engine.evaluate_step(
        action=Action.ISOLATE,
        y_true=1,
        prev_action=Action.ISOLATE,
        in_cooldown=False,
        consecutive_alerts=0,
    )

    assert base == 2.0  # Attack contained
    assert chatter == 0.0
    assert fatigue == 0.0
    assert total == 2.0
    assert reward == -2.0
