"""Unit tests verifying Phase 2 multi-dimensional evaluation metrics (Task 8 & 11)."""

import numpy as np
import pytest

from xrlids.response.metrics import (
    compute_action_chattering_index,
    compute_business_availability_score,
    compute_cumulative_cost,
    compute_false_quarantine_rate,
    compute_mean_cost,
    compute_mitigation_delay,
    compute_relative_cost_reduction,
    evaluate_response_run,
    paired_bootstrap_cost_comparison,
)
from xrlids.response.types import Action


def test_cumulative_and_mean_cost():
    """Verify cumulative and mean cost formulas."""
    costs = [1.0, 2.0, 3.0, 4.0]
    assert compute_cumulative_cost(costs) == 10.0
    assert compute_mean_cost(costs) == 2.5


def test_false_quarantine_rate():
    """Verify FQR computes fraction of benign flows erroneously isolated."""
    # 4 benign flows (y=0), 1 attack (y=1)
    # actions: [ALLOW, ISOLATE, RATE_LIMIT, ALLOW, ISOLATE(attack)]
    actions = [Action.ALLOW, Action.ISOLATE, Action.RATE_LIMIT, Action.ALLOW, Action.ISOLATE]
    y_true = [0, 0, 0, 0, 1]

    # Only flow 1 was a false quarantine (1 out of 4 benign flows)
    fqr = compute_false_quarantine_rate(actions, y_true)
    assert np.isclose(fqr, 0.25)


def test_action_chattering_index():
    """Verify ACI computes fraction of consecutive steps with |a_t - a_(t-1)| >= 2."""
    # sequence: ALLOW (0) -> ISOLATE (3) -> ALLOW (0) -> ALERT (1)
    # transitions:
    # 0 -> 3: delta 3 (>=2, yes)
    # 3 -> 0: delta 3 (>=2, yes)
    # 0 -> 1: delta 1 (<2, no)
    # Total transitions = 3, chattering jumps = 2 -> ACI = 2/3 = 0.667
    actions = [Action.ALLOW, Action.ISOLATE, Action.ALLOW, Action.ALERT]
    aci = compute_action_chattering_index(actions)
    assert np.isclose(aci, 2.0 / 3.0)


def test_business_availability_score():
    """Verify BAS computes percentage of benign flows that are uninterrupted (ALLOW)."""
    # 5 benign flows: 3 ALLOW, 1 ALERT, 1 RATE_LIMIT
    actions = [Action.ALLOW, Action.ALLOW, Action.ALLOW, Action.ALERT, Action.RATE_LIMIT]
    y_true = [0, 0, 0, 0, 0]
    bas = compute_business_availability_score(actions, y_true)
    assert np.isclose(bas, 60.0)


def test_mitigation_delay():
    """Verify mitigation delay computes steps from attack start to first mitigation (RATE_LIMIT or ISOLATE)."""
    # y: [0, 1, 1, 1, 0] (attack at step 1, 2, 3)
    # actions: [ALLOW, ALLOW, RATE_LIMIT, ISOLATE, ALLOW]
    # Attack started at step 1, mitigated at step 2 -> delay = 2 - 1 = 1 step
    actions = [Action.ALLOW, Action.ALLOW, Action.RATE_LIMIT, Action.ISOLATE, Action.ALLOW]
    y_true = [0, 1, 1, 1, 0]
    delay = compute_mitigation_delay(actions, y_true)
    assert np.isclose(delay, 1.0)


def test_relative_cost_reduction():
    """Verify relative cost reduction formula."""
    # Baseline cost = 100, policy cost = 75 -> 25% cost reduction
    red = compute_relative_cost_reduction(100.0, 75.0)
    assert np.isclose(red, 25.0)


def test_paired_bootstrap_cost_comparison():
    """Verify paired bootstrap hypothesis test comparing two policies."""
    # Policy A has high cost, Policy B has consistently lower cost
    costs_a = [10.0, 12.0, 15.0, 10.0, 14.0] * 20
    costs_b = [2.0, 3.0, 2.0, 1.0, 2.0] * 20

    res = paired_bootstrap_cost_comparison(
        costs_baseline=costs_a,
        costs_candidate=costs_b,
        baseline_name="Policy_A",
        candidate_name="Policy_B",
        n_bootstraps=500,
        seed=42,
    )

    assert res["is_significant"] is True
    assert res["superior_policy"] == "Policy_B"
    assert res["p_value"] < 0.01
    assert res["relative_cost_reduction_pct"] > 0.0
