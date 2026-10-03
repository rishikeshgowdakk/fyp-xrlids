"""Unit tests verifying Phase 2 causal state representation (Task 3 & 12)."""

import numpy as np
import pytest

from xrlids.response.state import StateBuilder
from xrlids.response.types import Action


def test_state_builder_dimensions_and_initial_bounds():
    """Verify that StateBuilder constructs a 6D float32 vector within mathematical bounds."""
    builder = StateBuilder()
    state = builder.build_state(attack_score=0.45, flow_bytes_per_s=1000.0)

    assert isinstance(state, np.ndarray)
    assert state.shape == (6,)
    assert state.dtype == np.float32

    # s0: attack score in [0, 1]
    assert 0.0 <= state[0] <= 1.0
    assert np.isclose(state[0], 0.45)

    # s1: score trajectory (0.0 on step 0 with no history)
    assert -1.0 <= state[1] <= 1.0
    assert state[1] == 0.0

    # s2: alert density in [0, 1] (0.0 because 0.45 < 0.50)
    assert 0.0 <= state[2] <= 1.0
    assert state[2] == 0.0

    # s3: previous action (0.0 for ALLOW)
    assert 0.0 <= state[3] <= 1.0
    assert state[3] == 0.0

    # s4: cooldown remaining (0.0 on start)
    assert 0.0 <= state[4] <= 1.0
    assert state[4] == 0.0

    # s5: volumetric scale in [0, 1]
    # log10(1 + 1000) / 8.0 = ~3.0 / 8.0 = ~0.375
    assert 0.0 <= state[5] <= 1.0
    assert 0.35 <= state[5] <= 0.40


def test_state_builder_score_trajectory_causality():
    """Verify trajectory s1 = S_t - mean(S_{t-k : t-1}) over past k=5 steps."""
    builder = StateBuilder(score_trajectory_k=5)

    # Feed past scores: 0.1, 0.1, 0.1
    for _ in range(3):
        builder.update_history(attack_score=0.1, enforced_action=Action.ALLOW, cooldown_remaining=0)

    # Now step with higher score 0.6 -> trajectory should be 0.6 - 0.1 = +0.5
    state = builder.build_state(attack_score=0.6, flow_bytes_per_s=0.0)
    assert np.isclose(state[1], 0.5, atol=1e-5)


def test_state_builder_alert_density_causality():
    """Verify alert density s2 accurately reflects windowed fraction of scores >= 0.50."""
    builder = StateBuilder(alert_density_window_w=4, alert_threshold=0.50)

    # Feed 2 benign and 1 alert
    builder.update_history(0.1, Action.ALLOW, 0)
    builder.update_history(0.2, Action.ALLOW, 0)
    builder.update_history(0.8, Action.RATE_LIMIT, 0)

    # Current flow is an alert (0.9)
    # Window history has: [0, 0, 1] + [1] = 2 alerts out of 4 flows = 0.50
    state = builder.build_state(attack_score=0.9, flow_bytes_per_s=0.0)
    assert np.isclose(state[2], 0.50, atol=1e-5)


def test_state_builder_normalized_action_and_cooldown():
    """Verify previous action normalization and cooldown fraction."""
    builder = StateBuilder(cooldown_max_steps=30)

    # Cooldown remaining = 15 -> fraction = 15/30 = 0.5
    # Last action = ISOLATE (3) -> normalized = 3/3 = 1.0
    builder.update_history(0.5, Action.ISOLATE, cooldown_remaining=15)
    state = builder.build_state(attack_score=0.5, flow_bytes_per_s=0.0)

    assert np.isclose(state[3], 1.0)
    assert np.isclose(state[4], 0.5)


def test_state_builder_no_label_leakage():
    """Verify that build_state and StateBuilder contain no parameter or attribute for ground-truth label y."""
    builder = StateBuilder()
    import inspect

    sig = inspect.signature(builder.build_state)
    param_names = list(sig.parameters.keys())
    assert "y" not in param_names
    assert "y_true" not in param_names
    assert "label" not in param_names
    assert "ground_truth" not in param_names

    # Check instance attributes
    assert not hasattr(builder, "y")
    assert not hasattr(builder, "y_true")
    assert not hasattr(builder, "labels")
