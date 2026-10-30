"""Unit tests for the DQNResponseService and response recommendations."""

from pathlib import Path
import pytest
import torch

from xrlids.response.service import DQNResponseService, ResponseRecommendation
from xrlids.response.types import Action

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_dqn_service_initialization():
    service = DQNResponseService()
    assert service.network is not None
    assert service.action_dim == 4


def test_dqn_service_recommendation_benign_traffic():
    service = DQNResponseService()

    # Score S_t = 0.01 (clean benign flow)
    rec = service.recommend_action(
        attack_score=0.01,
        flow_bytes_per_s=1500.0,
        host_id="192.168.1.50",
    )

    assert isinstance(rec, ResponseRecommendation)
    assert rec.action == Action.ALLOW
    assert rec.action_index == 0
    assert len(rec.q_values) == 4
    assert len(rec.state_vector) == 6
    assert rec.state_vector[0] == pytest.approx(0.01)
    assert rec.best_q_value == max(rec.q_values.values())
    assert rec.inference_time_ms > 0
    assert "ALLOW" in rec.justification


def test_dqn_service_recommendation_attack_traffic():
    service = DQNResponseService()

    # Simulate heavy attack burst
    rec = None
    for _ in range(5):
        rec = service.recommend_action(
            attack_score=0.99,
            flow_bytes_per_s=10000000.0,
            host_id="10.0.0.99",
            auto_update_history=True,
        )

    assert rec is not None
    # For heavy repeated attack, DQN should select an active mitigation (ALERT, RATE_LIMIT, or ISOLATE)
    assert rec.action in (Action.ALERT, Action.RATE_LIMIT, Action.ISOLATE)
    assert rec.state_vector[0] == pytest.approx(0.99)
    assert rec.state_vector[2] > 0.5  # High alert density
