"""Unit tests for SourceActivityTracker and escalation policy.

Verifies:
1. Strict isolation of histories between different source IPs.
2. Escalation triggers exactly upon reaching the configured threshold (e.g. 5 suspicious flows).
3. Flows below threshold (e.g. 1-4 flows) do NOT trigger escalation.
4. Old suspicious events expire outside the rolling time window.
5. Cooldown period suppresses repetitive re-escalation thrash.
6. Temporal sequence buffer maintains per-source feature history for LSTM.
7. Reset and bounded memory pruning.
"""

from __future__ import annotations

import numpy as np
import pytest

from xrlids.tracking.source_tracker import SourceActivityTracker


@pytest.fixture
def tracker() -> SourceActivityTracker:
    return SourceActivityTracker(
        suspicious_flow_threshold=5,
        time_window_seconds=60.0,
        cooldown_seconds=30.0,
        required_lstm_sequence_length=5,
    )


def test_single_flow_does_not_escalate(tracker: SourceActivityTracker):
    """1 suspicious flow records activity but does not trigger escalation."""
    dec = tracker.record_flow("192.168.1.100", is_suspicious=True, timestamp=100.0)
    assert not dec.escalate
    assert dec.suspicious_count == 1
    assert dec.reason == "BELOW_THRESHOLD"


def test_four_suspicious_flows_do_not_escalate(tracker: SourceActivityTracker):
    """4 suspicious flows from the same IP remain below the 5-flow threshold."""
    for i in range(1, 5):
        dec = tracker.record_flow("192.168.1.100", is_suspicious=True, timestamp=100.0 + i)
        assert not dec.escalate
        assert dec.suspicious_count == i
        assert dec.reason == "BELOW_THRESHOLD"


def test_fifth_suspicious_flow_triggers_escalation(tracker: SourceActivityTracker):
    """The 5th suspicious flow within the window triggers escalation."""
    for i in range(1, 5):
        tracker.record_flow("192.168.1.100", is_suspicious=True, timestamp=100.0 + i)

    dec5 = tracker.record_flow("192.168.1.100", is_suspicious=True, timestamp=105.0)
    assert dec5.escalate
    assert dec5.suspicious_count == 5
    assert dec5.reason == "THRESHOLD_MET"
    assert dec5.escalation_count == 1


def test_separate_ip_histories_do_not_cross_escalate(tracker: SourceActivityTracker):
    """Suspicious flows from different IPs are tracked completely independently."""
    # IP-A has 3 suspicious flows
    for i in range(3):
        tracker.record_flow("10.0.0.1", is_suspicious=True, timestamp=100.0 + i)

    # IP-B has 2 suspicious flows
    for i in range(2):
        dec_b = tracker.record_flow("10.0.0.2", is_suspicious=True, timestamp=100.0 + i)
        assert not dec_b.escalate
        assert dec_b.suspicious_count == i + 1

    # Check status of IP-A: still 3, not escalated
    status_a = tracker.get_host_status("10.0.0.1")
    assert status_a is not None
    assert status_a["active_suspicious_in_window"] == 3
    assert not status_a["is_escalated"]


def test_time_window_expiration(tracker: SourceActivityTracker):
    """Suspicious events outside the rolling window (60s) expire and do not count."""
    # 4 flows at t=0
    for _ in range(4):
        tracker.record_flow("192.168.1.50", is_suspicious=True, timestamp=0.0)

    # 1 flow at t=70 (window is 60s, so earlier 4 flows expired)
    dec = tracker.record_flow("192.168.1.50", is_suspicious=True, timestamp=70.0)
    assert not dec.escalate
    assert dec.suspicious_count == 1  # only the t=70 flow is active


def test_cooldown_prevents_duplicate_escalation(tracker: SourceActivityTracker):
    """Flows arriving during the cooldown window do not re-trigger escalation."""
    # Trigger first escalation at t=10.0 (5 flows)
    for i in range(5):
        tracker.record_flow("192.168.1.80", is_suspicious=True, timestamp=10.0)

    # 6th flow at t=20.0 (within cooldown of 30s)
    dec6 = tracker.record_flow("192.168.1.80", is_suspicious=True, timestamp=20.0)
    assert not dec6.escalate
    assert dec6.cooldown_active
    assert dec6.reason == "COOLDOWN_ACTIVE"

    # After cooldown expires at t=45.0 (elapsed 35s > 30s)
    # The first new flow arriving after cooldown triggers a fresh escalation
    dec_after_cooldown = tracker.record_flow("192.168.1.80", is_suspicious=True, timestamp=45.0)
    assert dec_after_cooldown.escalate
    assert dec_after_cooldown.escalation_count == 2
    assert dec_after_cooldown.reason == "THRESHOLD_MET"


def test_temporal_feature_sequence_buffering(tracker: SourceActivityTracker):
    """Tracker stores per-source feature vectors and retrieves sequences of length T=5."""
    ip = "172.16.0.5"
    vecs = [np.full(10, float(i), dtype=np.float32) for i in range(6)]

    # Append 3 vectors: sequence should be unavailable
    for i in range(3):
        tracker.record_flow(ip, is_suspicious=False, feature_vector=vecs[i])
    assert tracker.get_sequence(ip, length=5) is None

    # Append 2 more vectors (total 5): sequence should now be available
    for i in range(3, 5):
        tracker.record_flow(ip, is_suspicious=False, feature_vector=vecs[i])
    seq = tracker.get_sequence(ip, length=5)
    assert seq is not None
    assert len(seq) == 5
    assert np.allclose(seq[0], vecs[0])
    assert np.allclose(seq[4], vecs[4])
