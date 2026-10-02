"""Tests for the frozen Main Cross-Dataset 10-Feature Contract (R10).

Verifies build spec sections 8-10, Decision D-002, and Task 1 requirements:
- Expected columns exist where direct.
- Mathematical derivations and unit conversions are verified.
- No silent feature substitution occurs.
- Feature order is strictly deterministic and schema hash is frozen.
- All 10 features are validated before model training.
- Live and offline inference schemas match.
- UNSW-NB15 correctly reports the 6-feature data-availability blocker.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.features.compute import (
    FeatureValidationError,
    compute_features,
    extract_semantics,
)
from xrlids.features.definitions import FEATURES, feature_spec
from xrlids.features.registry import FeatureRegistry, load_feature_registry
from xrlids.utils.hashing import feature_schema_hash

FROZEN_R10_FEATURES = (
    "flow_duration_ms",
    "flow_packets_per_s",
    "flow_bytes_per_s",
    "packet_length_mean",
    "packet_length_std",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "syn_ack_ratio",
)

FROZEN_R10_SCHEMA_HASH = (
    "d74897f18b669ea806488222fda4514b28b335921ce019ebd41fc49ff6b65e21"
)


@pytest.fixture
def registry() -> FeatureRegistry:
    return load_feature_registry()


def test_r10_contract_frozen_and_deterministic_order(registry: FeatureRegistry) -> None:
    """R10 contract must be marked frozen with exact deterministic feature ordering."""
    assert registry.status == "frozen"
    r10 = registry.rung_features("R10")
    assert tuple(r10) == FROZEN_R10_FEATURES
    assert len(r10) == 10
    # Schema hash must match the frozen hash
    assert feature_schema_hash(r10) == FROZEN_R10_SCHEMA_HASH
    assert registry.schema_hash("R10") == FROZEN_R10_SCHEMA_HASH


def test_all_10_features_are_live_compatible(registry: FeatureRegistry) -> None:
    """All 10 features of R10 must be live-compatible (computable by Scapy / packet builder)."""
    assert registry.rungs["R10"]["live_compatible"] is True
    for feat in FROZEN_R10_FEATURES:
        spec = feature_spec(feat)
        assert spec.live_available is True, f"Feature {feat} must be live_available"


def test_cicids2017_full_10_feature_support(registry: FeatureRegistry) -> None:
    """CIC-IDS2017 must support all 10 features without missing columns or absent semantics."""
    assert registry.rung_fully_supported("cicids2017", "R10") is True
    assert registry.unsupported_features("cicids2017", "R10") == []

    # Mock CIC-IDS2017 canonical frame
    mock_cic = pd.DataFrame(
        {
            "Flow Duration": [1000000.0, 500000.0],  # 1s, 0.5s (in microseconds)
            "Total Fwd Packets": [10, 5],
            "Total Backward Packets": [10, 5],
            "Total Length of Fwd Packets": [1000, 500],
            "Total Length of Bwd Packets": [1000, 500],
            "Packet Length Mean": [100.0, 100.0],
            "Packet Length Std": [15.0, 10.0],
            "SYN Flag Count": [1, 0],
            "ACK Flag Count": [2, 1],
            "RST Flag Count": [0, 0],
            "FIN Flag Count": [1, 1],
            # extra fields required by extraction
            "Flow IAT Mean": [1000.0, 1000.0],
            "Flow IAT Std": [50.0, 50.0],
            "Fwd Packet Length Mean": [100.0, 100.0],
            "Bwd Packet Length Mean": [100.0, 100.0],
            "Active Mean": [0.0, 0.0],
            "Idle Mean": [0.0, 0.0],
            "Subflow Fwd Bytes": [1000, 500],
            "Subflow Bwd Bytes": [1000, 500],
        }
    )

    semantics, report = extract_semantics(mock_cic, "cicids2017", registry, strict=True)
    assert report["semantic_absent"] == []
    assert report["raw_columns_missing"] == []

    feats, avail, unavail = compute_features(
        semantics, registry.rung_features("R10"), dataset="cicids2017", strict=True
    )
    assert unavail == []
    assert len(avail) == 10

    # Verify unit conversions
    # 1,000,000 microseconds * 1e-6 * 1000 = 1,000 ms
    assert feats.loc[0, "flow_duration_ms"] == 1000.0
    # 20 packets / 1 second = 20 packets/s
    assert feats.loc[0, "flow_packets_per_s"] == 20.0
    # 2000 bytes / 1 second = 2000 bytes/s
    assert feats.loc[0, "flow_bytes_per_s"] == 2000.0
    # syn_ack_ratio = 1 / max(2, 1) = 0.5
    assert feats.loc[0, "syn_ack_ratio"] == 0.5


def test_cse_cic_ids2018_full_10_feature_support(registry: FeatureRegistry) -> None:
    """CSE-CIC-IDS2018 must support all 10 features with 100% semantic parity with CIC-IDS2017."""
    assert registry.rung_fully_supported("cse_cic_ids2018", "R10") is True
    assert registry.unsupported_features("cse_cic_ids2018", "R10") == []

    mock_cse = pd.DataFrame(
        {
            "Flow Duration": [2000000.0],  # 2s in microseconds
            "Tot Fwd Pkts": [20],
            "Tot Bwd Pkts": [30],
            "TotLen Fwd Pkts": [2000],
            "TotLen Bwd Pkts": [3000],
            "Pkt Len Mean": [100.0],
            "Pkt Len Std": [25.0],
            "SYN Flag Cnt": [1],
            "ACK Flag Cnt": [0],  # test zero ACK handling
            "RST Flag Cnt": [1],
            "FIN Flag Cnt": [0],
            # extra fields
            "Flow IAT Mean": [2000.0],
            "Flow IAT Std": [100.0],
            "Fwd Pkt Len Mean": [100.0],
            "Bwd Pkt Len Mean": [100.0],
            "Active Mean": [0.0],
            "Idle Mean": [0.0],
            "Subflow Fwd Byts": [2000],
            "Subflow Bwd Byts": [3000],
        }
    )

    semantics, report = extract_semantics(mock_cse, "cse_cic_ids2018", registry, strict=True)
    assert report["semantic_absent"] == []

    feats, avail, unavail = compute_features(
        semantics, registry.rung_features("R10"), dataset="cse_cic_ids2018", strict=True
    )
    assert unavail == []
    assert feats.loc[0, "flow_duration_ms"] == 2000.0
    assert feats.loc[0, "flow_packets_per_s"] == 25.0  # 50 pkts / 2 s
    assert feats.loc[0, "flow_bytes_per_s"] == 2500.0  # 5000 bytes / 2 s
    # syn_ack_ratio with 0 ACK: 1 / max(0, 1) = 1.0 (no division by zero)
    assert feats.loc[0, "syn_ack_ratio"] == 1.0


def test_unsw_nb15_reports_blocker_on_missing_6_features(registry: FeatureRegistry) -> None:
    """UNSW-NB15 must report exactly 4 supported features and 6 unsupported features."""
    supported = registry.features_supported("unsw_nb15", "R10")
    unsupported = registry.unsupported_features("unsw_nb15", "R10")

    assert set(supported) == {
        "flow_duration_ms",
        "flow_packets_per_s",
        "flow_bytes_per_s",
        "packet_length_mean",
    }
    assert set(unsupported) == {
        "packet_length_std",
        "syn_count",
        "ack_count",
        "rst_count",
        "fin_count",
        "syn_ack_ratio",
    }
    assert registry.rung_fully_supported("unsw_nb15", "R10") is False

    mock_unsw = pd.DataFrame(
        {
            "dur": [0.5],
            "spkts": [10],
            "dpkts": [10],
            "sbytes": [500],
            "dbytes": [500],
        }
    )

    # In strict mode, extract_semantics must fail loudly
    with pytest.raises(FeatureValidationError):
        extract_semantics(mock_unsw, "unsw_nb15", registry, strict=True)

    # In non-strict mode, extract_semantics reports absent semantics
    semantics, report = extract_semantics(mock_unsw, "unsw_nb15", registry, strict=False)
    assert "syn_flags" in report["semantic_absent"]
    assert "ack_flags" in report["semantic_absent"]
    assert "pkt_len_std" in report["semantic_absent"]

    # When computing R10 features, missing 6 features must be in unavailable list
    _, avail, unavail = compute_features(
        semantics, registry.rung_features("R10"), dataset="unsw_nb15", strict=False
    )
    assert set(avail) == set(supported)
    assert set(unavail) == set(unsupported)


def test_common_transfer_contract_intersection(registry: FeatureRegistry) -> None:
    """Transfer contract between CIC and CSE is full 10 features; with UNSW it is 4 features."""
    cic_cse_transfer = registry.common_transfer_contract("cicids2017", "cse_cic_ids2018", candidate_features="R10")
    assert len(cic_cse_transfer) == 10
    assert set(cic_cse_transfer) == set(FROZEN_R10_FEATURES)

    cic_unsw_transfer = registry.common_transfer_contract("cicids2017", "unsw_nb15", candidate_features="R10")
    assert len(cic_unsw_transfer) == 4
    assert set(cic_unsw_transfer) == {
        "flow_duration_ms",
        "flow_packets_per_s",
        "flow_bytes_per_s",
        "packet_length_mean",
    }


def test_no_silent_feature_substitution(registry: FeatureRegistry) -> None:
    """Missing declared columns must raise KeyError / FeatureValidationError, never substitute."""
    incomplete_frame = pd.DataFrame(
        {
            "Flow Duration": [1000.0],
            # missing Total Fwd Packets, etc.
        }
    )
    with pytest.raises(FeatureValidationError):
        extract_semantics(incomplete_frame, "cicids2017", registry, strict=True)
