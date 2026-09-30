"""Feature tests: formulas, documented edge cases, and the compatibility matrix."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.features import build_feature_matrix
from xrlids.features.compute import extract_semantics
from xrlids.features.registry import FeatureRegistryError


def test_rungs_have_expected_sizes(registry):
    assert len(registry.rung_features("R10")) == 10
    assert len(registry.rung_features("R15")) == 15
    assert len(registry.rung_features("R20")) == 20
    # rungs are nested: R15 starts with R10, R20 with R15
    assert registry.rung_features("R15")[:10] == registry.rung_features("R10")
    assert registry.rung_features("R20")[:15] == registry.rung_features("R15")


def test_schema_hash_is_order_sensitive(registry):
    assert registry.schema_hash("R10") != registry.schema_hash("R15")


def test_gate_covers_all_rung_features(registry):
    for rung in registry.rungs:
        for feature in registry.rung_features(rung):
            gate = registry.gate_for(feature)
            assert "Q1_live" in gate and "Q10_justify" in gate


def test_identifier_columns_are_excluded(registry):
    for col in ["Source IP", "src_ip", "Destination Port", "Flow ID", "Timestamp", "Label"]:
        assert registry.is_excluded_column(col), col
    assert not registry.is_excluded_column("packet_length_mean")


def test_zero_duration_rate_policy(cic_raw_frame, registry):
    fm = build_feature_matrix(cic_raw_frame, "cicids2017", "R10", registry, strict=True, validate=False)
    frame = fm.frame
    # row 0: 1s duration, 18 packets -> 18 pkt/s
    assert frame.loc[0, "flow_packets_per_s"] == pytest.approx(18.0)
    # row 1: 2s duration, 32 packets -> 16 pkt/s
    assert frame.loc[1, "flow_packets_per_s"] == pytest.approx(16.0)
    # row 2: zero packets and zero duration -> 0.0 (nothing happened)
    assert frame.loc[2, "flow_packets_per_s"] == pytest.approx(0.0)
    # row 3: zero duration but 5 packets -> undefined rate => NaN, never Infinity
    assert np.isnan(frame.loc[3, "flow_packets_per_s"])
    assert not np.isinf(frame.loc[3, "flow_packets_per_s"])


def test_syn_ack_ratio_denominator_floored(cic_raw_frame, registry):
    fm = build_feature_matrix(cic_raw_frame, "cicids2017", "R10", registry, strict=True, validate=False)
    # row 0 has SYN=1, ACK=0 -> ratio 1/1 = 1
    assert fm.frame.loc[0, "syn_ack_ratio"] == pytest.approx(1.0)
    # row 3 has SYN=5, ACK=0 -> ratio 5
    assert fm.frame.loc[3, "syn_ack_ratio"] == pytest.approx(5.0)


def test_flow_duration_converted_to_ms(cic_raw_frame, registry):
    fm = build_feature_matrix(cic_raw_frame, "cicids2017", "R10", registry, strict=True, validate=False)
    assert fm.frame.loc[0, "flow_duration_ms"] == pytest.approx(1000.0)


def test_unsupported_features_reported_for_unsw(registry):
    """UNSW-NB15 cannot satisfy the R10 contract; that must be visible, not hidden."""
    unsupported = registry.unsupported_features("unsw_nb15", "R10")
    assert "syn_count" in unsupported
    assert not registry.rung_fully_supported("unsw_nb15", "R10")
    assert registry.rung_fully_supported("cicids2017", "R10")


def test_extract_semantics_fails_loudly_on_missing_columns(registry):
    from xrlids.features.compute import FeatureValidationError

    with pytest.raises(FeatureValidationError, match="missing required raw columns"):
        extract_semantics(pd.DataFrame({"Flow Duration": [1.0]}), "cicids2017", registry, strict=True)


def test_infinite_values_rejected_by_validation(registry):
    from xrlids.features.compute import FeatureValidationError, validate_feature_matrix

    frame = pd.DataFrame({"a": [1.0, np.inf], "b": [1.0, 2.0]})
    with pytest.raises(FeatureValidationError, match="infinite"):
        validate_feature_matrix(frame, ["a", "b"], strict=True)
