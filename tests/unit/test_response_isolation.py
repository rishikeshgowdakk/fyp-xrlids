"""Unit tests for dataset isolation and policy population partitioning (Phase 2A Task 9)."""

import numpy as np
import pandas as pd
import pytest

from xrlids.response.isolation import (
    PolicySplitManifest,
    partition_policy_development_population,
)


def test_partition_policy_development_population_ratios():
    """Verify validation population is partitioned strictly into 60% train and 40% validation."""
    n_rows = 1000
    features = pd.DataFrame({
        "f1": np.random.randn(n_rows),
        "f2": np.random.randn(n_rows),
    })
    # 80% benign (0), 20% attack (1)
    labels = pd.Series(np.array([0] * 800 + [1] * 200))
    provenance = pd.DataFrame({"source_file": ["file1.csv"] * n_rows})

    feat_splits, label_splits, prov_splits, manifest = partition_policy_development_population(
        val_features=features,
        val_labels=labels,
        val_provenance=provenance,
        dataset="cicids2017",
        source_experiment_id="EXP-P1-CIC2017-R10-001",
        phase1_test_row_count=355865,
        train_fraction=0.60,
        seed=42,
    )

    # Row counts
    assert len(feat_splits["D_pol_train"]) == 600
    assert len(feat_splits["D_pol_val"]) == 400
    assert len(label_splits["D_pol_train"]) == 600
    assert len(label_splits["D_pol_val"]) == 400
    assert len(prov_splits["D_pol_train"]) == 600
    assert len(prov_splits["D_pol_val"]) == 400

    # Stratification check
    train_attack_ratio = np.mean(label_splits["D_pol_train"] == 1)
    val_attack_ratio = np.mean(label_splits["D_pol_val"] == 1)
    assert train_attack_ratio == pytest.approx(0.20, abs=0.01)
    assert val_attack_ratio == pytest.approx(0.20, abs=0.01)

    # Manifest verification
    assert isinstance(manifest, PolicySplitManifest)
    assert manifest.d_pol_train_rows == 600
    assert manifest.d_pol_val_rows == 400
    assert manifest.d_pol_test_untouched_rows == 355865
    assert len(manifest.manifest_hash) == 64  # SHA-256


def test_partition_empty_population_raises():
    """Verify attempting to partition an empty dataframe raises ValueError."""
    empty_features = pd.DataFrame()
    empty_labels = pd.Series(dtype=int)

    with pytest.raises(ValueError, match="Cannot partition empty validation population"):
        partition_policy_development_population(
            val_features=empty_features,
            val_labels=empty_labels,
        )


def test_partition_deterministic_reproducibility():
    """Verify partitioning with same seed yields bitwise identical splits."""
    features = pd.DataFrame({"f": np.arange(100)})
    labels = pd.Series([0, 1] * 50)

    res1 = partition_policy_development_population(features, labels, seed=42)
    res2 = partition_policy_development_population(features, labels, seed=42)

    pd.testing.assert_frame_equal(res1[0]["D_pol_train"], res2[0]["D_pol_train"])
    pd.testing.assert_frame_equal(res1[0]["D_pol_val"], res2[0]["D_pol_val"])
    assert res1[3].manifest_hash == res2[3].manifest_hash
