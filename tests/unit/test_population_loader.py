"""Unit tests for Multi-File Dataset Population Loader and Accounting (Tasks 1, 2, 5, 6, 7)."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.datasets.population import (
    AccountingReconciliationError,
    DuplicateConflictReport,
    PopulationAccounting,
    PopulationConfig,
    analyze_duplicate_label_conflicts,
)


def test_population_accounting_reconciliation_pass():
    acct = PopulationAccounting(
        aggregate={
            "raw_rows": 1000,
            "removed_unknown_label": 50,
            "removed_invalid": 20,
            "removed_exact_duplicates": 30,
            "removed_non_finite": 10,
            "removed_feature_duplicates": 15,
            "removed_label_conflicts": 5,
            "final_modeling_rows": 870,  # 1000 - (50+20+30+10+15+5) = 870
        }
    )
    acct.validate_reconciliation()
    assert acct.reconciled is True


def test_population_accounting_reconciliation_fail():
    acct = PopulationAccounting(
        aggregate={
            "raw_rows": 1000,
            "removed_unknown_label": 50,
            "removed_invalid": 20,
            "removed_exact_duplicates": 30,
            "removed_non_finite": 10,
            "removed_feature_duplicates": 15,
            "removed_label_conflicts": 5,
            "final_modeling_rows": 900,  # Discrepancy: should be 870!
        }
    )
    with pytest.raises(AccountingReconciliationError, match="(?i)discrepancy"):
        acct.validate_reconciliation()


def test_analyze_duplicate_label_conflicts():
    # Construct 4 vectors:
    # Row 0 & 1: identical vector [1.0, 2.0], label 0 and label 1 (CONFLICT!)
    # Row 2 & 3: identical vector [3.0, 4.0], both label 0 (NO CONFLICT)
    # Row 4: unique vector [5.0, 6.0], label 1
    features = pd.DataFrame({
        "f1": [1.0, 1.0, 3.0, 3.0, 5.0],
        "f2": [2.0, 2.0, 4.0, 4.0, 6.0],
    })
    labels = pd.Series([0, 1, 0, 0, 1])
    prov = pd.DataFrame({
        "label_family": ["BENIGN", "DoS", "BENIGN", "BENIGN", "PortScan"],
        "source_file": ["file1.csv"] * 5,
    })

    # Policy: reject_conflicts
    retain_idx, report = analyze_duplicate_label_conflicts(
        features, labels, prov, policy="reject_conflicts"
    )

    assert report.total_conflicting_vectors == 1
    assert report.total_conflicting_rows == 2
    assert report.benign_attack_conflicts == 1
    assert report.rows_dropped == 2
    # Retained rows should be rows 2, 3, 4 (the non-conflicting ones)
    assert list(retain_idx) == [2, 3, 4]


def test_analyze_duplicate_label_conflicts_keep_first():
    features = pd.DataFrame({
        "f1": [1.0, 1.0, 5.0],
        "f2": [2.0, 2.0, 6.0],
    })
    labels = pd.Series([0, 1, 1])
    prov = pd.DataFrame({
        "label_family": ["BENIGN", "DoS", "PortScan"],
        "source_file": ["file1.csv"] * 3,
    })

    retain_idx, report = analyze_duplicate_label_conflicts(
        features, labels, prov, policy="keep_first"
    )

    assert report.total_conflicting_vectors == 1
    assert report.rows_dropped == 0
    assert len(retain_idx) == 3
