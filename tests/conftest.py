"""Shared test fixtures. All fixtures are tiny and deterministic (build spec section 34)."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.features.registry import load_feature_registry
from xrlids.labels.contract import load_label_contract


@pytest.fixture(scope="session")
def registry():
    return load_feature_registry("configs/features/features.yaml")


@pytest.fixture(scope="session")
def contract():
    return load_label_contract("configs/labels/label_mapping.yaml")


@pytest.fixture
def cic_raw_frame() -> pd.DataFrame:
    """Minimal CIC-shaped frame exercising zero-duration and zero-ACK edge cases."""
    return pd.DataFrame(
        {
            "Flow Duration": [1_000_000, 2_000_000, 0, 0],
            "Total Fwd Packets": [10, 20, 0, 5],
            "Total Backward Packets": [8, 12, 0, 0],
            "Total Length of Fwd Packets": [1000, 2000, 0, 500],
            "Total Length of Bwd Packets": [800, 1200, 0, 0],
            "Packet Length Mean": [100.0, 120.0, 0.0, 100.0],
            "Packet Length Std": [10.0, 20.0, 0.0, 0.0],
            "SYN Flag Count": [1, 2, 0, 5],
            "ACK Flag Count": [0, 5, 0, 0],
            "RST Flag Count": [0, 1, 0, 1],
            "FIN Flag Count": [2, 3, 0, 0],
            "Flow IAT Mean": [5000, 6000, 0, 0],
            "Flow IAT Std": [100, 200, 0, 0],
            "Fwd Packet Length Mean": [100.0, 120.0, 0.0, 100.0],
            "Bwd Packet Length Mean": [100.0, 120.0, 0.0, 0.0],
            "Active Mean": [1000, 2000, 0, 0],
            "Idle Mean": [2000, 3000, 0, 0],
            "Subflow Fwd Bytes": [600, 700, 0, 300],
            "Subflow Bwd Bytes": [400, 500, 0, 0],
            "Label": ["BENIGN", "DoS Hulk", "BENIGN", "PortScan"],
        }
    )


@pytest.fixture
def binary_labels() -> pd.Series:
    return pd.Series([0, 1, 1, 0, 1, 0, 1, 1, 0, 1])


@pytest.fixture
def scores_perfect(binary_labels: pd.Series) -> np.ndarray:
    return np.array([0.1, 0.9, 0.8, 0.2, 0.95, 0.05, 0.7, 0.6, 0.3, 0.85])
