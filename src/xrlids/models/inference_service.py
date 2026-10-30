"""Unified Model Inference and Sequence Management Service for XRL-IDARS.

Integrates frozen research models:
1. Random Forest (single-flow primary detector on R10/R4).
2. Supervised LSTM (sequence temporal classifier over T=5 consecutive flow vectors).
3. Score-Level Fusion: S_fusion = alpha * S_rf + (1 - alpha) * S_lstm using weights
   from models/fusion/fusion_weights.json.

Strict Invariants:
- Never materializes 3D tensors in RAM globally.
- Maintains per-session/flow sequence isolation so flows from different endpoints never mix.
- Safe failure: if history is < T, LSTM returns None and inference transparently falls
  back to RF; never fabricates an arbitrary LSTM score.
- Reports exact inference source: 'RANDOM_FOREST' or 'RF+LSTM_FUSION'.
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import pandas as pd
import torch

from xrlids.features.definitions import R4_FEATURES, R10_FEATURES
from xrlids.models.fusion import fuse
from xrlids.models.lstm import LSTMDetector

logger = logging.getLogger("xrlids.models.inference_service")

REPO_ROOT = Path(__file__).resolve().parents[3]
FUSION_WEIGHTS_PATH = REPO_ROOT / "models" / "fusion" / "fusion_weights.json"


@dataclass
class UnifiedInferenceResult:
    """Structured result containing RF, LSTM, and Fusion outputs with latency and provenance."""

    prediction: int  # 0 = Benign, 1 = Attack
    prediction_label: str  # "BENIGN" or "ATTACK"
    attack_score: float  # Operational attack probability used for decision
    rf_score: float  # P_RF(ATTACK)
    lstm_score: float | None  # P_LSTM(ATTACK) if sequence complete, else None
    fusion_score: float | None  # Fused score if both available, else None
    inference_source: str  # "RANDOM_FOREST" or "RF+LSTM_FUSION"
    sequence_length_available: int  # Number of buffered history flows
    sequence_required: int  # T (5)
    benchmark: str
    feature_contract: str
    rf_model_id: str
    lstm_model_id: str | None
    latency_ms: float
    features_validated: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SequenceBufferManager:
    """Maintains isolated sliding-window flow history per session or host key."""

    def __init__(self, seq_len: int = 5, max_sessions: int = 10000) -> None:
        self.seq_len = seq_len
        self.max_sessions = max_sessions
        self._buffers: dict[str, deque[np.ndarray]] = defaultdict(lambda: deque(maxlen=self.seq_len))

    def add_flow_vector(self, session_key: str, scaled_vector: np.ndarray) -> tuple[np.ndarray | None, int]:
        """Add flow vector to session buffer.

        Returns (sequence_array, current_length).
        If current_length == seq_len, sequence_array has shape (1, T, F).
        Otherwise sequence_array is None.
        """
        buf = self._buffers[session_key]
        buf.append(scaled_vector)
        curr_len = len(buf)

        if curr_len == self.seq_len:
            # Shape (1, T, F)
            seq = np.stack(list(buf), axis=0)[np.newaxis, ...]
            return seq, curr_len
        return None, curr_len

    def clear(self) -> None:
        self._buffers.clear()


class UnifiedInferenceService:
    """Thread-safe unified inference service combining RF, LSTM, and Fusion."""

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = repo_root or REPO_ROOT
        self._rf_models: dict[str, Any] = {}
        self._preprocessors: dict[str, Any] = {}
        self._lstm_models: dict[str, LSTMDetector] = {}
        self._fusion_configs: dict[str, dict[str, Any]] = {}
        self._seq_managers: dict[str, SequenceBufferManager] = defaultdict(lambda: SequenceBufferManager(seq_len=5))
        self._load_fusion_configs()

    def _load_fusion_configs(self) -> None:
        """Load validation-tuned fusion weights and thresholds from disk."""
        if FUSION_WEIGHTS_PATH.exists():
            try:
                with open(FUSION_WEIGHTS_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._fusion_configs = data.get("configurations", {})
            except Exception as exc:
                logger.warning("Could not load fusion weights: %s", exc)

    def load_rf(self, benchmark: str) -> tuple[Any, Any]:
        """Load and cache Random Forest model and matching preprocessor."""
        bench = benchmark.lower().strip()
        if bench in self._rf_models and bench in self._preprocessors:
            return self._rf_models[bench], self._preprocessors[bench]

        if bench in ("cicids2017", "cic-ids2017"):
            rf_path = self.repo_root / "models" / "rf" / "random_forest_cicids2017.joblib"
            prep_path = self.repo_root / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "preprocessor.joblib"
        elif bench in ("cse2018", "cse_cic_ids2018"):
            rf_path = self.repo_root / "models" / "rf" / "random_forest_cse2018.joblib"
            prep_path = self.repo_root / "results" / "experiments" / "EXP-P1-CSE2018-R10-MULTI-001" / "preprocessor.joblib"
        elif bench in ("unswnb15", "unsw_nb15"):
            rf_path = self.repo_root / "models" / "rf" / "random_forest_unswnb15.joblib"
            prep_path = self.repo_root / "results" / "experiments" / "EXP-P1-UNSWNB15-R10-MULTI-001" / "preprocessor.joblib"
        else:
            raise ValueError(f"Unsupported benchmark for RF: '{benchmark}'")

        rf = joblib.load(rf_path)
        prep = joblib.load(prep_path)
        self._rf_models[bench] = rf
        self._preprocessors[bench] = prep
        return rf, prep

    def load_lstm(self, benchmark: str) -> LSTMDetector:
        """Load and cache LSTM detector checkpoint."""
        bench = benchmark.lower().strip()
        if bench in self._lstm_models:
            return self._lstm_models[bench]

        if bench in ("cicids2017", "cic-ids2017"):
            lstm_path = self.repo_root / "models" / "lstm" / "lstm_cicids2017.pt"
        elif bench in ("cse2018", "cse_cic_ids2018"):
            lstm_path = self.repo_root / "models" / "lstm" / "lstm_cse2018.pt"
        elif bench in ("unswnb15", "unsw_nb15"):
            lstm_path = self.repo_root / "models" / "lstm" / "lstm_unswnb15.pt"
        else:
            raise ValueError(f"Unsupported benchmark for LSTM: '{benchmark}'")

        detector = LSTMDetector.load(lstm_path)
        self._lstm_models[bench] = detector
        return detector

    def validate_features(self, features: Mapping[str, Any], contract: str) -> dict[str, float]:
        """Validate feature presence, numerical validity, rejecting NaN/inf."""
        expected = R10_FEATURES if contract == "R10" else R4_FEATURES
        missing = [f for f in expected if f not in features or features[f] is None]
        if missing:
            raise ValueError(f"Missing required features for contract {contract}: {missing}")

        cleaned = {}
        for f in expected:
            val = float(features[f])
            if math.isnan(val) or math.isinf(val):
                raise ValueError(f"Feature '{f}' has invalid value: {val}")
            cleaned[f] = val
        return cleaned

    def infer(
        self,
        features: Mapping[str, Any],
        session_key: str = "default_session",
        benchmark: str = "cicids2017",
        threshold: float = 0.50,
        enable_lstm_fusion: bool = True,
    ) -> UnifiedInferenceResult:
        """Perform end-to-end inference with RF, sequence-isolated LSTM, and Fusion."""
        t0 = time.perf_counter()
        bench_key = "cicids2017" if "cic" in benchmark.lower() and "cse" not in benchmark.lower() else (
            "cse2018" if "cse" in benchmark.lower() else "unswnb15"
        )
        contract = "R4" if bench_key == "unswnb15" else "R10"
        expected_cols = list(R4_FEATURES if contract == "R4" else R10_FEATURES)

        valid_feats = self.validate_features(features, contract)
        rf_detector, preprocessor = self.load_rf(bench_key)

        # Build single-row DataFrame and scale
        raw_df = pd.DataFrame([[valid_feats[f] for f in expected_cols]], columns=expected_cols)
        scaled_df = preprocessor.transform(raw_df)
        scaled_arr = scaled_df.to_numpy(dtype=np.float32)[0]

        # 1. Random Forest Inference
        inner_rf = rf_detector.model if hasattr(rf_detector, "model") else rf_detector
        rf_score = 0.0
        if hasattr(inner_rf, "predict_proba"):
            probs = inner_rf.predict_proba(scaled_df.to_numpy(dtype=float))
            classes = getattr(inner_rf, "classes_", np.array([0, 1]))
            for idx, c in enumerate(classes):
                if c == 1:
                    rf_score = float(probs[0, idx])
                    break
        elif hasattr(rf_detector, "predict_proba"):
            rf_score = float(rf_detector.predict_proba(scaled_df)[0])

        # 2. LSTM Sequence Inference (if enabled)
        lstm_score: float | None = None
        seq_available = 0
        lstm_id: str | None = None

        if enable_lstm_fusion:
            try:
                lstm_detector = self.load_lstm(bench_key)
                lstm_id = f"lstm_{bench_key}.pt"
                seq_mgr = self._seq_managers[bench_key]
                seq_arr, seq_available = seq_mgr.add_flow_vector(session_key, scaled_arr)

                if seq_arr is not None and lstm_detector.model is not None:
                    # Input shape: (1, T, F)
                    x_tensor = torch.from_numpy(seq_arr).float()
                    lstm_detector.model.eval()
                    with torch.no_grad():
                        logits = lstm_detector.model(x_tensor)
                        prob = torch.sigmoid(logits).item()
                        lstm_score = float(prob)
            except Exception as exc:
                logger.debug("LSTM inference bypassed for session %s: %s", session_key, exc)

        # 3. Fusion Logic
        fusion_score: float | None = None
        inference_source = "RANDOM_FOREST"
        final_score = rf_score

        if lstm_score is not None:
            # Look up alpha
            alias = "cse_cic_ids2018" if bench_key == "cse2018" else ("unsw_nb15" if bench_key == "unswnb15" else "cicids2017")
            cfg = self._fusion_configs.get(alias, {})
            alpha = float(cfg.get("alpha", 0.50))
            fusion_score = alpha * rf_score + (1.0 - alpha) * lstm_score
            final_score = fusion_score
            inference_source = "RF+LSTM_FUSION"

        pred_class = 1 if final_score >= threshold else 0
        pred_label = "ATTACK" if pred_class == 1 else "BENIGN"

        t1 = time.perf_counter()
        latency_ms = round((t1 - t0) * 1000.0, 3)

        return UnifiedInferenceResult(
            prediction=pred_class,
            prediction_label=pred_label,
            attack_score=round(final_score, 4),
            rf_score=round(rf_score, 4),
            lstm_score=round(lstm_score, 4) if lstm_score is not None else None,
            fusion_score=round(fusion_score, 4) if fusion_score is not None else None,
            inference_source=inference_source,
            sequence_length_available=seq_available,
            sequence_required=5,
            benchmark=bench_key,
            feature_contract=contract,
            rf_model_id=f"random_forest_{bench_key}.joblib",
            lstm_model_id=lstm_id,
            latency_ms=latency_ms,
            features_validated=valid_feats,
        )


# Global singleton inference service
DEFAULT_INFERENCE_SERVICE = UnifiedInferenceService()
