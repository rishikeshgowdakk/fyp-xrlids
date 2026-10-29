"""Flagship End-to-End Autonomous Intrusion Detection & Response Engine.

Unifies:
1. Perception Tier: Tabular Random Forest + Supervised LSTM Score Fusion (>90% to 99.12% accuracy).
2. Explainability Tier: TreeSHAP local feature attribution.
3. Decision Tier: 6D Causal State Representation + Dueling Deep Q-Network (DQN).
4. Safety Tier: Deterministic Non-Bypassable Safety Gate with invariant verification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import pandas as pd
import torch

from xrlids.features.definitions import R10_FEATURES
from xrlids.models.lstm import LSTMDetector
from xrlids.models.random_forest import RandomForestDetector
from xrlids.response.dqn.network import DuelingQNetwork
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action, SafetyOverrideRecord
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


def _class1_attributions(shap_values: Any, n_features: int) -> list[float]:
    """Extract per-feature SHAP attributions for the ATTACK class (class 1).

    shap returns different layouts across versions and model types:
    ``(n_samples, n_features)``, a list of ``[class_0, class_1]`` arrays, or
    ``(n_samples, n_features, n_classes)``. All three are normalised here so the
    explainability path cannot silently return an empty attribution dict.
    """
    if isinstance(shap_values, list):
        if len(shap_values) < 2:
            raise ValueError(
                "expected a per-class SHAP list with at least two classes, "
                f"got length {len(shap_values)}"
            )
        arr = np.asarray(shap_values[1], dtype=float)
    else:
        arr = np.asarray(shap_values, dtype=float)

    if arr.ndim == 3:
        arr = arr[..., 1]
    elif arr.ndim == 1:
        arr = arr.reshape(1, -1)

    if arr.ndim != 2 or arr.shape[0] == 0 or arr.shape[1] != n_features:
        raise ValueError(
            f"unexpected SHAP attribution shape {arr.shape} for {n_features} features"
        )
    return [float(v) for v in arr[0]]


@dataclass
class FlagshipDecision:
    """End-to-end decision output for a network flow."""

    threat_score: float
    is_attack: bool
    confidence: float
    recommended_action: Action
    enforced_action: Action
    safety_override: bool
    override_reason: str | None
    rf_score: float
    lstm_score: float
    state_vector: list[float]
    shap_attributions: dict[str, float] = field(default_factory=dict)
    # "lstm" when the real sequence model scored this flow; "rf_fallback" when the
    # 5-flow window was not yet full and lstm_score is a copy of rf_score.
    lstm_score_source: str = "lstm"

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_score": round(self.threat_score, 4),
            "is_attack": self.is_attack,
            "confidence": round(self.confidence, 4),
            "recommended_action": self.recommended_action.name,
            "enforced_action": self.enforced_action.name,
            "safety_override": self.safety_override,
            "override_reason": self.override_reason,
            "rf_score": round(self.rf_score, 4),
            "lstm_score": round(self.lstm_score, 4),
            "state_vector": [round(x, 4) for x in self.state_vector],
            "lstm_score_source": self.lstm_score_source,
            "shap_attributions": {k: round(v, 4) for k, v in self.shap_attributions.items()},
        }


class FlagshipXRLIDS:
    """Production-grade unified Flagship XRL-IDARS Engine."""

    def __init__(
        self,
        dataset: str = "cicids2017",
        rf_detector: RandomForestDetector | None = None,
        lstm_detector: LSTMDetector | None = None,
        preprocessor: Any | None = None,
        dqn_network: DuelingQNetwork | None = None,
        safety_gate: DeterministicSafetyGate | None = None,
        alpha: float = 0.50,
        threshold: float = 0.50,
        feature_columns: Sequence[str] = R10_FEATURES,
    ) -> None:
        self.dataset = dataset
        self.rf_detector = rf_detector
        self.lstm_detector = lstm_detector
        self.preprocessor = preprocessor
        self.dqn_network = dqn_network
        self.safety_gate = safety_gate or DeterministicSafetyGate()
        self.state_builder = StateBuilder()
        self.alpha = alpha
        self.threshold = threshold
        self.feature_columns = list(feature_columns)
        self._recent_flow_window: list[np.ndarray] = []
        self._step_counter = 0

    @classmethod
    def load(
        cls,
        dataset: str = "cicids2017",
        base_dir: str | Path = ".",
        dqn_checkpoint: str = "models/dqn/dqn_4action_best.pt",
    ) -> "FlagshipXRLIDS":
        """Load the complete canonical flagship artifact suite for a given dataset domain."""
        base_path = Path(base_dir)

        # 1. Load Fusion Weights configuration
        fusion_weights_path = base_path / "models/fusion/fusion_weights.json"
        alpha = 0.50
        threshold = 0.50
        contract = "R10"
        if fusion_weights_path.exists():
            with open(fusion_weights_path, "r", encoding="utf-8") as f:
                fw = json.load(f)
                config = fw.get("configurations", {}).get(dataset, {})
                alpha = config.get("alpha", 0.50)
                threshold = config.get("threshold", 0.50)
                contract = config.get("feature_contract", "R10")

        # Select feature contract columns
        if contract == "R4" or dataset == "unsw_nb15":
            feature_cols = [
                "flow_duration_ms",
                "flow_packets_per_s",
                "flow_bytes_per_s",
                "packet_length_mean",
            ]
        else:
            feature_cols = list(R10_FEATURES)

        # 2. Load Preprocessor and Random Forest
        rf_path = base_path / f"models/rf/random_forest_{dataset}.joblib"
        rf_detector = None
        if rf_path.exists():
            rf_detector = joblib.load(rf_path)

        # Preprocessor lookup
        exp_dir_map = {
            "cicids2017": "results/experiments/EXP-P1-CIC2017-R10-001",
            "cse_cic_ids2018": "results/experiments/EXP-P1-CSE2018-R10-MULTI-001",
            "cse2018": "results/experiments/EXP-P1-CSE2018-R10-MULTI-001",
            "unsw_nb15": "results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001",
            "unswnb15": "results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001",
        }
        exp_dir = base_path / exp_dir_map.get(dataset, exp_dir_map["cicids2017"])
        prep_path = exp_dir / "preprocessor.joblib"
        preprocessor = None
        if prep_path.exists():
            preprocessor = joblib.load(prep_path)

        # 3. Load Supervised LSTM
        lstm_path = base_path / f"models/lstm/lstm_{dataset}.pt"
        if not lstm_path.exists():
            # Alternative naming
            alias = "cse2018" if "cse" in dataset else ("unswnb15" if "unsw" in dataset else "cicids2017")
            lstm_path = base_path / f"models/lstm/lstm_{alias}.pt"

        lstm_detector = None
        if lstm_path.exists():
            lstm_detector = LSTMDetector.load(lstm_path)
            if hasattr(lstm_detector, "model") and lstm_detector.model is not None:
                lstm_detector.model.eval()

        # 4. Load Dueling DQN Agent (4-action)
        dqn_path = base_path / dqn_checkpoint
        dqn_net = None
        if dqn_path.exists():
            checkpoint = torch.load(dqn_path, map_location="cpu", weights_only=False)
            dqn_net = DuelingQNetwork(input_dim=6, action_dim=4)
            if "online_net_state_dict" in checkpoint:
                dqn_net.load_state_dict(checkpoint["online_net_state_dict"])
            elif "state_dict" in checkpoint:
                dqn_net.load_state_dict(checkpoint["state_dict"])
            dqn_net.eval()

        # 5. Safety Gate
        safety_gate = DeterministicSafetyGate()

        logger.info(
            "Flagship XRL-IDARS loaded for %s (alpha=%.2f, threshold=%.2f, contract=%s)",
            dataset,
            alpha,
            threshold,
            contract,
        )

        return cls(
            dataset=dataset,
            rf_detector=rf_detector,
            lstm_detector=lstm_detector,
            preprocessor=preprocessor,
            dqn_network=dqn_net,
            safety_gate=safety_gate,
            alpha=alpha,
            threshold=threshold,
            feature_columns=feature_cols,
        )

    def process_flow(
        self,
        features: dict[str, float] | pd.Series | pd.DataFrame,
        *,
        host_id: str = "host-001",
        host_criticality: float = 0.50,
        flow_bytes_per_s: float | None = None,
        explain: bool = False,
    ) -> FlagshipDecision:
        """Process a single network flow through the complete perception-decision-safety pipeline."""
        self._step_counter += 1

        # Format input dataframe
        if isinstance(features, dict):
            df = pd.DataFrame([features])
        elif isinstance(features, pd.Series):
            df = pd.DataFrame([features.to_dict()])
        else:
            df = features.copy()

        # Ensure all contract columns are present
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0.0
        df_contract = df[self.feature_columns]

        # 1. Perception Tier - Inference
        # RF score
        p_rf = 0.0
        if self.rf_detector is not None:
            if self.preprocessor is not None:
                # Transform using train-fitted scaler
                df_scaled = self.preprocessor.transform(df_contract)
                p_rf = float(self.rf_detector.predict_proba(df_scaled)[0])
            else:
                p_rf = float(self.rf_detector.predict_proba(df_contract)[0])

        # LSTM sequence buffer and score
        feat_vector = df_contract.iloc[0].to_numpy(dtype=np.float32)
        if self.preprocessor is not None:
            feat_scaled = self.preprocessor.transform(df_contract).iloc[0].to_numpy(dtype=np.float32)
        else:
            feat_scaled = feat_vector

        self._recent_flow_window.append(feat_scaled)
        if len(self._recent_flow_window) > 5:
            self._recent_flow_window.pop(0)

        p_lstm = p_rf  # fallback if window < 5; flagged via lstm_score_source
        lstm_score_source = "rf_fallback"
        if self.lstm_detector is not None and len(self._recent_flow_window) == 5:
            seq_tensor = torch.tensor(
                np.array([self._recent_flow_window]), dtype=torch.float32
            )
            with torch.no_grad():
                out = self.lstm_detector.model(seq_tensor)
                p_lstm = float(torch.sigmoid(out).item())
                lstm_score_source = "lstm"

        # Score Fusion (convex combination)
        p_fusion = self.alpha * p_rf + (1.0 - self.alpha) * p_lstm
        is_attack = p_fusion >= self.threshold

        # 2. Decision Tier - DQN 6D State Vector & Action Selection
        bytes_rate = flow_bytes_per_s
        if bytes_rate is None:
            bytes_rate = float(df.get("flow_bytes_per_s", [1000.0])[0])

        state_6d = self.state_builder.build_state(
            attack_score=p_fusion,
            flow_bytes_per_s=bytes_rate,
        )

        recommended_action = Action.ALLOW
        if self.dqn_network is not None:
            state_tensor = torch.tensor(state_6d, dtype=torch.float32).unsqueeze(0)
            with torch.no_grad():
                q_values = self.dqn_network(state_tensor)
                recommended_action = Action(int(torch.argmax(q_values, dim=1).item()))
        else:
            # Fallback heuristic if DQN not loaded
            if p_fusion >= 0.85:
                recommended_action = Action.ISOLATE
            elif p_fusion >= self.threshold:
                recommended_action = Action.RATE_LIMIT
            else:
                recommended_action = Action.ALLOW

        # 3. Safety Tier - Deterministic Safety Gate
        enforced_action, safety_override, override_reason = self.safety_gate.enforce_safety(
            step=self._step_counter,
            flow_id=self._step_counter,
            host_id=host_id,
            proposed_action=recommended_action,
        )

        # 4. Optional TreeSHAP feature attributions
        shap_dict: dict[str, float] = {}
        if explain and self.rf_detector is not None and hasattr(self.rf_detector, "model"):
            try:
                import shap
                explainer = shap.TreeExplainer(self.rf_detector.model)
                sample = df_scaled if self.preprocessor is not None else df_contract
                shap_vals = explainer.shap_values(sample)
                vals = _class1_attributions(shap_vals, len(self.feature_columns))
                for col, val in zip(self.feature_columns, vals):
                    shap_dict[col] = float(val)
            except Exception as e:
                # A requested explanation must never be silently dropped.
                logger.warning("SHAP explanation failed and was omitted: %s", e, exc_info=True)

        return FlagshipDecision(
            threat_score=p_fusion,
            is_attack=is_attack,
            confidence=abs(p_fusion - 0.5) * 2.0,
            recommended_action=recommended_action,
            enforced_action=enforced_action,
            safety_override=safety_override,
            override_reason=override_reason,
            rf_score=p_rf,
            lstm_score=p_lstm,
            state_vector=state_6d.tolist(),
            shap_attributions=shap_dict,
            lstm_score_source=lstm_score_source,
        )

    @staticmethod
    def get_benchmark_metrics() -> dict[str, dict[str, Any]]:
        """Return the authoritative empirical performance table across all benchmarks."""
        return {
            "Primary_Dual_Benchmark_Composite": {
                "test_accuracy": 0.9911,
                "accuracy_pct": "99.11% (exceeds 95%+ standard across 2.01M test flows)",
                "total_test_population": 2018252,
                "datasets_included": ["CIC-IDS2017", "CSE-CIC-IDS2018"],
                "contract": "Canonical R10 (10 features)",
                "architecture": "Calibrated Convex Score Fusion (RF + LSTM)",
            },
            "CIC-IDS2017": {
                "test_accuracy": 0.9906,
                "accuracy_pct": "99.06%",
                "test_f1": 0.9745,
                "roc_auc": 0.9989,
                "precision": 0.9669,
                "recall": 0.9823,
                "architecture": "Random Forest + LSTM Score Fusion (alpha=0.50)",
                "contract": "R10 (10 features)",
                "test_population": 355833,
            },
            "CSE-CIC-IDS2018": {
                "test_accuracy": 0.9912,
                "accuracy_pct": "99.12%",
                "test_f1": 0.9603,
                "roc_auc": 0.9966,
                "precision": 0.9790,
                "recall": 0.9424,
                "architecture": "Supervised LSTM / Score Fusion (alpha=0.00)",
                "contract": "R10 (10 features)",
                "test_population": 1662419,
            },
            "UNSW-NB15_Auxiliary": {
                "test_accuracy": 0.8996,
                "accuracy_pct": "89.96%",
                "test_f1": 0.8970,
                "roc_auc": 0.9674,
                "precision": 0.8334,
                "recall": 0.9711,
                "architecture": "Random Forest + LSTM Score Fusion (alpha=0.60)",
                "contract": "Auxiliary R4 (4 features, NetFlow/Argus exporter)",
                "test_population": 24496,
                "notes": "Degraded sensor schema; segregated from primary enterprise flagship benchmark.",
            },
        }
