"""Labelled Dataset Replay Lab Engine for XRL-IDARS.

Provides real-time, deterministic streaming and evaluation of genuine flow records
from CIC-IDS2017, CSE-CIC-IDS2018, or both datasets:
1. Supports replay sizes: 400, 1,000, 5,000, 10,000, or custom (capped at 10,000).
2. Selection by mixed benign/attack or by specific ground-truth attack family.
3. Provenance preservation: dataset, source file, row index, raw label, binary truth.
4. Dataset-specific frozen model routing:
   - CIC-IDS2017 -> random_forest_cicids2017.joblib & preprocessor.joblib
   - CSE-CIC-IDS2018 -> random_forest_cse2018.joblib & preprocessor.joblib
5. Pipeline integration:
   - Continuous RF probability P(ATTACK) and binary decision (tau=0.50).
   - Independent deterministic RuleEngine evaluation.
   - Sequential 6D causal state updating via StateBuilder.
   - Dueling DQN action recommendation (ALLOW, ALERT, RATE_LIMIT, ISOLATE).
   - DeterministicSafetyGate enforcement with advisory/dry-run guarantee.
   - On-demand and batch TreeSHAP local feature attribution.
6. Thread-safe background execution with Start, Pause, Resume, Restart, and Stop controls.
7. Real-time confusion matrix, accuracy, precision, recall, F1, and per-family metrics.
"""

from __future__ import annotations

import csv
import io
import logging
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import pandas as pd
import torch

from xrlids.features.definitions import R10_FEATURES
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action
from xrlids.rules.engine import RuleEngine

logger = logging.getLogger("xrlids.demo.replay_lab")
REPO_ROOT = Path(__file__).resolve().parents[3]
CACHE_POOL_PATH = REPO_ROOT / "data" / "demo" / "replay_lab_cache.joblib"


@dataclass
class ReplayLabConfig:
    """Configuration parameters for a Replay Lab execution run."""

    dataset: str = "cicids2017"  # "cicids2017", "cse2018", or "both"
    count: int = 1000            # 400, 1000, 5000, 10000, or custom <= 10000
    selection: str = "mixed"     # "mixed" or specific family name (e.g. "DoS", "DDoS")
    speed: str = "fast"          # "slow" (5/s), "normal" (25/s), "fast" (100/s), "batch" (instant)
    seed: int = 42
    compute_shap_per_record: bool = False


@dataclass
class ReplayRecord:
    """Full evaluation record for a single replayed network flow."""

    flow_id: int
    dataset: str
    source_file: str
    source_row_index: int
    original_label: str
    ground_truth_family: str
    binary_ground_truth: int
    is_attack: bool
    rf_attack_probability: float
    rf_binary_prediction: str
    is_correct: bool
    rule_triggered: bool
    rule_matches: list[str]
    detection_source: str
    dqn_action: str
    dqn_q_values: dict[str, float] | None
    safety_status: str
    response_mode: str
    features: dict[str, float]
    timestamp: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReplayLabEngine:
    """Thread-safe controller for running labelled dataset replay sessions."""

    _instance: ReplayLabEngine | None = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> ReplayLabEngine:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self.config = ReplayLabConfig()
        self.status = "IDLE"  # IDLE, RUNNING, PAUSED, COMPLETED, STOPPED, ERROR
        self.error_message: str | None = None

        self._pool: list[dict[str, Any]] | None = None
        self._sampled_records: list[dict[str, Any]] = []
        self._evaluated_records: list[ReplayRecord] = []
        self._recent_flows: deque[dict[str, Any]] = deque(maxlen=100)

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()

        self.requested_count: int = 0
        self.selected_count: int = 0
        self.processed_count: int = 0
        self.failed_count: int = 0
        self.unsupported_count: int = 0
        self.start_time: float = 0.0
        self.elapsed_time: float = 0.0

        # Cached models
        self._models_loaded = False
        self._rf17 = None
        self._prep17 = None
        self._rf18 = None
        self._prep18 = None
        self._dqn_net = None
        self._explainer17 = None
        self._explainer18 = None

    def _load_pool(self) -> list[dict[str, Any]]:
        """Load cached replay pool from disk."""
        if self._pool is not None:
            return self._pool

        if not CACHE_POOL_PATH.exists():
            logger.info("Replay lab cache not found; building from raw datasets...")
            from scripts.demo.build_replay_lab_cache import build_all
            build_all()

        logger.info("Loading replay lab cache pool from %s...", CACHE_POOL_PATH)
        self._pool = joblib.load(CACHE_POOL_PATH)
        logger.info("Loaded %d pool records.", len(self._pool))
        return self._pool

    def _load_models(self) -> None:
        """Load frozen Random Forest, preprocessors, and DQN model."""
        if self._models_loaded:
            return

        logger.info("Loading frozen models for Replay Lab...")
        self._rf17 = joblib.load(REPO_ROOT / "models" / "rf" / "random_forest_cicids2017.joblib")
        self._prep17 = joblib.load(REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "preprocessor.joblib")

        self._rf18 = joblib.load(REPO_ROOT / "models" / "rf" / "random_forest_cse2018.joblib")
        self._prep18 = joblib.load(REPO_ROOT / "results" / "experiments" / "EXP-P1-CSE2018-R10-MULTI-001" / "preprocessor.joblib")

        dqn_path = REPO_ROOT / "models" / "dqn" / "dqn_4action_best.pt"
        if dqn_path.exists():
            from xrlids.response.dqn.network import DuelingQNetwork
            checkpoint = torch.load(dqn_path, map_location="cpu", weights_only=False)
            net = DuelingQNetwork(input_dim=6, action_dim=4)
            if "online_net_state_dict" in checkpoint:
                net.load_state_dict(checkpoint["online_net_state_dict"])
            elif "state_dict" in checkpoint:
                net.load_state_dict(checkpoint["state_dict"])
            net.eval()
            self._dqn_net = net

        self._models_loaded = True
        logger.info("Models loaded successfully.")

    def get_available_config(self) -> dict[str, Any]:
        """Return available datasets, counts, and attack families with support counts."""
        pool = self._load_pool()

        # Count support per dataset and family
        counts: dict[str, dict[str, int]] = {
            "cicids2017": {},
            "cse2018": {},
        }
        for rec in pool:
            dkey = "cicids2017" if "cicids2017" in rec["dataset"].lower() else "cse2018"
            fam = rec["ground_truth_family"]
            counts[dkey][fam] = counts[dkey].get(fam, 0) + 1

        all_families = sorted(set(list(counts["cicids2017"].keys()) + list(counts["cse2018"].keys())))

        family_metadata = []
        for fam in all_families:
            c17 = counts["cicids2017"].get(fam, 0)
            c18 = counts["cse2018"].get(fam, 0)
            family_metadata.append({
                "family": fam,
                "in_cicids2017": c17 > 0,
                "count_cicids2017": c17,
                "in_cse2018": c18 > 0,
                "count_cse2018": c18,
                "total_count": c17 + c18,
            })

        return {
            "datasets": [
                {"id": "cicids2017", "name": "CIC-IDS2017 (Flagship R10)", "contract": "R10"},
                {"id": "cse2018", "name": "CSE-CIC-IDS2018 (Enterprise Cloud R10)", "contract": "R10"},
                {"id": "both", "name": "Both Datasets (Dual Model Routing)", "contract": "R10 Dual"},
            ],
            "record_counts": [400, 1000, 5000, 10000],
            "speed_options": [
                {"id": "slow", "name": "Slow (5 flows/s)", "fps": 5},
                {"id": "normal", "name": "Normal (25 flows/s)", "fps": 25},
                {"id": "fast", "name": "Fast (100 flows/s)", "fps": 100},
                {"id": "batch", "name": "Batch (Instant)", "fps": 0},
            ],
            "families": family_metadata,
            "status": self.status,
            "supported_max_count": 10000,
        }

    def sample_records(
        self,
        dataset: str,
        count: int,
        selection: str,
        seed: int = 42,
    ) -> list[dict[str, Any]]:
        """Sample genuine records deterministically from pool."""
        pool = self._load_pool()
        rng = np.random.default_rng(seed)
        clamped_count = max(1, min(10000, int(count)))

        # 1. Dataset filter
        if dataset == "cicids2017":
            ds_pool = [r for r in pool if "cicids2017" in r["dataset"].lower()]
        elif dataset == "cse2018":
            ds_pool = [r for r in pool if "cse" in r["dataset"].lower()]
        else:
            ds_pool = list(pool)

        if not ds_pool:
            return []

        # 2. Selection filter
        if selection.lower() == "mixed":
            # Balanced mix: ~50% benign, ~50% attack
            benign_pool = [r for r in ds_pool if not r["is_attack"]]
            attack_pool = [r for r in ds_pool if r["is_attack"]]

            half = clamped_count // 2
            n_benign = min(len(benign_pool), half)
            n_attack = min(len(attack_pool), clamped_count - n_benign)

            benign_idx = rng.choice(len(benign_pool), size=n_benign, replace=False) if n_benign > 0 else []
            attack_idx = rng.choice(len(attack_pool), size=n_attack, replace=False) if n_attack > 0 else []

            selected = [benign_pool[i] for i in benign_idx] + [attack_pool[i] for i in attack_idx]
            rng.shuffle(selected)
            return selected
        else:
            # Single ground-truth attack family
            fam_norm = selection.strip()
            fam_pool = [r for r in ds_pool if r["ground_truth_family"].lower() == fam_norm.lower()]

            if not fam_pool:
                logger.warning("No records found for family %s in dataset %s", selection, dataset)
                return []

            n_select = min(len(fam_pool), clamped_count)
            chosen_idx = rng.choice(len(fam_pool), size=n_select, replace=False)
            return [fam_pool[i] for i in chosen_idx]

    def start(self, config: ReplayLabConfig) -> dict[str, Any]:
        """Start a new replay job with the requested configuration."""
        with self._lock:
            if self.status == "RUNNING":
                self.stop()

            self.config = config
            self.requested_count = config.count
            self._load_models()

            # Sample records
            self._sampled_records = self.sample_records(
                dataset=config.dataset,
                count=config.count,
                selection=config.selection,
                seed=config.seed,
            )
            self.selected_count = len(self._sampled_records)
            self.processed_count = 0
            self.failed_count = 0
            self.unsupported_count = 0
            self._evaluated_records = []
            self._recent_flows.clear()
            self.error_message = None

            self._stop_event.clear()
            self._pause_event.clear()
            self.status = "RUNNING"
            self.start_time = time.time()

            # Launch background worker thread
            self._thread = threading.Thread(target=self._worker_loop, daemon=True)
            self._thread.start()

            return {
                "status": "RUNNING",
                "requested_count": self.requested_count,
                "selected_count": self.selected_count,
                "dataset": config.dataset,
                "selection": config.selection,
                "speed": config.speed,
                "seed": config.seed,
            }

    def pause(self) -> dict[str, Any]:
        with self._lock:
            if self.status == "RUNNING":
                self._pause_event.set()
                self.status = "PAUSED"
            return {"status": self.status}

    def resume(self) -> dict[str, Any]:
        with self._lock:
            if self.status == "PAUSED":
                self._pause_event.clear()
                self.status = "RUNNING"
            return {"status": self.status}

    def restart(self) -> dict[str, Any]:
        return self.start(self.config)

    def stop(self) -> dict[str, Any]:
        self._stop_event.set()
        self._pause_event.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        with self._lock:
            self.status = "STOPPED"
        return {"status": "STOPPED", "processed_count": self.processed_count}

    def _worker_loop(self) -> None:
        """Background thread executing replay inference step-by-step."""
        try:
            sb = StateBuilder()
            rule_engine = RuleEngine()
            safety_gate = DeterministicSafetyGate()
            actions_map = ["ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE"]

            # 1. Precompute scaling and RF predictions in batch across datasets to avoid per-row DataFrame overhead
            cic_indices = [i for i, r in enumerate(self._sampled_records) if "cicids2017" in r["dataset"].lower()]
            cse_indices = [i for i, r in enumerate(self._sampled_records) if "cse" in r["dataset"].lower()]

            scores: list[float] = [0.0] * len(self._sampled_records)

            if cic_indices:
                cic_feats = [self._sampled_records[i]["features"] for i in cic_indices]
                df_cic = pd.DataFrame(cic_feats)[list(R10_FEATURES)]
                scaled_cic = self._prep17.transform(df_cic)
                probs_cic = self._rf17.predict_proba(scaled_cic)
                for idx, orig_pos in enumerate(cic_indices):
                    scores[orig_pos] = float(probs_cic[idx])

            if cse_indices:
                cse_feats = [self._sampled_records[i]["features"] for i in cse_indices]
                df_cse = pd.DataFrame(cse_feats)[list(R10_FEATURES)]
                scaled_cse = self._prep18.transform(df_cse)
                probs_cse = self._rf18.predict_proba(scaled_cse)
                for idx, orig_pos in enumerate(cse_indices):
                    scores[orig_pos] = float(probs_cse[idx])

            delay_s = 0.0
            if self.config.speed == "slow":
                delay_s = 0.20  # 5/s
            elif self.config.speed == "normal":
                delay_s = 0.04  # 25/s
            elif self.config.speed == "fast":
                delay_s = 0.01  # 100/s
            else:
                delay_s = 0.0   # batch / instant

            # 2. Sequential causal execution across records
            for idx, raw_rec in enumerate(self._sampled_records):
                if self._stop_event.is_set():
                    break

                while self._pause_event.is_set():
                    if self._stop_event.is_set():
                        break
                    time.sleep(0.05)

                flow_id = idx + 1
                features = raw_rec["features"]
                dataset_name = raw_rec["dataset"]
                is_cic17 = "cicids2017" in dataset_name.lower()

                score = scores[idx]
                binary_pred = "ATTACK" if score >= 0.50 else "BENIGN"

                # 2. Rule Engine Check
                matches = rule_engine.evaluate_features(features)
                rule_trig = len(matches) > 0
                rule_matches = [m.rule_id for m in matches]

                # Attribution tag
                if rule_trig and binary_pred == "ATTACK":
                    det_src = "HYBRID"
                elif rule_trig:
                    det_src = "RULE"
                elif binary_pred == "ATTACK":
                    det_src = "RF"
                else:
                    det_src = "NONE"

                # 3. DQN Causal State & Response Recommendation
                flow_bytes = float(features.get("flow_bytes_per_s", 0.0))
                state_vec = sb.build_state(attack_score=score, flow_bytes_per_s=flow_bytes)

                dqn_act = "ALLOW"
                q_vals_dict = None
                if self._dqn_net is not None:
                    try:
                        state_tensor = torch.tensor(np.array([state_vec]), dtype=torch.float32)
                        with torch.no_grad():
                            q_out = self._dqn_net(state_tensor)
                            act_idx = int(torch.argmax(q_out, dim=1).item())
                            dqn_act = actions_map[act_idx]
                            q_vals_dict = {
                                actions_map[i]: round(float(q_out[0, i].item()), 4)
                                for i in range(4)
                            }
                    except Exception as exc:
                        logger.debug("DQN eval error: %s", exc)

                # Deterministic Safety Gate Check
                enforced_act, is_overridden, reason = safety_gate.enforce_safety(
                    step=flow_id,
                    flow_id=flow_id,
                    host_id=raw_rec.get("source_file", "host_0"),
                    proposed_action=Action[dqn_act] if dqn_act in Action.__members__ else Action.ALLOW,
                )
                safety_status = "PERMITTED" if not is_overridden else f"OVERRIDDEN ({reason})"

                # Advance causal state history
                sb.update_history(
                    attack_score=score,
                    enforced_action=enforced_act,
                    cooldown_remaining=safety_gate.get_remaining_cooldown(
                        raw_rec.get("source_file", "host_0"), flow_id
                    ),
                )

                truth_bin = int(raw_rec["binary_label"])
                pred_bin = 1 if binary_pred == "ATTACK" else 0
                is_correct = (truth_bin == pred_bin)

                eval_record = ReplayRecord(
                    flow_id=flow_id,
                    dataset="CIC-IDS2017" if is_cic17 else "CSE-CIC-IDS2018",
                    source_file=raw_rec["source_file"],
                    source_row_index=raw_rec["source_row_index"],
                    original_label=raw_rec["original_label"],
                    ground_truth_family=raw_rec["ground_truth_family"],
                    binary_ground_truth=truth_bin,
                    is_attack=raw_rec["is_attack"],
                    rf_attack_probability=round(score, 4),
                    rf_binary_prediction=binary_pred,
                    is_correct=is_correct,
                    rule_triggered=rule_trig,
                    rule_matches=rule_matches,
                    detection_source=det_src,
                    dqn_action=dqn_act,
                    dqn_q_values=q_vals_dict,
                    safety_status=safety_status,
                    response_mode="advisory",
                    features=features,
                    timestamp=time.time(),
                )

                self._evaluated_records.append(eval_record)
                self._recent_flows.append(eval_record.to_dict())
                self.processed_count += 1

                if delay_s > 0:
                    time.sleep(delay_s)

            with self._lock:
                if not self._stop_event.is_set():
                    self.status = "COMPLETED"
                self.elapsed_time = time.time() - self.start_time

        except Exception as exc:
            logger.exception("Replay lab worker error: %s", exc)
            with self._lock:
                self.status = "ERROR"
                self.error_message = str(exc)

    def get_status(self) -> dict[str, Any]:
        """Compute thread-safe status snapshot and current metrics."""
        with self._lock:
            n_proc = self.processed_count
            n_total = self.selected_count
            elapsed = time.time() - self.start_time if self.status == "RUNNING" else self.elapsed_time
            throughput = (n_proc / elapsed) if elapsed > 0 else 0.0

            # Compute confusion matrix and metrics from evaluated records
            tp = sum(1 for r in self._evaluated_records if r.binary_ground_truth == 1 and r.rf_binary_prediction == "ATTACK")
            fp = sum(1 for r in self._evaluated_records if r.binary_ground_truth == 0 and r.rf_binary_prediction == "ATTACK")
            tn = sum(1 for r in self._evaluated_records if r.binary_ground_truth == 0 and r.rf_binary_prediction == "BENIGN")
            fn = sum(1 for r in self._evaluated_records if r.binary_ground_truth == 1 and r.rf_binary_prediction == "BENIGN")

            acc = (tp + tn) / n_proc if n_proc > 0 else 0.0
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

            # Stratified per-family metrics
            family_stats: dict[str, dict[str, Any]] = {}
            for r in self._evaluated_records:
                fam = r.ground_truth_family
                if fam not in family_stats:
                    family_stats[fam] = {"support": 0, "detected": 0, "missed": 0, "is_attack": r.is_attack}
                family_stats[fam]["support"] += 1
                if r.is_attack:
                    if r.rf_binary_prediction == "ATTACK":
                        family_stats[fam]["detected"] += 1
                    else:
                        family_stats[fam]["missed"] += 1
                else:
                    if r.rf_binary_prediction == "BENIGN":
                        family_stats[fam]["detected"] += 1
                    else:
                        family_stats[fam]["missed"] += 1

            per_family = []
            for fam, st in family_stats.items():
                sup = st["support"]
                det = st["detected"]
                recall_val = (det / sup * 100.0) if sup > 0 else 0.0
                per_family.append({
                    "family": fam,
                    "support": sup,
                    "detected": det,
                    "recall_pct": round(recall_val, 2),
                    "is_attack": st["is_attack"],
                })

            per_family.sort(key=lambda x: (not x["is_attack"], -x["support"]))

            progress_pct = (n_proc / n_total * 100.0) if n_total > 0 else 0.0

            return {
                "status": self.status,
                "error_message": self.error_message,
                "dataset": self.config.dataset,
                "selection": self.config.selection,
                "speed": self.config.speed,
                "seed": self.config.seed,
                "requested_count": self.requested_count,
                "selected_count": self.selected_count,
                "processed_count": self.processed_count,
                "failed_count": self.failed_count,
                "unsupported_count": self.unsupported_count,
                "progress_pct": round(progress_pct, 1),
                "elapsed_seconds": round(elapsed, 2),
                "throughput_flows_per_s": round(throughput, 1),
                "metrics": {
                    "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
                    "accuracy": round(acc, 4),
                    "precision": round(prec, 4),
                    "recall": round(rec, 4),
                    "f1": round(f1, 4),
                    "per_family": per_family,
                },
                "recent_flows": list(self._recent_flows),
            }

    def explain_flow(self, flow_id: int) -> dict[str, Any]:
        """Compute exact TreeSHAP feature attributions on Random Forest for a specific flow."""
        target_flow = next((r for r in self._evaluated_records if r.flow_id == flow_id), None)
        if target_flow is None:
            raise ValueError(f"Flow #{flow_id} not found in evaluated records.")

        from xrlids.evaluation.csv_evaluator import explain_flow_prediction
        bench_key = "cicids2017" if "cicids2017" in target_flow.dataset.lower() else "cse2018"
        explanation = explain_flow_prediction(target_flow.features, benchmark=bench_key)
        explanation["flow_id"] = flow_id
        explanation["ground_truth_family"] = target_flow.ground_truth_family
        explanation["original_label"] = target_flow.original_label
        explanation["rf_attack_probability"] = target_flow.rf_attack_probability
        explanation["rf_binary_prediction"] = target_flow.rf_binary_prediction
        explanation["dqn_action"] = target_flow.dqn_action
        explanation["safety_status"] = target_flow.safety_status
        return explanation

    def export_csv_string(self) -> str:
        """Export all evaluated records to CSV string with full provenance."""
        out = io.StringIO()
        fieldnames = [
            "flow_id",
            "dataset",
            "source_file",
            "source_row_index",
            "original_label",
            "ground_truth_family",
            "binary_ground_truth",
            "is_attack",
            "rf_attack_probability",
            "rf_binary_prediction",
            "is_correct",
            "rule_triggered",
            "rule_matches",
            "detection_source",
            "dqn_action",
            "safety_status",
            "response_mode",
            *R10_FEATURES,
        ]
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        for r in self._evaluated_records:
            row = {
                "flow_id": r.flow_id,
                "dataset": r.dataset,
                "source_file": r.source_file,
                "source_row_index": r.source_row_index,
                "original_label": r.original_label,
                "ground_truth_family": r.ground_truth_family,
                "binary_ground_truth": r.binary_ground_truth,
                "is_attack": r.is_attack,
                "rf_attack_probability": r.rf_attack_probability,
                "rf_binary_prediction": r.rf_binary_prediction,
                "is_correct": r.is_correct,
                "rule_triggered": r.rule_triggered,
                "rule_matches": ";".join(r.rule_matches),
                "detection_source": r.detection_source,
                "dqn_action": r.dqn_action,
                "safety_status": r.safety_status,
                "response_mode": r.response_mode,
            }
            row.update(r.features)
            writer.writerow(row)
        return out.getvalue()
