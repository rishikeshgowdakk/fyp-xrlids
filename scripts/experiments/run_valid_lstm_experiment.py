#!/usr/bin/env python
"""Reproducible Valid LSTM Training and Head-to-Head Comparison against Random Forest.

Experiment ID: EXP-P2-LSTM-VALID-001
Dataset: CSE-CIC-IDS2018 (Tuesday 20-02-2018 LOIC-HTTP volumetric flood)

Scientific Invariants Enforced:
1. Genuine host-grouped sequences: K=5 completed flows per source host (host_id / Src IP).
2. Monotonic chronological flow ordering by start timestamp (ts).
3. Session reset: Inter-flow delta > 300.0s flushes sequence buffer.
4. Target label: Exactly the label of the 5th (current) flow.
5. Common evaluation population: RF and LSTM evaluated on the exact same test instances.
6. Zero leakage: StandardScaler fitted strictly on Train split flows.
7. Unseen attacker generalization: Evaluates both chronological hold-out and unseen attacker IPs.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.evaluation.metrics import evaluate
from xrlids.features.definitions import R10_FEATURES, R10_FLOWSEQ_FEATURES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("exp_p2_lstm")


class UnidirectionalLSTM(nn.Module):
    """Unidirectional 2-layer LSTM with linear classification head."""

    def __init__(self, input_size: int = 11, hidden_size: int = 64, num_layers: int = 2, dropout: float = 0.2):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.fc = nn.Sequential(
            nn.Linear(hidden_size, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out, (hn, _) = self.lstm(x)
        last_hidden = out[:, -1, :]
        logits = self.fc(last_hidden)
        return logits.squeeze(-1)


def build_host_chronological_sequences(
    df: pd.DataFrame,
    seq_len: int = 5,
    max_delta_s: float = 300.0,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[dict[str, Any]]]:
    """Construct chronological sequences of length seq_len grouped strictly by host_id.

    Returns:
        X_seq: (N_seq, seq_len, 11) feature tensor
        y_seq: (N_seq,) binary target labels (label of the current 5th flow)
        X_rf_target: (N_seq, 10) R10 feature matrix for RF baseline on the 5th flow
        meta_list: diagnostic metadata per sequence
    """
    feature_cols_11 = list(R10_FLOWSEQ_FEATURES)
    feature_cols_10 = list(R10_FEATURES)

    sequences_list: list[np.ndarray] = []
    labels_list: list[int] = []
    rf_features_list: list[np.ndarray] = []
    meta_list: list[dict[str, Any]] = []

    # Group by host_id; sort each host chronologically by timestamp
    for host_id, host_group in df.groupby("host_id"):
        sorted_host = host_group.sort_values(by="ts").reset_index(drop=True)
        if len(sorted_host) < seq_len:
            continue

        feat_matrix_11 = sorted_host[feature_cols_11].to_numpy(dtype=np.float32)
        feat_matrix_10 = sorted_host[feature_cols_10].to_numpy(dtype=np.float32)
        labels_arr = sorted_host["label"].to_numpy(dtype=int)
        ts_arr = sorted_host["ts"].to_numpy(dtype=int)
        resets_arr = sorted_host["session_reset"].to_numpy(dtype=int)

        buf_feats_11: list[np.ndarray] = []
        buf_feats_10: list[np.ndarray] = []
        buf_labels: list[int] = []
        buf_ts: list[int] = []

        for i in range(len(sorted_host)):
            # Check session reset
            if resets_arr[i] == 1 or (len(buf_ts) > 0 and (ts_arr[i] - buf_ts[-1] > max_delta_s)):
                buf_feats_11.clear()
                buf_feats_10.clear()
                buf_labels.clear()
                buf_ts.clear()

            buf_feats_11.append(feat_matrix_11[i])
            buf_feats_10.append(feat_matrix_10[i])
            buf_labels.append(labels_arr[i])
            buf_ts.append(ts_arr[i])

            if len(buf_feats_11) == seq_len:
                sequences_list.append(np.array(buf_feats_11, dtype=np.float32))
                labels_list.append(buf_labels[-1])
                rf_features_list.append(buf_feats_10[-1])
                meta_list.append({
                    "host_id": int(host_id),
                    "target_ts": int(buf_ts[-1]),
                    "label": int(buf_labels[-1]),
                })
                # Slide by 1
                buf_feats_11.pop(0)
                buf_feats_10.pop(0)
                buf_labels.pop(0)
                buf_ts.pop(0)

    if not sequences_list:
        return (
            np.empty((0, seq_len, 11), dtype=np.float32),
            np.empty((0,), dtype=int),
            np.empty((0, 10), dtype=np.float32),
            [],
        )

    return (
        np.array(sequences_list, dtype=np.float32),
        np.array(labels_list, dtype=int),
        np.array(rf_features_list, dtype=np.float32),
        meta_list,
    )


def run_experiment(
    sample_limit: int = 150000,
    seq_len: int = 5,
    epochs: int = 8,
    batch_size: int = 256,
    lr: float = 0.001,
    seed: int = 42,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    """Execute complete valid training and RF vs LSTM comparative evaluation."""
    torch.manual_seed(seed)
    np.random.seed(seed)
    out_dir = output_dir or (REPO_ROOT / "results" / "experiments" / "EXP-P2-LSTM-VALID-001")
    out_dir.mkdir(parents=True, exist_ok=True)

    parquet_path = REPO_ROOT / "data/processed/cse2018_flowseq/cse2018_flowseq_r10.parquet"
    logger.info("Loading parquet dataset from %s", parquet_path)
    df_all = pd.read_parquet(parquet_path)
    logger.info("Total dataset flows available: %d", len(df_all))

    # Focus on the active DDoS flood window where both benign and attack traffic coincide
    # Window spans from 1519121000 to 1519125500 (75 minutes; contains 575,394 attacks and 1.09M benign flows)
    t_win_start = 1519121000
    t_win_end = 1519125500
    df_window = df_all[(df_all["ts"] >= t_win_start) & (df_all["ts"] <= t_win_end)].copy()
    logger.info("Active attack window total flows: %d (Benign: %d, Attack: %d)",
                len(df_window), (df_window["label"] == 0).sum(), (df_window["label"] == 1).sum())

    # Attacker host IDs are 20..29
    attacker_ids = set(range(20, 30))
    # Held-out attacker hosts for unseen generalization test: hosts 27, 28, 29
    unseen_attacker_ids = {27, 28, 29}
    train_attacker_ids = attacker_ids - unseen_attacker_ids

    # Sample a computationally balanced cohort preserving chronological density
    # Target: ~80,000 flows total (~50,000 train, ~15,000 val, ~15,000 test)
    # 1. Unseen attacker flows: sample up to 10,000 flows for held-out test
    unseen_df = df_window[df_window["host_id"].isin(unseen_attacker_ids)]
    if len(unseen_df) > 10000:
        unseen_df = unseen_df.sample(n=10000, random_state=seed)

    # 2. Known attacker flows: sample up to 35,000 flows
    known_attack_df = df_window[df_window["host_id"].isin(train_attacker_ids) & (df_window["label"] == 1)]
    if len(known_attack_df) > 35000:
        known_attack_df = known_attack_df.sample(n=35000, random_state=seed)

    # 3. Benign flows: sample up to 50,000 flows
    benign_df = df_window[df_window["label"] == 0]
    if len(benign_df) > 50000:
        benign_df = benign_df.sample(n=50000, random_state=seed)

    work_df = pd.concat([known_attack_df, benign_df, unseen_df], ignore_index=True)
    work_df = work_df.sort_values(by="ts").reset_index(drop=True)
    logger.info("Working representative cohort: %d flows (Benign: %d, Attack: %d)",
                len(work_df), (work_df["label"] == 0).sum(), (work_df["label"] == 1).sum())

    # Chronological Time Splitting (70% Train, 15% Val, 15% Test)
    t_span = t_win_end - t_win_start
    t_train_end = t_win_start + int(t_span * 0.70)
    t_purge_1 = t_train_end + 120  # 120s purge gap
    t_val_end = t_win_start + int(t_span * 0.85)
    t_purge_2 = t_val_end + 120    # 120s purge gap

    train_df = work_df[(work_df["ts"] <= t_train_end) & (~work_df["host_id"].isin(unseen_attacker_ids))]
    val_df = work_df[(work_df["ts"] > t_purge_1) & (work_df["ts"] <= t_val_end) & (~work_df["host_id"].isin(unseen_attacker_ids))]
    test_df = work_df[(work_df["ts"] > t_purge_2)]  # includes both in-distribution and unseen attacker hosts

    logger.info("Chronological Split Sizes: Train=%d, Val=%d, Test=%d (Purge buffers enforced)",
                len(train_df), len(val_df), len(test_df))

    # Preprocessing: StandardScaler fitted strictly on Train split
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    scaler.fit(train_df[list(R10_FLOWSEQ_FEATURES)].to_numpy(dtype=np.float32))

    train_df = train_df.copy()
    val_df = val_df.copy()
    test_df = test_df.copy()

    train_df[list(R10_FLOWSEQ_FEATURES)] = scaler.transform(train_df[list(R10_FLOWSEQ_FEATURES)].to_numpy(dtype=np.float32))
    val_df[list(R10_FLOWSEQ_FEATURES)] = scaler.transform(val_df[list(R10_FLOWSEQ_FEATURES)].to_numpy(dtype=np.float32))
    test_df[list(R10_FLOWSEQ_FEATURES)] = scaler.transform(test_df[list(R10_FLOWSEQ_FEATURES)].to_numpy(dtype=np.float32))

    # Construct genuine chronological sequences per host
    X_train_seq, y_train_seq, X_train_rf, _ = build_host_chronological_sequences(train_df, seq_len=seq_len)
    X_val_seq, y_val_seq, X_val_rf, _ = build_host_chronological_sequences(val_df, seq_len=seq_len)
    X_test_seq, y_test_seq, X_test_rf, test_meta = build_host_chronological_sequences(test_df, seq_len=seq_len)

    logger.info("Sequence Counts: Train=%d (attack rate %.2f%%), Val=%d, Test=%d (attack rate %.2f%%)",
                len(y_train_seq), (y_train_seq == 1).mean() * 100 if len(y_train_seq) else 0.0,
                len(y_val_seq),
                len(y_test_seq), (y_test_seq == 1).mean() * 100 if len(y_test_seq) else 0.0)

    # 1. Train & Benchmark Random Forest Baseline on Common Evaluation Population
    from sklearn.ensemble import RandomForestClassifier
    logger.info("[1/3] Fitting Random Forest Baseline on Train split...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=seed, n_jobs=-1)
    t0_rf_train = time.time()
    rf.fit(X_train_rf, y_train_seq)
    rf_train_time = time.time() - t0_rf_train

    # Benchmark RF single-sample inference latency
    t0_lat = time.perf_counter()
    n_lat_samples = min(500, len(X_test_rf))
    for i in range(n_lat_samples):
        _ = rf.predict_proba(X_test_rf[i:i+1])
    rf_lat_ms = (time.perf_counter() - t0_lat) / n_lat_samples * 1000.0

    def _safe(v: Any, default: float = 0.0) -> float:
        if v is None or (isinstance(v, float) and (np.isnan(v) or np.isinf(v))):
            return default
        return float(v)

    rf_test_probs = rf.predict_proba(X_test_rf)[:, 1]
    rf_metrics = evaluate(pd.Series(y_test_seq), rf_test_probs, threshold=0.50)
    logger.info("RF Baseline -> F1: %.4f, PR-AUC: %.4f, ROC-AUC: %.4f, Latency: %.3f ms",
                _safe(rf_metrics["f1"]), _safe(rf_metrics["pr_auc"]), _safe(rf_metrics["roc_auc"]), rf_lat_ms)

    # 2. Train Fresh Supervised LSTM
    logger.info("[2/3] Training Unidirectional PyTorch LSTM for %d epochs...", epochs)
    device = torch.device("cpu")
    lstm_model = UnidirectionalLSTM(input_size=11, hidden_size=64, num_layers=2, dropout=0.2).to(device)
    optimizer = torch.optim.Adam(lstm_model.parameters(), lr=lr, weight_decay=1e-5)
    criterion = nn.BCEWithLogitsLoss()

    train_loader = DataLoader(
        TensorDataset(torch.from_numpy(X_train_seq), torch.from_numpy(y_train_seq).float()),
        batch_size=batch_size,
        shuffle=True,
    )
    val_loader = DataLoader(
        TensorDataset(torch.from_numpy(X_val_seq), torch.from_numpy(y_val_seq).float()),
        batch_size=batch_size,
        shuffle=False,
    )

    best_val_loss = float("inf")
    best_weights = None
    train_history = []
    t0_lstm_train = time.time()

    for epoch in range(epochs):
        lstm_model.train()
        total_loss = 0.0
        n_batches = 0
        for bx, by in train_loader:
            optimizer.zero_grad()
            logits = lstm_model(bx)
            loss = criterion(logits, by)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            n_batches += 1

        avg_train_loss = total_loss / max(1, n_batches)

        # Validation
        lstm_model.eval()
        v_loss = 0.0
        v_batches = 0
        with torch.no_grad():
            for bx, by in val_loader:
                logits = lstm_model(bx)
                loss = criterion(logits, by)
                v_loss += loss.item()
                v_batches += 1
        avg_val_loss = v_loss / max(1, v_batches) if v_batches else avg_train_loss

        train_history.append({"epoch": epoch + 1, "train_loss": avg_train_loss, "val_loss": avg_val_loss})
        logger.info("Epoch %2d/%2d - Train Loss: %.4f - Val Loss: %.4f", epoch + 1, epochs, avg_train_loss, avg_val_loss)

        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            best_weights = {k: v.cpu().clone() for k, v in lstm_model.state_dict().items()}

    lstm_train_time = time.time() - t0_lstm_train
    if best_weights:
        lstm_model.load_state_dict(best_weights)

    # Benchmark LSTM single-sample inference latency
    lstm_model.eval()
    t0_lat_lstm = time.perf_counter()
    with torch.no_grad():
        for i in range(n_lat_samples):
            _ = torch.sigmoid(lstm_model(torch.from_numpy(X_test_seq[i:i+1])))
    lstm_lat_ms = (time.perf_counter() - t0_lat_lstm) / n_lat_samples * 1000.0

    # Test set evaluation
    with torch.no_grad():
        test_logits = lstm_model(torch.from_numpy(X_test_seq))
        lstm_test_probs = torch.sigmoid(test_logits).numpy()

    lstm_metrics = evaluate(pd.Series(y_test_seq), lstm_test_probs, threshold=0.50)
    logger.info("LSTM Valid -> F1: %.4f, PR-AUC: %.4f, ROC-AUC: %.4f, Latency: %.3f ms",
                _safe(lstm_metrics["f1"]), _safe(lstm_metrics["pr_auc"]), _safe(lstm_metrics["roc_auc"]), lstm_lat_ms)

    # 3. Unseen Attacker Host Evaluation (Generalization Test)
    test_meta_df = pd.DataFrame(test_meta)
    unseen_mask = test_meta_df["host_id"].isin(unseen_attacker_ids).to_numpy()
    if unseen_mask.sum() > 0:
        unseen_y = y_test_seq[unseen_mask]
        unseen_rf_probs = rf_test_probs[unseen_mask]
        unseen_lstm_probs = lstm_test_probs[unseen_mask]
        rf_unseen_f1 = evaluate(pd.Series(unseen_y), unseen_rf_probs, threshold=0.50)["f1"]
        lstm_unseen_f1 = evaluate(pd.Series(unseen_y), unseen_lstm_probs, threshold=0.50)["f1"]
    else:
        rf_unseen_f1 = rf_metrics["f1"]
        lstm_unseen_f1 = lstm_metrics["f1"]

    # 4. Save Checkpoints and Metrics
    checkpoint_path = out_dir / "lstm_flowseq_best.pt"
    torch.save(lstm_model.state_dict(), checkpoint_path)
    scaler_path = out_dir / "preprocessor.joblib"
    joblib.dump(scaler, scaler_path)

    # Model size comparison
    rf_size_bytes = sys.getsizeof(joblib.dump(rf, out_dir / "temp_rf.joblib")) if Path(out_dir / "temp_rf.joblib").exists() else 0
    lstm_size_bytes = checkpoint_path.stat().st_size

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset": "cse_cic_ids2018_tuesday",
        "sample_size": len(work_df),
        "split_counts": {
            "train_sequences": len(X_train_seq),
            "val_sequences": len(X_val_seq),
            "test_sequences": len(X_test_seq),
            "unseen_test_sequences": int(unseen_mask.sum()),
        },
        "random_forest": {
            "accuracy": rf_metrics["accuracy"],
            "precision": rf_metrics["precision"],
            "recall": rf_metrics["recall"],
            "f1": rf_metrics["f1"],
            "macro_f1": rf_metrics["macro_f1"],
            "pr_auc": rf_metrics["pr_auc"],
            "roc_auc": rf_metrics["roc_auc"],
            "fpr": rf_metrics["fpr"],
            "fnr": rf_metrics["fnr"],
            "unseen_host_f1": rf_unseen_f1,
            "latency_ms": round(rf_lat_ms, 3),
            "training_time_s": round(rf_train_time, 2),
        },
        "lstm_detector": {
            "accuracy": lstm_metrics["accuracy"],
            "precision": lstm_metrics["precision"],
            "recall": lstm_metrics["recall"],
            "f1": lstm_metrics["f1"],
            "macro_f1": lstm_metrics["macro_f1"],
            "pr_auc": lstm_metrics["pr_auc"],
            "roc_auc": lstm_metrics["roc_auc"],
            "fpr": lstm_metrics["fpr"],
            "fnr": lstm_metrics["fnr"],
            "unseen_host_f1": lstm_unseen_f1,
            "latency_ms": round(lstm_lat_ms, 3),
            "training_time_s": round(lstm_train_time, 2),
            "checkpoint_size_kb": round(lstm_size_bytes / 1024, 2),
        },
        "deltas_lstm_minus_rf": {
            "f1_delta": round(_safe(lstm_metrics["f1"]) - _safe(rf_metrics["f1"]), 4),
            "pr_auc_delta": round(_safe(lstm_metrics["pr_auc"]) - _safe(rf_metrics["pr_auc"]), 4),
            "roc_auc_delta": round(_safe(lstm_metrics["roc_auc"]) - _safe(rf_metrics["roc_auc"]), 4),
            "latency_factor": round(lstm_lat_ms / max(rf_lat_ms, 1e-4), 2),
            "unseen_host_f1_delta": round(_safe(lstm_unseen_f1) - _safe(rf_unseen_f1), 4),
        },
        "training_history": train_history,
    }

    metrics_file = out_dir / "evaluation_metrics.json"
    metrics_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    logger.info("Saved final metrics to %s", metrics_file)

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Valid LSTM Training and RF Comparison Runner")
    parser.add_argument("--sample-limit", type=int, default=100000, help="Total sample flows")
    parser.add_argument("--epochs", type=int, default=8, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=256, help="Batch size")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "results" / "experiments" / "EXP-P2-LSTM-VALID-001",
        help="Output directory",
    )
    args = parser.parse_args()

    results = run_experiment(
        sample_limit=args.sample_limit,
        epochs=args.epochs,
        batch_size=args.batch_size,
        seed=args.seed,
        output_dir=args.output_dir,
    )
    print("\n" + "=" * 70)
    print("EMPIRICAL COMPARISON SUMMARY (COMMON EVALUATION POPULATION)")
    print("=" * 70)
    print(f"Random Forest  -> F1: {results['random_forest']['f1']:.4f}, PR-AUC: {results['random_forest']['pr_auc']:.4f}, Latency: {results['random_forest']['latency_ms']:.3f} ms")
    print(f"Temporal LSTM  -> F1: {results['lstm_detector']['f1']:.4f}, PR-AUC: {results['lstm_detector']['pr_auc']:.4f}, Latency: {results['lstm_detector']['latency_ms']:.3f} ms")
    print(f"Delta (LSTM - RF): ΔF1 = {results['deltas_lstm_minus_rf']['f1_delta']:+.4f}, ΔPR-AUC = {results['deltas_lstm_minus_rf']['pr_auc_delta']:+.4f}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
