"""Cross-Dataset Generalization and Out-of-Domain Transfer Engine (Task 4: Build Spec §§28, 30, 31, 38).

Implements strict scientific isolation for cross-dataset generalization:
1. Feature Strategy:
   - Primary 10-feature transfer: CIC-IDS2017 <-> CSE-CIC-IDS2018 under frozen R10 contract.
   - Auxiliary 4-feature transfer: UNSW-NB15 <-> other datasets under verified 4-feature contract.
2. Scientific Isolation:
   - Scaler is fit strictly on SOURCE training population. Target domain never influences preprocessing.
   - Source models (Majority, LR, DT, RF, LSTM) are trained strictly on SOURCE domain.
   - Score fusion weight alpha is tuned strictly on SOURCE validation set. Target test performance never tunes alpha.
   - Target domain test split is evaluated strictly out-of-domain.
3. Complete Provenance & Degradation Accounting:
   - Evaluates full baseline ladder, Supervised LSTM, and Fusion on fair aligned target test populations.
   - Calculates transfer degradation: Delta F1 = target_transfer_f1 - source_reference_f1.
   - Quantifies distribution shift: per-feature moments, Kolmogorov-Smirnov 2-sample tests, Wasserstein distances.
   - Error analysis: model disagreements, confusion matrices, and per-attack-family detection rates.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import pandas as pd
from scipy.stats import ks_2samp, wasserstein_distance

from xrlids.artifacts.metadata import ArtifactMetadata, write_json_artifact
from xrlids.datasets.loading import dataset_availability, load_manifest
from xrlids.datasets.population import (
    DatasetPopulation,
    PopulationConfig,
    load_dataset_population,
)
from xrlids.evaluation.error_analysis import (
    analyze_model_disagreements,
    compute_error_analysis,
    compute_per_family_metrics,
)
from xrlids.evaluation.metrics import evaluate
from xrlids.experiments.registry import (
    ExperimentRecord,
    load_yaml_config,
    write_experiment_record,
)
from xrlids.features.registry import load_feature_registry
from xrlids.labels.contract import load_label_contract
from xrlids.models.baselines import (
    DecisionTreeDetector,
    LogisticRegressionDetector,
    MajorityClassDetector,
)
from xrlids.models.fusion import align_scores, fuse_scores, tune_fusion_alpha
from xrlids.models.lstm import (
    LSTMDetector,
    SequenceSet,
    build_sequences,
)
from xrlids.models.random_forest import RandomForestDetector
from xrlids.preprocessing.pipeline import Preprocessor
from xrlids.splitting.splitter import SplitConfig, build_splits
from xrlids.utils.env import environment_fingerprint, git_commit
from xrlids.utils.hashing import dict_hash, feature_schema_hash
from xrlids.utils.logging_utils import get_logger
from xrlids.utils.profiler import ResourceProfiler
from xrlids.utils.seeding import set_global_seeds

logger = get_logger("transfer_experiment")

R10_FEATURES = [
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
]

R4_FEATURES = [
    "flow_duration_ms",
    "flow_packets_per_s",
    "flow_bytes_per_s",
    "packet_length_mean",
]


def compute_distribution_shift(
    X_source: pd.DataFrame,
    X_target: pd.DataFrame,
    y_source: pd.Series,
    y_target: pd.Series,
    features: list[str],
) -> dict[str, Any]:
    """Quantify covariate shift and label shift between source training and target test populations."""
    shift_report: dict[str, Any] = {
        "features": {},
        "label_distribution": {
            "source": {
                "total": int(len(y_source)),
                "benign": int(np.sum(y_source == 0)),
                "attack": int(np.sum(y_source == 1)),
                "attack_fraction": float(np.mean(y_source == 1)),
            },
            "target": {
                "total": int(len(y_target)),
                "benign": int(np.sum(y_target == 0)),
                "attack": int(np.sum(y_target == 1)),
                "attack_fraction": float(np.mean(y_target == 1)),
            },
            "class_prevalence_shift": float(np.mean(y_target == 1) - np.mean(y_source == 1)),
        },
    }

    for feat in features:
        s_vals = X_source[feat].dropna().to_numpy(dtype=float)
        t_vals = X_target[feat].dropna().to_numpy(dtype=float)

        s_mean, s_std = float(np.mean(s_vals)), float(np.std(s_vals))
        t_mean, t_std = float(np.mean(t_vals)), float(np.std(t_vals))
        s_med, t_med = float(np.median(s_vals)), float(np.median(t_vals))

        # Subsample for KS test if arrays are massive (scipy ks_2samp is O(N log N))
        max_ks_samples = 50000
        if len(s_vals) > max_ks_samples:
            s_ks = np.random.choice(s_vals, max_ks_samples, replace=False)
        else:
            s_ks = s_vals

        if len(t_vals) > max_ks_samples:
            t_ks = np.random.choice(t_vals, max_ks_samples, replace=False)
        else:
            t_ks = t_vals

        ks_res = ks_2samp(s_ks, t_ks)
        wd = float(wasserstein_distance(s_ks, t_ks))

        shift_report["features"][feat] = {
            "source": {
                "mean": s_mean,
                "std": s_std,
                "median": s_med,
                "min": float(np.min(s_vals)),
                "max": float(np.max(s_vals)),
                "q25": float(np.percentile(s_vals, 25)),
                "q75": float(np.percentile(s_vals, 75)),
            },
            "target": {
                "mean": t_mean,
                "std": t_std,
                "median": t_med,
                "min": float(np.min(t_vals)),
                "max": float(np.max(t_vals)),
                "q25": float(np.percentile(t_vals, 25)),
                "q75": float(np.percentile(t_vals, 75)),
            },
            "mean_difference": float(t_mean - s_mean),
            "median_difference": float(t_med - s_med),
            "std_ratio": float(t_std / max(1e-9, s_std)),
            "ks_statistic": float(ks_res.statistic),
            "ks_pvalue": float(ks_res.pvalue),
            "wasserstein_distance": wd,
        }

    return shift_report


def generate_transfer_card(
    record: ExperimentRecord,
    target_population: DatasetPopulation,
    *,
    source_dataset: str,
    target_dataset: str,
    contract_name: str,
    feature_names: list[str],
    source_reference: dict[str, Any],
    transfer_metrics: dict[str, Any],
    degradation_table: list[dict[str, Any]],
    shift_report: dict[str, Any],
    error_analysis: dict[str, Any],
    per_family_metrics: dict[str, Any],
    resource_info: dict[str, Any],
    frozen_alpha: float,
) -> str:
    """Generate self-contained, auditable Markdown experiment card for cross-dataset transfer."""
    commit_str = record.git_commit or git_commit() or "uncommitted"
    aligned_size = transfer_metrics.get("aligned", {}).get("population_size", 0)

    lines = [
        f"# EXPERIMENT CARD: `{record.experiment_id}`",
        "",
        "> [!IMPORTANT]",
        "> This experiment card documents cross-dataset transfer evaluation under strict scientific isolation.",
        "> Preprocessing and source models were fitted exclusively on source training data.",
        "> Target domain data was evaluated strictly out-of-domain with zero target parameter tuning.",
        "",
        "## 1. Overview & Provenance",
        "",
        f"- **Experiment ID**: `{record.experiment_id}`",
        f"- **Research Question**: `RQ5_CROSS_DATASET_TRANSFER`",
        f"- **Source Dataset**: `{source_dataset}`",
        f"- **Target Dataset**: `{target_dataset}`",
        f"- **Feature Contract**: `{contract_name}` ({len(feature_names)} features)",
        f"- **Execution Status**: `EMPIRICALLY_OBSERVED`",
        f"- **Git Commit**: `{commit_str}`",
        f"- **Random Seed**: `{record.random_seed}`",
        f"- **Frozen Source Fusion Alpha**: `{frozen_alpha:.2f}`",
        f"- **Peak RSS**: `{resource_info.get('peak_rss_mib', 0.0):.2f} MiB` (CPU Count: `{resource_info.get('cpu_count', 'N/A')}`)",
        f"- **Wall-Clock Duration**: `{resource_info.get('duration_s', 0.0):.2f}s`",
        "",
        "---",
        "## 2. Feature Contract & Strict Isolation Protocol",
        "",
        f"Active features evaluated ({len(feature_names)}):",
    ]
    for idx, f in enumerate(feature_names, 1):
        lines.append(f"{idx}. `{f}`")

    lines.extend([
        "",
        "### Isolation Guarantees",
        "1. **Zero Preprocessor Leakage**: Preprocessor parameters (means, scales, medians) were learned exclusively from the source training population. The target dataset never fitted the preprocessor.",
        "2. **Frozen Model Weights**: Detectors (Majority, LR, DT, RF, LSTM) were trained exclusively on source data. No fine-tuning or adaptation was performed on target data.",
        "3. **Decision Parameters & Isolation**: Fusion weight $\\alpha$ was selected using source validation data. Decision threshold 0.50 was fixed as the neutral baseline (threshold optimization remains OPEN under D-003). Target data was never used to tune either parameter.",
        "4. **Sequence Safety**: LSTM sequence windows ($T=5$, stride=1, label_rule='last') were strictly isolated by target source capture file, with no synthetic sequences crossing capture boundaries.",
        "",
        "---",
        "## 3. Transfer Degradation Matrix (Fair Aligned Target Population)",
        "",
        f"> Aligned target evaluation population: **{aligned_size:,}** rows.",
        "",
        "| Model | Contract | Source Reference F1 | Target Transfer F1 | ΔF1 (Degradation) | Source FPR | Target FPR | ΔFPR | Target ROC-AUC | Target PR-AUC |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])

    for row in degradation_table:
        d_f1 = f"{row['delta_f1']:+.4f}"
        d_fpr = f"{row['delta_fpr']:+.4f}"
        lines.append(
            f"| **{row['model'].upper()}** | `{contract_name}` | "
            f"{row['source_f1']:.4f} | {row['transfer_f1']:.4f} | **{d_f1}** | "
            f"{row['source_fpr']:.4f} | {row['transfer_fpr']:.4f} | {d_fpr} | "
            f"{row['transfer_roc_auc']:.4f} | {row['transfer_pr_auc']:.4f} |"
        )

    lines.extend([
        "",
        "---",
        "## 4. Covariate & Label Distribution Shift Analysis",
        "",
        f"- **Source Train Class Balance**: Benign = {shift_report['label_distribution']['source']['benign']:,} ({1.0 - shift_report['label_distribution']['source']['attack_fraction']:.1%}), Attack = {shift_report['label_distribution']['source']['attack']:,} ({shift_report['label_distribution']['source']['attack_fraction']:.1%})",
        f"- **Target Test Class Balance**: Benign = {shift_report['label_distribution']['target']['benign']:,} ({1.0 - shift_report['label_distribution']['target']['attack_fraction']:.1%}), Attack = {shift_report['label_distribution']['target']['attack']:,} ({shift_report['label_distribution']['target']['attack_fraction']:.1%})",
        f"- **Class Prevalence Shift**: {shift_report['label_distribution']['class_prevalence_shift']:+.4f}",
        "",
        "| Feature | Source Mean ± Std | Target Mean ± Std | Median Shift | KS Statistic ($D$) | Wasserstein Distance |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ])

    for feat, f_data in shift_report["features"].items():
        s_str = f"{f_data['source']['mean']:.2f} ± {f_data['source']['std']:.2f}"
        t_str = f"{f_data['target']['mean']:.2f} ± {f_data['target']['std']:.2f}"
        med_shift = f"{f_data['median_difference']:+.2f}"
        lines.append(
            f"| `{feat}` | {s_str} | {t_str} | {med_shift} | {f_data['ks_statistic']:.4f} | {f_data['wasserstein_distance']:.2f} |"
        )

    lines.extend([
        "",
        "---",
        "## 5. Model Disagreements & Error Analysis on Target Domain",
        "",
        f"- **Aligned Evaluation Size**: {aligned_size:,} rows",
        f"- **RF vs LSTM Disagreements**: {error_analysis.get('disagreement_count', 0):,} ({error_analysis.get('disagreement_fraction', 0.0):.2%})",
        f"- **RF Positive, LSTM Negative**: {error_analysis.get('rf_pos_lstm_neg', {}).get('count', 0):,} (RF Correct: {error_analysis.get('rf_pos_lstm_neg', {}).get('rf_correct_when_lstm_wrong', 0):,}, RF False Alarm: {error_analysis.get('rf_pos_lstm_neg', {}).get('rf_wrong_when_lstm_right', 0):,})",
        f"- **LSTM Positive, RF Negative**: {error_analysis.get('rf_neg_lstm_pos', {}).get('count', 0):,} (LSTM Correct: {error_analysis.get('rf_neg_lstm_pos', {}).get('lstm_correct_when_rf_wrong', 0):,}, LSTM False Alarm: {error_analysis.get('rf_neg_lstm_pos', {}).get('lstm_wrong_when_rf_right', 0):,})",
    ])

    if "summary_table" in per_family_metrics:
        lines.extend([
            "",
            "---",
            "## 6. Target Domain Per-Attack-Family Detection Breakdown",
            "",
            "| Attack Family | Class | Target Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ])
        for row in per_family_metrics["summary_table"]:
            cls_str = "ATTACK" if row.get("is_attack") else "BENIGN"
            lines.append(
                f"| `{row['family']}` | {cls_str} | {row['support']:,} | {row['correct']:,} | "
                f"{row['false_positives']:,} | {row['false_negatives']:,} | "
                f"{row['detection_rate']:.2%} | {row['error_rate']:.2%} |"
            )

    lines.extend([
        "",
        "---",
        "## 7. Artifact Traceability",
        "",
        "All cross-dataset transfer artifacts are recorded deterministically in the experiment directory:",
        "- `experiment_record.json`: Complete experiment metadata and provenance sidecar",
        "- `test_metrics.json`: Full metric dictionary across all detectors on target test set",
        "- `transfer_comparison.json`: Detailed degradation accounting against source-domain baseline",
        "- `distribution_shift.json`: Covariate moments, KS-test statistics, and Wasserstein distances",
        "- `error_analysis.json`: Model disagreements, false alarms, and attack misses",
        "- `per_family_metrics.csv`: Per-attack-family detection rates on target domain",
        "- `resource_profile.json`: Peak RSS, duration, CPU count, and memory footprint",
    ])

    return "\n".join(lines)
