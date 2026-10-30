# XRL-IDARS — Master Repository Baseline & Change Control

**Document ID:** `DOC-FINAL-PHASE0-BASELINE-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & VERIFIED  
**Date:** October 30, 2026  
**Repository:** `/home/rishikesh/Desktop/fyp-xrlids`  
**GitHub Upstream:** `rishikeshgowdakk/fyp-xrlids`  
**Branch:** `feature/scapy-live-demo`  
**Commit SHA:** `596535e52169142cc21c5d0d40daec1ce15bc666`  
**Execution Runtime:** Python 3.14.4 in `.venv`  
**Test Suite Status:** 605 passed, 19 warnings in 48.01s (100% pass rate)  

---

## 1. Executive Summary

This document establishes the official change control baseline for the **XRL-IDARS** (Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System) finalisation phase. It records the complete source inventory, verified models, data artifacts, test suites, known historical issues, and operational boundaries.

### Architectural Core Boundaries
1. **Primary Operational Detector**: **Random Forest (RF)** is the sole operational classifier for intrusion detection in live packet capture and replay streaming. It operates independently on individual flows with $< 1.0\,\text{ms}$ latency and zero warm-up buffering.
2. **LSTM Research Role**: The Long Short-Term Memory (**LSTM**) network is strictly retained as an **independent research/experimental detector** evaluated on temporal sequences ($T=5$). It is completely removed from the operational detection and response critical path.
3. **Zero Ensemble / Score Fusion**: There is **no RF-LSTM score-level fusion**, weighted voting, or ensemble probability blending in live production. Both models execute independently.
4. **Autonomous Response & Safety Gate**: The Dueling DQN policy agent produces advisory mitigation recommendations (e.g., rate-limiting, IP blocking, deep inspection) evaluated against a deterministic safety gate. All live network firewall mutations (`iptables`, `nftables`) are disabled by default (advisory/dry-run mode).

---

## 2. Git Status and Working Tree State

```bash
Branch: feature/scapy-live-demo
Commit: 596535e52169142cc21c5d0d40daec1ce15bc666
Tracking: origin/feature/scapy-live-demo (up to date)
Working Tree:
  - Untracked: results/experiments/EXP-P2-LSTM-VALID-001/
  - Untracked: scripts/experiments/run_valid_lstm_experiment.py
  - Modified: reports/generated/phase1_final_report.md (commit stamp update)
  - Modified: reports/generated/phase1_status.md (commit stamp update)
```

---

## 3. Repository Directory Structure & Module Inventory

```
fyp-xrlids/
├── configs/                     # System, feature, and experiment configurations
│   ├── features/features.yaml   # Canonical R10 / R4 feature contracts
│   └── ...
├── data/                        # Benchmark datasets and processed flow caches
│   ├── raw/
│   │   ├── cicids2017/          # 8 CSV files (ISCX 2017)
│   │   ├── cse_cic_ids2018/     # 10 CSV files (AWS CSE-CIC-IDS2018)
│   │   └── unsw_nb15/           # 2 CSV files (Train/Test sets)
│   └── processed/
│       ├── cse2018_flowseq/     # Parquet cache of Tuesday 2018 flow sequences
│       └── phase2_cache/        # Cached flows and features for DQN policy training
├── docs/                        # Complete technical and academic documentation
│   ├── 00_PROJECT/ to 04_QUESTIONS/  # Foundational specifications and requirements
│   ├── academic/                # Viva preparation, report guide, demo script
│   ├── architecture/            # Architecture specifications and diagrams
│   ├── audit/                   # Security, baseline, and feature audits
│   ├── evaluation/              # Model evaluations, RF vs LSTM, dataset eligibility
│   ├── finalisation/            # Change control, baseline, and release checklists
│   ├── ml/                      # Machine learning models, features, preprocessing
│   ├── response/                # DQN agent, policy rules, and safety gate
│   ├── research/                # Scientific papers, feasibility studies, methodology
│   └── testing/                 # Test strategy, results, and end-to-end evidence
├── models/                      # Verified model checkpoints and registries
│   ├── dqn/                     # Dueling DQN 3-action and 4-action checkpoints
│   ├── lstm/                    # Historical and experimental PyTorch LSTM models
│   ├── rf/                      # Scikit-Learn Random Forest models (.joblib)
│   └── registry/                # Model manifest and YAML registry metadata
├── reports/generated/           # Automated CI/audit output reports
├── results/                     # Experiment runs, metrics, and ablation logs
│   ├── experiments/
│   │   ├── EXP-P1-CIC2017-R10-001/    # CIC-IDS2017 RF benchmark
│   │   ├── EXP-P1-CSE2018-R10-MULTI-001/ # CSE-CIC-IDS2018 RF multi-seed
│   │   ├── EXP-P1-UNSWNB15-R10-MULTI-001/ # UNSW-NB15 RF multi-seed
│   │   └── EXP-P2-LSTM-VALID-001/     # Scientifically verified LSTM vs RF experiment
├── scripts/                     # Operational, demo, training, and benchmarking scripts
│   ├── benchmark_latency.py     # Microsecond latency benchmarks for RF and LSTM
│   ├── demo/                    # Live dashboard, replay, and Scapy packet runners
│   └── experiments/             # LSTM sequence training and DQN evaluation runners
├── src/xrlids/                  # Production Python source package
│   ├── capture/                 # Scapy packet capture and PCAP replay engine
│   ├── datasets/                # Dataset loaders, schema validators, sanitizers
│   ├── demo/                    # Unified inference service and dashboard API
│   ├── enforcement/             # Linux iptables / nftables actuators (with dry-run)
│   ├── evaluation/              # Precision, Recall, F1, PR-AUC, ROC-AUC metrics
│   ├── explainability/          # TreeSHAP explainer and waterfall plot generators
│   ├── features/                # R10 contract definitions, vectorizers, extractors
│   ├── flow/                    # Canonical bidirectional FlowKey and FlowEngine
│   ├── labels/                  # Attack taxonomy and binary/multiclass mapping
│   ├── live/                    # Streaming flow builder and sliding sequence buffers
│   ├── models/                  # RF and PyTorch LSTM model wrappers
│   ├── preprocessing/           # Robust scalers, missing value imputers
│   ├── response/                # DQN network, replay memory, epsilon-greedy agent
│   └── rules/                   # Deterministic safety gate and action constraints
└── tests/                       # Pytest automated test suite (605 tests)
    ├── data/                    # Dataset validation and leakage tests
    ├── integration/             # End-to-end pipeline and dashboard integration tests
    ├── model/                   # Model loading, scoring, and output shape tests
    └── unit/                    # Unit tests for flow, features, DQN, and safety
```

---

## 4. Model and Checkpoint Inventory

| Checkpoint Path | Type | Architecture / Estimator | Target Dataset | Status |
| :--- | :--- | :--- | :--- | :--- |
| `models/rf/random_forest_cicids2017.joblib` | Scikit-Learn | RandomForestClassifier (n=100) | CIC-IDS2017 | **Verified Operational Baseline** |
| `models/rf/random_forest_cse2018.joblib` | Scikit-Learn | RandomForestClassifier (n=100) | CSE-CIC-IDS2018 | **Verified Operational Baseline** |
| `models/rf/random_forest_unswnb15.joblib` | Scikit-Learn | RandomForestClassifier (n=100) | UNSW-NB15 | **Verified Operational Baseline** |
| `results/experiments/EXP-P2-LSTM-VALID-001/lstm_flowseq_best.pt` | PyTorch | 2-layer LSTM (hidden=64, dropout=0.2) | CSE-CIC-IDS2018 | **Verified Experimental Research** |
| `models/lstm/lstm_cse2018.pt` | PyTorch | 2-layer LSTM | CSE-CIC-IDS2018 | Historical Checkpoint (Data Leakage) |
| `models/lstm/lstm_cicids2017.pt` | PyTorch | 2-layer LSTM | CIC-IDS2017 | Historical Checkpoint (Invalid Timing) |
| `models/lstm/lstm_unswnb15.pt` | PyTorch | 2-layer LSTM | UNSW-NB15 | Historical Checkpoint (Invalid Timing) |
| `models/dqn/dqn_3action_best.pt` | PyTorch | Dueling DQN (state=6, action=3) | Response Policy | **Verified Operational Advisory** |
| `models/dqn/dqn_4action_best.pt` | PyTorch | Dueling DQN (state=6, action=4) | Response Policy | **Verified Operational Advisory** |

---

## 5. Automated Test Suite Inventory

Executing `.venv/bin/pytest tests/` confirms **605 passed, 19 warnings in 48.01s**:

- **Unit Tests (`tests/unit/`)**: 496 tests covering flow engine, packet dissection, R10 feature calculation, TCP flag binary representations, TreeSHAP explainer, DQN action selection, and deterministic safety rules.
- **Integration Tests (`tests/integration/`)**: 46 tests verifying Scapy packet capture to flow assembly, feature extraction to RF prediction, alert generation to TreeSHAP attribution, and DQN advisory triggering.
- **Data Validation Tests (`tests/data/`)**: 45 tests verifying schema integrity, zero test-set leakage, chronological split constraints, and missing-value imputation.
- **Model Tests (`tests/model/`)**: 18 tests verifying model serialization, batch inference invariance, and output probability calibration.

---

## 6. Known Historical Defects & Resolution Status

1. **Historical LSTM Sequence Leakage**:
   - *Defect*: Prior LSTM models were trained using `stratified_random` row splitting without grouping by IP or ordering by timestamp, resulting in non-consecutive, synthetic sequences of unrelated flows.
   - *Resolution*: Investigated in `docs/LSTM_TRAINING_LIVE_PARITY_AUDIT.md` and resolved in experiment `EXP-P2-LSTM-VALID-001` using strict host-grouped, chronological 5-flow sequences with 120-second purge gaps and unseen host holdout.
2. **TCP Flag Representation Mismatch**:
   - *Defect*: Raw CICFlowMeter CSV columns (`SYN Flag Cnt`, etc.) represent binary flags ($\in \{0, 1\}$), but naive Scapy live flow counting produced cumulative packet counts ($> 100$), causing severe $+121\sigma$ out-of-distribution scaler distortion.
   - *Resolution*: Enforced exact binary indicator mapping ($\min(\text{packet\_count}, 1.0)$) in [`src/xrlids/flow/flow.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/flow/flow.py) with automated unit test validation in [`tests/unit/test_r10_flowseq_parity.py`](file:///home/rishikesh/Desktop/fyp-xrlids/tests/unit/test_r10_flowseq_parity.py).
3. **Operational Detector Architecture**:
   - *Decision*: Due to buffering delay ($T=5$ flows required per host before first prediction), vulnerability to buffer-exhaustion attacks, and marginal accuracy gain ($+0.19\%$ F1), LSTM is excluded from live operational detection. Random Forest remains the sole operational intrusion classifier.

---

## 7. Change Control Invariants for Master Finalisation

- **DO NOT** modify or overwrite frozen checkpoints in `models/rf/`, `models/dqn/`, or historical checkpoints in `models/lstm/`.
- **DO NOT** introduce RF-LSTM fusion, weighted probabilities, or voting logic into the operational inference service.
- **DO NOT** mutate host network firewall rules during test runs or live demonstrations.
- **DO NOT** fabricate metrics, latency figures, or test execution counts.
