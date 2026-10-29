# XRL-IDARS — Comprehensive Test and Verification Report

**Project:** Explainable Reinforcement Learning-Based Network Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Date:** October 30, 2026  
**Environment:** Linux 7.0.0-42-generic (x86_64) | Python 3.14.4 | PyTorch 2.14.0+cpu | scikit-learn 1.9.1 | SHAP 0.52.0 | Scapy 2.6.1  
**Authoritative Status:** 560 passed tests, 0 failed, 0 skipped, 100% pass rate.

---

## 1. Executive Summary

This document records the complete, authoritative test execution and verification evidence for the XRL-IDARS codebase following the implementation of the Master Addendum.

All regression suites, targeted semantic invariant tests, safety gate constraints, model checkpoint integrity verifications, fresh-clone exhibition suites, and microsecond latency benchmarks have been executed live and verified.

```text
================================================================================
TOTAL TESTS:      560
PASSED:           560
FAILED:             0
SKIPPED:            0
WARNINGS:          18 (Deprecation/UserWarnings from third-party scientific libs)
EXECUTION TIME:   54.98 seconds
EXIT CODE:          0 (CLEAN PASS)
================================================================================
```

---

## 2. Test Suite Breakdown

### 2.1 Targeted Semantic Invariant Tests (Addendum)
- **Command:** `pytest tests/unit/test_attack_family_and_response_semantics.py -v`
- **Results:** 10 passed in 2.61s (Exit Code 0)
- **Verified Capabilities:**
  1. `test_rf_models_are_strictly_binary`: All 3 Random Forest checkpoints (`CIC-IDS2017`, `CSE-CIC-IDS2018`, `UNSW-NB15`) have `classes_=[0, 1]` and output binary probabilities.
  2. `test_label_mapping_defines_attack_families_as_ground_truth`: `configs/labels/label_mapping.yaml` defines 17 ground-truth families, separate from model prediction capabilities.
  3. `test_flagship_decision_semantics`: `FlagshipDecision` carries `detection_type="binary"`, `attack_family_prediction=None`, and `response_mode="advisory"`.
  4. `test_flagship_process_flow_semantics`: `FlagshipXRLIDS.process_flow()` outputs verified binary decisions with advisory response recommendations.
  5. `test_dqn_state_contract_is_6d_causal`: DQN state vector is strictly $\mathbf{s}_t = [S_t, \Delta S_t, N_{\text{alert}}, a_{t-1}, c_t, v_t] \in \mathbb{R}^6$; contains no attack-family label.
  6. `test_dqn_response_advisory_mode_invariant`: Response actions default to `response_mode="advisory"`; zero live network mutations permitted.
  7. `test_safety_gate_blocks_invalid_actions`: `DeterministicSafetyGate` enforces cooldown and invariant validation.
  8. `test_dashboard_semantic_contract_separation`: Workbench provider explicitly separates binary detection from ground-truth families and XAI attributions.
  9. `test_csv_evaluator_dqn_state_builder_alignment`: CSV flow evaluator builds states using canonical `StateBuilder` rather than ad-hoc vectors.
  10. `test_per_family_metrics_use_ground_truth_labels`: Error analysis computes stratified binary metrics against ground truth.

### 2.2 Flagship & Core Architecture Integration
- **Command:** `pytest tests/unit/test_flagship.py tests/unit/test_rules_engine.py tests/unit/test_response_safety.py tests/unit/test_workbench_api.py tests/integration/test_safety_invariants.py -v`
- **Results:** 41 passed in 3.98s (Exit Code 0)
- **Key Modules Verified:**
  - `src/xrlids/flagship.py`: End-to-end flow processing, rules checking, RF prediction, TreeSHAP explanation, and DQN advisory response.
  - `src/xrlids/rules/engine.py`: Deterministic RFC violation detection (`RULE-TCP-INVALID-FLAGS`, `RULE-SYN-FLOOD`, `RULE-PORT-SCAN`, `RULE-HIGH-RATE-BURST`, `RULE-IP-SPOOF-RESERVED`).
  - `src/xrlids/response/safety.py`: Fail-closed gate, blast-radius restrictions, cooldown limits.
  - `dashboard/workbench_data.py`: API payload schemas, statistical integrity, scenario definitions.

### 2.3 CSV Flow Evaluation Workflow
- **Command:** `pytest tests/unit/test_csv_evaluation_workflow.py -v`
- **Results:** 29 passed in 8.51s (Exit Code 0)
- **Verified Capabilities:**
  - Full evaluation across Mode A (Held-Out Test), Mode B (Exhibition 200 Demo), Mode C (Custom CSV Upload).
  - Sequence boundary isolation across multiple packet captures.
  - Non-finite (`NaN`, `Inf`) value reconciliation and schema rejection.
  - Exact TreeSHAP local attribution generation via `/api/csv/explain`.

### 2.4 Autonomous Response Baselines (Phase 2A)
- **Command:** `pytest tests/integration/test_phase2a_baselines.py -v`
- **Results:** 3 passed in 2.45s (Exit Code 0)
- **Verified Capabilities:**
  - Verification of `CostOptimalThresholdPolicy`, `StaticAllowPolicy`, `StaticBlockPolicy`, and `ProportionalPolicy`.
  - Exact cost matrix computation across 6 enterprise cost regimes.

### 2.5 Full Repository Regression Suite
- **Command:** `pytest tests/ -ra --tb=short`
- **Results:** 560 passed, 0 failed, 0 skipped in 54.98s (Exit Code 0)
- **Coverage:** Complete test coverage across `src/xrlids/` (preprocessing, feature extraction, models, explainability, reinforcement learning, live capture, rules, evaluation).

---

## 3. Fresh-Clone Exhibition Verification Suite

- **Script:** `scripts/verify_fresh_clone_exhibition.py`
- **Execution Command:** `python scripts/verify_fresh_clone_exhibition.py`
- **Runtime:** 4.15 seconds
- **Output Verdict:** `OVERALL VERDICT: PASS`
- **Verified Subsystems:**
  1. **Environment:** Python 3.14.4, PyTorch 2.14.0+cpu, scikit-learn 1.9.1, SciPy 1.18.1, pandas 3.0.6, NumPy 2.5.3, SHAP 0.52.0, PyYAML 6.0.3.
  2. **Model Integrity:** 9/9 canonical checkpoints verified bit-for-bit against SHA-256 hashes in `models/registry/model_manifest.json`.
  3. **PCAP Pipeline:** 42 packets parsed, 6 bidirectional flows extracted, exact R10 contract computed.
  4. **Dashboard Backend:** `index.html`, `app.js`, `demo.html`, `demo.js`, `dashboard/server.py`, and all API endpoints verified.
  5. **Safety Invariants:** Observational mode enforced (`applies_action=False`), 127.0.0.1 loopback bind enforced.

---

## 4. Empirical Latency Microbenchmarking

- **Script:** `scripts/benchmark_latency.py`
- **Execution Command:** `python scripts/benchmark_latency.py`
- **Methodology:** 100 trials (25 for TreeSHAP) on Linux x86_64, single-threaded isolated execution.

| Pipeline Component | Scope | Median Latency | P95 Latency | P99 Latency |
|---|---|---|---|---|
| **Feature Extraction** | `Flow.to_features()` on 10 packets | 0.018 ms | 0.035 ms | 0.039 ms |
| **Pure RF Inference** | 100-tree traversal on float32 array | 37.317 ms | 50.713 ms | 80.363 ms |
| **RF with Preprocessing** | StandardScaler transform + RF predict | 42.816 ms | 72.508 ms | 83.373 ms |
| **TreeSHAP Attribution** | TreeExplainer on 10-feature vector | 49.622 ms | 50.868 ms | 55.348 ms |
| **End-to-End Prediction** | Packet stream -> Flow -> Feat -> RF | 43.156 ms | 62.532 ms | 95.477 ms |
| **End-to-End Explanation** | Packet stream -> Flow -> Feat -> RF -> SHAP | 101.013 ms | 114.495 ms | 116.445 ms |

> [!NOTE]
> Single-flow microbenchmarks measure per-flow algorithmic computational latencies on isolated CPU threads. They exclude packet burst queue contention, kernel socket buffer drops, network interface interrupts, and inter-process IPC, and must not be cited as sustained production line-rate throughput.

---

## 5. Artifact Cryptographic Hash Verification

Every canonical checkpoint in `models/` was verified against `models/registry/model_manifest.json`:

| Relative Path | Size (Bytes) | SHA-256 Checksum | Match Status |
|---|---|---|---|
| `models/rf/random_forest_cicids2017.joblib` | 26,363,055 | `7c6ad493b8c634c03ba8fe90e7208d519f7dd93f4c0ce814ae80749e75c6bf7f` | ✅ MATCH |
| `models/rf/random_forest_cse2018.joblib` | 68,240,031 | `b7d2dc7bac14c818aa8480523297a731efc7793d56d1a10ea693d2042738faaa` | ✅ MATCH |
| `models/rf/random_forest_unswnb15.joblib` | 22,639,151 | `c432eb0671c6ae79b8f15858cf83a8f4305c7438c641f92e35fbb77f51174983` | ✅ MATCH |
| `models/lstm/lstm_cicids2017.pt` | 60,949 | `2cdbf88df2cb740d7c5ee15d96f9cbe0d359a35e468da40e0cfc5f0f353eb3c0` | ✅ MATCH |
| `models/lstm/lstm_cse2018.pt` | 60,949 | `ea5b8198c8ae08e92a8e807ea762bf5ce7efca46033bb759163e77f0a8d67280` | ✅ MATCH |
| `models/lstm/lstm_unswnb15.pt` | 57,813 | `4d9386ff464ce726ae0742f534ea720519391aa268be9719323b7b919d3fbc91` | ✅ MATCH |
| `models/dqn/dqn_4action_best.pt` | 43,189 | `6a5afc6691fa30a082c5cb448eaebf552b71fa08d3e21074a3f433989c676bc1` | ✅ MATCH |
| `models/dqn/dqn_3action_best.pt` | 42,997 | `c06a61fb71676f254e2694f4a3ea3ec2ec617937a444a70b0c609db278a55bfe` | ✅ MATCH |
| `models/fusion/fusion_weights.json` | 1,214 | `e35df251752b07d61fe7db8a99478148c2b535805f63934dca95995aa421bc2e` | ✅ MATCH |

**Result:** Zero trained artifacts modified, retrained, regenerated, or corrupted. Bit-for-bit preservation confirmed.
