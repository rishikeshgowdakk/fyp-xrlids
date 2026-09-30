# FUNCTIONAL REQUIREMENTS

Status: draft. Verification status is tracked per requirement; nothing is "met" until a
linked test or artifact exists.

## Data lineage

| ID | Requirement | Phase | Verification | Status |
| --- | --- | --- | --- | --- |
| FR-001 | Every dataset file is recorded in a registry with source, version, license, size, rows, columns, label column, and SHA256 | 1 | `data/manifests/dataset_registry.yaml` | ⬜ |
| FR-002 | Download pipeline verifies SHA256 and hard-fails on mismatch | 1 | test in `tests/data/` | ⬜ |
| FR-003 | Audit script reports rows, dtypes, label values, class counts, NaN/Inf, duplicates, constant columns, negative/zero durations, outliers, malformed rows | 1 | `scripts/phase1/01_dataset_audit.py` | ⬜ |
| FR-004 | Data accounting reconciles raw → accepted rows with no unexplained loss | 1 | audit report arithmetic check | ⬜ |
| FR-005 | Every cleaning rule is documented with problem, detection, count, action, reason, risk, alternative | 1 | `docs/phase1/DATA_CLEANING_POLICY.md` | ⬜ |

## Labels

| ID | Requirement | Phase | Verification | Status |
| --- | --- | --- | --- | --- |
| FR-006 | Binary mapping maps BENIGN/NORMAL→0 and ATTACK→1, preserving original labels separately | 1 | `configs/labels/label_mapping.yaml`, `src/preprocessing/labels.py` | ⬜ |
| FR-007 | Unknown labels are rejected, never silently mapped to BENIGN | 1 | unit test | ⬜ |
| FR-008 | Attack taxonomy maps native → normalized → binary → family, documenting imperfect mappings | 1 | `docs/phase1/` | ⬜ |

## Features

| ID | Requirement | Phase | Verification | Status |
| --- | --- | --- | --- | --- |
| FR-009 | Every canonical feature has a written mathematical definition | 1 | `docs/phase1/FEATURE_DEFINITIONS.md` | ⬜ |
| FR-010 | Feature rungs R10/R15/R20 each have an explicit list, rationale and compatibility flags | 1 | `configs/features/features.yaml` | ⬜ |
| FR-011 | Feature selection passes the 10-point decision gate before freezing | 1 | decision record | ⬜ |

## Splitting and preprocessing

| ID | Requirement | Phase | Verification | Status |
| --- | --- | --- | --- | --- |
| FR-012 | Scalers are fit on training data only, then applied to validation/test/live | 1 | unit test | ⬜ |
| FR-013 | Split leakage audit checks duplicate, near-duplicate, group, source-IP, temporal, and sequence overlap | 1 | `results/splits/leakage_report.json` | ⬜ |
| FR-014 | No LSTM sequence crosses a train/validation/test boundary | 1 | sequence-boundary test | ⬜ |

## Modelling and evaluation

| ID | Requirement | Phase | Verification | Status |
| --- | --- | --- | --- | --- |
| FR-015 | RF, LSTM and Fusion produce metrics.json, metrics.csv, confusion_matrix.csv, classification_report.csv, predictions.parquet per dataset | 1 | `results/baselines/` | ⬜ |
| FR-016 | Metric implementations document definition, library function, input type (score vs label), averaging and edge cases | 1 | `src/evaluation/metrics.py` + tests | ⬜ |
| FR-017 | Threshold is selected on validation data according to a predefined policy, never on the test set | 1 | `results/thresholding/` | ⬜ |
| FR-018 | Calibration is measured (reliability diagram, Brier, ECE) before scores are called "confidence" | 1 | `results/calibration/` | ⬜ |
| FR-019 | Error analysis enumerates top FP/FN, hardest classes and score distributions | 1 | `results/error_analysis/` | ⬜ |

## Platform (Phase 2)

| ID | Requirement | Phase | Verification | Status |
| --- | --- | --- | --- | --- |
| FR-020 | Every trained artifact is registered with model ID, dataset, feature/preprocessor version, config, seed, metrics, date, commit, checksum | 2 | `models/registry/` | ⬜ |
| FR-021 | ML API exposes /predict, /explain, /health, /model, /version with documented schemas | 2 | `services/ml-api/` + API tests | ⬜ |
| FR-022 | Training and live paths share a single feature contract (names, order, units, formulas, scaler, missing-value rules) | 2 | shared module + integration test | ⬜ |
| FR-023 | Replay engine drives historical flows through the full chain deterministically | 2 | `tests/system/` | ⬜ |
| FR-024 | DQN is compared against Always-ALLOW, Always-BLOCK, fixed-threshold, RF and Fusion policies | 2 | `results/dqn/` | ⬜ |
| FR-025 | Every prediction persists as an event and every action is audit-logged | 2 | database + audit log | ⬜ |

## Live system (Phase 3)

| ID | Requirement | Phase | Verification | Status |
| --- | --- | --- | --- | --- |
| FR-026 | Packet capture builds flows keyed by 5-tuple, then flow statistics → feature vector | 3 | `src/inference/` | ⬜ |
| FR-027 | Live feature parity is verified per feature against tolerance; one failing feature blocks enforcement | 3 | `results/realtime/feature_parity.csv` | ⬜ |
| FR-028 | Replay and live conclusions are reported separately and never merged | 3 | `docs/phase3/` | ⬜ |
| FR-029 | Response modes OBSERVE / DRY-RUN / ENFORCE exist, defaulting to non-enforcing | 3 | config + code | ⬜ |
| FR-030 | BLOCK passes a safety gate: confidence, repeat confirmation, protected-source check, existing-block check, cooldown | 3 | `configs/safety/` + tests | ⬜ |
| FR-031 | Rollback of any applied block is possible and audited | 3 | runbook + test | ⬜ |
| FR-032 | Failure injection covers API/DB/capture/model/firewall failures and the system fails safe | 3 | `docs/failures/` | ⬜ |
