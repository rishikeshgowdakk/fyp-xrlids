# PROJECT STATUS

Last updated: 2026-10-02
Project: **XRL-IDARS v1** · Repository: `fyp-xrlids`
Phase: **1 — Data + Research + Model Foundation**
Overall: **FOUNDATION COMPLETE & VERIFIED — all 20 dataset CSVs physically present, SHA-256 verified, audited per-file; memory-bounded streaming pipelines, pre-flight gate, and ML models active.**

Legend: ✅ done / verified · 🟡 implemented / empirically observed on partial data · ⛔ blocked on research decision · ⬜ planned / not started

## Implementation status

| Component | Status | Evidence |
| --- | --- | --- |
| Package + pinned environment | ✅ | `pyproject.toml`, `requirements.txt` (Python 3.14.4) |
| Reproducibility utils (seeding, hashing, env fingerprint) | ✅ | `src/xrlids/utils/` |
| Canonical column normalization | ✅ | `src/xrlids/utils/columns.py` (bidirectional mapping, raw provenance preserved) |
| Artifact metadata + sidecars | ✅ | `src/xrlids/artifacts/metadata.py` |
| Centralized metrics (single module) | ✅ | `src/xrlids/evaluation/metrics.py` + tests |
| Label contract + unknown-label rejection | ✅ | `src/xrlids/labels/contract.py` + `configs/labels/label_mapping.yaml` + regression tests |
| Feature definitions + registry + rungs | ✅ | `src/xrlids/features/`; candidate rungs R10/R15/R20 + 4-feature transfer contract |
| Feature computation + canonical column maps | ✅ | `src/xrlids/features/compute.py` + tests (CIC-IDS2017 R10 verified) |
| Feature compatibility matrix | ✅ | `reports/generated/feature_compatibility.md` |
| Cleaning + row accounting | ✅ | `src/xrlids/preprocessing/cleaning.py` + tests |
| Chunked streaming data pipeline | ✅ | `src/xrlids/preprocessing/streaming.py` + equivalence tests |
| Leakage-safe splits + leakage audit | ✅ | `src/xrlids/splitting/` + tests |
| Preprocessing (train-only fit) | ✅ | `src/xrlids/preprocessing/pipeline.py` + tests |
| Memory-bounded Random Forest (capped parallelism) | ✅ | `src/xrlids/models/random_forest.py` (`n_jobs=min(4, os.cpu_count())`) |
| Memory-bounded Supervised LSTM (lazy sequence batching) | ✅ | `src/xrlids/models/lstm.py` (`SequenceArray` on-the-fly mini-batching) |
| Fusion (aligned populations) | ✅ | `src/xrlids/models/fusion.py` + tests |
| Calibration (Brier/ECE/reliability/Platt) | ✅ | `src/xrlids/evaluation/calibration.py` + tests |
| Threshold sweep + candidate operating points | ✅ | `src/xrlids/evaluation/thresholding.py` + tests |
| Experiment registry + result metadata | ✅ | `src/xrlids/experiments/registry.py` |
| Dataset manifest + checksum enforcement | ✅ | `src/xrlids/datasets/loading.py` (`verify_dataset_file`) + tests |
| Dataset acquisition workflow (register/verify) | ✅ | `src/xrlids/datasets/prepare.py` + `scripts/phase1/prepare_dataset.py` + tests |
| Real-file schema validation (canonical headers) | ✅ | `src/xrlids/datasets/schema.py` + tests |
| Real-data per-file streaming audit runner | ✅ | `scripts/phase1/03_run_audit.py` (25 structured audit fields per file) |
| Unified experiment runner + pre-flight gate | ✅ | `scripts/phase1/run_experiment.py` + `src/xrlids/experiments/preflight.py` (10-point check) |
| Resource profiler (RSS MiB, duration, CPU, disk) | ✅ | `src/xrlids/utils/profiler.py` + tests |
| Baseline experiment configs | ✅ | `configs/experiments/` |
| Dataset audit module | ✅ | `src/xrlids/datasets/audit.py` + tests |
| CLI | ✅ | `src/xrlids/cli.py` |
| Report generation from artifacts | ✅ | `scripts/phase1/generate_reports.py` (dynamic git hashes, live manifests) |
| Test suite | ✅ | 120+ tests passing, 0 failures |
| SHAP explainability module | ✅ | `src/xrlids/explainability/shap_analysis.py` + tests |
| Error-analysis & disagreement module | ✅ | `src/xrlids/evaluation/error_analysis.py` + tests |
| Cross-dataset transfer module | ✅ | `src/xrlids/features/registry.py` + `run_experiment.py` (4-feature contract) |

## Empirical status

| Experiment | Status | Reason / Evidence |
| --- | --- | --- |
| Dataset acquisition | ✅ VERIFIED | All 20 physical CSV files acquired and verified (8 CIC-IDS2017, 10 CSE-CIC-IDS2018, 2 UNSW-NB15) |
| Dataset audit (real files) | ✅ COMPLETED | All 20 files audited via chunked streaming with per-file JSON artifacts in `results/audits/` |
| Splits / leakage (real data) | ✅ VALIDATED | Naive split fails L-01; Policy A feature-dedup split passes L-01/L-02 cleanly (0 duplicates) |
| RF / LSTM / Fusion baselines | 🟡 EMPIRICALLY OBSERVED | Executed on CSE-CIC-IDS2018 (`EXP-P1-CSE2018-R10-001`, `EXP-P1-CSE2018-POLICY-B-001`) |
| Feature contract (R10/R15/R20) | ✅ VERIFIED | CIC-IDS2017 and CSE-CIC-IDS2018 satisfy R10/R15/R20; UNSW-NB15 satisfies 4-feature transfer contract |
| Cross-dataset transfer | 🟡 PARTIAL | Programmatic 4-feature contract evaluated source-side in `EXP-P1-TRANSFER-CSE-TO-UNSW-001` |
| SHAP (real data) | 🟡 EMPIRICALLY OBSERVED | TreeSHAP evaluated on CSE-CIC-IDS2018 RF (`EXP-P1-CSE2018-R10-001`, top feature `packet_length_std`) |
| Calibration (real data) | 🟡 EMPIRICALLY OBSERVED | Platt scaling, ECE, reliability curves evaluated on CSE-CIC-IDS2018 (`EXP-P1-CSE2018-R10-001`) |
| Threshold objective | 🟡 CANDIDATES EVALUATED | Evaluated across 0.00–1.00; neutral 0.5 baseline reported; operational freeze gated on D-003 |
| End-to-end streaming equivalence | ✅ VERIFIED | In-memory vs chunked streaming pipeline produces exact identical features, splits, and predictions (`tests/data/test_streaming_pipeline_equivalence.py`) |

## Research decisions status

| ID | Decision | Status |
| --- | --- | --- |
| D-001 | Normalization & Cleaning contract | RESOLVED: Canonical column contract established with preserved raw provenance |
| D-002 | Feature contract R10/R15/R20 | OPEN: R10 verified on CIC-IDS2017 and CSE-CIC-IDS2018; 4-feature contract for cross-dataset with UNSW-NB15 |
| D-003 | Threshold objective | OPEN: Neutral 0.5 baseline used pending operational deployment criteria |
| D-004 | Dataset acquisition | RESOLVED: All 20 modeling files acquired, verified, and audited |
| D-005 | Cross-dataset normalisation | OPEN: Train-only standard scaling applied within source domain |

## Explicitly not claimed

- No claims of universal performance or production readiness across all three benchmark domains.
- No claims that empirical findings on a single capture day generalize universally without multi-day and cross-dataset confirmation.
- No final threshold frozen (D-003 remains open; reporting uses neutral 0.5 baseline).
- Auxiliary event list `UNSW-NB15_LIST_EVENTS.csv` is absent (`DATA_NOT_AVAILABLE`); modeling relies solely on the two verified train/test partitions.
- `CLAIMS_REGISTRY.md` records only scoped, traceable empirical claims directly supported by committed `results/` artifacts.
