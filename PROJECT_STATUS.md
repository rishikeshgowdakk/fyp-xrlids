# PROJECT STATUS

Last updated: 2026-10-03
Project: **XRL-IDARS v1** · Repository: `fyp-xrlids`
Phase: **1 — Data + Research + Model Foundation**
Overall: **FOUNDATION REPAIRED & EVIDENCE RECONCILED — all 20 dataset CSVs physically present, SHA-256 verified, audited per-file; memory-bounded streaming pipelines, pre-flight gate, baseline ladder, and error analysis active; multi-file in-domain baseline experiments executed; Supervised LSTM and RF+LSTM Fusion empirically demonstrated on full multi-file populations for CIC-IDS2017 (`EXP-P1-CIC2017-R10-001`), CSE-CIC-IDS2018 (`EXP-P1-CSE2018-R10-MULTI-001`), and UNSW-NB15 (`EXP-P1-UNSWNB15-R10-MULTI-001`); full cross-dataset generalization matrix (6 directions) completed answering RQ5 under frozen R10 and R4 contracts.**

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
| Multi-file dataset population loader | ✅ | `src/xrlids/datasets/population.py` (reconciled accounting, conflict resolution) |
| Chunked streaming data pipeline | ✅ | `src/xrlids/preprocessing/streaming.py` + equivalence tests |
| Leakage-safe splits + leakage audit | ✅ | `src/xrlids/splitting/` + tests |
| Preprocessing (train-only fit) | ✅ | `src/xrlids/preprocessing/pipeline.py` + tests |
| Baseline ladder detectors (Majority, LR, DT) | ✅ | `src/xrlids/models/baselines.py` + tests |
| Memory-bounded Random Forest (capped parallelism) | ✅ | `src/xrlids/models/random_forest.py` (`n_jobs=min(4, os.cpu_count())`) |
| Memory-bounded Supervised LSTM (lazy sequence batching) | ✅ | `src/xrlids/models/lstm.py` (`SequenceArray` on-the-fly mini-batching) |
| Fusion (aligned populations) | ✅ | `src/xrlids/models/fusion.py` + tests |
| Calibration (Brier/ECE/reliability/Platt) | ✅ | `src/xrlids/evaluation/calibration.py` + tests |
| Threshold sweep + candidate operating points | ✅ | `src/xrlids/evaluation/thresholding.py` + tests |
| Statistical hypothesis testing & paired bootstrap | ✅ | `src/xrlids/evaluation/statistics.py` (empirical 95% CIs, p-values) |
| Per-attack-family evaluation | ✅ | `src/xrlids/evaluation/error_analysis.py` + tests |
| Experiment registry + result metadata | ✅ | `src/xrlids/experiments/registry.py` |
| Dataset manifest + checksum enforcement | ✅ | `src/xrlids/datasets/loading.py` (`verify_dataset_file`) + tests |
| Dataset acquisition workflow (register/verify) | ✅ | `src/xrlids/datasets/prepare.py` + `scripts/phase1/prepare_dataset.py` + tests |
| Real-file schema validation (canonical headers) | ✅ | `src/xrlids/datasets/schema.py` + tests |
| Real-data per-file streaming audit runner | ✅ | `scripts/phase1/03_run_audit.py` (25 structured audit fields per file) |
| Unified experiment runner + pre-flight gate | ✅ | `scripts/phase1/run_experiment.py` + `src/xrlids/experiments/preflight.py` (10-point check) |
| Resource profiler (instantaneous RSS, peak ru_maxrss) | ✅ | `src/xrlids/utils/profiler.py` + tests |
| Baseline experiment configs | ✅ | `configs/experiments/` |
| Dataset audit module | ✅ | `src/xrlids/datasets/audit.py` + tests |
| CLI | ✅ | `src/xrlids/cli.py` |
| Report generation from artifacts | ✅ | `scripts/phase1/generate_reports.py` (dynamic git hashes, live manifests) |
| Test suite | ✅ | 196 unit and integration tests passing (0 failures) |
| SHAP explainability module | ✅ | `src/xrlids/explainability/shap_analysis.py` + tests |
| Cross-dataset transfer module | ✅ | `src/xrlids/experiments/transfer.py` + `scripts/phase1/run_transfer.py` + configs (6 directions executed) |

## Empirical status

| Experiment | Status | Reason / Evidence |
| --- | --- | --- |
| Dataset acquisition | ✅ VERIFIED | All 20 physical CSV files acquired and verified against canonical manifest (8 CIC-IDS2017, 10 CSE-CIC-IDS2018, 2 UNSW-NB15) |
| Dataset audit (real files) | ✅ COMPLETED | All 20 files audited via chunked streaming with per-file JSON artifacts in `results/audits/` |
| Splits / leakage (real data) | ✅ VALIDATED | Policy A feature-dedup split passes L-01/L-02 cleanly (0 cross-split duplicate vectors) |
| CIC-IDS2017 Multi-File Baselines | ✅ EMPIRICALLY OBSERVED | Executed across all 8 files (2,830,743 raw rows -> 1,779,322 modeling rows); baseline ladder evaluated (`EXP-P1-CIC2017-R10-001`, RF test acc=0.9815, F1=0.9512) |
| CSE-CIC-IDS2018 Multi-File Baselines | ✅ EMPIRICALLY OBSERVED | Executed across all 10 files (16,233,002 raw rows -> 8,312,295 modeling rows); baseline ladder evaluated (`EXP-P1-CSE2018-R10-MULTI-001`, RF test acc=0.9723, F1=0.8861, ROC-AUC=0.9902) |
| UNSW-NB15 Multi-File Baselines | ✅ EMPIRICALLY OBSERVED | Executed across both files (257,673 raw rows -> 122,520 modeling rows); full baseline ladder, Supervised LSTM, and RF+LSTM Fusion evaluated under native 4-feature contract (`EXP-P1-UNSWNB15-R10-MULTI-001`, Fusion test acc=0.8996, F1=0.8970, ROC-AUC=0.9674) |
| Supervised LSTM (Multi-file) | ✅ EMPIRICALLY OBSERVED (ALL 3 DOMAINS) | Full multi-file training executed on CIC-IDS2017 (F1=0.9633), CSE-CIC-IDS2018 (F1=0.9603), and UNSW-NB15 (F1=0.8637, outperforming RF with $\text{LSTM} - \text{RF} = +0.0089$, $p=0.0000$) |
| Score Fusion (Multi-file) | ✅ EMPIRICALLY OBSERVED (ALL 3 DOMAINS) | Tuned fusion evaluated on CIC-IDS2017 ($\alpha=0.50$, F1=0.9745), CSE-CIC-IDS2018 ($\alpha=0.00$, F1=0.9603), and UNSW-NB15 ($\alpha=0.60$, F1=0.8970; $\Delta \text{F1}=+0.0421$ over RF, $\Delta \text{F1}=+0.0332$ over LSTM, $p=0.0000$) |
| Multi-seed evaluation | 🟡 PARTIAL | Runner supports multi-seed loop and aggregate metrics; full multi-file runs executed with seed 42 only |
| Cross-dataset transfer | ✅ EMPIRICALLY OBSERVED | Executed across all 6 directions: Primary R10 (CIC ↔ CSE) and Auxiliary R4 (UNSW ↔ CIC, UNSW ↔ CSE); severe domain degradation demonstrated (ΔF1 -0.52 to -0.95), answering RQ5 |
| SHAP (real data) | ✅ EMPIRICALLY OBSERVED | TreeSHAP evaluated on CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15 Random Forest models |
| Calibration (real data) | ✅ EMPIRICALLY OBSERVED | Platt scaling evaluated on CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15 models |
| Threshold objective | 🟡 CANDIDATES EVALUATED | Evaluated across 0.00–1.00; neutral 0.5 baseline reported; operational freeze gated on D-003 |

## Research decisions status

| ID | Decision | Status |
| --- | --- | --- |
| D-001 | Normalization & Cleaning contract | RESOLVED: Canonical column contract established with preserved raw provenance |
| D-002 | Feature contract R10/R15/R20 | RESOLVED: R10 frozen as Main Cross-Dataset 10-Feature Contract for CIC-IDS2017/CSE-CIC-IDS2018; UNSW-NB15 blocked on 6 missing features (auxiliary fallback) |
| D-003 | Threshold objective | OPEN: Neutral 0.5 baseline used pending operational deployment criteria |
| D-004 | Dataset acquisition | RESOLVED: All 20 modeling files acquired, verified, and audited |
| D-005 | Cross-dataset normalisation | OPEN: Train-only standard scaling applied within source domain |

## Explicitly not claimed

- No claims of universal performance or production readiness across arbitrary networks.
- No claims that intrusion detectors generalize out-of-domain without target adaptation; empirical evaluation across all 6 cross-dataset pairs demonstrates 52% to 95% F1 degradation under unadapted transfer (answering RQ5).
- No claims that sequence models capture true physical packet arrival timelines; sequence ordering represents capture flow arrival order within sample partitions.
- No claims of three-seed empirical averaging; full multi-file experiments reflect single-seed (seed=42) execution.
- No final threshold frozen (D-003 remains open; reporting uses neutral 0.5 baseline).
- Auxiliary event list `UNSW-NB15_LIST_EVENTS.csv` is absent (`DATA_NOT_AVAILABLE`); modeling relies solely on the two verified train/test partitions.
- `CLAIMS_REGISTRY.md` records only scoped, traceable empirical claims directly supported by committed `results/` artifacts.
