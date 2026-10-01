# PROJECT STATUS

Last updated: 2026-10-01
Project: **XRL-IDARS v1** · Repository: `fyp-xrlids`
Phase: **1 — Data + Research + Model Foundation**
Overall: **PARTIALLY COMPLETE — implementation complete, initial empirical baseline observed on CSE-CIC-IDS2018, multi-dataset programme pending remaining data**

Legend: ✅ done / verified · 🟡 implemented / empirically observed on partial data · ⛔ blocked on research decision / missing data · ⬜ planned / not started

## Implementation status

| Component | Status | Evidence |
| --- | --- | --- |
| Package + pinned environment | ✅ | `pyproject.toml`, `requirements.txt` (Python 3.14.4) |
| Reproducibility utils (seeding, hashing, env fingerprint) | ✅ | `src/xrlids/utils/` |
| Artifact metadata + sidecars | ✅ | `src/xrlids/artifacts/metadata.py` |
| Centralized metrics (single module) | ✅ | `src/xrlids/evaluation/metrics.py` + tests |
| Label contract + unknown-label rejection | ✅ | `src/xrlids/labels/contract.py` + tests |
| Feature definitions + registry + rungs | 🟡 | `src/xrlids/features/`; candidate rungs R10/R15/R20 |
| Feature computation + semantic column maps | ✅ | `src/xrlids/features/compute.py` + tests |
| Feature compatibility matrix | ✅ | `reports/generated/feature_compatibility.md` |
| Cleaning + row accounting | ✅ | `src/xrlids/preprocessing/cleaning.py` + tests |
| Leakage-safe splits + leakage audit | ✅ | `src/xrlids/splitting/` + tests |
| Preprocessing (train-only fit) | ✅ | `src/xrlids/preprocessing/pipeline.py` + tests |
| Random Forest detector | ✅ | `src/xrlids/models/random_forest.py` + tests |
| Supervised LSTM + sequence safety | ✅ | `src/xrlids/models/lstm.py` + tests |
| Fusion (aligned populations) | ✅ | `src/xrlids/models/fusion.py` + tests |
| Calibration (Brier/ECE/reliability/Platt) | ✅ | `src/xrlids/evaluation/calibration.py` + tests |
| Threshold sweep + candidate operating points | ✅ | `src/xrlids/evaluation/thresholding.py` + tests |
| Experiment registry + result metadata | ✅ | `src/xrlids/experiments/registry.py` |
| Dataset manifest + integrity/availability | ✅ | `src/xrlids/datasets/loading.py` |
| Dataset acquisition workflow (register/verify) | ✅ | `src/xrlids/datasets/prepare.py` + `scripts/phase1/prepare_dataset.py` + tests |
| Real-file schema validation (header vs column map) | ✅ | `src/xrlids/datasets/schema.py` + tests |
| D-002 evidence artifact | ✅ | `results/audits/feature_contract_evidence.json` (decision remains OPEN) |
| Real-data audit runner | ✅ | `scripts/phase1/03_run_audit.py` (reports DATA_NOT_AVAILABLE honestly) |
| Unified experiment runner | ✅ | `scripts/phase1/run_experiment.py` |
| Baseline experiment configs | ✅ | `configs/experiments/` (`p1_cse_cic_ids2018_r10.yaml`, `p1_cse_cic_ids2018_policy_b.yaml`, `p1_transfer_cse_to_unsw.yaml`) |
| Dataset audit | ✅ | `src/xrlids/datasets/audit.py` + tests |
| CLI | ✅ | `src/xrlids/cli.py` |
| Report generation from artifacts | ✅ | `scripts/phase1/generate_reports.py` |
| Test suite | ✅ | 101 tests passing |
| SHAP explainability module | ✅ | `src/xrlids/explainability/shap_analysis.py` + tests |
| Error-analysis & disagreement module | ✅ | `src/xrlids/evaluation/error_analysis.py` + tests |
| Cross-dataset transfer module | ✅ | `src/xrlids/features/registry.py` + `run_experiment.py` (4-feature contract) |
| OOD / multi-dataset sweep runners | ⬜ | planned |
| Report generators (per-experiment Markdown) | ✅ | `scripts/phase1/generate_reports.py` |

## Empirical status

| Experiment | Status | Reason / Evidence |
| --- | --- | --- |
| Dataset acquisition | 🟡 PARTIAL | CSE-CIC-IDS2018 1 file acquired/verified; CIC-IDS2017 & UNSW-NB15 `DATA_NOT_AVAILABLE` (auth/session barriers) |
| Dataset audit (real files) | ✅ COMPLETED | CSE-CIC-IDS2018 audited (331,125 rows, 80 cols, 25 unknown headers rejected) |
| Splits / leakage (real data) | ✅ VALIDATED | Naive split fails L-01 (7,559 duplicate vectors); Policy A feature-dedup split passes L-01/L-02 cleanly (0 duplicates) |
| RF / LSTM / Fusion baselines | 🟡 EMPIRICALLY OBSERVED | Executed on CSE-CIC-IDS2018 (`EXP-P1-CSE2018-R10-001`, `EXP-P1-CSE2018-POLICY-B-001`); multi-dataset baselines pending remaining data |
| Feature sweep (27 conditions) | ⛔ BLOCKED | D-002 open; UNSW-NB15 cannot satisfy R10; remaining datasets pending acquisition |
| Cross-dataset (6 directions) | 🟡 PARTIAL | Programmatic 4-feature contract evaluated source-side in `EXP-P1-TRANSFER-CSE-TO-UNSW-001`; target evaluation blocked on data |
| OOD / unseen attack | ⛔ BLOCKED | Target datasets absent |
| SHAP (real data) | 🟡 EMPIRICALLY OBSERVED | TreeSHAP evaluated on CSE-CIC-IDS2018 RF (`EXP-P1-CSE2018-R10-001`, top feature `packet_length_std`) |
| Calibration (real data) | 🟡 EMPIRICALLY OBSERVED | Platt scaling, ECE, reliability curves evaluated on CSE-CIC-IDS2018 (`EXP-P1-CSE2018-R10-001`) |
| Threshold objective | 🟡 CANDIDATES EVALUATED | Evaluated across 0.00–1.00; neutral 0.5 baseline reported; operational freeze gated on D-003 |
| End-to-end smoke on synthetic fixture | ✅ EXECUTED | `results/smoke/smoke_R10.json` (Code test only) |

## Blocked on research decisions

| ID | Decision | Blocks |
| --- | --- | --- |
| D-002 | Feature contract R10/R15/R20 | Full 27-condition feature sweep, multi-dataset baselines |
| D-003 | Threshold objective | Freezing single operational operating point |
| D-004 | Dataset acquisition | Remaining empirical work for CIC-IDS2017 and UNSW-NB15 |
| D-005 | Cross-dataset normalisation | Target evaluation on transferred feature spaces |
| — | Duplicate-Split Policy | Formal adoption of Policy A (`deduplicate_features`) vs Policy B |
| — | UNSW-NB15 cannot satisfy R10 (4/10 features) | 1/3 of primary feature sweep |

## Explicitly not claimed

- No claims of universal performance or production readiness across all three benchmark domains.
- No claims that empirical findings on a single CSE-CIC-IDS2018 day file generalize universally without cross-dataset confirmation.
- No final threshold frozen (D-003 remains open; reporting uses neutral 0.5 baseline).
- No claims of target evaluation on UNSW-NB15 or CIC-IDS2017 until files are acquired and verified.
- `CLAIMS_REGISTRY.md` records only scoped, traceable empirical claims directly supported by committed `results/` artifacts.
