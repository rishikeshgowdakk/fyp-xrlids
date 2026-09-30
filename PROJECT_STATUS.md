# PROJECT STATUS

Last updated: 2026-09-30
Project: **XRL-IDARS v1** · Repository: `fyp-xrlids`
Phase: **1 — Data + Research + Model Foundation**
Overall: **PARTIALLY COMPLETE — implementation complete, empirical programme pending datasets**

Legend: ✅ done · 🟡 implemented, not yet run on real data · ⛔ blocked on research decision · ⬜ not started

## Implementation status

| Component | Status | Evidence |
| --- | --- | --- |
| Package + pinned environment | ✅ | `pyproject.toml`, `requirements.txt` (Python 3.14.4) |
| Reproducibility utils (seeding, hashing, env fingerprint) | ✅ | `src/xrlids/utils/` |
| Artifact metadata + sidecars | ✅ | `src/xrlids/artifacts/metadata.py` |
| Centralized metrics (single module) | ✅ | `src/xrlids/evaluation/metrics.py` + tests |
| Label contract + unknown-label rejection | ✅ | `src/xrlids/labels/contract.py` + tests |
| Feature definitions + registry + rungs | 🟡 | `src/xrlids/features/`; contract `candidate_not_frozen` |
| Feature computation + semantic column maps | 🟡 | `src/xrlids/features/compute.py`; maps `unverified_pending_audit` |
| Feature compatibility matrix | ✅ | `reports/generated/feature_compatibility.md` |
| Cleaning + row accounting | ✅ | `src/xrlids/preprocessing/cleaning.py` + tests |
| Leakage-safe splits + leakage audit | ✅ | `src/xrlids/splitting/` + tests |
| Preprocessing (train-only fit) | ✅ | `src/xrlids/preprocessing/pipeline.py` + tests |
| Random Forest detector | ✅ | `src/xrlids/models/random_forest.py` + tests |
| Supervised LSTM + sequence safety | ✅ | `src/xrlids/models/lstm.py` + tests |
| Fusion (aligned populations) | ✅ | `src/xrlids/models/fusion.py` + tests |
| Calibration (Brier/ECE/reliability/Platt) | ✅ | `src/xrlids/evaluation/calibration.py` |
| Threshold sweep + candidate operating points | ✅ | `src/xrlids/evaluation/thresholding.py` |
| Experiment registry + result metadata | ✅ | `src/xrlids/experiments/registry.py` |
| Dataset manifest + integrity/availability | ✅ | `src/xrlids/datasets/loading.py` |
| Dataset audit | ✅ | `src/xrlids/datasets/audit.py` + tests |
| CLI | ✅ | `src/xrlids/cli.py` |
| Report generation from artifacts | ✅ | `scripts/phase1/generate_reports.py` |
| Test suite | ✅ | 67 tests passing |
| SHAP module | ⬜ | documented only |
| Error-analysis module | ⬜ | planned |
| OOD / cross-dataset runners | ⬜ | planned |
| Report generators (per-experiment Markdown) | 🟡 | summary generator done |

## Empirical status

| Experiment | Status | Reason |
| --- | --- | --- |
| Dataset audit (real files) | `DATA_NOT_AVAILABLE` | datasets not acquired |
| Splits / leakage (real data) | `DATA_NOT_AVAILABLE` | datasets not acquired |
| RF / LSTM / Fusion baselines | `DATA_NOT_AVAILABLE` | datasets not acquired |
| Feature sweep (27 conditions) | ⛔ blocked | D-002 open; UNSW-NB15 cannot satisfy R10 |
| Cross-dataset (6 directions) | ⛔ blocked | D-005 open; datasets absent |
| OOD / unseen attack | ⛔ blocked | datasets absent |
| SHAP | ⛔ blocked | no trained model on real data |
| Calibration (real data) | `DATA_NOT_AVAILABLE` | datasets not acquired |
| Threshold objective | ⛔ blocked | D-003 open |
| End-to-end smoke on synthetic fixture | ✅ executed | `results/smoke/smoke_R10.json` (NOT evidence) |

## Blocked on research decisions

| ID | Decision | Blocks |
| --- | --- | --- |
| D-002 | Feature contract R10/R15/R20 | feature sweep, baselines, SHAP |
| D-003 | Threshold objective | freezing any operating point |
| D-004 | Dataset acquisition | all empirical work |
| D-005 | Cross-dataset normalisation | transfer experiments |
| — | UNSW-NB15 cannot satisfy R10 (4/10 features) | 1/3 of primary sweep |

## Explicitly not claimed

- No accuracy, precision, recall, F1, ROC-AUC, PR-AUC or confusion matrix for any dataset.
- No cross-dataset, OOD, SHAP or calibration finding.
- No statement that any model is trained on real data.
- `CLAIMS_REGISTRY.md` is empty of verified claims **by design**.
