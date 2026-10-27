# CHANGELOG

## [Unreleased] — CSV evaluation workflow and documentation

### Added
- Custom CSV evaluation workflow in the dashboard: upload, paste, or load a sample of flow records and evaluate against compatible frozen Random Forest artifacts.
- Explicit benchmark-to-feature-contract pairing (CIC-IDS2017/R10, CSE-CIC-IDS2018/R10, UNSW-NB15/R4), strict binary-label parsing, non-finite feature handling, row accounting, and regression coverage.
- Evaluation export workflow and UI contract selection safeguards.

### Clarifications
- This is an addition to the dashboard's offline research workbench, not a redesign of the core packet-to-flow detection pipeline.
- CSV evaluation does not retrain models or overwrite historical benchmark artifacts.
- Previously reported research limitations remain: temporal generalization is weak on the CSE-CIC-IDS2018 future-day holdout, LSTM sequence-order benefit is not demonstrated by the shuffled-window ablation, and the analytic cost-optimal response baseline outperforms DQN in several evaluated regimes.
- The README test count was removed in favour of running the current suite, so documentation does not become stale when tests are added.

All notable changes to `fyp-xrlids` (project XRL-IDARS v1).

## [Unreleased] — Phase 1 implementation

### Added
- Python package `xrlids` (`src/xrlids/`) with a pinned environment (`pyproject.toml`, `requirements.txt`).
- Reproducibility utilities: deterministic seeding (Python/NumPy/PyTorch), file/schema/dict hashing,
  environment fingerprinting, structured logging.
- Artifact metadata with `*.meta.json` sidecars (experiment id, Git commit, dataset SHA-256,
  feature-schema hash, seed, environment).
- Centralized metrics module — the single implementation of accuracy, precision, recall, F1,
  macro/weighted F1, balanced accuracy, specificity, FPR, FNR, ROC-AUC and PR-AUC, including a
  guard that rejects thresholded 0/1 inputs passed as scores.
- Label contract with explicit per-dataset attack allow-lists, normalization and
  **unknown-label rejection with accounting** (unknown labels are never relabelled BENIGN).
- Feature system: 20 mathematically defined canonical features, candidate R10/R15/R20 rungs,
  per-feature decision-gate answers, per-dataset semantic column maps, feature validation.
- Cleaning pipeline with full row accounting that fails loudly when the arithmetic does not reconcile.
- Leakage-safe splitting with a six-check leakage audit (four enforced, two reported as not performed).
- Preprocessing with train-only fitting, frozen feature order and serialized metadata.
- Random Forest detector with config-driven hyperparameters and continuous probability output.
- Supervised LSTM with boundary-safe sequence construction (no sequence can cross a split).
- Score fusion on explicitly aligned populations, plus an RF/LSTM/fusion comparison helper.
- Calibration analysis (reliability curve, Brier score, ECE, validation-only Platt scaling).
- Threshold sweep and **candidate** operating points for four objectives — no objective selected
  (D-003 remains open).
- Experiment registry, dataset manifest loading with checksum verification and availability reporting.
- Dataset audit producing machine-readable findings (NaN/Inf, duplicates, constants, duration
  sanity, label audit, unknown-label rejections).
- CLI (`python -m xrlids.cli`) with `info`, `compatibility`, `verify-datasets`, `audit` and `smoke`.
- Phase 1 scripts: `01_dataset_audit.py`, `02_build_splits.py`, `generate_reports.py`.
- Test suite: 67 tests across unit, data, model and integration layers.
- Documentation: `FEATURE_DEFINITIONS`, `FEATURE_COMPATIBILITY`, `DATA_CLEANING_POLICY`, `METRICS`,
  `LABEL_CONTRACT`, `SPLIT_METHODOLOGY`, `LEAKAGE_AUDIT`, `PHASE1_REVIEW`.

### Findings
- **UNSW-NB15 cannot satisfy the R10 feature contract** (4/10 features supported: no TCP flag counts,
  no IAT, no active/idle, no subflow). The pipeline reports `BLOCKED_FEATURE_INCOMPATIBLE` rather
  than substituting columns. Recorded as an open decision.
- Zero-duration flows make rate features genuinely undefined; an explicit NaN-then-row-policy
  approach was adopted instead of silently substituting a value.

### Notes
- No datasets are present; all empirical experiments report `DATA_NOT_AVAILABLE`.
- The end-to-end pipeline was exercised on synthetic fixtures (`results/smoke/`) and those outputs
  are labelled `SMOKE_ONLY` and are explicitly **not** evidence.
- `docs/03_DECISIONS/CLAIMS_REGISTRY.md` remains empty of verified claims **by design**.
