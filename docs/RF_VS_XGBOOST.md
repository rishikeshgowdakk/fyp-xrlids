# XRL-IDARS — XGBoost and Random Forest Comparison

**Purpose:** record the XGBoost candidate work without overstating its integration or the strength of the available benchmark evidence.

## 1. Current implementation boundary

The repository contains `src/xrlids/models/xgboost_detector.py`, an `XGBoostDetector` wrapper that provides:

- configuration-driven `XGBClassifier` construction;
- fit with optional validation evaluation set and early stopping;
- ordered DataFrame feature-name checks and NumPy feature-dimension checks;
- continuous positive-class score and thresholded prediction methods;
- feature-importance reporting;
- native XGBoost JSON model persistence with a companion metadata JSON file;
- model reload with classifier metadata re-established for sklearn compatibility.

The unit tests in `tests/unit/test_xgboost_detector.py` cover fit/predict, NumPy input, validation failures, feature importances, and save/load prediction parity.

**Important boundary:** the canonical model manifest (`models/registry/model_manifest.json`) does not currently register XGBoost artifacts, and `src/xrlids/models/registry.py` registers the three canonical Random Forest models. The authoritative architecture therefore describes RF as the live/replay detector. XGBoost is not yet established as the deployed live champion.

## 2. Reported comparison figures (not independently revalidated here)

The previous benchmark record reports the following test-set values:

| Dataset / contract | Model | Accuracy | Attack precision | Attack recall | Attack F1 | PR-AUC | ROC-AUC | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| CIC-IDS2017 / R10 | RF | 98.15% | 91.51% | 99.01% | 0.9512 | 0.9824 | 0.9968 | 2.04% |
| CIC-IDS2017 / R10 | XGBoost | 98.48% | 95.19% | 96.53% | 0.9585 | 0.9812 | 0.9965 | 1.09% |
| CSE-CIC-IDS2018 / R10 | RF | 78.33% | 70.61% | 10.19% | 0.1780 | 0.3564 | 0.6061 | 1.27% |
| CSE-CIC-IDS2018 / R10 | XGBoost | 78.93% | 86.37% | 10.13% | 0.1814 | 0.4111 | 0.6445 | 0.48% |
| UNSW-NB15 / R4 | RF | 85.88% | 79.62% | 92.23% | 0.8546 | 0.9321 | 0.9485 | 19.32% |
| UNSW-NB15 / R4 | XGBoost | 85.62% | 81.23% | 88.51% | 0.8471 | 0.9214 | 0.9414 | 16.74% |

These values are transcribed from the repository's prior comparison record. The training/evaluation scripts, split manifests, per-row predictions, and XGBoost model artifacts were not available in the paths inspected for this documentation update. Therefore the table is explicitly **reported, not reproduced or independently verified**. Do not present it as a fresh run.

### Interpretation

- **CIC-IDS2017:** XGBoost has a slightly higher reported F1 and lower reported FPR, while RF has higher reported recall and PR-AUC.
- **CSE-CIC-IDS2018:** both reported attack recalls are close to 10% and F1 is approximately 0.18. Neither result supports a claim of a strong operational detector. The XGBoost F1 difference (0.0034) is small.
- **UNSW-NB15:** RF has higher reported recall, F1, PR-AUC, and ROC-AUC; XGBoost has a lower reported FPR.

No single global winner follows from these results. Operational selection depends on the use case's false-negative and false-positive costs, and must be performed on validation data rather than by selecting whichever model has the better final test score.

## 3. Timing discrepancy — do not quote a single speedup yet

The repository's comparison and latency documents do not agree:

- The comparison table reports XGBoost median latency of 0.6909 ms (CIC), 0.2995 ms (CSE), and 0.2925 ms (UNSW), against RF values around 37 ms.
- The latency report separately lists XGBoost median 0.2428 ms and RF median 47.2357 ms.
- The comparison document's prose gives another XGBoost range (0.12–0.15 ms), which does not match its table.

These may reflect different benchmark harnesses, machines, warm-up policies, batch sizes, or measurement units, but the repository evidence inspected does not reconcile them. The previously advertised 50x–194x speedups must therefore be treated as **unverified across comparable conditions**.

A valid re-benchmark must record hardware/OS, Python and package versions, model and preprocessor hashes, batch size, warm-up count, number of repetitions, single-row versus batch inference, thread count, and median/p95/p99. Measure RF and XGBoost with the same input arrays and timing harness.

## 4. Requirements before XGBoost can become a live champion

1. Train a separate candidate for each supported dataset using the same approved train/validation/test boundaries as its RF baseline.
2. Fit preprocessing only on the training partition; persist the exact matching preprocessor and ordered feature list.
3. Select hyperparameters and threshold on validation data only.
4. Store each candidate in a dataset-specific artifact path. Avoid one generic filename that can overwrite another dataset's model.
5. Add manifest entries containing model type, dataset, R10/R4 contract, model path, preprocessor path, SHA-256, package versions, split identifier, and validation-selection metrics.
6. Extend the model registry with explicit XGBoost registrations without replacing the frozen RF artifacts.
7. Verify class-label-to-probability mapping from `classes_`; do not assume column 1 means ATTACK unless the class mapping confirms it.
8. Run unit, integration, persistence, feature-parity, TreeSHAP, and end-to-end live/replay tests for each dataset contract.
9. Benchmark latency under one identical harness and publish raw measurements plus summary statistics.
10. Compare RF and XGBoost on the untouched test split once, then record the result without further tuning on that split.
11. Only after validation and integration pass should a versioned champion configuration route live traffic to XGBoost. Keep RF as a rollback/baseline option.

## 5. Persistence and compatibility notes

XGBoost's native `save_model` / `load_model` format is the appropriate model persistence interface used by this wrapper. The model file does not by itself preserve all training configuration or application metadata; the companion metadata file is therefore required for this project's feature contract and reproducibility. See the [official XGBoost model API](https://xgboost.readthedocs.io/en/latest/python/python_api.html) and [model-saving guidance](https://xgboost.readthedocs.io/en/stable/tutorials/saving_model.html).

The current wrapper explicitly restores `_estimator_type = "classifier"` after construction and loading to preserve compatibility with code paths that inspect sklearn estimator type metadata. Keep a regression test around fit and load behavior when changing XGBoost or scikit-learn versions.

## 6. Decision

**Current decision: retain XGBoost as an offline candidate; keep the registered Random Forest as the documented live detector.**

This is a conservative integration decision, not a claim that RF is universally more accurate. The XGBoost candidate has promising reported efficiency and dataset-specific results, but canonical artifacts, provenance, comparable timing evidence, and live-registry integration must be completed before switching the operational path.
