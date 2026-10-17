# Training & Artifacts Guide (Plain-Language Walkthrough)

This guide explains, from zero, **how XRL-IDARS trains its detection models, how the data splits work, and what every artifact in `results/` means**. Companion to `docs/review/SENIOR_ML_REVIEW.md` (which contains the critique and the improvement plan).

If you read only one thing: the pipeline is a straight line —

```
raw CSV files
   → clean + reconcile (remove junk, exact dupes, conflicting labels)
   → deduplicate feature vectors
   → split into TRAIN / VALIDATION / TEST (60/20/20)
   → fit scaler on TRAIN ONLY, transform all three
   → train Random Forest (tabular) and LSTM (sequence of 5 flows)
   → combine their scores (Fusion)
   → measure on TEST once
   → save models + every number as an artifact
```

---

## 1. The three datasets

| Dataset | What it is | Feature contract | Has IP/timestamp? |
| --- | --- | --- | --- |
| **CIC-IDS2017** | 5 days of lab traffic, 8 CSVs, CICFlowMeter features | **R10** (10 features) | **No** — 79 columns, no IP/time |
| **CSE-CIC-IDS2018** | 10 days of enterprise-scale traffic, 10 CSVs | **R10** | **Yes** — has `Timestamp` (col 3) |
| **UNSW-NB15** | NetFlow/Argus records (IXIA PerfectStorm), 2 published CSVs | **R4** (only 4 features exist) | No |

**R10** = `flow_duration_ms, flow_packets_per_s, flow_bytes_per_s, packet_length_mean, packet_length_std, syn_count, ack_count, rst_count, fin_count, syn_ack_ratio`.

**R4** (UNSW fallback) = `flow_duration_ms, flow_packets_per_s, flow_bytes_per_s, packet_length_mean`. UNSW cannot supply TCP flags or packet-length std, so the 10-feature contract cannot be used there.

---

## 2. How the data is cleaned (and why the numbers shrink)

Before any model sees the data, `load_dataset_population` removes:

1. rows with unknown labels (e.g. repeated header rows labelled `Label`) — never silently converted to BENIGN;
2. invalid rows (negative durations, non-finite values);
3. **exact duplicate rows**;
4. **duplicate feature vectors** — after projecting to the 10 features, identical vectors are collapsed;
5. **label-conflicting vectors** — when the *same* feature vector appears with both BENIGN and attack labels, all copies are dropped (`reject_conflicts`).

On CIC-IDS2017: 2,830,743 raw → **1,779,322 modeling rows**. The biggest single loss is **319,537 conflicting rows** (~18%). Those rows are exactly the flows where these coarse features cannot tell benign from attack — keep that in mind when reading §5.

Everything is reconciled with an accounting formula (raw − removals = final), and every file is SHA-256 verified first.

---

## 3. How the split works

- Ratios **60% train / 20% validation / 20% test**, `seed=42`, stratified on the binary label.
- **Feature-level deduplication happens BEFORE splitting**, so no identical feature vector lands in two splits (leakage checks L-01/L-02 = 0 overlap).
- Roles are strict:
  - **TRAIN** → learns scaler parameters and model weights.
  - **VALIDATION** → picks fusion weight α, calibration, thresholds/early stopping.
  - **TEST** → touched **once**, for the final number only.
- It is a **row-level random split**, not grouped by host or time. This means near-duplicate flows from the same attack burst can still appear in both train and test. This is why the in-domain scores are optimistic, and why CSE (which has a timestamp) should also get a temporal split.

---

## 4. How training actually runs

Command:
```bash
python scripts/phase1/run_experiment.py --config configs/experiments/p1_cicids2017_r10.yaml
```

Steps the runner performs (mirrors the docstring in `scripts/phase1/run_experiment.py`):

1. **Pre-flight gate** — verify SHA-256 + schema of every file (10-point check). Fails loudly if data is missing/tampered.
2. **Load + reconcile** the multi-file population and record the accounting.
3. **Build splits** and run the leakage audit.
4. **Fit the `Preprocessor` on TRAIN ONLY** (median imputation + `StandardScaler`), then transform validation and test with the frozen train statistics.
5. **Baseline ladder:** Majority → Logistic Regression → Decision Tree → Random Forest.
6. **Random Forest** (`n_estimators=100, max_depth=16, min_samples_leaf=2, class_weight=balanced_subsample`).
7. **Supervised LSTM** over sequences of 5 consecutive flows (`seq_len=5, stride=1, label_rule="last"`, hidden 32, 2 layers, early stopping). Sequences are built **within** each split only, so no window can span train/test.
8. **Fusion:** `P_fusion = α · P_rf + (1−α) · P_lstm`; α is chosen on validation by ROC-AUC.
9. **Evaluation on TEST:** accuracy, precision, recall, F1, macro/weighted F1, balanced accuracy, specificity, FPR, FNR, ROC-AUC, PR-AUC — plus per-attack-family metrics and paired bootstrap significance tests (B=1000).
10. **Explainability:** TreeSHAP feature importances.

---

## 5. What each artifact means

Inside e.g. `results/experiments/EXP-P1-CIC2017-R10-001/`:

| File | Meaning |
| --- | --- |
| `random_forest.joblib`, `lstm.pt`, `decision_tree.joblib`, `logistic_regression.joblib`, `majority_class.joblib` | Trained models |
| `preprocessor.joblib` + `preprocessor.meta.json` | **Required** to run a model — holds feature order + scaling statistics. A model without its preprocessor is unusable |
| `experiment_population.json` | Every input file, its SHA-256, and the exact row accounting |
| `split_manifest.json` | Split sizes, class balance, seed, config hash |
| `leakage_report.json` | L-01…L-06 check results (`not_performed` where impossible) |
| `test_metrics.json` | All metrics for every model, on native and aligned populations |
| `per_family_metrics.csv` | Recall/error **per attack family** — this is where the real story is |
| `model_comparisons.json` | Paired bootstrap ΔF1, 95% CI, p-value |
| `calibration_report.json` | Brier/ECE/reliability + Platt calibration |
| `threshold_candidates.json` | Recalls/FPRs across thresholds (D-003 is open) |
| `shap_summary.json` | TreeSHAP global importances |
| `predictions_test.csv` | Per-row scores for all models |
| `experiment_card.md` / `experiment_record.json` | Human- and machine-readable summary |

**Canonical model copies** live in `models/rf`, `models/lstm`, `models/fusion/` and are listed in `models/registry/registry.yaml`.

To use a saved model you must load **both** the model and its `preprocessor.joblib` (verified working for the CIC RF: 10 features in → probability out).

---

## 6. How to read the results honestly

1. **Never quote a single aggregate F1 alone.** The CIC test set is ~90% DoS/DDoS, so 0.95 F1 mostly measures DoS detection.
2. **Always check `per_family_metrics.csv`.** That is where Infiltration (10.7% recall on CSE), XSS (2.8% on CIC) and Web-Brute-Force (15.9% on CIC) show up.
3. **Treat families with tiny support as `INSUFFICIENT_SUPPORT`,** not as 0% failure (CIC Infiltration has only 8 test rows; SQLi 3; Heartbleed 3).
4. **Remember the split is row-level** → in-domain numbers are an optimistic ceiling, not deployment accuracy.
5. **UNSW is auxiliary.** Different features (R4), ~19% false alarms — don't average it with CIC/CSE.

---

## 7. Quick commands

```bash
# activate env
source .venv/bin/activate

# run the full test suite (verified: all pass)
python -m pytest -q

# run a detection experiment
python scripts/phase1/run_experiment.py --config configs/experiments/p1_cicids2017_r10.yaml

# multi-seed (for mean ± std) — writes seed_<n>/ subdirs
python scripts/phase1/run_experiment.py --config configs/experiments/p1_cicids2017_r10.yaml --seeds 42 123 456

# aggregate a completed sweep (mean ± std across RF / LSTM / Fusion)
python scripts/phase1/summarize_multi_seed.py --experiments results/experiments/EXP-P1-CIC2017-R10-001

# replay demonstration (uses committed models + demo PCAP)
python scripts/demo/run_replay_demo.py
```

---

## 8. Glossary

- **Rung (R10/R15/R20):** a named set of features; R10 is frozen for CIC/CSE, R4 is the UNSW fallback.
- **Leakage:** information from test contaminating training, which fakes high scores. Checks L-01…L-06 look for it.
- **Aligned population:** the subset of test rows where *all* models (including the sequence LSTM) have a valid prediction, so comparisons are fair.
- **Fusion α:** weight given to the RF vs the LSTM in the combined score.
- **D-003:** the still-open decision on which decision threshold to use operationally.
- **Platt scaling:** a post-hoc calibration that turns raw scores into better-calibrated probabilities (fit on validation).
