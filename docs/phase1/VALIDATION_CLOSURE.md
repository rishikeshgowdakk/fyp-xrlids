# Validation Closure — GAP-M03 and GAP-P06

Status: **closed (2026-10-20)**.

This note records the two validation gaps that were previously tracked as pending and the exact
evidence that closes them. It is a companion to `SPLIT_METHODOLOGY.md`,
`reports/generated/bootstrap_ci_report.md`, and `reports/generated/temporal_split_report.md`.

## GAP-M03 — Bootstrap confidence intervals

**Status:** closed.

Per-seed 95% non-parametric bootstrap intervals were computed directly from the saved held-out
`predictions_test.csv` artifacts. No model was retrained and no test row was used for model or
threshold selection.

- **Threshold metrics** (accuracy, precision, recall, F1): exact row-bootstrap of the full held-out
  confusion matrix, $B=1000$.
- **ROC-AUC:** $B=1000$ stratified bootstrap resamples of a fixed 100,000-flow sample; the point
  estimate is computed on the full test set.
- **What the intervals mean:** test-set sampling uncertainty. They do **not** include training-seed
  variance; the 3-seed mean ± std is reported separately in `reports/generated/multi_seed_report.md`.

Seed-42 results:

| Dataset | Model | Accuracy [95% CI] | F1 [95% CI] | ROC-AUC [95% CI] |
|:---|:---|:---:|:---:|:---:|
| CIC-IDS2017 | Random Forest | 0.9815 [0.9811, 0.9819] | 0.9512 [0.9500, 0.9524] | 0.9968 [0.9965, 0.9971] |
| CIC-IDS2017 | Supervised LSTM | 0.9867 [0.9863, 0.9871] | 0.9633 [0.9622, 0.9643] | 0.9974 [0.9971, 0.9977] |
| CIC-IDS2017 | Fusion ($\alpha=0.50$) | 0.9906 [0.9903, 0.9910] | 0.9745 [0.9737, 0.9754] | 0.9989 [0.9987, 0.9991] |
| CSE-CIC-IDS2018 | Random Forest | 0.9723 [0.9720, 0.9725] | 0.8861 [0.8851, 0.8872] | 0.9902 [0.9893, 0.9914] |
| CSE-CIC-IDS2018 | Supervised LSTM | 0.9912 [0.9911, 0.9914] | 0.9603 [0.9597, 0.9610] | 0.9966 [0.9962, 0.9972] |
| CSE-CIC-IDS2018 | Fusion ($\alpha=0.00$) | 0.9912 [0.9911, 0.9914] | 0.9603 [0.9597, 0.9610] | 0.9966 [0.9962, 0.9972] |
| UNSW-NB15 | Random Forest | 0.8590 [0.8545, 0.8634] | 0.8548 [0.8502, 0.8599] | 0.9487 [0.9462, 0.9511] |
| UNSW-NB15 | Supervised LSTM | 0.8683 [0.8639, 0.8728] | 0.8637 [0.8591, 0.8687] | 0.9334 [0.9305, 0.9365] |
| UNSW-NB15 | Fusion ($\alpha=0.60$) | 0.8996 [0.8959, 0.9033] | 0.8970 [0.8930, 0.9009] | 0.9674 [0.9654, 0.9693] |

Artifacts:

- `reports/generated/bootstrap_ci_report.md` — full per-seed table.
- `results/experiments/<EXP>/bootstrap_cis.json` — machine-readable intervals and confusion counts.
- Dashboard **Offline Model Comparison** table — seed-42 point estimate plus 95% CI per metric.

## GAP-P06 — Temporal validation

**Status:** closed for temporal validation. Grouped-by-host validation was not executed because the
CSE provenance has no stable host key (source IP is not reliable across NAT/replay).

**Design.** CSE-CIC-IDS2018 ships a real capture `Timestamp`. `EXP-P1-CSE2018-TEMPORAL-R10-001`
sorts all 8,312,295 modelling rows by that timestamp and cuts at hour boundaries:

| Split | Rows | Window | Attack fraction |
|:---|:---:|:---|:---:|
| Train | 5,053,051 | 2018-02-14 01:00 → 2018-02-20 10:59 | 12.63% |
| Validation | 1,627,614 | 2018-02-20 11:00 → 2018-02-22 10:59 | 15.19% |
| Test | 1,631,630 | 2018-02-22 11:00 → 2018-03-02 12:59 | 3.08% |

No class stratification is applied. L-01 (exact duplicates), L-02 (rounded near-duplicates), and
L-05 (temporal overlap) pass; `leakage_report.json` status is `pass`.

**Why the test attack fraction is 3.08%.** Policy A conflict rejection removed 4,496,789 rows and
feature deduplication removed 2,944,601 duplicate vectors before splitting. Many later bot and
infiltration flows were exact feature duplicates of earlier rows or conflicted with benign labels.
The surviving 50,306 future attacks are the unique, conflict-free cases; this is a deliberately hard
test, not the raw future-period prevalence.

**Result (frozen Random Forest, $\tau=0.50$):**

| Metric | Random split | Temporal holdout | Δ |
|:---|:---:|:---:|:---:|
| Accuracy | 0.9723 | 0.9633 | -0.0090 |
| Precision | 0.8242 | 0.0332 | -0.7911 |
| Recall | 0.9580 | 0.0068 | -0.9512 |
| F1 | 0.8861 | **0.0113** [0.0101, 0.0124] | -0.8748 |
| ROC-AUC | 0.9902 | 0.3905 | -0.5997 |

Per-family collapse (families present in both test populations):

| Family | Random support / detection | Temporal support / detection |
|:---|:---:|:---:|
| BOT | 2,999 / 99.17% | 15,214 / 0.09% |
| INFILTERATION | 7,027 / 10.70% | 34,807 / 0.94% |
| BRUTE FORCE -WEB | 49 / 91.84% | 179 / 0.00% |
| BRUTE FORCE -XSS | 22 / 95.45% | 75 / 0.00% |
| SQL INJECTION | 15 / 73.33% | 31 / 0.00% |

**Interpretation.** The random-split CSE F1 0.8861 is an in-domain upper bound, not a future-day
estimate. The detector is worse than the majority baseline on the future test (majority accuracy
0.9692, F1 0). The near-perfect random-split bot score was largely same-day near-duplicate
memorization; on unique future bot flows, recall collapses to 0.09%. This is a negative
generalization result and is reported as such. The 99% headline must not be presented as
future-day or production readiness.

**Scope.** Single seed (42); LSTM/fusion were not trained in the temporal run; grouped-by-host
validation was not executed.

Artifacts:

- `results/experiments/EXP-P1-CSE2018-TEMPORAL-R10-001/` — full experiment artifacts.
- `reports/generated/temporal_split_report.md` — generated random-vs-temporal comparison.
- `results/experiments/EXP-P1-CSE2018-TEMPORAL-R10-001/temporal_validation.json` — machine-readable comparison.

## Claims supported after closure

- Same-day, deduplicated in-domain detection is strong on the CSE/CIC benchmarks (with the
  per-family blind spots documented in the final report).
- Detector metrics carry per-seed 95% bootstrap intervals; seed variance is reported separately.
- The CSE detector does **not** generalize to the later, unique future attacks in this holdout;
  aggregate accuracy is dominated by benign prevalence.

## Claims not supported

- “99% accuracy means the detector works on future traffic.”
- “Bot detection is 99% reliable in deployment.”
- “The model is production-ready.”

## Reproduction

```bash
# 1. Temporal holdout (full CSE population; ~46 min on the reference machine)
.venv/bin/python scripts/phase1/run_experiment.py \
  --config configs/experiments/p1_cse_cic_ids2018_temporal_r10.yaml \
  --skip-lstm --skip-shap

# 2. Random-vs-temporal report
.venv/bin/python scripts/phase1/summarize_temporal_validation.py \
  --random-experiment results/experiments/EXP-P1-CSE2018-R10-MULTI-001 \
  --temporal-experiment results/experiments/EXP-P1-CSE2018-TEMPORAL-R10-001 \
  --out reports/generated/temporal_split_report.md

# 3. Bootstrap intervals for all experiments
.venv/bin/python scripts/phase1/bootstrap_confidence_intervals.py \
  --experiments \
    results/experiments/EXP-P1-CIC2017-R10-001 \
    results/experiments/EXP-P1-CSE2018-R10-MULTI-001 \
    results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001 \
    results/experiments/EXP-P1-CSE2018-TEMPORAL-R10-001 \
  --out reports/generated/bootstrap_ci_report.md
```
