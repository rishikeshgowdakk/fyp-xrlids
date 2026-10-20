# SPLIT METHODOLOGY

Status: **implemented** in `src/xrlids/splitting/`.

## Roles

| Split | Purpose |
| --- | --- |
| TRAIN | learn parameters (scaler, RF, LSTM) |
| VALIDATION | select hyperparameters, thresholds, calibration |
| TEST | final evaluation only — touched once |

The scaler is fit on TRAIN only (scientific RULE 6), enforced by
`Preprocessor.fit(train_frame)` accepting only training data.

## Primary methodology: stratified random (Policy A)

`stratified_random`, ratios 60/20/20, seed 42, stratified on the binary label.
Feature-identical rows are removed before splitting, and conflicting duplicate
vectors are rejected. This is the in-domain benchmark used by the main Phase 1
experiment cards.

## Temporal holdout (GAP-P06)

CSE-CIC-IDS2018 ships a real capture `Timestamp` column. The temporal run
(`EXP-P1-CSE2018-TEMPORAL-R10-001`) sorts all modelling rows by that timestamp
and cuts them into contiguous train / validation / test blocks:

- train: earliest ~60% of rows;
- validation: next ~20%;
- test: latest ~20%, strictly later than validation;
- cut points are moved to the nearest hour boundary so flows sharing the same
  timestamp are not split across populations;
- class stratification is intentionally **not** applied. The observed class
  distribution is reported in `split_manifest.json` and is part of the evidence;
- malformed/epoch-zero timestamps, if any survive cleaning, are repaired from
  the maximum valid timestamp of the same `source_file`; the repaired count is
  recorded as `temporal.fallback_count`. In the executed run the count was
  **0** because the malformed raw rows were removed before the final modelling
  population;
- L-05 (`temporal_overlap`) is executed against the real timestamp column, and
  L-01/L-02/L-06 remain active. The split is rejected if a temporal overlap is
  detected.

The temporal experiment trains the same R10 Random Forest on the earlier period
and evaluates once on the later period. It does **not** replace the random-split
benchmark: the random split answers “can the model separate flows from the same
capture period?”, while the temporal holdout answers “how well does it transfer
to later capture days and unseen attack families?”.

### Why not a whole-day grouped split?

CSE-CIC-IDS2018 is highly unbalanced at the capture-day level. The
20 February file alone contributes about 95% of the deduplicated modelling
population. Assigning whole capture days to train/validation/test cannot produce
a 60/20/20 split without putting almost everything in one population. The
row-level temporal split keeps all days represented while still enforcing a
strict time ordering. The day-level imbalance is itself reported as a limitation.

## Determinism

Same seed + same input ⇒ identical assignment. Verified by unit test
(`test_deterministic_given_seed`) and by the split manifest hash.

## Leakage audit

Six checks are attempted after splitting (see `LEAKAGE_AUDIT.md`). A failing check
sets the overall status to `fail`; the pipeline logs it and `02_build_splits.py`
exits non-zero. The project does **not** continue with a tainted split.

For the temporal holdout, the audit frame carries the real `timestamp` column from
provenance so L-05 can be executed. The random-split benchmarks continue to report
L-03/L-04/L-05 as `not_performed` when those columns are absent.

## Results

`EXP-P1-CSE2018-TEMPORAL-R10-001` completed successfully. The split contains
5,053,051 train / 1,627,614 validation / 1,631,630 test rows, with observed
ratios 60.79% / 19.58% / 19.63%. The windows are:

| Split | Window | Attack fraction |
|:---|:---|:---:|
| Train | 2018-02-14 01:00 → 2018-02-20 10:59 | 12.63% |
| Validation | 2018-02-20 11:00 → 2018-02-22 10:59 | 15.19% |
| Test | 2018-02-22 11:00 → 2018-03-02 12:59 | 3.08% |

L-01/L-02/L-05 pass with zero cross-split exact/near-duplicate vectors and no
temporal overlap. The test attack fraction is 3.08% because Policy A removed
4,496,789 label-conflicting rows and 2,944,601 duplicate feature vectors before
splitting; the surviving 50,306 future attacks are the unique, conflict-free
cases, not the raw future-period prevalence.

The frozen RF degrades sharply on the future holdout:

| Metric | Random split | Temporal holdout | Δ |
|:---|:---:|:---:|:---:|
| Accuracy | 0.9723 | 0.9633 | -0.0090 |
| Precision | 0.8242 | 0.0332 | -0.7911 |
| Recall | 0.9580 | 0.0068 | -0.9512 |
| F1 | 0.8861 | 0.0113 | -0.8748 |
| ROC-AUC | 0.9902 | 0.3905 | -0.5997 |

The per-family collapse is the key evidence: bot recall falls from 99.17%
(random) to 0.09% (temporal), infiltration from 10.70% to 0.94%, web brute force
from 91.84% to 0.00%, XSS from 95.45% to 0.00%, and SQL injection from 73.33% to
0.00%. The random-split CSE F1 0.8861 is therefore an in-domain upper bound, not
a future-day estimate. This is reported as a negative generalization result, not
hidden. Full generated comparison: `reports/generated/temporal_split_report.md`;
machine-readable: `results/experiments/EXP-P1-CSE2018-TEMPORAL-R10-001/temporal_validation.json`.

## Cross-dataset splits

For transfer experiments the source dataset's train split trains the model and the
target dataset provides an external test population. Dataset normalisation strategy
is **D-005** (open); only the "source-trained preprocessing applied unchanged to
target" option is implemented, and alternatives must be added as explicit
configurations rather than implicit transformations.
