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

## Current methodology

`stratified_random`, ratios 60/20/20, seed 42, stratified on the binary label.

Rationale: none of the three datasets is assumed to ship a trustworthy timestamp or
grouping key. A temporal or grouped split would be *stronger* evidence, but assuming a time
column that may not exist (or may be meaningless after export) would fabricate rigour.
The group/temporal leakage checks are therefore reported as **not performed** rather than
silently passed — visible in every run's `leakage_audit.not_performed` list.

**This is a candidate methodology, not a frozen one.** If the audit reveals a usable
timestamp or flow-grouping key, a temporal/grouped split should be adopted and the
difference reported.

## Determinism

Same seed + same input ⇒ identical assignment. Verified by unit test
(`test_deterministic_given_seed`).

## Leakage audit

Six checks are attempted after splitting (see `LEAKAGE_AUDIT.md`). A failing check sets the
overall status to `fail`; the pipeline logs it and `02_build_splits.py` exits non-zero. The
project does **not** continue with a tainted split.

## Cross-dataset splits

For transfer experiments the source dataset's train split trains the model and the target
dataset provides an external test population. Dataset normalisation strategy is **D-005**
(open); only the "source-trained preprocessing applied unchanged to target" option is
implemented, and alternatives must be added as explicit configurations rather than implicit
transformations.
