# LEAKAGE AUDIT

Status: **implemented** in `src/xrlids/splitting/leakage.py`. Output:
`results/splits/leakage_report.json` (per run) and the `leakage_audit` block of every
pipeline result.

A check that **cannot** be performed is reported as `not_applicable`/`not_performed` with a
reason. It is never silently counted as a pass.

| ID | Check | How | Status |
| --- | --- | --- | --- |
| L-01 | duplicate overlap | SHA-256 of each feature row; intersection across splits must be empty | implemented, enforced |
| L-02 | near-duplicate overlap | rows rounded to 6 dp, exact match on the rounded vector (bounded sample) | implemented, **proxy only** |
| L-03 | group overlap | shared group key across splits | implemented, runs when a group column is supplied |
| L-04 | source-IP overlap | shared source IP across splits | implemented, runs when a source-IP column exists |
| L-05 | temporal overlap | overlapping timestamp ranges | implemented, runs when a timestamp column is supplied |
| L-06 | sequence overlap | LSTM windows crossing split boundaries | enforced **by construction** |

## L-06 — why it is structural, not a check

Sequences are built **independently within each split**
(`build_sequences(..., split=...)` only ever receives one split's rows), and each sequence
records its originating split. `assert_no_boundary_crossing` recomputes
`origin + seq_len <= split_size` for every sequence and raises otherwise. Unit-tested,
including a deliberate violation case.

## Current status on fixture runs

On synthetic fixture runs, L-01 and L-02 pass and are reported; L-03, L-04 and L-05 are
reported as **not performed** because the fixtures carry no group, source-IP or timestamp
columns. That is the honest result: those leakage vectors are currently **unverified for the
real datasets**, and remain unverified until the datasets are audited and a split with those
columns is actually run.

## What is NOT covered

- L-02 uses a rounding proxy, so it will miss near-duplicates that differ by more than
  10⁻⁶ in any feature. A principled distance-based near-duplicate check remains TODO.
- Attack-instance overlap (the same attack run appearing in two splits) is only detected if
  a group column that encodes the instance is supplied. None is currently declared.
- Class-balance shift caused by duplicate removal is measured (per-class duplicate counts
  are in the audit) but not yet formally tested as a leakage check.
