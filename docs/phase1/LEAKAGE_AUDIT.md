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

## Current status on real data (2026-09-30)

### Real data split audit (`CSE-CIC-IDS2018`, Thursday-01-03-2018)
- **Split config:** `stratified_random` 60/20/20, seed 42.
- **Accepted rows:** 331,027.
- **Findings:**
  - **L-01 (Duplicate overlap): FAILED.**
    - Train / Validation duplicate overlap: **7,576** rows.
    - Train / Test duplicate overlap: **7,559** rows.
    - Validation / Test duplicate overlap: **4,357** rows.
  - **L-02 (Near-duplicate overlap): FAILED.**
    - Train / Validation: **245** rows.
    - Train / Test: **258** rows.
    - Validation / Test: **258** rows.
  - **L-03, L-04, L-05:** Not performed (`not_performed`) because no group, source-IP or valid timestamp range grouping was enforced.

### Root Cause Analysis:
1. **Row-level vs Feature-level Duplication:** The cleaning step removes exact duplicates across the full 80-column raw frame (97 rows removed). However, when projected into the 10-feature candidate R10 space, **114,315 rows (34.53%)** are identical across feature values (common for short scan packets and repetitive background flows).
2. **Naive Splitting Leakage:** A naive stratified random split assigns these identical feature vectors independently across train, validation, and test sets.
3. **Mitigation verification:** When feature-level deduplication is applied prior to splitting, **L-01 and L-02 pass cleanly with 0 duplicate overlaps**.
4. **Research Decision Required:** Whether to adopt feature-level deduplication (reducing sample count from 331,027 to 216,712 unique feature vectors) or enforce group/temporal splitting is an open research decision for the team.

## What is NOT covered

- L-02 uses a rounding proxy, so it will miss near-duplicates that differ by more than
  10⁻⁶ in any feature. A principled distance-based near-duplicate check remains TODO.
- Attack-instance overlap (the same attack run appearing in two splits) is only detected if
  a group column that encodes the instance is supplied. None is currently declared.
- Class-balance shift caused by duplicate removal is measured (per-class duplicate counts
  are in the audit) but not yet formally tested as a leakage check.
