# Dataset Audit Report (generated)

Status: `EMPIRICALLY OBSERVED` on real CSE-CIC-IDS2018 capture file.

## Summary Findings

| Audit Item | Observed Value | System Action | Status |
| --- | --- | --- | --- |
| Total Raw Rows | 331,125 | Loaded via streaming / memory-efficient pandas | `VERIFIED` |
| Total Columns | 80 | Validated against declared schema contract | `VERIFIED` |
| Exact Duplicate Raw Rows | 97 | Dropped deterministically during cleaning | `EMPIRICALLY OBSERVED` |
| Missing Values (NaN) | 1,834 cells (`Flow Byts/s`) | Imputed using training-set median only | `EMPIRICALLY OBSERVED` |
| Infinite Values (Inf) | 0 cells | Verified 0 infinite values | `VERIFIED` |
| Repeated Header Rows | 25 rows (`Label == 'Label'`) | Rejected as `UNKNOWN` (never converted to `BENIGN`) | `EMPIRICALLY OBSERVED` |
| Near-Constant Columns | 8 columns | Tracked in audit manifest | `EMPIRICALLY OBSERVED` |

## Class Distribution (Raw vs Cleaned)

| Label Token | Raw Count | Cleaned Count | Status in Label Contract | Canonical Mapping |
| --- | --- | --- | --- | --- |
| `BENIGN` | 238,037 | 237,940 | `ACCEPTED` | `BENIGN` (0) |
| `Infilteration` | 93,063 | 93,063 | `ACCEPTED` | `ATTACK` (1) |
| `Label` (Repeated Header) | 25 | 0 | `REJECTED_UNKNOWN` | `UNKNOWN` (Dropped) |

> [!IMPORTANT]
> The 25 repeated header rows were rejected because `Label` is not in the declared known-attack allowlist
> and not a recognized benign token. They were never silently converted to BENIGN.
