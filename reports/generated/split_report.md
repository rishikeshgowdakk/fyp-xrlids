# Split Manifest Report (generated)

Target Ratios: **60% Train**, **20% Validation**, **20% Test** (configured in `configs/splits/splits.yaml`).

## Split Manifest Comparison

| Split Policy | Total Cleaned Rows | Deduplicated Rows Removed | Train Rows (60%) | Validation Rows (20%) | Test Rows (20%) | Leakage Status |
| --- | --- | --- | --- | --- | --- | --- |
| **Policy A** (`deduplicate_features`) | 331,027 | 111,414 (33.96%) | 130,017 | 43,339 | 43,340 | `PASS` (0 overlap) |
| **Policy B** (`retain_with_subset_evaluation`) | 331,027 | 0 (0.00%) | 198,616 | 66,205 | 66,206 | `FAIL` (7,559 overlap) |

## Preprocessing and Boundary Safety

- **Preprocessing Isolation**: `StandardScaler` and `SimpleImputer` (median) are fit **exclusively on the training split**.
  Validation and Test sets are transformed using the fitted training parameters.
- **Sequence Boundary Safety**: LSTM sequence construction is performed **after** splitting.
  Sequences are strictly bounded within their respective split partition; crossing train/val/test boundaries raises `SequenceError`.
