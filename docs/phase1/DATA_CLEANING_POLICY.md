# DATA CLEANING POLICY

Status: **implemented** in `src/xrlids/preprocessing/cleaning.py`.

Every operation is measured and reconciled: `raw - removed + recovered = accepted`. The
pipeline raises `CleaningAccountingError` if the arithmetic does not hold, so no row can
disappear without a reason.

## Rules

### C-01 — Column-name normalization

| Field | Value |
| --- | --- |
| Problem | Leading/trailing whitespace in headers (e.g. `"Label "`) breaks column lookups |
| Detection | strip every column name |
| Affected | all rows (metadata only) |
| Action | strip column names |
| Reason | eliminates a known source of silent lookup failure |
| Risk | two columns that differ only by whitespace would collide; not observed in the fixtures |
| Alternative | fuzzy column matching (rejected: hides schema problems) |

### C-02 — Exact duplicate rows

| Field | Value |
| --- | --- |
| Problem | Byte-identical rows carry no additional information and are a leakage vector |
| Detection | `drop_duplicates(keep='first')` |
| Affected | counted per dataset; CICIDS2017 historically reported many (to be re-verified) |
| Action | remove duplicates, keep first |
| Reason | duplicates can otherwise appear in both train and test |
| Risk | **if duplicates concentrate in one class, removal shifts class balance** |
| Alternative | retain duplicates and block cross-split duplication in the splitter |
| Status | Risk is mitigated by the split leakage audit (`L-01`) which runs after cleaning |

### C-03 — Unknown / unmapped labels

| Field | Value |
| --- | --- |
| Problem | Labels not declared benign and not in the dataset's known-attack allow-list |
| Detection | `xrlids.labels.contract.apply_label_contract` |
| Affected | reported per label in `results/audits/label_rejections.csv` |
| Action | **reject the row**; never relabel it BENIGN |
| Reason | mapping unknown → BENIGN would silently create false negatives |
| Risk | a typo in the contract rejects real attack rows; the audit surfaces an unexpected rejection count |
| Alternative | map unknowns to ATTACK (inflates recall) or BENIGN (**forbidden**) |

### C-04 — Negative flow duration

| Field | Value |
| --- | --- |
| Problem | Physically impossible duration; derived rate features become meaningless |
| Detection | `duration < 0` on `Flow Duration` / `dur` |
| Affected | counted |
| Action | remove the row |
| Reason | any recomputed rate from it is invalid |
| Risk | if the raw column is unsigned and overflowed, removing hides a parse bug |
| Alternative | absolute value (rejected: masks corruption rather than reporting it) |

### C-05 — Non-finite feature values (downstream)

| Field | Value |
| --- | --- |
| Problem | A computed rate can be genuinely undefined (zero duration with non-zero packets) |
| Detection | `validate_feature_matrix` counts NaN/Inf; the pipeline drops rows where a rung feature is non-finite |
| Affected | reported as `rows_dropped_non_finite` in the pipeline warning list |
| Action | drop the row for modelling, after counting it |
| Reason | a model must not silently learn from NaN |
| Risk | zero-duration attack flows may be disproportionately dropped, biasing results |
| Alternative | impute; rejected for training rows because it fabricates behaviour that was never observed |
| Note | the corresponding count is always surfaced, never hidden |

## Explicitly NOT done

- **No deletion of extreme-but-valid values.** Extreme is not invalid.
- **No Infinity patching of vendor rate columns.** The canonical features *recompute* rates
  from source quantities (`total_packets / duration`, `total_bytes / duration`), so vendor
  rate columns are never model inputs and their Infinity values are irrelevant. This is the
  historical "recompute rather than replace" decision, preserved and made explicit.
- **No automatic `dropna()`.** Missingness is handled per-rule with accounting.
