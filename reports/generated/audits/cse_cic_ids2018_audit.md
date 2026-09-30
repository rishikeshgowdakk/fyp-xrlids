# Dataset audit - cse_cic_ids2018 (generated)

Files audited: 1 · Rows total: 331125 · Duplicate rows: 97
Schema validation: `validated`

## Per-file

| file | rows | columns | duplicates | NaN | Inf |
| --- | --- | --- | --- | --- | --- |
| Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv | 331125 | 80 | 97 | 1834 | 0 |

## Label audit (first file)

```json
{
  "dataset": "cse_cic_ids2018",
  "label_column": "Label",
  "rows_total": 331125,
  "rows_accepted": 331100,
  "rows_rejected_unknown_label": 25,
  "benign_rows": 238037,
  "attack_rows": 93063,
  "distinct_raw_labels": 3,
  "distinct_labels": {
    "BENIGN": 238037,
    "INFILTERATION": 93063,
    "LABEL": 25
  }
}
```

## Unknown-label rejections

```json
[
  {
    "dataset": "cse_cic_ids2018",
    "original_label": "Label",
    "normalized_label": "LABEL",
    "row_count": 25,
    "percentage": 0.00755,
    "reason": "label not in benign tokens and not in declared known-attack allow-list"
  }
]
```
