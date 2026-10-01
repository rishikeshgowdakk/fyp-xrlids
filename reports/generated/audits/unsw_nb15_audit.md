# Dataset audit - unsw_nb15 (generated)

Files audited: 2 · Rows total: 257673 · Duplicate rows: 0
Schema validation: `validated`

## Per-file

| file | rows | columns | duplicates | NaN | Inf |
| --- | --- | --- | --- | --- | --- |
| UNSW_NB15_testing-set.csv | 82332 | 45 | 0 | 0 | 0 |
| UNSW_NB15_training-set.csv | 175341 | 45 | 0 | 0 | 0 |

## Label audit (first file)

```json
{
  "dataset": "unsw_nb15",
  "label_column": "attack_cat",
  "rows_total": 82332,
  "rows_accepted": 82332,
  "rows_rejected_unknown_label": 0,
  "benign_rows": 37000,
  "attack_rows": 45332,
  "distinct_raw_labels": 10,
  "distinct_labels": {
    "-N-O-R-M-A-L-": 37000,
    "-G-E-N-E-R-I-C-": 18871,
    "-E-X-P-L-O-I-T-S-": 11132,
    "-F-U-Z-Z-E-R-S-": 6062,
    "-D-O-S-": 4089,
    "-R-E-C-O-N-N-A-I-S-S-A-N-C-E-": 3496,
    "-A-N-A-L-Y-S-I-S-": 677,
    "-B-A-C-K-D-O-O-R-": 583,
    "-S-H-E-L-L-C-O-D-E-": 378,
    "-W-O-R-M-S-": 44
  }
}
```
