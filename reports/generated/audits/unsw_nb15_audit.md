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
  "label_column": "attack_cat",
  "rows_total": 82332,
  "rows_accepted": 82332,
  "rows_rejected_unknown_label": 0,
  "distinct_labels": {
    "Normal": 37000,
    "Generic": 18871,
    "Exploits": 11132,
    "Fuzzers": 6062,
    "DoS": 4089,
    "Reconnaissance": 3496,
    "Analysis": 677,
    "Backdoor": 583,
    "Shellcode": 378,
    "Worms": 44
  }
}
```
