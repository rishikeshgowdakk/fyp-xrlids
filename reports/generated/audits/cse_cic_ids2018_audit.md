# Dataset audit - cse_cic_ids2018 (generated)

Files audited: 10 · Rows total: 16233002 · Duplicate rows: 410706
Schema validation: `validated`

## Per-file

| file | rows | columns | duplicates | NaN | Inf |
| --- | --- | --- | --- | --- | --- |
| Friday-02-03-2018_TrafficForML_CICFlowMeter.csv | 1048575 | 80 | 5450 | 2558 | 5542 |
| Friday-16-02-2018_TrafficForML_CICFlowMeter.csv | 1048575 | 80 | 147543 | 0 | 0 |
| Friday-23-02-2018_TrafficForML_CICFlowMeter.csv | 1048575 | 80 | 2614 | 3754 | 7662 |
| Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv | 7948748 | 84 | 2 | 36767 | 82139 |
| Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv | 331125 | 80 | 92 | 1834 | 2388 |
| Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv | 1048575 | 80 | 2421 | 4921 | 11133 |
| Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv | 1048575 | 80 | 3278 | 3569 | 7651 |
| Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv | 1048575 | 80 | 225628 | 2277 | 5371 |
| Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv | 1048575 | 80 | 17557 | 0 | 0 |
| Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv | 613104 | 80 | 6121 | 4041 | 0 |

## Label audit (first file)

```json
{
  "label_column": "Label",
  "rows_total": 1048575,
  "rows_accepted": 1048575,
  "rows_rejected_unknown_label": 0,
  "distinct_labels": {
    "Benign": 762384,
    "Bot": 286191
  }
}
```

## Unknown-label rejections

```json
[
  {
    "raw_label": "Label",
    "normalized": "LABEL",
    "count": 1,
    "reason": "NOT_IN_BENIGN_OR_ATTACK_ALLOWLIST"
  },
  {
    "raw_label": "Label",
    "normalized": "LABEL",
    "count": 25,
    "reason": "NOT_IN_BENIGN_OR_ATTACK_ALLOWLIST"
  },
  {
    "raw_label": "Label",
    "normalized": "LABEL",
    "count": 33,
    "reason": "NOT_IN_BENIGN_OR_ATTACK_ALLOWLIST"
  }
]
```
