# Dataset audit - cicids2017 (generated)

Files audited: 8 · Rows total: 2830743 · Duplicate rows: 256479
Schema validation: `validated`

## Per-file

| file | rows | columns | duplicates | NaN | Inf |
| --- | --- | --- | --- | --- | --- |
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 225745 | 79 | 2633 | 4 | 64 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 286467 | 79 | 72353 | 15 | 727 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | 191033 | 79 | 6888 | 28 | 216 |
| Monday-WorkingHours.pcap_ISCX.csv | 529918 | 79 | 26935 | 64 | 810 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 288602 | 79 | 35630 | 18 | 396 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 170366 | 79 | 6066 | 20 | 250 |
| Tuesday-WorkingHours.pcap_ISCX.csv | 445909 | 79 | 24065 | 201 | 327 |
| Wednesday-workingHours.pcap_ISCX.csv | 692703 | 79 | 81909 | 1008 | 1586 |

## Label audit (first file)

```json
{
  "dataset": "cicids2017",
  "label_column": " Label",
  "rows_total": 225745,
  "rows_accepted": 225745,
  "rows_rejected_unknown_label": 0,
  "benign_rows": 97718,
  "attack_rows": 128027,
  "distinct_raw_labels": 2,
  "distinct_labels": {
    "-D-D-O-S-": 128027,
    "-B-E-N-I-G-N-": 97718
  }
}
```
