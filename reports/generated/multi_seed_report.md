# Multi-Seed Robustness Report (generated)

Aligned test metrics aggregated across seeds (population std, ddof=0, matching
`multi_seed_summary.json`) via `scripts/phase1/summarize_multi_seed.py`.
Per-seed records: `seed_*/experiment_record.json`.

| Dataset | Model | Accuracy (mean ± std) | F1 (mean ± std) | ROC-AUC (mean ± std) | Seeds |
|:---|:---|:---:|:---:|:---:|:---:|
| UNSW-NB15 | random_forest | 0.8637 ± 0.0037 | 0.8580 ± 0.0029 | 0.9501 ± 0.0013 | 42, 123, 456 |
| UNSW-NB15 | lstm | 0.8684 ± 0.0003 | 0.8640 ± 0.0011 | 0.9330 ± 0.0004 | 42, 123, 456 |
| UNSW-NB15 | fusion | 0.8988 ± 0.0008 | 0.8963 ± 0.0006 | 0.9674 ± 0.0004 | 42, 123, 456 |
| CIC-IDS2017 | random_forest | 0.9816 ± 0.0002 | 0.9515 ± 0.0004 | 0.9968 ± 0.0000 | 42, 123, 456 |
| CIC-IDS2017 | lstm | 0.9858 ± 0.0007 | 0.9610 ± 0.0019 | 0.9973 ± 0.0002 | 42, 123, 456 |
| CIC-IDS2017 | fusion | 0.9903 ± 0.0005 | 0.9735 ± 0.0016 | 0.9986 ± 0.0002 | 42, 123, 456 |
| CSE-CIC-IDS2018 | random_forest | 0.9721 ± 0.0002 | 0.8854 ± 0.0007 | 0.9900 ± 0.0001 | 42, 123, 456 |
| CSE-CIC-IDS2018 | lstm | 0.9912 ± 0.0001 | 0.9600 ± 0.0007 | 0.9965 ± 0.0000 | 42, 123, 456 |
| CSE-CIC-IDS2018 | fusion | 0.9912 ± 0.0001 | 0.9602 ± 0.0004 | 0.9965 ± 0.0000 | 42, 123, 456 |
