# CLAIMS REGISTRY

Every major project claim gets a unique ID, linked evidence, and a status. This exists to
prevent accidental unsupported claims. If a claim has no evidence path, its status is Pending.

Status values: `VERIFIED` · `NOT REPRODUCED` · `PENDING` · `RETIRED`

## Format

```text
CLAIM-00X
"<claim text>"
Research question: RQ<n>
Evidence: EXP-<...> / results/<path>
Status: VERIFIED | NOT REPRODUCED | PENDING | RETIRED
Evidence path: <results/... / experiment card / commit>
Last checked: <date>
```

## Registered claims

The registry records claims that are directly supported by committed, reproducible artifacts. Universal claims across multiple datasets remain PENDING until the full empirical programme is executed.

| ID | Claim | RQ | Evidence | Status | Evidence path |
| --- | --- | --- | --- | --- | --- |
| CLAIM-001 | On CSE-CIC-IDS2018 (`Thursday-01-03-2018`), Random Forest flow baseline achieves 0.6443 ROC-AUC and 0.4742 Recall (at 0.5 threshold) on deduplicated flow features with 0 split leakage. | RQ1 | `EXP-P1-CSE2018-R10-001` | `VERIFIED` | `results/experiments/EXP-P1-CSE2018-R10-001/test_metrics.json` |
| CLAIM-002 | On CSE-CIC-IDS2018 (`Thursday-01-03-2018`), Supervised LSTM sequence classifier ($T=5$) achieves 0.7938 Accuracy and 0.0169 FPR on aligned test sequences, significantly reducing false alarms compared to flow-only RF (FPR 0.3002). | RQ2 | `EXP-P1-CSE2018-R10-001` | `VERIFIED` | `results/experiments/EXP-P1-CSE2018-R10-001/test_metrics.json` |
| CLAIM-003 | On CSE-CIC-IDS2018 (`Thursday-01-03-2018`), RF + LSTM score fusion ($\alpha=0.30$ tuned on validation ROC-AUC) achieves 0.7978 Accuracy and 0.7452 ROC-AUC on aligned test data (43,336 rows), rescuing 10,478 samples where one individual model failed with 0 dual-correct degradations. | RQ3 | `EXP-P1-CSE2018-R10-001` | `VERIFIED` | `results/experiments/EXP-P1-CSE2018-R10-001/test_metrics.json`, `error_analysis.json` |
| CLAIM-004 | On CSE-CIC-IDS2018 (`Thursday-01-03-2018`), TreeSHAP feature attribution identifies `packet_length_std`, `rst_count`, and `flow_duration_ms` as the top 3 associative drivers of Random Forest attack predictions. | RQ6 | `EXP-P1-CSE2018-R10-001` | `VERIFIED` | `results/experiments/EXP-P1-CSE2018-R10-001/shap_summary.json` |
| CLAIM-005 | In the 10-feature candidate R10 space for CSE-CIC-IDS2018 (`Thursday-01-03-2018`), 34.53% (114,315 rows) of raw samples share identical feature vectors; naive random splitting causes cross-split duplicate leakage (L-01 fail: 7,559 shared train/test vectors), whereas feature-level deduplication (Policy A) completely eliminates duplicate leakage (L-01 pass: 0 overlap). | RQ1 | `cse_cic_ids2018_audit.json`, `EXP-P1-CSE2018-R10-001` | `VERIFIED` | `results/audits/cse_cic_ids2018_audit.json`, `results/experiments/EXP-P1-CSE2018-R10-001/leakage_report.json` |
| CLAIM-006 | On the complete multi-file CIC-IDS2017 benchmark (8 files, 2,830,743 raw rows -> 1,779,322 modeling rows under Policy A deduplication), Random Forest achieves 0.9815 Accuracy, 0.9512 F1, 0.9901 Recall, and 0.9968 ROC-AUC on 355,833 test rows. | RQ1 | `EXP-P1-CIC2017-R10-001` | `VERIFIED` | `results/experiments/EXP-P1-CIC2017-R10-001/test_metrics.json` |
| CLAIM-007 | On the complete multi-file CIC-IDS2017 benchmark (8 files, 1,067,557 sequences), Supervised LSTM ($T=5$, file-bounded) achieves 0.9867 Accuracy, 0.9633 F1, 0.0068 FPR, and 0.9974 ROC-AUC on aligned test data (355,833 rows), reducing false alarms by 66.7% compared to RF (1,982 vs 5,951 FPs) and significantly outperforming RF in F1 ($\Delta = -0.0121$, 95% CI [-0.0134, -0.0109], $p = 0.0000$). | RQ2 | `EXP-P1-CIC2017-R10-001` | `VERIFIED` | `results/experiments/EXP-P1-CIC2017-R10-001/test_metrics.json`, `model_comparisons.json` |
| CLAIM-008 | On the complete multi-file CIC-IDS2017 benchmark, RF + LSTM score fusion ($\alpha=0.50$ tuned on validation ROC-AUC) achieves 0.9906 Accuracy, 0.9745 F1, 0.9823 Recall, 0.0075 FPR, and 0.9989 ROC-AUC on aligned test data (355,833 rows), delivering statistically significant F1 improvements over RF ($\Delta = +0.0234$, 95% CI [+0.0224, +0.0244], $p = 0.0000$) and LSTM ($\Delta = +0.0113$, 95% CI [+0.0104, +0.0120], $p = 0.0000$), rescuing 6,397 of 8,126 disagreement samples (78.72% rescue rate) with 0 dual-correct degradations. | RQ3 | `EXP-P1-CIC2017-R10-001` | `VERIFIED` | `results/experiments/EXP-P1-CIC2017-R10-001/test_metrics.json`, `model_comparisons.json`, `error_analysis.json` |

---

## Claims that must NOT be made yet

These are plausible-sounding statements that currently have **zero** or incomplete support in this repository. They must not appear in the README, reports or a demonstration until multi-dataset evidence cards exist.

| Forbidden-until-proven claim | Why it is currently unsupported |
| --- | --- |
| "The detector achieves universal >95% accuracy across all domains." | Only 1 capture day of CSE-CIC-IDS2018 has been evaluated; CIC-IDS2017 and UNSW-NB15 remain to be benchmarked. |
| "The system detects attacks in real time on live networks." | Phase 3 live capture, flow assembler, and live feature parity harness are not yet deployed. |
| "DQN response policy outperforms static threshold baselines." | RQ7 response intelligence experiments have not yet run in Phase 2. |
| "SHAP shows feature X causes network intrusions." | Model feature attribution is associative relative to background expectation; attribution is not physical causality. |
| "Live accuracy is 100% on unlabelled network traffic." | Ground truth labels are unavailable for live network streams; live telemetry measures latency and action distributions. |
| "Adding more features always improves intrusion detection." | RQ4 27-condition sweep across R10/R15/R20 is pending remaining datasets. |
| "The system is fully production-ready for arbitrary networks." | Full multi-domain benchmarking, failure injection, and operational runbook testing are required. |

---

## Historical claims

Numbers reported by the previous XRL-IDARS repository are **not** registered here as claims.
They are quarantined in [`../04_QUESTIONS/HISTORICAL_RESULTS.md`](../04_QUESTIONS/HISTORICAL_RESULTS.md)
with status *historical — not reproduced*, and may only be converted into a claim after a
new experiment reproduces them.
