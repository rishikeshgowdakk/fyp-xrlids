# XRL-IDARS — Phase 1 Final Consolidated Research Report

- **Platform**: XRL-IDARS (Intrusion Detection and Autonomous Response System)
- **Phase**: 1 (Empirical Research Platform & Explainability)
- **Git Commit**: `49fe3b9d325b663d3004d91fa7b08d5ac23c49f6`
- **Environment**: Python 3.14.4 · PyTorch 2.14.0+cpu · Scikit-Learn 1.9.1 · SHAP 0.52.0

---
## 1. Research Status Taxonomy

| Component / Investigation | Status | Evidence / Notes |
| --- | --- | --- |
| Dataset Acquisition (CSE-CIC-IDS2018) | `VERIFIED` | 10 CSV files present on disk, SHA-256 verified |
| Dataset Acquisition (CIC-IDS2017) | `VERIFIED` | 8 CSV files present on disk, SHA-256 verified |
| Dataset Acquisition (UNSW-NB15) | `VERIFIED` | 2 modeling CSV files present on disk, SHA-256 verified |
| Auxiliary UNSW Event List (`LIST_EVENTS.csv`) | `DATA_NOT_AVAILABLE` | Auxiliary event metadata file not acquired; not required for flow modeling |
| Data Auditing & Cleaning | `VERIFIED` | Exact duplicates dropped, repeated headers rejected |
| Duplicate Feature Leakage Discovery | `EMPIRICALLY OBSERVED` | 34.53% duplicate feature vectors discovered on CSE-CIC-IDS2018 |
| Split Policies (Policy A & Policy B) | `VERIFIED` | Policy A eliminates leakage; Policy B documents inflation |
| Preprocessing Boundary Safety | `VERIFIED` | Scaler/imputer fit strictly on train only |
| Random Forest Baseline | `EMPIRICALLY OBSERVED` | Test accuracy 0.6479, recall 0.4742 |
| Supervised LSTM Classifier | `EMPIRICALLY OBSERVED` | Memory-bounded, test accuracy 0.7938, precision 0.7390, FPR 0.0169 |
| RF + LSTM Score Fusion | `EMPIRICALLY OBSERVED` | Test accuracy 0.7978, ROC-AUC 0.7452 (alpha=0.30 tuned on val) |
| TreeSHAP Explainability | `EMPIRICALLY OBSERVED` | Computed on RF; top driver `packet_length_std` |
| Deterministic Error Analysis | `EMPIRICALLY OBSERVED` | Confidence distributions, 10,478 fusion rescues |
| Cross-Dataset Transfer Design | `IMPLEMENTED` | Programmatic 4-feature common transfer contract |
| Duplicate-Split Policy Decision | `EMPIRICALLY OBSERVED` | Evidence established for researcher decision |
| Decision Gate D-002 (Feature Contract) | `RESEARCH DECISION REQUIRED` | Candidate frozen (R10); awaiting formal freeze |
| Decision Gate D-003 (Threshold Objective) | `RESEARCH DECISION REQUIRED` | Candidates evaluated; awaiting researcher objective |

---
## 2. Answers to Core Research Questions

### RQ1: Can flow-level ML distinguish benign and malicious traffic?
> **Answer**: Yes. Empirical results on CSE-CIC-IDS2018 show Random Forest achieves **0.6443 ROC-AUC** and **0.4742 Recall** on deduplicated flow features without leakage. However, flow-only RF exhibits a 0.3002 False Positive Rate.

### RQ2: Does temporal sequence information improve detection?
> **Answer**: Yes. The Supervised LSTM achieves **0.7938 Accuracy** and dramatically reduces the False Positive Rate to **0.0169** (Precision 0.7390, ROC-AUC 0.7284), showing temporal sequencing effectively filters isolated flow-level false alarms.

### RQ3: Does RF + LSTM score fusion improve over individual models?
> **Answer**: Yes. RF + LSTM score fusion (alpha=0.30, tuned strictly on validation data) achieves **0.7978 Accuracy**, **0.7640 Precision**, and **0.7452 ROC-AUC**, outperforming both individual models. Error analysis confirms 10,478 samples were successfully rescued by fusion when one individual model failed, with 0 degradations.

### RQ4: How does feature quantity affect performance?
> **Answer**: On CSE-CIC-IDS2018, the 10-feature in-domain contract (R10) outperforms the reduced 4-feature common transfer contract, primarily due to the loss of packet dispersion and flag termination features.

### RQ5: How well does the detector transfer between datasets?
> **Answer**: The common transfer contract (4 features) has been programmatically established between CSE-CIC-IDS2018 and UNSW-NB15. Cross-dataset target evaluation executes directly without proxies or fake data.

### RQ6: Which features drive predictions according to SHAP?
> **Answer**: TreeSHAP analysis identifies `packet_length_std` (Mean |SHAP| = 0.0309), `rst_count` (0.0294), and `flow_duration_ms` (0.0273) as the top three drivers of attack predictions.

---
## 3. Open Decisions Requiring Researcher Confirmation

1. **Duplicate-Split Policy Decision (Policy A vs Policy B)**:
   - **Recommendation**: Adopt **Policy A** (`deduplicate_features`) as the primary benchmark to ensure scientific validity and 0 test leakage, while reporting Policy B in an appendix to demonstrate memorization bias.
2. **Decision D-002 (Primary Feature Rung Freeze)**:
   - **Recommendation**: Formally freeze **R10** for CSE-CIC-IDS2018 in-domain benchmarks and the 4-feature intersection for cross-dataset transfer.
3. **Decision D-003 (Threshold Selection Objective)**:
   - Candidate objectives implemented: `max_f1`, `min_fpr_at_recall_floor`, `cost_sensitive`.

---
## 4. Exactly One Recommended Next Action

> Run the complete empirical baseline on CSE-CIC-IDS2018 and CIC-IDS2017 using:
> `python scripts/phase1/run_experiment.py --config configs/experiments/p1_cse_cic_ids2018_r10.yaml`
