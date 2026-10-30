# XRL-IDARS — Scientific Evaluation Methodology

**Document ID:** `DOC-ML-EVAL-METHODOLOGY-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Classification Metrics Formulation

Because network intrusion detection datasets exhibit severe class imbalance (often $> 90\%$ benign traffic), overall accuracy is insufficient. XRL-IDARS evaluates models using multi-metric threshold-independent criteria:

1. **Precision ($P$)**: $\frac{TP}{TP + FP}$ (Minimizing false alarms).
2. **Recall ($R$)**: $\frac{TP}{TP + FN}$ (Detection sensitivity).
3. **F1-Score ($F1$)**: $2 \cdot \frac{P \cdot R}{P + R}$ (Harmonic mean of precision and recall).
4. **False Positive Rate ($FPR$)**: $\frac{FP}{FP + TN}$ (Fraction of benign flows erroneously blocked).
5. **False Negative Rate ($FNR$)**: $\frac{FN}{FN + TP}$ (Fraction of attacks missed).
6. **Precision-Recall AUC (PR-AUC)**: $\int P(R) dR$ (Primary metric under severe class imbalance).
7. **Receiver Operating Characteristic AUC (ROC-AUC)**: $\int TPR(FPR) dFPR$.

---

## 2. Chronological vs. Stratified Splitting Protocols

- **Tabular Policy (Policy A)**: Stratified 70/15/15 train/val/test split across flow records for datasets lacking temporal continuity (CIC-IDS2017, UNSW-NB15).
- **Temporal Policy (Policy B)**: Chronological forward-chaining split with 120-second purge gaps for datasets with monotonic timestamps (CSE-CIC-IDS2018 Tuesday):
  $$\mathcal{T}_{\text{train}} < \mathcal{T}_{\text{gap1}} < \mathcal{T}_{\text{val}} < \mathcal{T}_{\text{gap2}} < \mathcal{T}_{\text{test}}$$
- **Unseen Attacker Isolation**: Dedicated attacker IP subnets held out exclusively in the test set to evaluate true generalization to novel threat actors.
