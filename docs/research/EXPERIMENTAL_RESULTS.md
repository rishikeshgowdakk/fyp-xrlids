# XRL-IDARS — Comprehensive Experimental Results

**Document ID:** `DOC-RES-RESULTS-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Summary of Verified Experimental Findings

### 1. Tabular Intrusion Detection (Random Forest Baseline)
- **CIC-IDS2017 (355k test flows)**: Precision $0.9984$, Recall $0.9972$, **F1-Score $0.9978$**, PR-AUC $0.9998$.
- **CSE-CIC-IDS2018 (8.7k test flows)**: Precision $0.9977$, Recall $0.9977$, **F1-Score $0.9977$**, PR-AUC $0.9999$.
- **UNSW-NB15 (82.3k test flows, R4 contract)**: Precision $0.9120$, Recall $0.8950$, **F1-Score $0.9034$**, PR-AUC $0.9340$.

### 2. Temporal Sequence Modeling (Experiment EXP-P2-LSTM-VALID-001)
- Evaluated on 8,726 common held-out chronological test instances.
- Random Forest: $F1 = 0.9977$, $99.72\%$ accuracy.
- PyTorch LSTM ($T=5$): $F1 = 0.9996$, $99.95\%$ accuracy.
- **Empirical Delta**: $+0.0019$ (+0.19% F1 gain), representing only **16 additional flows** correctly classified.

### 3. Latency & Execution Speed
- Flow feature extraction: **$0.041\,\text{ms}$ median**.
- Random Forest inference: **$24.43\,\text{ms}$ median** (100 trees).
- TreeSHAP explanation: **$27.39\,\text{ms}$ median**.
- End-to-end packet to alert: **$67.08\,\text{ms}$ median**.
