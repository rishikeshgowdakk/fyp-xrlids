# XRL-IDARS — Final-Year Project Report Guidance

**Document ID:** `DOC-ACAD-REPORT-GUIDE-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  
**Audience:** Final-Year B.Tech / B.E. Computer Science & Engineering Candidates  

---

## 1. Overview & Report Structure

This guide outlines the chapter-by-chapter structure, theoretical grounding, and empirical data required to write a high-scoring Final-Year Engineering Project Report for XRL-IDARS.

```
Standard Thesis Structure:
├── Chapter 1: Introduction
├── Chapter 2: Literature Survey
├── Chapter 3: System Requirements & Specifications
├── Chapter 4: System Architecture & Design
├── Chapter 5: Methodology & Implementation
├── Chapter 6: Experimental Results & Analysis
├── Chapter 7: Testing & Quality Assurance
└── Chapter 8: Conclusion & Future Scope
```

---

## 2. Chapter-by-Chapter Writing Guidelines

### Chapter 1: Introduction
- **1.1 Background**: Growth of high-speed encrypted internet traffic; limitations of perimeter signature firewalls.
- **1.2 Motivation**: The need for explainable AI in security operations centers and the risks of unconstrained autonomous mitigation.
- **1.3 Problem Statement**: Precise formulation of intrusion detection on tabular flow statistics and safe mitigation policy learning.
- **1.4 Project Objectives**: List the primary engineering objectives (real-time Scapy capture, R10 feature extraction, RF classification, TreeSHAP attribution, DQN advisory, and safety shielding).

### Chapter 2: Literature Survey
- **2.1 Flow-Based NIDS**: Review CIC-IDS2017, CSE-CIC-IDS2018 (Sharafaldin et al. 2018), and UNSW-NB15 (Moustafa & Slay 2015).
- **2.2 Tabular Machine Learning vs. Deep Learning**: Cite Grinsztajn et al. (NeurIPS 2022) to academically justify why tree ensembles outperform deep neural networks on tabular flow statistics.
- **2.3 Explainable AI (XAI)**: Cite Lundberg & Lee (NeurIPS 2017) and Lundberg et al. (Nature Machine Intelligence 2020) explaining the mathematical derivation of Shapley values and TreeSHAP.
- **2.4 Autonomous Mitigation**: Cite Alshiekh et al. (AAAI 2018) on formal shielding for reinforcement learning and Amodei et al. (2016) on AI safety.

### Chapter 3: System Architecture & Mathematical Formulation
- **3.1 Canonical 5-Tuple Key**: $\text{endpoint\_a} < \text{endpoint\_b}$ sorting.
- **3.2 The R10 Feature Contract**: Provide the exact formulas for all 10 features, highlighting the binary TCP flag capping ($\min(\text{count}, 1.0)$) and population standard deviation ($\text{ddof}=0$).
- **3.3 Dueling DQN Formulation**: Decoupled value ($V(s)$) and advantage ($A(s, a)$) aggregation equations.
- **3.4 Deterministic Safety Model**: Formal mathematical definitions of the Critical Host Allowlist, Cooldown Hysteresis, and Blast-Radius Circuit Breaker.

### Chapter 4: Methodology & Implementation
- **4.1 Ingestion & Flow Engine**: `ScapyCaptureService`, `FlowKey`, and `FlowEngine`.
- **4.2 Model Training & Calibration**: Random Forest training with balanced class weighting.
- **4.3 TreeSHAP Integration**: Computing local feature attributions in $< 28\,\text{ms}$.
- **4.4 Safety Gate Actuator**: Advisory dry-run execution architecture.
- **4.5 Dashboard Implementation**: Pure-Python HTTP/WebSocket server architecture.

### Chapter 5: Experimental Results & Comparative Discussion
- **5.1 Operational RF Baseline**: Report F1-scores ($0.9978$ on CIC-2017, $0.9977$ on CSE-2018, $0.9034$ on UNSW-NB15).
- **5.2 The Temporal Sequence Reconciliation**: Present the head-to-head comparison from `EXP-P2-LSTM-VALID-001` (RF F1: $0.9977$ vs LSTM F1: $0.9996$, $+0.19\%$ delta). Discuss the four reasons why LSTM is excluded from operational deployment.
- **5.3 Empirical Latency Analysis**: Feature extraction ($41\,\mu\text{s}$), pure RF inference ($24.4\,\text{ms}$), TreeSHAP ($27.4\,\text{ms}$), end-to-end packet to alert ($67.1\,\text{ms}$).

### Chapter 6: Testing & Quality Assurance
- **6.1 Automated Test Pyramid**: 605 passing automated tests across unit, integration, data, and model suites.
- **6.2 Anti-Mock Verification**: Document the time-shape experiment from `explain_score.py` proving that scores are computed dynamically rather than stored in a lookup table.

### Chapter 7: Conclusion & Future Scope
- **7.1 Summary of Contributions**: Complete, working end-to-end NIDS integrating detection, explainability, and safe response.
- **7.2 Future Work**: Kernel-bypass packet capture (eBPF/XDP), continuous online model adaptation, and multi-sensor distributed correlation.
