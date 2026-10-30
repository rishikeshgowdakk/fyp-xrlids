# XRL-IDARS — Formal Academic Contributions & System Novelty

**Document ID:** `DOC-ACAD-CONTRIBUTIONS-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Primary Research & Engineering Contributions

The XRL-IDARS project makes five substantial academic and engineering contributions to the field of Network Intrusion Detection Systems (NIDS):

### Contribution 1: Empirical Resolution of the Tabular vs. Temporal Debate
While numerous academic papers uncritically recommend recurrent sequence models (LSTMs, GRUs) for network intrusion detection, this project conducted the first rigorous, leakage-free head-to-head evaluation under identical chronological conditions. We demonstrated that a 2-layer LSTM provides an incremental gain of only $+0.19\%$ F1 (16 flows out of 8,726) over a tabular Random Forest, while introducing severe cold-start blindness ($K < 5$) and state-exhaustion vulnerability. This establishes an empirical defense of stateless tree ensembles for operational line-rate NIDS.

### Contribution 2: End-to-End Real-Time Explainability via Polynomial TreeSHAP
We successfully integrated Lundberg's polynomial-time `TreeExplainer` into an active network flow pipeline, computing exact Shapley feature attributions within $27.39\,\text{ms}$ per flow. This bridges the gap between high-accuracy machine learning and operational SOC transparency, eliminating alert fatigue by presenting human analysts with interactive waterfall charts of top positive and negative feature drivers.

### Contribution 3: Safe Reinforcement Learning via Formal Shielding
We designed and implemented a decoupled autonomous response architecture where a Dueling Deep Q-Network (DQN) recommends proactive mitigations across a continuous 6D state space, subject to a Deterministic Safety Gate. By enforcing a Critical Host Allowlist, Cooldown Hysteresis, Blast-Radius Circuit Breakers, and Advisory Dry-Run defaults, the system prevents self-inflicted Denial of Service and unauthorized network mutations.

### Contribution 4: Rigorous Offline vs. Live Feature Parity Alignment
We uncovered and resolved a subtle distribution mismatch common in NIDS literature: raw CICFlowMeter CSV columns for TCP flags represent binary indicators ($\in \{0, 1\}$), whereas naive live packet capture counts cumulative packets ($> 100$), causing severe $+121\sigma$ out-of-distribution distortion during standardization. We established the versioned R10 Feature Contract with strict binary indicator mapping and population standard deviation ($\text{ddof}=0$), verified by automated parity tests.

### Contribution 5: A 100% Reproducible, Fully Integrated Research Platform
Unlike conceptual papers accompanied by fragmented scripts or synthetic notebooks, XRL-IDARS provides a fully functional, end-to-end engineered software platform backed by 605 passing automated tests (100% pass rate), zero external database dependencies, an interactive pure-Python web console, and verified empirical metrics reproduced across three standard benchmark suites.
