# XRL-IDARS v1 — DECISION INDEX

> **Scope:** Mapping of formal project decisions (D-001 through D-006) to evidence, status, and downstream impacts.  
> **Status:** AUDITED & FROZEN  
> **Source Document:** [`docs/03_DECISIONS/DECISION_LOG.md`](file:///home/rishikesh/Desktop/fyp-xrlids/docs/03_DECISIONS/DECISION_LOG.md)

---

## Master Decision Summary Table

| ID | Title / Domain | Alternatives Considered | Decided Option | Evidence Base | Current Status | Downstream Architecture Impact |
|:---:|:---|:---|:---|:---|:---:|:---|
| **D-001** | Repository & Governance Architecture | A. Start by hacking models immediately<br>B. Formal governance layer first | **Option B** (Formal recording & governance first) | Historical irreproducibility; §99 build spec mandate | **DECIDED** | All experiments bound to immutable configs, seeds, and git commits. |
| **D-002** | Feature Contract: R10 Derivation | A. Use 78 raw features<br>B. Derive R10/R15/R20<br>C. Synthesize missing features | **Option B** (Freeze R10; quarantine UNSW to R4) | `FEATURE_CONTRACT_AUDIT.md`; 6 missing features in UNSW Argus logs | **DECIDED** | Main cross-dataset contract R10 frozen (v1.0.0, `9d6c3826...`); UNSW R4 auxiliary fallback. |
| **D-003** | Primary Operational Objective for Thresholds | A. Single hard threshold<br>B. Min-FPR optimization<br>C. Two-tier governance framework | **Option C** (Freeze reporting $\tau=0.50$; operational $\tau_{\text{ops}}=0.40$ candidate; selection open) | `threshold_candidates.json`; stealth attack blind spots (Infiltration 10.70% recall) | **RESOLVED (FRAMEWORK)** | Research baseline frozen at $\tau=0.50$; RL policy consumes continuous scores $S \in [0, 1]$. |
| **D-004** | Dataset Benchmark Acquisition | A. Single dataset (CIC only)<br>B. Full multi-file 3-dataset suite | **Option B** (Full 20-file multi-dataset suite) | `data/manifests/dataset_registry.yaml`; SHA-256 chunked streaming audit | **DECIDED** | Multi-file benchmarking (>19M flows) across CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15. |
| **D-005** | Cross-Dataset Normalization Fit | A. Target domain min-max scaling<br>B. Strict source-only preprocessing | **Option B** (Source-only preprocessing fit) | Cross-dataset transfer collapse; zero target data leakage | **DECIDED** | Exposed true out-of-domain degradation (52% to 95% F1 drop) without target leakage. |
| **D-006** | Flow Completion & Idle Timeout Policy | A. Packet count window<br>B. Pure fixed idle timeout<br>C. Hybrid FIN/RST + 120s timeout | **Option C / Option D** (Hybrid FIN/RST + 120.0s idle timeout fallback) | CICFlowMeter extraction semantics; TCP teardown behavior | **DECIDED** | Standardized streaming flow construction across Scapy capture, replay, and live lab runner. |

---

## Detailed Decision Descriptions

### D-001: Governance Layer First
- **Core Dilemma:** Whether to begin development by quickly generating ML models or establishing an auditable research infrastructure first.
- **Resolution:** Mandated the creation of dataset registries, experiment configs, schemas, and claim tracking before model execution.
- **Impact:** Guaranteed full traceability: every metric cited in Phase 1, Phase 2, and Phase 3 traces to a specific commit and JSON artifact.

### D-002: Feature Contract R10 vs R4
- **Core Dilemma:** Raw datasets provide divergent feature sets (e.g. CICFlowMeter provides 78 features; UNSW Argus provides 49 features).
- **Resolution:** Defined R10 as the intersection of portable statistical and transport features. When UNSW was found to lack 6 of the 10 features, the project strictly refused to fabricate synthetic data, quarantining UNSW as an auxiliary R4 benchmark.
- **Impact:** Preserved scientific honesty; established that domain shift analysis between CIC and CSE is fully comparable under R10.

### D-003: Threshold Governance
- **Core Dilemma:** Choosing between optimizing overall F1 versus minimizing false alarms versus prioritizing stealth attack recall.
- **Resolution:** Established a dual-tier framework:
  1. The academic reporting baseline is frozen at $\tau = 0.50$ for benchmark comparability.
  2. Operational threshold selection remains open; continuous risk scores $S \in [0, 1]$ are emitted to the RL agent, which balances asymmetric operational costs dynamically.
- **Impact:** Prevented arbitrary threshold tuning; allowed the DQN policy to learn non-linear cost balancing directly.

### D-004: Comprehensive Dataset Acquisition
- **Core Dilemma:** Evaluating models on subset samples versus full multi-file datasets.
- **Resolution:** Acquired all 20 physical CSV files (>19 million rows) and verified each against authoritative SHA-256 hashes.
- **Impact:** Ensured evaluations reflect real multi-day network traffic distributions with diverse attack families.

### D-005: Strict Source-Only Normalization
- **Core Dilemma:** Whether to fit scalers on target datasets to achieve higher transfer scores.
- **Resolution:** Enforced strict source-only scaling. Target evaluation traffic is transformed strictly using source-domain parameters.
- **Impact:** Revealed the true reality of IDS transferability: unadapted models suffer catastrophic performance collapse in new environments.

### D-006: Hybrid Flow Completion
- **Core Dilemma:** How to decide when a live network flow is complete and ready for feature extraction.
- **Resolution:** TCP flows are immediately closed upon observing `FIN` or `RST` flags; inactive or connectionless (UDP) flows are expired after 120.0 seconds of idle time.
- **Impact:** Aligned real-time streaming flow construction with the offline batch extraction semantics of CICFlowMeter, enabling live feature parity within $\text{atol} \le 10^{-4}$.
