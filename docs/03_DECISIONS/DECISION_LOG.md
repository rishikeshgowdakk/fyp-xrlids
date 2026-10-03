# DECISION LOG

Every real project decision gets an entry. Research decisions are made by the **user/team**,
not silently by the agent. Open decisions block the work that depends on them.

Status values: `OPEN` (awaiting user) · `DECIDED` · `SUPERSEDED`

---

## D-001 — Repository and governance layer before any data or code

- **Status:** DECIDED
- **Date:** 2026-09-30
- **Question:** Should the project begin with datasets/models, or with the research-recording layer?
- **Options:**
  - A. Start by rewriting old scripts and downloading datasets immediately.
  - B. Build the repository structure and governance layer first (research questions, registries, templates, configs), then acquire data.
- **Evidence:** The historical repo produced results that are hard to trace back to config/commit. §99 of the build spec mandates the record-before-research order.
- **Trade-offs:** Option B delays the first model result by roughly a day, but prevents non-reproducible numbers and documentation drift later.
- **Decision:** B.
- **Reason:** A result that cannot be traced is not evidence. Recording structure is cheaper to build now than to retrofit.
- **Artifacts:** repository tree, `docs/00_PROJECT/`, `docs/03_DECISIONS/`, `docs/templates/`, `configs/`, `data/manifests/`.

---

## D-002 — Feature contract: inherit R10/R15/R20 or re-derive

- **Status:** **DECIDED**
- **Date decided:** 2026-10-02
- **Evidence gathered:** `docs/phase1/FEATURE_CONTRACT_AUDIT.md`, empirical range profiling across CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15.
- **Decision:** Freeze R10 (`flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean`, `packet_length_std`, `syn_count`, `ack_count`, `rst_count`, `fin_count`, `syn_ack_ratio`) as the **MAIN CROSS-DATASET 10-FEATURE CONTRACT** (v1.0.0, schema hash `9d6c3826...`) for CIC-IDS2017 and CSE-CIC-IDS2018.
- **UNSW-NB15 Blocker Resolution:** UNSW-NB15 supports only 4 of the 10 features (`flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean`). The remaining 6 features (`packet_length_std`, `syn_count`, `ack_count`, `rst_count`, `fin_count`, `syn_ack_ratio`) are absent from Argus/Bro flow logs and cannot be derived without raw PCAPs. Under the scientific integrity mandate, these 6 features are **never fabricated**. The 4-feature contract is quarantined as an auxiliary/fallback domain-shift benchmark.
- **Artifacts:** `configs/features/features.yaml`, `docs/phase1/FEATURE_CONTRACT_AUDIT.md`, `tests/unit/test_common_10_feature_contract.py`.

---

## D-003 — Primary operational objective for threshold selection

- **Status:** **DECIDED (GOVERNANCE FRAMEWORK RESOLVED; RESEARCH BASELINE FROZEN AT 0.50; OPERATIONAL THRESHOLD SELECTION REMAINS OPEN)**
- **Date decided:** 2026-10-03
- **Evidence gathered:** `results/experiments/EXP-P1-CIC2017-R10-001/threshold_candidates.json` evaluated across validation data candidates: max-F1 ($\tau=0.50$, F1=0.9743), min-FPR subject to recall $\ge 0.95$ ($\tau=0.75$, FPR=0.0038), min-FNR subject to FPR $\le 0.01$ ($\tau=0.47$, FNR=0.0125, FPR=0.0097), and illustrative cost-sensitive candidate with $C_{\text{FP}}=1, C_{\text{FN}}=10$ ($\tau=0.20$); `decision_status` remains `OPEN - USER DECISION REQUIRED` in committed artifacts; per-attack family error analysis reveals stealth attack blindspots (Infiltration recall 10.70%, Web attacks 2.78% at $\tau=0.50$).
- **Decision:** Establish a two-tier threshold governance framework:
  1. **Research Reporting Baseline ($\tau = 0.50$)**: Formally frozen across all academic benchmark tables, published comparisons, paired bootstrap hypothesis tests, cross-dataset transfer evaluations, and Phase 1 reports to ensure direct comparability with published IDS literature.
  2. **Operational Autonomous Response Policy (Proposed Candidate $\tau_{\text{ops}} = 0.40$, Selection Remains Open)**: Designated strictly as a proposed Phase 2 operational candidate under asymmetric operational loss ($C_{\text{FN}} \ge 5 \cdot C_{\text{FP}}$) to illustrate sensitivity to stealth attack recall. Note: $\tau_{\text{ops}}=0.40$ is ONLY a proposed candidate, NOT an empirically selected optimum, NOT justified as the deployment threshold, and must NOT be described as producing a guaranteed or generally improved FPR or recall. Actual operational threshold selection remains open pending real-world deployment loss and cost evidence. Model outputs are treated as posterior attack score estimates; Phase 2 RL agents will receive continuous risk scores $S \in [0, 1]$ rather than uncalibrated probabilities or hard binary outputs.
- **Summary:** D-003 governance framework resolved; operational threshold selection remains open.
- **Artifacts:** `src/xrlids/evaluation/thresholding.py`, `results/experiments/*/threshold_candidates.json`.

---

## D-004 — Dataset acquisition

- **Status:** **DECIDED**
- **Date decided:** 2026-10-01
- **Evidence gathered:** All 20 canonical modeling CSV files acquired, cryptographically verified against SHA-256 digests in `data/manifests/dataset_registry.yaml`, and audited via streaming chunked pipelines.
- **Decision:** Full multi-file acquisition of all three benchmark suites: CIC-IDS2017 (8 files, 2,830,743 raw rows), CSE-CIC-IDS2018 (10 files, 16,233,002 raw rows), and UNSW-NB15 (2 files, 257,673 raw rows).
- **Artifacts:** `data/manifests/dataset_registry.yaml`, `results/audits/`, `tests/unit/test_dataset_checksum_enforcement.py`.

---

## D-005 — Cross-dataset normalization

- **Status:** **DECIDED**
- **Date decided:** 2026-10-03
- **Evidence gathered:** Task 4 cross-dataset transfer experiments (`EXP-P1-TRANSFER-*`).
- **Decision:** Enforce Option A + B: strict source-only preprocessing fit (zero target data leakage) under frozen semantic feature contracts (R10 for CIC↔CSE, R4 for UNSW). No target domain normalization is applied, exposing true unadapted covariate shift and domain degradation.
- **Artifacts:** `src/xrlids/experiments/transfer.py`, `reports/generated/transfer_report.md`.

---

## D-006 — Flow timeout / completion policy for live inference and replay

- **Status:** **DECIDED**
- **Date decided:** 2026-10-03
- **Evidence gathered:** Task 5 demonstration foundation design; CICFlowMeter 120s bidirectional flow specification.
- **Decision:** Option D (Hybrid flow completion policy): TCP FIN/RST packets terminate active flow tracking; 120.0s idle timeout acts as expiration fallback for inactive/UDP flows. This matches the flow construction semantics of the training dataset extractors.
- **Artifacts:** `src/xrlids/demo/flow.py`, `src/xrlids/demo/pcap.py`.
