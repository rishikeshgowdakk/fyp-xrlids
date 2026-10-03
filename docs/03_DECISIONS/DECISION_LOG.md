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

- **Status:** **DECIDED (TWO-TIER THRESHOLD CONTRACT)**
- **Date decided:** 2026-10-03
- **Evidence gathered:** `threshold_candidates.json` evaluated across all benchmark models; cost-sensitive curve analysis ($C_{\text{FP}} : C_{\text{FN}} \in \{1:1, 1:5, 1:10, 1:50\}$); per-attack error rates (Infiltration recall 10.70%, Web attacks 2.78% at $\tau=0.50$).
- **Decision:** Establish a two-tier operational threshold architecture:
  1. **Research Reporting Baseline ($\tau = 0.50$)**: Preserved across all academic benchmark tables, paired bootstrap hypothesis tests, and final reports to ensure direct comparability with published IDS literature.
  2. **Operational Autonomous Response Policy ($\tau_{\text{ops}} = 0.40$, Cost-Sensitive Parameterization)**: For Phase 2 autonomous response deployment under asymmetric operational loss ($C_{\text{FN}} \ge 5 \cdot C_{\text{FP}}$), the operational threshold shifts to $\tau=0.40$, improving stealth attack recall while maintaining benign false alarms below 1.2%. Furthermore, the Phase 2 RL agent receives continuous calibrated posterior probabilities $P(\text{attack} \mid x, s)$ rather than hard binary outputs, enabling dynamic cost-weighted response.
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
