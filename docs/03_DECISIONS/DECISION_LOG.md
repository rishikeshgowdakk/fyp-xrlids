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

- **Status:** **OPEN — USER DECISION REQUIRED**
- **Date raised:** 2026-09-30
- **Question:** Is maximising F1 the correct operational objective for this IDS, or should the threshold optimise something else?
- **Options:**
  - A. Maximum F1.
  - B. Minimum FPR subject to a recall floor.
  - C. Minimum FNR subject to an acceptable FPR.
  - D. Cost-sensitive objective (explicit FP/FN costs).
- **Trade-offs:** A is conventional and comparable to literature but treats FP and FN as equally costly. B/C reflect operational reality but require choosing a floor. D is most honest but requires cost estimates that do not yet exist in this project.
- **Impact if deferred:** Threshold policy, DQN reward study and response safety thresholds all depend on it.
- **Note:** This is explicitly a **research decision** (§32); the agent reports alternatives and does not choose.
- **USER DECISION REQUIRED.**

---

## D-004 — Dataset acquisition

- **Status:** **OPEN — USER DECISION REQUIRED** (acquisition workflow complete; downloads blocked)
- **Date raised:** 2026-09-30
- **Evidence gathered (2026-09-30):** Reproducible preparation workflow implemented
  (`scripts/phase1/prepare_dataset.py`, `src/xrlids/datasets/prepare.py`) with manifest
  registration/verification of real checksums. **Acquisition constraint discovered:** the
  historical primary mirror `iscxdownloads.cs.unb.ca` is unreachable from this network
  (DNS NXDOMAIN; general internet verified working via control hosts). Manual download from
  the official pages is required; exact per-file instructions: `prepare_dataset.py instructions`.
  No checksum was invented and no file was fabricated.
- **Question:** Which datasets to acquire, from which mirrors, and under what storage budget?
- **Options:**
  - A. All three (CICIDS2017, CSE-CIC-IDS2018, UNSW-NB15) — matches the historical scope and RQ5.
  - B. CICIDS2017 + UNSW-NB15 only (smaller, faster, but RQ5 loses two transfer directions).
  - C. CICIDS2017 only to unblock Phase 1 quickly, add others later.
- **Trade-offs:** CSE-CIC-IDS2018 is large and has heterogeneous per-file schemas, so it costs the most time; dropping it weakens the cross-dataset story.
- **Impact if deferred:** All Phase 1 data work is blocked.
- **USER DECISION REQUIRED.**

---

## D-005 — Cross-dataset normalization

- **Status:** **OPEN — USER DECISION REQUIRED**
- **Date raised:** 2026-09-30
- **Question:** For cross-dataset experiments, is any normalization/alignment applied between source and target, or are raw per-dataset features used with per-dataset scalers?
- **Options:**
  - A. No alignment: fit scaler on source train, apply to target — exposes true domain shift.
  - B. Feature-space intersection only: restrict to features with identical semantics everywhere.
  - C. Distribution alignment (e.g. standardization to each dataset's own statistics) — measures separability after removing scale effects.
- **Trade-offs:** A answers "what happens when you deploy as-is". C can flatter results and hide the shift the project is trying to expose. B reduces the feature set and may break the R10/R15/R20 design.
- **Impact if deferred:** RQ5 methodology cannot be frozen.
- **USER DECISION REQUIRED.**

---

## D-006 — Flow timeout / completion policy

- **Status:** **OPEN — USER DECISION REQUIRED** (blocks Phase 3 enforcement)
- **Date raised:** 2026-09-30
- **Question:** When is a live flow considered complete enough to extract features from?
- **Options:**
  - A. TCP FIN/RST terminates the flow (accurate but long-lived for some protocols).
  - B. Fixed idle timeout (simple, predictable, but truncates long flows and splits slow ones).
  - C. Sliding window / periodic emission (enables detection during a flow, but statistics are partial).
  - D. Hybrid: FIN/RST when available, idle timeout as fallback, windowed emission for long flows.
- **Trade-offs:** A maximises feature fidelity but adds latency and unbounded flow duration. C gives the best detection latency but makes live features differ from dataset features that were computed on completed flows — which directly threatens RQ8 feature parity.
- **Impact if deferred:** Live feature parity and live detection cannot be implemented meaningfully.
- **USER DECISION REQUIRED.**
