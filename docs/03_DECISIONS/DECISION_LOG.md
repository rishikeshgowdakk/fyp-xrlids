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

- **Status:** **OPEN — USER DECISION REQUIRED**
- **Date raised:** 2026-09-30
- **Question:** Are the historical R10/R15/R20 rungs accepted as the feature contract, or re-derived from first principles against the §21 decision gate?
- **Options:**
  - A. Inherit the historical rung definitions as the starting contract, then test them.
  - B. Re-derive rungs from the feature taxonomy and compatibility constraints, then compare to historical lists.
  - C. Run both and report the difference.
- **Trade-offs:** A is faster and preserves continuity with previous work, but risks inheriting unexamined choices. B is more defensible but is more work and may diverge from the professor's expectations. C is the strongest evidentially but costs more compute.
- **Impact if deferred:** Feature-dependent experiments (RQ4 sweep, all baselines) cannot be frozen.
- **Recommended evidence-gathering step:** Produce the feature taxonomy + definitions and the 10-point gate answers for each candidate feature, then choose.
- **USER DECISION REQUIRED.**

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

- **Status:** **OPEN — USER DECISION REQUIRED**
- **Date raised:** 2026-09-30
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
