# ASSUMPTION REGISTRY

Assumptions are things the project currently believes but has not proven. Each one has a
status, a risk if wrong, and a method that would validate or falsify it. An assumption that
blocks a research decision must be flagged, not silently relied upon.

Status values: `UNVALIDATED` · `PARTIALLY VALIDATED` · `VALIDATED` · `FALSIFIED`

---

## A-001 — CIC-style flow features can be reconstructed from live packets

- **Status:** UNVALIDATED
- **Statement:** The canonical feature set (or its live-compatible subset) can be computed from captured packets with the same semantics as the dataset features.
- **Risk if wrong:** RQ8 fails; the model cannot be applied to live traffic at all; the entire live stage is invalid.
- **Validation method:** FR-027 live feature parity harness — same synthetic flow through the dataset-side and Scapy-side calculators, per-feature tolerance check.
- **Owner:** Phase 3 (with Phase 1 feature definitions as prerequisite).

## A-002 — The selected flow timeout is appropriate for the target traffic

- **Status:** UNVALIDATED (blocked by D-006)
- **Statement:** Whichever flow-completion policy is chosen produces flows whose statistics are comparable to dataset flows.
- **Risk if wrong:** Live features drift systematically from training features; parity may pass on synthetic flows yet fail on real traffic.
- **Validation method:** Compare feature distributions of replayed PCAPs reconstructed with the chosen policy against the original dataset flows.
- **Owner:** Phase 3.

## A-003 — Fusion scores are meaningful as DQN state

- **Status:** UNVALIDATED
- **Statement:** RF probability, LSTM score and fusion score are sufficiently informative and comparably scaled to serve as the DQN state.
- **Risk if wrong:** The policy learns from a distorted state; reward study results are misleading.
- **Validation method:** Calibration analysis (FR-018) plus state-distribution inspection before DQN training.
- **Owner:** Phase 1 → Phase 2 boundary.

## A-004 — The controlled lab represents the operational scenario sufficiently

- **Status:** UNVALIDATED
- **Statement:** A small isolated lab generates traffic representative enough to demonstrate controlled response safely.
- **Risk if wrong:** Safety demonstrations do not transfer; overclaiming operational readiness.
- **Validation method:** Document lab topology, generated traffic and observed ground truth; state explicitly what it does not cover.
- **Owner:** Phase 3.

## A-005 — Unknown labels are rare enough to reject safely

- **Status:** UNVALIDATED
- **Statement:** Rejecting unrecognised labels (FR-007) does not remove a scientifically significant share of rows.
- **Risk if wrong:** Rejection accounting shows large unexplained loss, weakening the dataset's representativeness.
- **Validation method:** Rejection accounting in the audit report (§13).
- **Owner:** Phase 1.

## A-006 — Duplicate rows in the historical data are genuinely non-informative

- **Status:** UNVALIDATED
- **Statement:** Duplicate removal does not preferentially remove one class in a way that biases the benchmark.
- **Risk if wrong:** Cleaning itself changes class balance and inflates measured performance.
- **Validation method:** Per-class duplicate accounting (§13) and Cleaning Checkpoint 1 questions (§81).
- **Owner:** Phase 1.

## A-007 — Datasets are not blindly mergeable

- **Status:** UNVALIDATED (believed, inherited)
- **Statement:** Schema, label taxonomy and feature-definition differences make naive merging scientifically unsafe.
- **Risk if wrong (over-conservative):** We forgo a larger pooled training set.
- **Validation method:** Distribution comparison and PSI-style diagnostics across datasets (§37).
- **Owner:** Phase 1.

## A-008 — Threshold selection on validation transfers to test

- **Status:** UNVALIDATED
- **Statement:** A threshold chosen on validation data performs acceptably on the untouched test set.
- **Risk if wrong:** Reported operating point is optimistic.
- **Validation method:** Compare validation-selected threshold behaviour against the test distribution; report threshold stability.
- **Owner:** Phase 1.

## A-009 — Ground truth is unavailable for live traffic

- **Status:** VALIDATED (by design, §64)
- **Statement:** Live capture yields predictions but not automatic correctness labels.
- **Risk if ignored:** Reporting "live accuracy".
- **Validation method:** Report flows processed, latency, throughput, stability and action distribution instead.
- **Owner:** Phase 3.

## A-010 — Historical configurations are starting points, not conclusions

- **Status:** PARTIALLY VALIDATED
- **Statement:** Historical RF/LSTM/fusion/DQN configurations are reasonable seeds for the rebuild but their reported performance is not inherited.
- **Risk if ignored:** Copying numbers and configurations without re-derivation.
- **Validation method:** Every configuration is re-run and recorded as "newly reproduced", distinct from "historical" (§25).
- **Owner:** All phases.
