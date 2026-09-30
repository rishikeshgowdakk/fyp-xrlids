# PROJECT SCOPE

Status: **frozen** (change requires a Decision ID per §9)

## Purpose

Rebuild XRL-IDARS from scratch as a reproducible, auditable, research-grade and
production-style prototype of:

> **Explainable Reinforcement Learning Based Intrusion Detection and Autonomous Response System**

## What the system classifies

**Network traffic / flow behavior — not people.**

Explicitly out of scope as targets: user identity, user profiling, content inspection,
attribution of activity to individuals.

## Historical vs new

The previous XRL-IDARS repository is a **historical blueprint only**. It is:

- NOT the implementation to blindly copy
- NOT the source of truth for new experimental results
- NOT proof that previously reported numbers are reproducible

It *is* the source of: architecture, historical decisions, previously discovered problems,
feature definitions, baseline configurations, historical results, mistakes to avoid,
and professor questions already raised.

## Preserved foundations

The rebuild preserves these principles established historically:

1. Three datasets, kept **separate** — never blindly merged.
2. Unknown labels are **rejected**, never converted to BENIGN.
3. The final test set stays separate and is touched once.
4. LSTM is a **supervised** temporal classifier, not a generative or self-supervised model.
5. DQN is a **response policy**, not the detector.
6. No live accuracy claim when ground truth is unavailable.
7. SHAP is model attribution, **not causality**.
8. Controlled response: the system only enforces on traffic it has authority over.

## New depth required beyond the old repo

Provenance · manifests · checksums · schemas · mathematical feature definitions ·
data lineage · rejection accounting · leakage analysis · class-imbalance analysis ·
threshold and trade-off analysis · calibration · full confusion matrices · error analysis ·
per-class metrics · dataset compatibility · domain-shift analysis · model cards ·
experiment cards · failure investigations · inference/API contracts · live feature parity ·
latency and resource profiling · operational safety · controlled network testing ·
incident replay · audit logs · deployment runbook · rollback · limitations ·
unresolved questions.

**Target: more evidence and reasoning than the old repo — not merely more Markdown.**

## Non-goals

- Not a production security product; it is a research prototype with production-style discipline.
- Not a comparative benchmark paper; it is a system with defensible evidence.
- Not an exercise in maximising a single accuracy number.
