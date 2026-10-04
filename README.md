# XRL-IDARS v1

**Explainable Reinforcement Learning Based Intrusion Detection and Autonomous Response System**

| Field | Value |
| --- | --- |
| Project | XRL-IDARS v1 |
| Repository | `fyp-xrlids` |
| Python package | `xrlids` |
| Phase 1 — Data + Research + Model Foundation | **COMPLETE & FROZEN** |
| Phase 2 — ML Platform + Autonomous Response | **COMPLETE & FROZEN** |
| Phase 3 — Live Capture + Laboratory Validation | **COMPLETE (LABORATORY VALIDATION)** |
| Final Synthesis & Project Closure | **COMPLETE** |
| Status detail | See [`PROJECT_STATUS.md`](PROJECT_STATUS.md) and [`docs/final/FINAL_RESEARCH_REPORT.md`](docs/final/FINAL_RESEARCH_REPORT.md) |

> **Operational Scope & Safety Boundary:**
> - **Offline Research Benchmarking:** VALIDATED & SCIENTIFICALLY FROZEN (`11f32f658cde525300f8bc46088a0143e8329c21`)
> - **Isolated Laboratory Response:** VALIDATED & AUDITED (`10.200.1.0/24` network namespace, 0 host mutations)
> - **Production Deployment:** NOT VALIDATED (Strictly out of scope; zero host network mutations performed)

---

## Primary Navigation

The complete research outcomes, experimental evidence, and verification procedures are documented in the following authoritative artifacts:

| Document | Purpose |
|:---|:---|
| [`PROJECT_STATUS.md`](PROJECT_STATUS.md) | Authoritative milestone, empirical status, and implementation matrix |
| [`docs/final/FINAL_RESEARCH_REPORT.md`](docs/final/FINAL_RESEARCH_REPORT.md) | Comprehensive 10-section final research synthesis |
| [`docs/final/REPRODUCIBILITY_MAP.md`](docs/final/REPRODUCIBILITY_MAP.md) | Environment setup, execution commands, and artifact regeneration paths |
| [`docs/final/EXPERIMENT_INDEX.md`](docs/final/EXPERIMENT_INDEX.md) | Master registry of all empirical experiments across Phases 1, 2, and 3 |
| [`docs/final/DECISION_INDEX.md`](docs/final/DECISION_INDEX.md) | Governance and architecture decision log (D-001 through D-006) |
| [`docs/final/RELEASE_AUDIT.md`](docs/final/RELEASE_AUDIT.md) | Formal pre-release audit, verification checklist, and integrity bounds |
| [`docs/final/V1.0.0_RELEASE_NOTES.md`](docs/final/V1.0.0_RELEASE_NOTES.md) | Official release notes for XRL-IDARS v1.0.0 |
| [`docs/viva/FINAL_VIVA_GUIDE.md`](docs/viva/FINAL_VIVA_GUIDE.md) | Comprehensive viva defense questions, methodology justifications, and empirical answers |
| [`docs/03_DECISIONS/CLAIMS_REGISTRY.md`](docs/03_DECISIONS/CLAIMS_REGISTRY.md) | 34 traceably verified research claims (CLAIM-001 through CLAIM-034) |

---

## What this system is

XRL-IDARS classifies **network traffic and flow behavior** — not people. The end-to-end pipeline:

```text
Network Traffic
      ↓
Packet Capture
      ↓
Flow Construction
      ↓
Feature Extraction
      ↓
Feature Validation
      ↓
Preprocessing
      ↓
┌─────────────────────────┐
│                         │
▼                         ▼
Random Forest            LSTM
│                         │
└───────────┬─────────────┘
            ▼
         Fusion
            │
       ┌────┴─────┐
       ▼          ▼
     SHAP        DQN
                  │
          ┌───────┼───────┐
          ▼       ▼       ▼
        ALLOW   ALERT   BLOCK
                          │
                    Safety Gate
                          │
                    Controlled Action
                          │
                      Dashboard
```

The project is **not** the model alone. It is:

```text
DATA + METHOD + MODEL + EVIDENCE + EXPLANATION + SYSTEM + SAFETY + LIMITATIONS
```

---

## Repository map

| Path | Purpose |
| --- | --- |
| [`docs/00_PROJECT/`](docs/00_PROJECT/) | Scope, research questions, objectives |
| [`docs/01_REQUIREMENTS/`](docs/01_REQUIREMENTS/) | Functional and non-functional requirements |
| [`docs/02_ARCHITECTURE/`](docs/02_ARCHITECTURE/) | System architecture and pipeline contracts |
| [`docs/03_DECISIONS/`](docs/03_DECISIONS/) | Decision log, claims registry, assumptions |
| [`docs/04_QUESTIONS/`](docs/04_QUESTIONS/) | Open questions, historical results |
| [`docs/phase1/`](docs/phase1/) | Dataset provenance, audits, schemas, features, methods |
| [`docs/phase2/`](docs/phase2/) | Platform, API, model cards, response policies |
| [`docs/phase3/`](docs/phase3/) | Live capture, parity, safety, operations, laboratory experiments |
| [`docs/final/`](docs/final/) | Final research report, reproducibility map, release audit, indexes |
| [`docs/viva/`](docs/viva/) | Viva defense questions and answers |
| [`configs/`](configs/) | All machine-readable experiment configurations |
| [`data/manifests/`](data/manifests/) | Dataset registry with cryptographic SHA-256 checksums |
| [`src/`](src/) | Source code package (`xrlids`) |
| [`tests/`](tests/) | Unit through integration and system tests (386 passing) |
| [`results/`](results/) | Generated machine-readable evidence, metrics, and sidecars |
| [`reports/`](reports/) | Generated human-readable reports and figures |

---

## Documentation contract (three levels)

A research result is complete only when all three exist:

| Level | Form | Answers |
| --- | --- | --- |
| 1 — Human-readable | Markdown | What did we do? Why? How? What happened? What did we learn? |
| 2 — Machine-readable | JSON / YAML / CSV | Exact parameters, counts, metrics, manifests, model metadata |
| 3 — Executable evidence | Python / scripts / tests | Code that regenerates the result |

---

## Tracing a claim

The repository allows external auditors to trace **"where did this number come from?"**:

```text
README → Claims Registry → Experiment Card → Config → Dataset Manifest → Split
       → Model Artifact → Prediction Artifact → Metric Implementation
       → Result JSON → Git Commit
```

To examine **"why did you make this decision?"**:

```text
Decision ID → Options → Evidence → Trade-offs → Final Decision (D-001 to D-006)
```

To verify **"what happens when it fails?"**:

```text
Failure Mode → Detection → Impact → Mitigation → Experiment → Result
```

---

## Reproducibility & Quickstart

For full environment setup, dataset verification, and reproduction workflows, see [`docs/final/REPRODUCIBILITY_MAP.md`](docs/final/REPRODUCIBILITY_MAP.md).

Quick verification:
```bash
# 1. Activate environment
source .venv/bin/activate

# 2. Run complete test suite (386 passing tests)
pytest -q

# 3. Inspect final research synthesis
cat docs/final/FINAL_RESEARCH_REPORT.md
```
