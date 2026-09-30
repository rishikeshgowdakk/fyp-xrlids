# XRL-IDARS v1

**Explainable Reinforcement Learning Based Intrusion Detection and Autonomous Response System**

| Field | Value |
| --- | --- |
| Project | XRL-IDARS v1 |
| Repository | `fyp-xrlids` |
| Python package | `xrlids` |
| Strategy | 3 phases / 3 weeks: data foundation → ML platform → live validation |
| Current phase | Phase 1 — Data + Research + Model Foundation |
| Phase 1 status | **PARTIALLY COMPLETE** — implementation complete, empirical programme pending datasets |
| Status detail | See [`PROJECT_STATUS.md`](PROJECT_STATUS.md) and [`docs/phase1/PHASE1_REVIEW.md`](docs/phase1/PHASE1_REVIEW.md) |

> **No metrics are reported in this README.** No dataset is present in the repository, so no
> detection result exists yet. Historical numbers from the previous project are quarantined in
> [`docs/04_QUESTIONS/HISTORICAL_RESULTS.md`](docs/04_QUESTIONS/HISTORICAL_RESULTS.md) and are
> **not** results of this repository.

> **Build rule:** this repository is *designed to record the research before the research starts*.
> No result without an artifact. No artifact without code. No code experiment without a config.
> No metric without a test population. No final claim without evidence.

---

## What this system is

XRL-IDARS classifies **network traffic and flow behavior** — not people. The end-to-end target pipeline:

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
                    Safety Layer
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
| [`docs/phase2/`](docs/phase2/) | Platform, API, model cards |
| [`docs/phase3/`](docs/phase3/) | Live capture, parity, safety, operations |
| [`docs/experiments/`](docs/experiments/) | Experiment registry and cards |
| [`docs/failures/`](docs/failures/) | Failure investigations |
| [`docs/viva/`](docs/viva/) | Professor/viva question mapping |
| [`configs/`](configs/) | All machine-readable experiment configuration |
| [`data/manifests/`](data/manifests/) | Dataset registry with checksums |
| [`src/`](src/) | Source code |
| [`services/`](services/) | ML API, backend, frontend |
| [`tests/`](tests/) | Unit through system tests |
| [`results/`](results/) | Generated machine-readable evidence |
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

The repository must let an outsider ask **"where did this number come from?"** and navigate:

```text
README → Experiment card → Config → Dataset manifest → Split
       → Model artifact → Prediction artifact → Metric implementation
       → Result → Git commit
```

Ask **"why did you make this decision?"**:

```text
Decision ID → Options → Evidence → Trade-offs → Final decision
```

Ask **"what happens when it fails?"**:

```text
Failure mode → Detection → Impact → Mitigation → Experiment → Result
```

---

## Start here

1. Read [`docs/00_PROJECT/PROJECT_SCOPE.md`](docs/00_PROJECT/PROJECT_SCOPE.md).
2. Read [`docs/00_PROJECT/RESEARCH_QUESTIONS.md`](docs/00_PROJECT/RESEARCH_QUESTIONS.md).
3. Read [`PROJECT_STATUS.md`](PROJECT_STATUS.md) for exactly what is done and what is blocked.
4. For setup/reproduction instructions see [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md).

## Nothing here is a final result yet

No metrics are committed in this README by hand. Final numbers are generated by
`scripts/reporting/` from result JSON and rendered into reports, so documentation
cannot drift from evidence.
