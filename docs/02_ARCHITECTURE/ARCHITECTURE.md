# ARCHITECTURE

## End-to-end pipeline

```text
Network Traffic
      ↓
Packet Capture                 (Phase 3 — Scapy)
      ↓
Flow Construction              (Phase 3 — 5-tuple grouping + timeout policy)
      ↓
Feature Extraction             (Phase 1 definitions, Phase 3 live implementation)
      ↓
Feature Validation             (Phase 3 — parity + range checks)
      ↓
Preprocessing                  (Phase 1 — scalers fit on train only)
      ↓
┌─────────────────────────┐
│                         │
▼                         ▼
Random Forest            LSTM              (Phase 1 — supervised)
│                         │
└───────────┬─────────────┘
            ▼
         Fusion                            (Phase 1 — mean of aligned scores)
            │
       ┌────┴─────┐
       ▼          ▼
     SHAP        DQN                         (SHAP Phase 1; DQN Phase 2)
                  │
          ┌───────┼───────┐
          ▼       ▼       ▼
        ALLOW   ALERT   BLOCK
                          │
                    Safety Layer             (Phase 3 — gate, never bypassed)
                          │
                    Controlled Action
                          │
                      Dashboard              (Phase 2)
```

## Components and responsibilities

| Component | Responsibility | Phase | Interface |
| --- | --- | --- | --- |
| Dataset layer | Acquire, checksum, audit, reject-account | 1 | `src/xrlids/datasets/` |
| Preprocessing | Cleaning, label contract, scaling | 1 | `src/xrlids/preprocessing/` |
| Features | Canonical feature computation | 1 | `src/xrlids/features/` |
| Models | RF, LSTM, Fusion training/inference | 1 | `src/xrlids/models/` |
| Evaluation | Metrics, thresholding, calibration, error analysis | 1 | `src/xrlids/evaluation/` |
| Explainability | SHAP attribution service | 1–2 | `src/xrlids/explainability/` |
| RL policy | DQN response policy + baselines | 2 | `src/xrlids/rl/` (planned) |
| Inference | Flow → features → prediction, live path | 2–3 | `src/xrlids/inference/` (planned) |
| Telemetry | Metrics, health, error counters | 2–3 | `src/xrlids/telemetry/` (planned) |
| ML API | `/predict`, `/explain`, `/health`, `/model`, `/version` | 2 | `services/ml-api/` |
| Backend | Events, audit log, orchestration | 2 | `services/backend/` |
| Frontend | Evidence-first dashboard | 2 | `services/frontend/` |

## Key architectural constraints

1. **One feature contract.** Training and live paths share a single implementation of feature
   computation (`src/xrlids/features/`). Manual duplication of feature maths is forbidden (FR-022).
2. **Detector ≠ policy.** RF/LSTM/Fusion detect; DQN selects a response. Neither writes
   firewall rules directly.
3. **Safety layer is mandatory.** Every BLOCK passes the gate in `configs/safety/`. Default
   mode is non-enforcing.
4. **Provenance is structural.** Every artifact carries model ID, config hash, dataset hash,
   feature-schema hash and commit.
5. **Fail safe.** Missing model, API, or DB degrades to OBSERVE, never to blocking.

See [`INFERENCE_CONTRACT.md`](INFERENCE_CONTRACT.md) for the shared feature/score contract.
