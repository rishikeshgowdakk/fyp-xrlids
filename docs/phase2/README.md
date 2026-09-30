# Phase 2 — ML Platform + Integration + Response Policy (Week 2)

Goal: turn Phase 1 artifacts into a real software system.

| Deliverable | Purpose | Status |
| --- | --- | --- |
| Model registry (`models/registry/`) | Register every trained artifact | ⬜ |
| Model cards (`docs/phase2/model_cards/`) | Intended use, limits, metrics, latency | ⬜ |
| ML API (`services/ml-api/`) | `/predict`, `/explain`, `/health`, `/model`, `/version` | ⬜ |
| Inference contract | Shared feature contract (see `../02_ARCHITECTURE/INFERENCE_CONTRACT.md`) | 🟡 skeleton |
| SHAP service | `POST /explain` with attributed features | ⬜ |
| DQN policy (`src/rl/`) | Response policy over detector state | ⬜ |
| DQN reward study | Reward configurations A/B/C compared | ⬜ |
| DQN baseline comparison | Always-ALLOW/BLOCK, fixed threshold, RF, Fusion | ⬜ |
| Database | Events + audit records | ⬜ |
| Backend (`services/backend/`) | Orchestration, audit log | ⬜ |
| Dashboard (`services/frontend/`) | Evidence-first screens | ⬜ |
| Replay engine | Deterministic historical-flow integration test | ⬜ |
| End-to-end integration test | One test covering the full chain | ⬜ |

## Exit criteria (§93)

Model registry ✓ · Model cards ✓ · FastAPI ✓ · Inference contract ✓ · SHAP API ✓ · DQN ✓ ·
DQN baseline comparison ✓ · Database ✓ · Backend ✓ · Dashboard ✓ · Replay engine ✓ ·
End-to-end integration ✓
