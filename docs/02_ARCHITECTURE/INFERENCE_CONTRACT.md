# INFERENCE CONTRACT

Status: **skeleton — not yet frozen.** Depends on D-002 (feature contract) and D-006 (flow policy).

The contract binds the training path and the live path together. If they diverge, every live
result is invalid regardless of how good the offline metrics look.

## Shared contract items

The training and live systems must agree on **all** of the following:

| Item | Requirement | Enforced by |
| --- | --- | --- |
| Feature names | Identical, case-exact | schema hash |
| Feature order | Identical | schema hash |
| Units | Identical | parity harness |
| Formulas | Identical implementation (single source) | `src/features/` |
| Scaler | Same fitted artifact | scaler hash |
| Missing-value rules | Identical | parity harness |
| Edge-case rules | Identical (e.g. duration = 0) | parity harness |
| Score semantics | Documented (probability or not) | calibration report |

## Feature schema hash

A stable hash over `(name, order, unit, dtype)` for the frozen feature set. Recorded in:

- the model registry entry,
- every model card,
- every experiment card,
- the scaler metadata.

If the schema hash changes, previously trained models are **invalid for that schema** and must
not be deployed. Mismatch is a hard error, not a warning.

## Score contract

| Producer | Output | Semantics | Calibrated? |
| --- | --- | --- | --- |
| RF | `rf_probability` | predicted probability of class 1 | measured (Phase 1) |
| LSTM | `lstm_score` | depends on final activation — **must be documented** | measured (Phase 1) |
| Fusion | `fusion_score` | mean of aligned component scores | inherited from components |
| DQN | action ∈ {ALLOW, ALERT, BLOCK} | policy recommendation, not a probability | N/A |

Rule: a raw score is **not** called "confidence" until calibration analysis (FR-018) supports it.

## Request/response shape (Phase 2, subject to change)

```json
// request (POST /predict)
{
  "flow_id": "string",
  "features": { "<feature_name>": 0.0 },
  "feature_schema_hash": "string"
}

// response
{
  "flow_id": "string",
  "rf_probability": 0.0,
  "lstm_score": 0.0,
  "fusion_score": 0.0,
  "prediction": 0,
  "recommended_action": "ALLOW",
  "model_id": "string",
  "model_version": "string",
  "schema_hash_match": true
}
```

A `feature_schema_hash` mismatch must produce an error response, not a silent fallback.

## Live parity gate

Live deployment is blocked until `results/realtime/feature_parity.csv` shows **every** feature
within tolerance. One failing feature blocks enforcement (FR-027, §62).
