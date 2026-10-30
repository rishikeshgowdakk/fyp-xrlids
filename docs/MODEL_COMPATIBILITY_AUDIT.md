# XRL-IDARS — Model Compatibility Audit (Phase 0)

**Audit date:** 2026-10-30
**Git HEAD:** `6408f5e`
**Scope:** Exact input/output contracts of every frozen model and the runtime paths that
consume them.
**Rule:** A contract is only "compatible" if the *actual runtime input distribution and
preprocessing* match what the checkpoint was fitted on. Shape compatibility alone is not
enough.

---

## 1. Canonical artifact inventory (verified)

All nine artifacts from `models/registry/model_manifest.json` were hashed with SHA-256 and
matched. Sizes are bytes on disk.

| Path | Type | Dataset | Contract | Size | SHA-256 |
|---|---|---|---:|---:|---|
| `models/rf/random_forest_cicids2017.joblib` | RF | cicids2017 | R10 | 26,363,055 | `7c6ad493b773b687da24a2a12dcb21bd03bd56b76809462b983454aeacf2b774` |
| `models/rf/random_forest_cse2018.joblib` | RF | cse_cic_ids2018 | R10 | 68,240,031 | `b7d2dc7bacca1a46f4da35aee2c19e1604020d429a5d29b72d742130215ba9b3` |
| `models/rf/random_forest_unswnb15.joblib` | RF | unsw_nb15 | R4 | 22,639,151 | `c432eb067507ad5b29a542b372ac6d35e609e783a9e6094c9764d0cfe654ec7c` |
| `models/lstm/lstm_cicids2017.pt` | LSTM | cicids2017 | R10 | 60,949 | `2cdbf88d2eda358619d66a5d001fa7dde8ab3a36d8e0548c8c529ae8e8870f5c` |
| `models/lstm/lstm_cse2018.pt` | LSTM | cse_cic_ids2018 | R10 | 60,949 | `ea5b8198c20faa15d5d45ae7d081b754a76dbae1342a93b8234e0e06cfe8a33a` |
| `models/lstm/lstm_unswnb15.pt` | LSTM | unsw_nb15 | R4 | 57,813 | `4d9386ff44c99eed822f8ace5c64429fab571b4f8aad847d6cc78bae5f308fbd` |
| `models/dqn/dqn_4action_best.pt` | DQN | cicids2017 | `response_state_v1` | 43,189 | `6a5afc669b4e699ecd2b1c01df885cef9030c93b8888b487dd386533920ce954` |
| `models/dqn/dqn_3action_best.pt` | DQN | cicids2017 | `response_state_v1` | 42,997 | `c06a61fb7777511600efd6db776745c4539da30c710fed8993145ed1b926be31` |
| `models/fusion/fusion_weights.json` | Fusion | multi | — | 1,214 | `e35df25179a4574c83192bf35ebd0041772007c8b360151df489a5d9bd5450d0` |

**Integrity result: PASS (9/9).** No checkpoint was modified during this audit.

Note: raw datasets are **not present** in the working tree (`data/raw/` contains only
`.gitkeep`). Dataset identity and hashes live in `data/manifests/dataset_registry.yaml` and
`results/audits/*.json`. Re-running training is therefore impossible from a clean clone
without re-acquiring data.

---

## 2. Random Forest contract

### 2.1 Architecture (verified by loading the estimator)

| Property | CIC | CSE | UNSW |
|---|---|---|---|
| `n_estimators` | 100 | 100 | 100 |
| `max_depth` | 16 | 16 | 16 |
| `min_samples_leaf` | 2 | 2 | 2 |
| `class_weight` | `balanced_subsample` | `balanced_subsample` | `balanced_subsample` |
| `classes_` | `[0, 1]` | `[0, 1]` | `[0, 1]` |
| Input features | 10 (R10) | 10 (R10) | 4 (R4) |

`configs/experiments/p1_cicids2017_r10.yaml` overrides `n_estimators: 100`; the library default
in `src/xrlids/models/random_forest.py` is `200`. The canonical artifacts are the **100-tree**
configuration. Reproducing from library defaults alone would produce a different model — this
is a reproducibility footgun, not a checkpoint defect.

### 2.2 Feature order

R10 (`src/xrlids/features/definitions.py`):

1. `flow_duration_ms`
2. `flow_packets_per_s`
3. `flow_bytes_per_s`
4. `packet_length_mean`
5. `packet_length_std`
6. `syn_count`
7. `ack_count`
8. `rst_count`
9. `fin_count`
10. `syn_ack_ratio`

R4: `flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean`.

Every runtime path that is contract-correct validates this exact order:
`ModelRegistry.infer`, `ReplayEngine.predict_features`, and the CSV evaluator.

### 2.3 Preprocessing

Each RF has a **matched train-fitted `StandardScaler`** stored beside the source experiment:

| RF | Preprocessor |
|---|---|
| `EXP-P1-CIC2017-R10-001` | `results/experiments/EXP-P1-CIC2017-R10-001/preprocessor.joblib` |
| `EXP-P1-CSE2018-R10-MULTI-001` | `results/experiments/EXP-P1-CSE2018-R10-MULTI-001/preprocessor.joblib` |
| `EXP-P1-UNSWNB15-R10-MULTI-001` | `results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001/preprocessor.joblib` |

The preprocessor is fitted **on the training split only** and applied exactly once. The
scikit-learn model itself has no `feature_names_in_` (fitted on a NumPy array), so schema
compatibility must be enforced by the caller. `ModelRegistry.infer` and
`ReplayEngine.predict_features` do this; `LivePipelineRunner` does **not** (see §9.3).

### 2.4 Score semantics

`predict_proba(X)[0, 1]` = fraction of trees voting for class 1 (attack). It is **not a
calibrated posterior** unless `FrozenDetector` is given a `PlattCalibrator`. No canonical
calibration artifact is registered, so all published RF scores are tree-vote fractions.

This matters because the DQN was trained on exactly this quantity (`score_type:
tree_vote_fraction`).

### 2.5 Verified performance (aligned test populations)

| Dataset | Population | RF F1 | RF Accuracy | RF ROC-AUC |
|---|---:|---:|---:|---:|
| CIC-IDS2017 | 355,833 | 0.9512 | 0.9815 | 0.99678 |
| CSE-CIC-IDS2018 | 1,662,419 | 0.8861 | 0.9723 | 0.99018 |
| UNSW-NB15 | 24,496 | 0.8548 | 0.8590 | 0.94866 |

Source: `results/experiments/EXP-P1-*/test_metrics.json` (`aligned.models.random_forest`) and
`models/registry/model_manifest.json`. Values agree to 4 decimal places.

---

## 3. LSTM contract

### 3.1 Architecture (verified from checkpoint)

```text
input_size = number of contract features (10 or 4)
hidden_size = 32
num_layers = 2
dropout = 0.2
output = 1 logit -> sigmoid
seq_len = 5
label_rule = "last"
seed = 42
loss = BCE
best_epoch: CIC 14 (1-based), CSE 11, UNSW 14
best_val_loss: CIC 0.043713, CSE 0.030368, UNSW (recorded in checkpoint)
```

The checkpoint stores `params`, `feature_names`, `seq_len`, `label_rule`, `best_epoch`,
`best_val_loss`, and `history`, so the contract is self-describing.

### 3.2 Verified performance (aligned sequences only)

| Dataset | Aligned population | LSTM F1 | LSTM Accuracy | LSTM ROC-AUC |
|---|---:|---:|---:|---:|
| CIC-IDS2017 | 355,833 | 0.9633 | 0.9867 | 0.99743 |
| CSE-CIC-IDS2018 | 1,662,419 | 0.9603 | 0.9912 | 0.99655 |
| UNSW-NB15 | 24,496 | 0.8637 | 0.8683 | 0.93343 |

Note the CIC *native* population is 355,865; the 32-row difference is the sequence warm-up
excluded from aligned metrics. This is correct, not a bug.

### 3.3 Sequence construction — the critical semantic

`build_sequences` (`src/xrlids/models/lstm.py:141`) creates windows of 5 **consecutive rows
within one split** and rejects any window that crosses a group boundary:

```python
if grp_arr is not None:
    if grp_arr[start + seq_len - 1] != first_grp or \
       np.any(grp_arr[start:start + seq_len] != first_grp):
        continue
```

`scripts/phase1/run_experiment.py:317-323` supplies:

```python
train_session = prov_train["source_file"]
```

So the grouping key is the **capture file name**, not host, not 5-tuple, not session. Combined
with the split manifest:

```json
"methodology": "stratified_random",
"ordering_basis": "arrival_order",
"checks_not_performed": [
  "strict_timestamp_monotonic_ordering (timestamps absent or non-monotonic in source data)"
]
```

the training distribution is:

> 5 consecutive CSV rows from one capture file, in file order, after a stratified random
> 60/20/20 split, with no guarantee of chronological ordering or shared endpoints.

This is compatible with the **offline evaluator** (which uses the same boundary columns) and
**incompatible** with per-source-IP live sequencing unless validated.

### 3.4 LSTM compatibility verdict by runtime

| Runtime | Sequence source | Compatible? | Reason |
|---|---|---|---|
| Phase 1 training/eval scripts | `source_file`, arrival order | ✅ | Same construction |
| CSV evaluator | boundary column (`source_file`/`session_id`/…) + row order | ✅ | Same construction, explicit warm-up |
| `FlagshipXRLIDS.process_flow` | global 5-flow buffer, all hosts | ⚠️ | Shape OK; distribution mixes hosts |
| Replay Lab | not used | n/a | RF-only scoring |
| Dashboard live | not used | n/a | RF + rules only |
| Proposed per-IP escalation | last 5 flows for one source IP | ❌ unvalidated | Homogeneous host, causal order, different timing → OOD |

**Blocker LSTM-1:** Do not present per-IP escalation + frozen LSTM as a validated detector.
Either (a) retrain/version an LSTM on per-IP sequences, or (b) treat the LSTM as an offline
benchmark model and do not wire it into live alerting. This requires explicit approval.

**Blocker LSTM-2:** `FlagshipXRLIDS` warms up by setting `p_lstm = p_rf` and flags it via
`lstm_score_source="rf_fallback"`. That is honest, but it means the first four flows per engine
are pure RF. Any fusion metric computed over those flows is not a fusion metric.

---

## 4. Fusion contract

`models/fusion/fusion_weights.json`:

```text
score = alpha * S_rf + (1 - alpha) * S_lstm
alpha_tuned_on_validation = true
probability_calibrated = false
```

| Dataset | alpha | threshold | Source experiment | Fusion F1 | Fusion Acc |
|---|---:|---:|---|---:|---:|
| neutral baseline | 0.50 | 0.50 | D-003 | — | — |
| cicids2017 | 0.50 | 0.50 | `EXP-P1-CIC2017-R10-001` | 0.9745 | 0.9906 |
| cse_cic_ids2018 | **0.00** | 0.50 | `EXP-P1-CSE2018-R10-MULTI-001` | 0.9603 | 0.9912 |
| unsw_nb15 | 0.60 | 0.50 | `EXP-P1-UNSWNB15-R10-MULTI-001` | 0.8970 | 0.8996 |

Critical observations:

1. **CSE fusion is pure LSTM** (`alpha=0.0`). Reporting "RF+LSTM fusion improves CSE" is false;
   the tuned optimum discarded RF entirely.
2. Fusion is a **convex score blend**, not a calibrated probability. Threshold 0.50 on the blend
   is a decision rule, not a posterior cut.
3. The `unsw_nb15` configuration carries `"feature_contract": "R4"`; the others are R10. A
   single hard-coded 10-feature fusion path would break UNSW.
4. Fusion is **offline only** in the deployed console.

---

## 5. DQN contract

### 5.1 State (authoritative, `src/xrlids/response/state.py`)

```text
s_t = [ S_t, ΔS_t, N_alert, a_(t-1), c_t, v_t ] ∈ R^6   (all dims in [0,1])

S_t      = clip(attack_score, 0, 1)
ΔS_t     = clip(S_t - mean(score history), -1, 1); 0 if no history
N_alert  = fraction of (history + current) above 0.50
a_(t-1)  = previous action enum / 3.0  (ALLOW=0, ALERT=1/3, RATE_LIMIT=2/3, ISOLATE=1)
c_t      = remaining cooldown / 30.0, clipped [0,1]
v_t      = clip(log10(1 + bytes_per_s) / volumetric_scale_log_max, 0, 1)
```

Any runtime that does not call `StateBuilder.update_history(...)` between flows produces
degenerate `ΔS_t`, `N_alert`, `c_t`, and `a_(t-1)`.

### 5.2 Training-time score source (verified, contradicts a common assumption)

`configs/experiments/p2b_cicids2017_dqn.yaml`:

```yaml
score_type: tree_vote_fraction
```

`scripts/phase2/run_phase2a_baselines.py`:

```python
detector = FrozenDetector.load("EXP-P1-CIC2017-R10-001")
scores = detector.predict_score(X_val)
host_id = f"host_{i % 250}"
```

Therefore:

- **Score source:** RF tree-vote fraction — **not fusion**, not calibrated probability.
- **Host identity:** 250 synthetic round-robin hosts — not real endpoints.
- **Order:** validation-split row order — not live arrival.
- **Dataset:** CIC-IDS2017 only.

**Blocker DQN-1:** Feeding a fusion score into these weights is off-contract (CSV evaluator
does exactly this). Feed the RF score, as Replay Lab does.

**Blocker DQN-2:** The synthetic `host_{i % 250}` mapping means the safety gate's blast-radius
and cooldown statistics were computed over an artificial host population. Real host cardinality
will change gate behavior; results do not transfer automatically.

### 5.3 Action spaces and checkpoints

| Checkpoint | Actions | Selected step | Selection metric | Validation value |
|---|---|---:|---|---:|
| `dqn_3action_best.pt` | ALLOW, ALERT, RATE_LIMIT | 10,000 | `mean_cost_per_flow` | 2.04373 |
| `dqn_4action_best.pt` | ALLOW, ALERT, RATE_LIMIT, ISOLATE | 45,000 | `mean_cost_per_flow` | 2.24160 |

Checkpoint `metrics.total_steps` is `15000` for both. This is the **validation evaluation
horizon**, not the training step; the manifest's `selected_step` is authoritative for the
training checkpoint. Recorded here to prevent misreading the checkpoint metadata.

### 5.4 Authoritative test metrics

From `results/phase2/EXP-P2-FINAL-TEST-001/final_test_metrics.json` (regime
`standard_enterprise`):

| Metric | 3-action | 4-action |
|---|---:|---:|
| Mean cost / flow | **1.4208** | 5.3256 |
| False quarantine rate | 0.0000 | 0.00196 |
| Business availability | 96.51% | 96.52% |
| Action chattering index | 0.00194 | 0.02145 |
| Mitigation delay (steps) | 31.66 | 23.55 |
| Contained attacks | 60,449 | 10,285 |
| Uncontained attacks | 4,371 | 54,535 |

The 3-action policy is selected for deployment because it has ~3.7× lower cost per flow and a
zero false-quarantine rate. Its "containment" relies on RATE_LIMIT because ISOLATE is not in
its action space. Comparing contained-attack counts across action spaces is therefore not
apples-to-apples.

`test_f1` / `test_accuracy` are `null` by design in the manifest: reinforcement-learning policy
metrics are not classification metrics.

---

## 6. Safety gate contract

`src/xrlids/response/safety.py`:

| Invariant | Parameter | Behavior |
|---|---|---|
| Action-space clamp | `action_mode` (`FOUR_ACTION` default) | In `THREE_ACTION`, `ISOLATE` → `RATE_LIMIT` |
| Critical infrastructure | `critical_hosts` (gateway, DNS, DC, aliases) | `ISOLATE` → `ALERT` |
| Blast radius | `blast_radius_threshold=0.05`, `min_hosts_for_circuit_breaker=20` | Projected isolation fraction > 5% → `ALERT` |
| Mandatory cooldown | `cooldown_steps=30`, `step_duration_s=1.0` | During cooldown, `ALLOW` after a disruptive action is held at the previous disruptive action |
| Audit | `_override_log` | Every override records step, flow, host, proposed, enforced, reason |

Important nuance: the cooldown prevents **de-escalation to ALLOW**, not new disruptive actions.
A CI test that expects "no new escalation during cooldown" would be testing the wrong semantics.

"Advisory mode" is not a gate parameter. It is an orchestration convention: the gate computes
an enforced action; the caller chooses not to execute it. The dashboard never calls the gate at
all.

---

## 7. TreeSHAP contract

- RF only. Input must be the **scaled** feature vector (`explain_flow_prediction` transforms
  with the benchmark preprocessor).
- Returns per-feature attributions for class 1 (attack), plus a base value.
- `shap.TreeExplainer` is cached per benchmark (`_EXPLAINER_CACHE`), so repeated explanations do
  not pay construction cost.
- Handles `(1, n_features, 2)` arrays and legacy list-of-arrays output.
- Latency: **28.156 ms** median per flow on this machine (25 samples).
- It does **not** explain the LSTM, the fusion score, or the DQN action.

**Blocker SHAP-1:** Any UI that presents SHAP as explaining "the model's decision" must specify
"the Random Forest component". Current code and docs mostly do; the wording must stay explicit.

**Blocker SHAP-2:** Do not compute SHAP per flow in the live loop at the current budget: it
raises packet→decision from ~40.6 ms to ~61.3 ms median.

---

## 8. Feature-contract compatibility matrix

| Path | Feature order validated | Preprocessor applied | Missing/NaN/inf rejected | Verdict |
|---|---:|---:|---:|---|
| `ModelRegistry.infer` | ✅ | ✅ once | ✅ | Correct |
| `ReplayEngine.predict_features` | ✅ | ✅ if configured | ✅ | Correct (dashboard live uses this) |
| CSV evaluator | ✅ | ✅ | ✅ (invalid rows dropped + counted) | Correct |
| Replay Lab | ✅ | ✅ batch | ✅ | Correct |
| `FlagshipXRLIDS.process_flow` | ✅ (but **zero-fills missing columns**, line ~272) | ✅ | ❌ silently 0.0 | **Conditional** |
| `LivePipelineRunner` | partial | ❌ | ❌ | **Incorrect** |

`FlagshipXRLIDS.process_flow`:

```python
for col in self.feature_columns:
    if col not in df.columns:
        df[col] = 0.0
```

This directly contradicts the "no silent zero-filling" invariant used everywhere else. It is
tolerable only because flagship has no production caller; it must be fixed before wiring.

---

## 9. End-to-end compatibility by runtime

### 9.1 Dashboard live monitor — **compatible with RF only**

- RF + frozen preprocessor via `ReplayEngine` ✅
- Rules independent of ML ✅
- No LSTM / fusion / DQN / gate → no cross-model incompatibility, but also no two-stage system
- On-demand SHAP uses the same preprocessor ✅

### 9.2 CSV evaluator — **detection compatible, response incompatible**

| Step | Contract | Verdict |
|---|---|---|
| RF scoring | R10/R4 + preprocessor | ✅ |
| LSTM sequencing | boundary-grouped T=5, `last` label | ✅ |
| Fusion | dataset alpha, 0.50 threshold | ✅ |
| DQN state | fresh `StateBuilder` per row, never `update_history` | ❌ |
| DQN score source | passes fusion score (trained on RF score) | ❌ |
| Safety gate | never called, reports `PASSED` | ❌ false claim |

### 9.3 `LivePipelineRunner` — **incompatible**

- Raw features → `predict_proba` without scaling: **shape works, values wrong**.
- No preprocessor injection point.
- Duplicate class definition.
- Not called by the dashboard, so the defect is latent rather than active.

### 9.4 Replay Lab — **response contract correct, detection RF-only**

- One `StateBuilder`, sequential `update_history` ✅
- RF score as `S_t` ✅ (matches training)
- Safety gate invoked ✅
- No LSTM/fusion → the "detection" is RF-only
- Offline dataset replay, not live

### 9.5 `FlagshipXRLIDS` — **full chain, contract issues**

- RF+LSTM+fusion ✅ (respects per-dataset alpha)
- 6-D state ✅, but per-engine buffer not per-host ⚠️
- DQN 4-action ✅
- Safety gate ✅
- Silent zero-fill for missing features ❌
- No production caller ❌

---

## 10. Compatibility blockers (must be resolved before implementation)

| ID | Blocker | Consequence if ignored | Required decision |
|---|---|---|---|
| **MC-01** | LSTM trained on file-grouped arrival-order sequences; live escalation is per-IP | OOD live sequences; invalid temporal claim | Retrain per-IP LSTM **or** keep LSTM offline-only |
| **MC-02** | DQN trained on RF tree-vote fraction, not fusion | Off-contract response policy | Standardize `S_t` on RF score in all runtimes |
| **MC-03** | CSV evaluator's DQN state has no history and no safety gate | Misleading `safety_status: PASSED` | Wire shared sequential state + gate, or remove response block |
| **MC-04** | `LivePipelineRunner` omits preprocessing | Silently wrong live scores if wired | Inject and apply frozen preprocessor |
| **MC-05** | Flagship zero-fills missing features | Silent corruption of incomplete inputs | Reject missing features explicitly |
| **MC-06** | DQN host population is synthetic (`host_{i%250}`) | Gate blast-radius/cooldown behavior differs on real hosts | Document as simulation-only, or re-evaluate with real host cardinality |
| **MC-07** | CSE fusion `alpha=0.0` | "Fusion" claim is false for CSE | Report as LSTM-only for CSE |
| **MC-08** | No calibration artifact for RF scores | Scores are tree-vote fractions, not posteriors | Do not call them probabilities |
| **MC-09** | Raw datasets absent | Cannot reproduce training from clone | Re-acquire via registry; do not retrain blindly |
| **MC-10** | 5-in-60 s escalation threshold uncalibrated | Unsupported operating point | Either calibrate offline or label as heuristic |

---

## 11. What is genuinely validated

| Claim | Status | Evidence |
|---|---|---|
| RF binary detection on three benchmarks | **Validated** | `test_metrics.json`, manifest |
| LSTM improves over RF on CSE/CIC (aligned) | **Validated offline** | aligned metrics tables |
| Fusion improves CIC over both components | **Validated offline** | 0.9745 vs 0.9633/0.9512 |
| Fusion improves CSE | **Not applicable** (alpha=0) | fusion_weights.json |
| DQN lowers cost vs baselines in simulation | **Validated offline** | `final_test_metrics.json` |
| Safety gate enforces invariants in simulation | **Validated offline + unit tested** | `tests/unit/test_safety*` |
| Live feature parity (R10) | **Validated** | `tests/integration/test_phase3_parity_harness.py` |
| LSTM live temporal detection | **Not validated** | no experiment |
| DQN live response | **Not validated / not wired** | dashboard note |
| End-to-end live two-stage system | **Does not exist** | architecture audit |

---

## 12. Evidence commands

```bash
# 1. Hash verification
python - <<'PY'
import json, hashlib
from pathlib import Path
m = json.load(open("models/registry/model_manifest.json"))
for a in m["artifacts"]:
    p = Path(a["canonical_path"])
    print("OK" if hashlib.sha256(p.read_bytes()).hexdigest() == a["sha256"] else "MISMATCH", p)
PY

# 2. RF architecture
python - <<'PY'
import joblib
for p in ["models/rf/random_forest_cicids2017.joblib",
          "models/rf/random_forest_cse2018.joblib",
          "models/rf/random_forest_unswnb15.joblib"]:
    m = joblib.load(p).model
    print(p, m.n_estimators, m.max_depth, m.min_samples_leaf, list(m.classes_))
PY

# 3. LSTM / DQN checkpoint contracts
python - <<'PY'
import torch
for p in ["models/lstm/lstm_cicids2017.pt", "models/lstm/lstm_cse2018.pt", "models/lstm/lstm_unswnb15.pt"]:
    c = torch.load(p, map_location="cpu", weights_only=False)
    print(p, c["params"], c["seq_len"], c["label_rule"], c["best_epoch"])
for p in ["models/dqn/dqn_4action_best.pt", "models/dqn/dqn_3action_best.pt"]:
    c = torch.load(p, map_location="cpu", weights_only=False)
    print(p, c["metrics"]["mean_cost_per_flow"])
PY

# 4. Full test suite (588 passed, 0 failed: 573 baseline + 15 user tests)
.venv/bin/python -m pytest tests -o addopts="" --tb=no -q

# 5. Latency
.venv/bin/python scripts/benchmark_latency.py
```

---

## 13. Phase 0 model-compatibility gate

| Gate | Result |
|---|---|
| Artifact integrity | **PASS (9/9)** |
| RF contract documented from checkpoints | **PASS** |
| LSTM contract documented from checkpoints | **PASS** |
| LSTM **live** semantic compatibility | **FAIL (OOD, unvalidated)** |
| DQN state contract documented | **PASS** |
| DQN score-source compatibility across runtimes | **FAIL (CSV evaluator)** |
| Safety gate wired where claimed | **FAIL (CSV evaluator)** |
| Preprocessing applied everywhere | **FAIL (`LivePipelineRunner`, flagship zero-fill)** |
| Fusion semantics reported honestly | **FAIL for CSE (alpha=0)** |
| Published metrics reproduced from result files | **PASS** |

**Conclusion:** the frozen artifacts are intact and internally consistent. The incompatibilities
are in **runtime wiring and semantics**, not in the checkpoints. No retraining or checkpoint
replacement is justified by this audit. Proceed to `docs/IMPLEMENTATION_PLAN.md`.
