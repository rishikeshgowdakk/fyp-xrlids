# XRL-IDARS — Developer & Contributor Guide

**Document ID:** `DOC-DEV-GUIDE-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Codebase Architecture & Source Layout

The production codebase resides inside `src/xrlids/`:

```
src/xrlids/
├── capture/            # Packet capture (ScapyCaptureService, AF_PACKET)
├── datasets/           # Benchmark loaders, CSV validators, and split generators
├── demo/               # Unified demo services (LiveLabMonitor, ReplayEngine, FlowBuilder)
├── enforcement/        # Linux network actuators (iptables/nftables dry-run)
├── evaluation/         # Performance metrics (PR-AUC, ROC-AUC, latency)
├── explainability/     # TreeSHAP explainer, Lundberg attributions
├── features/           # Canonical R10 / R4 definitions and vectorizers
├── flow/               # Canonical FlowKey, Flow, and FlowEngine
├── labels/             # 17-family attack taxonomy and binary mapping
├── live/               # Live pipeline runner, sliding sequence buffers
├── models/             # RF model wrappers, PyTorch LSTM, UnifiedInferenceService
├── preprocessing/      # Robust scalers, imputers, contract validators
├── response/           # Dueling DQN, replay buffer, state builder, safety gate
└── rules/              # Fast deterministic policy rules and invariants
```

---

## 2. Core Architectural Classes

### 1. `FlowKey` (`src/xrlids/flow/key.py`)
Represents the canonical bidirectional 5-tuple identifier. Always sort endpoints so that $A < B$:
```python
key = FlowKey.from_packet(src_ip, src_port, dst_ip, dst_port, protocol)
```

### 2. `Flow` & `FlowEngine` (`src/xrlids/flow/`)
Maintains running packet counters, directional byte counters, TCP flags, and inter-arrival timing:
```python
flow = Flow(key, start_time_s=now)
flow.add_packet(packet_len=1420, is_forward=True, flags={"SYN": True}, timestamp_s=now)
features = flow.to_features()  # Returns dict of 10 R10 features
```

### 3. `RandomForestDetector` (`src/xrlids/models/rf.py`)
Primary operational detector. Evaluates a single scaled feature array ($1 \times 10$) and produces calibrated attack probabilities:
```python
rf_detector = joblib.load("models/rf/random_forest_cicids2017.joblib")
attack_prob = rf_detector.predict_proba(scaled_features)[0, 1]
```

### 4. `TreeExplainer` & TreeSHAP (`src/xrlids/evaluation/csv_evaluator.py`)
Computes exact Shapley feature attributions:
```python
explanation = explain_flow_prediction(raw_features, benchmark="cicids2017")
```

### 5. `DeterministicSafetyGate` (`src/xrlids/response/safety.py`)
Evaluates proposed reinforcement learning actions against non-negotiable security constraints:
```python
enforced_action, overridden, reason = safety_gate.enforce_safety(
    step=step_idx, host_id=host_ip, proposed_action=action
)
```

---

## 3. Extending the System

### Adding a New Attack Scenario:
To add a new controlled attack scenario for demonstrations:
1. Define the scenario in `src/xrlids/demo/scapy_simulator.py` within `SCENARIO_BUILDERS`.
2. Generate genuine Scapy packets with calibrated packet lengths and flags.
3. Add a unit test in `tests/unit/test_attack_scenarios.py` verifying detection scores.

### Adding a New Safety Rule:
1. Open `src/xrlids/rules/engine.py`.
2. Subclass or register a new `SecurityRule` with unique `rule_id`, priority, and condition.
3. Verify that the rule evaluates in $< 0.1\,\text{ms}$.

---

## 4. Running the Test Suite & Quality Gates

Before committing any code, developers must run:

```bash
# 1. Run complete test suite (must pass 605 tests with 0 failures)
.venv/bin/pytest tests/ -v

# 2. Verify all package imports
.venv/bin/python -c "import pkgutil, xrlids, importlib; [importlib.import_module(m.name) for m in pkgutil.walk_packages(xrlids.__path__, xrlids.__name__ + '.')]"

# 3. Verify scenario calibrations
.venv/bin/python scripts/demo/verify_attack_scenarios.py
```
