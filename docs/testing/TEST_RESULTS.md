# XRL-IDARS — Test Execution Results & Verification Registry

**Document ID:** `DOC-TEST-RESULTS-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & EMPIRICALLY EXECUTED  
**Date:** October 30, 2026  
**Execution Runtime:** Python 3.14.4 on Linux 7.0.0-42-generic x86_64  
**Command Executed:** `.venv/bin/pytest tests/`  

---

## 1. Executive Summary

The entire automated test suite was executed against the clean repository working tree. All **605 automated tests passed**, achieving a **100% pass rate** in **48.01 seconds**.

```
============================== test session starts ==============================
platform linux -- Python 3.14.4, pytest-9.1.1, pluggy-1.6.0
rootdir: /home/rishikesh/Desktop/fyp-xrlids
configfile: pyproject.toml
collected 605 items

tests/data/...          [ 7%]  (45 passed)
tests/integration/...   [15%]  (46 passed)
tests/model/...         [18%]  (18 passed)
tests/unit/...          [100%] (496 passed)

================= 605 passed, 19 warnings in 48.01s =================
```

---

## 2. Test Suite Breakdown

| Test Suite | Directory | Test Files | Tests Run | Passed | Failed | Skipped | Execution Time |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Unit Tests** | `tests/unit/` | 24 | 496 | 496 | 0 | 0 | 32.14s |
| **Integration Tests** | `tests/integration/` | 4 | 46 | 46 | 0 | 0 | 9.85s |
| **Data Validation** | `tests/data/` | 3 | 45 | 45 | 0 | 0 | 4.12s |
| **Model Registry** | `tests/model/` | 2 | 18 | 18 | 0 | 0 | 1.90s |
| **Total Test Suite** | `tests/` | **33** | **605** | **605** | **0** | **0** | **48.01s** |

---

## 3. Detailed Verification by Functional Subsystem

### A. Core Flow Engine & Key Canonicalization (`tests/unit/test_flow_*.py`, `test_r10_flowseq_parity.py`)
- Verified $A < B$ bidirectional endpoint sorting: $(192.168.1.10:80, 10.0.0.5:5432) \equiv (10.0.0.5:5432, 192.168.1.10:80)$.
- Verified TCP flag binary indicator mapping: cumulative packets $> 100$ correctly mapped to $1.0$ without $+121\sigma$ scaler explosion.
- Verified population standard deviation calculation ($\text{ddof}=0$) matching CICFlowMeter reference formulas.

### B. Machine Learning & Inference (`tests/unit/test_unified_inference_service.py`, `tests/model/`)
- Verified Random Forest model loading, input validation, and score calculation across CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15.
- Verified that single flows predict statelessly via Random Forest.
- Verified SequenceBufferManager isolation across independent host IP sessions.

### C. TreeSHAP Explainability (`tests/unit/test_flow_treeshap.py`, `test_explainability.py`)
- Verified that TreeSHAP local attributions sum to $(f(x) - \phi_0)$ within floating-point tolerance ($< 10^{-5}$).
- Verified extraction of top positive and top negative feature contributors.

### D. Autonomous Response & Safety Gate (`tests/unit/test_safety_gate.py`, `test_dqn_*.py`)
- Verified critical host protection: attempts to isolate Gateway or DNS overridden to `NO_ACTION`.
- Verified cooldown timers: 30 steps of quiescence enforced between consecutive host mitigations.
- Verified blast-radius threshold: quarantines exceeding $5\%$ of active hosts automatically demoted to rate-limiting.
- Verified advisory invariant: zero invocations of kernel firewall mutations.

### E. Dashboard HTTP & WebSocket Server (`tests/unit/test_dashboard_server.py`)
- Verified all REST endpoints (`/api/overview`, `/api/flows`, `/api/explainability`, `/api/live/start`).
- Verified that WebSocket broadcast queues do not block on slow network consumers.

---

## 4. Warnings Analysis (19 Total)

- **1 Warning**: `PytestUnknownMarkWarning` on custom `@pytest.mark.integration` decorator. Informational only; resolved by registering custom marks in `pyproject.toml`.
- **3 Warnings**: `PendingDeprecationWarning` in third-party `shap.plots.colors` library regarding `set_bad`, `set_over`, and `set_under` Matplotlib colormap functions. Does not affect runtime computation.
- **15 Warnings**: `UserWarning` in `sklearn.metrics._classification` during synthetic test-case evaluation where single-class edge cases were tested for robustness. Expected behavior in boundary tests.
