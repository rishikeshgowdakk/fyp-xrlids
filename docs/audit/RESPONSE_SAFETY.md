# XRL-IDARS — Response Safety & Explainability Audit

**Document Path:** `docs/audit/RESPONSE_SAFETY.md`  
**Date:** 2026-10-28  
**Repository:** `https://github.com/rishikeshgowdakk/fyp-xrlids`  
**Status:** Verification of Safety Invariants, Sandboxing & Explainability Scope

---

## 1. Response Safety Mandate & Production NO-GO Policy

> ### ⚠️ STRICT SAFETY DIRECTIVE: AUTONOMOUS PRODUCTION FIREWALL ENFORCEMENT IS NO-GO
> The autonomous mitigation engine is strictly prohibited from altering production host firewalls, routing tables, or network interfaces. All response actions in standard execution are executed in **observational dry-run mode** (`RULE_DRY_RUN`) or isolated virtual network namespaces (`Phase 3I`).

### Multi-Tier Defense Architecture
1. **Tier 1 (Dry-Run Default):** `PipelineRunner` and `dashboard.server` operate with execution mode `DRY_RUN`. Proposed mitigations are logged with simulated impact; zero system calls are made to `iptables`, `nftables`, or `tc`.
2. **Tier 2 (Deterministic Safety Gate):** Positioned between the RL policy and the actuation layer. Any action proposed by the DQN must satisfy non-bypassable deterministic invariants (`src/xrlids/response/safety.py`).
3. **Tier 3 (Lab Sandboxing):** When lab enforcement is enabled for research (`src/xrlids/enforcement/lab.py`), it is confined exclusively to an isolated network namespace (`ip netns exec xrlids_lab`). Host network baseline is cryptographically preserved and checked before and after execution.

---

## 2. Deterministic Safety Gate Invariants

The `DeterministicSafetyGate` (`src/xrlids/response/safety.py`) evaluates every proposed action against formal invariant checks:

| Safety Invariant | Rule Definition | Failure Mode Prevented | Override Action |
|:---|:---|:---|:---:|
| **INV-001: Critical Asset Shield** | If host criticality $c_t \ge 0.80$, `ISOLATE` is prohibited unless threat score $S_t \ge 0.90$. | Denial-of-Service against mission-critical servers (e.g. Domain Controller, Database). | Overridden to `RATE_LIMIT` or `ALERT`. |
| **INV-002: Anti-Chattering Cooldown** | Prevents rapid alternation between `ISOLATE` and `ALLOW` within a 3-step cooldown window. | Route flapping, TCP session reset storms, and state table exhaustion. | Retains previous action state. |
| **INV-003: Parameter Validation** | Bandwidth limits for `RATE_LIMIT` must be bounded ($10\,\text{Kbps} \le R \le 100\,\text{Mbps}$). | Complete blackout from zero-rate limits or bypass from unbounded limits. | Clamped to safe range. |
| **INV-004: Allowlist Integrity** | Policy action integer must reside within $\{0, 1, 2, 3\}$. | Memory corruption or undefined behavior from invalid action indices. | Defaulted to `ALLOW` (`0`) with security alert. |

---

## 3. Explainability Tier: TreeSHAP Scope & Integrity

### Implementation Structure
- `src/xrlids/explainability/shap_analysis.py` and `src/xrlids/flagship.py::_class1_attributions`.
- Computes exact local Shapley values using TreeSHAP on the Random Forest tree ensemble.
- Renders per-feature attributions answering: *Which flow features increased or decreased the predicted attack probability relative to the baseline?*

### Critical Methodological Disclosures
1. **TreeSHAP Explains Random Forest Only:**
   - SHAP attributions reflect the tree ensemble splits. They do **NOT** explain the PyTorch LSTM neural network or the linear score fusion.
   - The UI and API responses explicitly attribute SHAP values to the Random Forest model to avoid misleading operators.
2. **Attribution is Correlation, Not Causality:**
   - High Shapley value for `syn_ack_ratio` proves that the feature strongly influenced the model's prediction. It does **not** prove malicious intent or physical causal origin.
3. **Shape Normalization:**
   - `_class1_attributions` explicitly handles differing SHAP output layouts (2D array, 3D tensor, list of class arrays) across SHAP library versions, guaranteeing consistent extraction of Class 1 (Attack) impact.

---

## 4. Negative Testing & Verification Evidence

Automated tests in `tests/unit/test_response_safety.py` and `tests/unit/test_phase3_gate.py` execute negative test suites:
- Injection of invalid action integers (`-1`, `99`) $\to$ Cleanly rejected and overridden.
- Rapid oscillation attacks $\to$ Cooldown invariant triggered; flapping prevented.
- Isolation commands on critical infrastructure under medium threat ($S_t = 0.60, c_t = 0.90$) $\to$ Successfully overridden to `ALERT`.
- Host firewall state check $\to$ Verified that running the complete test suite causes zero modifications to host firewall tables.
