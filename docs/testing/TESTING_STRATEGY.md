# XRL-IDARS — Comprehensive Testing & Quality Assurance Strategy

**Document ID:** `DOC-TEST-STRATEGY-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  
**QA Lead:** Senior Systems & ML Test Architect  

---

## 1. Testing Philosophy & Invariants

The XRL-IDARS test harness enforces four non-negotiable engineering principles:
1. **Zero Flakiness & Determinism**: All tests execute synchronously or with deterministic timeouts. Pseudo-random number generators are seeded ($42, 123, 456$).
2. **Zero Lookahead & Leakage**: Datasets and flow buffers are tested to ensure test sets never leak into training preprocessors (`StandardScaler`).
3. **No Mocks on Core Logic**: Machine learning models, feature vectorizers, flow key canonicalizers, and safety gates run on actual algorithms, not mock stubs.
4. **Zero Destructive Mutation**: All actuation tests verify that Linux kernel network firewall tables (`iptables`, `nftables`) remain completely unmutated.

---

## 2. Test Pyramid & Coverage Structure

```
                  /\
                 /  \
                / E2E\            End-to-End Validation (Scapy PCAP -> Safety Gate)
               /------\
              / Integr \          Integration Tests (Flow -> Feature -> RF -> SHAP -> DQN)
             /----------\
            / Model & Dat\        Data Validation & Model Registry Tests
           /--------------\
          /   Unit Tests   \      Unit Tests (FlowKey, R10 parity, rules, DQN networks)
         /------------------\
```

### Four Test Categories:
- **Unit Tests (`tests/unit/`)**: Verify localized mathematical transformations, canonical 5-tuple key ordering ($A < B$), TCP flag binary capping ($\min(\text{pkt}, 1.0)$), TreeSHAP attributions, Q-value computations, and safety gate invariants.
- **Integration Tests (`tests/integration/`)**: Verify cross-module data exchange from Scapy packet capture through live flow builders, Random Forest inference, TreeSHAP waterfall generation, and Dueling DQN advisory actions.
- **Data Validation Tests (`tests/data/`)**: Verify dataset schema contracts, chronological order constraints, missing-value imputation, and target leakage prevention.
- **Model Tests (`tests/model/`)**: Verify model checkpoint serialization, input tensor validation, and score stability under floating-point perturbations.

---

## 3. Test Execution Command & Environment

The test suite is executed using `pytest` inside the project virtual environment:

```bash
.venv/bin/pytest tests/ -v
```

Execution is monitored for memory leaks, unclosed socket handles, and pending deprecation warnings.
