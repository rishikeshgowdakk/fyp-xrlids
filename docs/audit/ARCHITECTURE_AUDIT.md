# XRL-IDARS — Architecture & Data Contract Audit

**Document Path:** `docs/audit/ARCHITECTURE_AUDIT.md`  
**Date:** 2026-10-28  
**Repository:** `https://github.com/rishikeshgowdakk/fyp-xrlids`  
**Status:** Comprehensive End-to-End Implementation Audit Complete

---

## 1. Verified Architecture Map & Data Flow

The following Mermaid diagram maps the **actual code implementation** across all 13 execution boundaries:

```mermaid
flowchart TD
    subgraph DataIngestion ["1. Data Ingestion & Preprocessing"]
        A1["Raw Benchmark CSVs<br/>(CIC-IDS2017 / CSE-2018 / UNSW-NB15)"] -->|Canonicalize Headers| A2["xrlids.utils.columns<br/>canonicalize_frame()"]
        A2 -->|Schema & Missing Check| A3["xrlids.preprocessing.cleaning<br/>clean_dataset_frame()"]
        A3 -->|Train-Only Scaling| A4["xrlids.preprocessing.pipeline<br/>Preprocessor.fit() / transform()"]
    end

    subgraph FeaturePipeline ["2. Feature Pipeline"]
        A4 -->|Semantic Mapping| B1["xrlids.features.compute<br/>extract_semantics()"]
        B1 -->|Canonical Formulas| B2["xrlids.features.definitions<br/>compute_features() [R10 / R4]"]
    end

    subgraph ModelTier ["3. Perception Tier (Dual-Model Fusion)"]
        B2 -->|Standardized Vector| C1["Random Forest Classifier<br/>(Joblib model, R10, n=200)"]
        B2 -->|Causal 5-Flow Sequence| C2["Supervised LSTM<br/>(PyTorch .pt, T=5, hidden=32)"]
        C1 -->|P_rf ∈ [0, 1]| C3["Convex Score Fusion<br/>S = α·P_rf + (1-α)·P_lstm"]
        C2 -->|P_lstm ∈ [0, 1]| C3
    end

    subgraph LiveCapture ["4. Live & PCAP Traffic Ingestion"]
        D1["Raw Network Interface<br/>(AF_PACKET / CAP_NET_RAW)"] -->|Ethernet Frame| D3["xrlids.demo.pcap<br/>parse_packet_bytes()"]
        D2["PCAP File Replay<br/>(sample_traffic.pcap)"] -->|PcapReader| D3
        D3 -->|PacketInfo| D4["xrlids.live.flow_builder<br/>LiveFlowBuilder (Decision D-006)"]
        D4 -->|120s Timeout or FIN/RST| D5["Flow.to_features()<br/>Numerical Parity atol ≤ 1e-4"]
        D5 -->|R10 Live Vector| A4
    end

    subgraph Explainability ["5. Explainability Tier"]
        C1 -->|TreeSHAP Attribution| E1["xrlids.explainability.shap_analysis<br/>ShapExplainer (RF Only)"]
        E1 -->|Attribution Weights| E2["Waterfall / Force Plot<br/>API: /api/csv/explain"]
    end

    subgraph DecisionSafety ["6. Decision & Safety Tier"]
        C3 -->|Threat Score S_t| F1["xrlids.response.state<br/>StateBuilder [S_t, ΔS_t, N_alert, a_t-1, c_t, v_t]"]
        F1 -->|6D State Vector| F2["xrlids.response.dqn<br/>DuelingQNetwork (4 Actions)"]
        F2 -->|Proposed Action| F3["xrlids.response.safety<br/>DeterministicSafetyGate"]
        F3 -->|Validated / Overridden Action| F4["Response Policy Outcome<br/>(ALLOW, ALERT, RATE_LIMIT, ISOLATE)"]
    end

    subgraph EnforcementSandbox ["7. Lab Enforcement & Safety Sandboxing"]
        F4 -->|Dry-Run Guard| G1["Observational Dry-Run<br/>(Zero Host Mutation)"]
        F4 -->|Precondition Gate| G2["xrlids.enforcement.lab<br/>Virtual Network Namespace (netns)"]
    end

    subgraph DashboardAPI ["8. Dashboard & API Service"]
        C3 --> H1["dashboard.server<br/>ThreadingHTTPServer (127.0.0.1)"]
        E2 --> H1
        F4 --> H1
        G1 --> H1
        H1 -->|REST APIs| H2["Frontend UI<br/>(HTML5 / Vanilla JS Dashboard)"]
    end
```

---

## 2. Boundary-by-Boundary Interface Contract Audit

| Boundary | Component | Input Schema | Output Schema | Types & Units | Ordering / Contract | Integration Status |
|:---|:---|:---|:---|:---|:---|:---:|
| **1. Dataset Ingestion** | `xrlids.datasets.loading` / `columns.py` | Raw CSV files with arbitrary header whitespace | Canonicalized `pd.DataFrame` with `attrs['raw_columns']` | Numeric floats / strings | Exact column preservation | ✅ Implemented & Tested |
| **2. Cleaning & Scaling** | `xrlids.preprocessing.pipeline` | Raw feature DataFrame | Imputed & StandardScaled feature DataFrame | Mean 0, Std 1 (`float64`) | Train-only fit; strict test isolation | ✅ Implemented & Tested |
| **3. Semantic Extraction** | `xrlids.features.compute` | Cleaned DataFrame | Semantic DataFrame | Durations in seconds, bytes in count | Semantic field dictionary | ✅ Implemented & Tested |
| **4. Feature Calculation** | `xrlids.features.definitions` | Semantic DataFrame | Canonical feature DataFrame (`R10` or `R4`) | Milliseconds, packets/s, bytes/s, ratios | `R10_FEATURES` (10 cols), `R4_FEATURES` (4 cols) | ✅ Implemented & Tested |
| **5. Model Training & Serialization** | `src/xrlids/models/` | Scaled `X_train`, labels `y_train` | Frozen `.joblib`, `.pt`, `.json` weights | Probabilities $\in [0, 1]$ | Feature names validated against model header | ✅ Implemented & Tested |
| **6. Live Packet Capture** | `src/xrlids/live/capture.py` | Raw byte frames from socket or PCAP | `PacketInfo` dataclass | Timestamps (float s), ports (int), flags (bool) | Ethernet/IPv4/TCP/UDP headers | ✅ Implemented & Tested |
| **7. Live Flow Aggregation** | `src/xrlids/live/flow_builder.py` | Stream of `PacketInfo` | Completed bidirectional `Flow` objects | 5-tuple, start/last timestamps, byte totals | Decision D-006: FIN/RST or 120s timeout | ✅ Implemented & Tested |
| **8. Live Feature Extraction** | `src/xrlids/demo/flow.py` | `Flow` object | 10D NumPy array / dict | Units strictly match offline R10 definitions | Ordered by `R10_FEATURES` ($\text{atol} \le 10^{-4}$) | ✅ Implemented & Tested |
| **9. Model Inference & Fusion** | `src/xrlids/flagship.py` | 10D feature vector | `FlagshipDecision` dataclass | Probabilities $P_{\text{rf}}, P_{\text{lstm}}, S_{\text{fusion}} \in [0, 1]$ | Score Fusion $\alpha = 0.50$ (CIC2017) | ✅ Implemented & Tested |
| **10. Explainability** | `src/xrlids/explainability/` | Scaled feature vector | Dict of per-feature attributions | SHAP values (log-odds impact on class 1) | Explains **Random Forest only** | ✅ Implemented & Tested |
| **11. RL Response Policy** | `src/xrlids/response/dqn/` | 6D causal state vector $s_t$ | Recommended action index ($0..3$) | Q-values per action (`float32`) | Actions: ALLOW, ALERT, RATE_LIMIT, ISOLATE | ✅ Implemented & Tested |
| **12. Safety Invariant Gate** | `src/xrlids/response/safety.py` | Recommended action + context | Enforced action + override record | Discrete Action enum | Invariants: no isolation without proof; anti-flap | ✅ Implemented & Tested |
| **13. Dashboard & API** | `dashboard/server.py` | HTTP GET / POST JSON | JSON responses / CSV streams | UTF-8 JSON / CSV payloads | Binds strictly to 127.0.0.1; origin validated | ✅ Implemented & Tested |

---

## 3. Verified Integration Defects & Anomalies

### Defect INT-001: Report Generation Hardcoding of Outdated Test Totals
- **Location:** `scripts/phase1/generate_reports.py` (line 826), `scripts/phase2/run_phase2b_readiness_audit.py` (lines 379-380, 908, 1006).
- **Description:** Hardcoded string `"466 passing tests"` rather than referencing dynamic collection or the updated 481-test inventory.
- **Severity:** Medium (Documentation / Reporting Integrity).
- **Resolution Plan:** Update templates to reflect the authoritative 481 test count (or dynamic collection).

### Defect INT-002: VLAN (802.1Q) Packet Parsing in `pcap.py`
- **Location:** `src/xrlids/demo/pcap.py::parse_packet_bytes` (lines 85-88).
- **Description:** Ethernet frames with EtherType `0x8100` (802.1Q VLAN) or `0x88A8` (802.1ad) are dropped because EtherType is compared strictly to `0x0800` at fixed offset 12..14 without checking for 4-byte 802.1Q tags. `src/xrlids/live/devices.py` already supports VLAN headers, creating an internal discrepancy.
- **Severity:** Low-Medium (Protocol Robustness in Managed LANs).
- **Resolution Plan:** Handle 802.1Q/802.1ad tags in `parse_packet_bytes()` by advancing the offset to the inner EtherType.

### Integration Note INT-003: TreeSHAP Scope Boundary
- **Location:** `src/xrlids/flagship.py`, `dashboard/server.py`.
- **Finding:** Local SHAP explanations explain the tree-based Random Forest model. They do not calculate gradients across the LSTM or the linear fusion score. This boundary is correctly documented in disclosures but must remain prominent in audit summaries.
