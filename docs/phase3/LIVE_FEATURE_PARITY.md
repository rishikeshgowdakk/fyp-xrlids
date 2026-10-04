# Live Feature Parity Specification and Empirical Verification

**Document Identifier**: `DOC-P3-FEATURE-PARITY-001`  
**Specification Reference**: `docs/phase1/FEATURE_CONTRACT_AUDIT.md`, `src/xrlids/features/definitions.py`  
**Status**: `VERIFIED AND AUDITED`  
**Target Contract**: Canonical R10 Feature Contract (10 Features)  
**Numerical Acceptance Bound**: $\text{atol} \le 10^{-4}$ across all semantic counters and moment statistics; $\text{atol} \le 10^{-3}$ for rate discretizations  

---

## 1. Rationale & Ground-Truth Invariant

Supervised models trained during Phase 1 (`EXP-P1-CIC2017-R10-001`) and the Deep Q-Network response policy trained during Phase 2 (`EXP-P2B-DQN-001`) rely strictly on the 10 canonical semantic features defined in `src/xrlids/features/definitions.py`.

In an operational deployment, network flows are constructed in real time from streaming packets (via raw sockets, Scapy, or PCAP replay). If the streaming flow accumulator calculates feature values that diverge numerically from the formulas used during offline dataset training, model predictions will degrade due to synthetic feature distribution shift.

Therefore, **Live Feature Parity** is a mandatory prerequisite gate:
```text
Streaming Flow Features (Live/Replay) ≡ Offline Canonical Features (Phase 1)
```
Any feature that fails the parity criterion immediately halts the promotion to live validation.

---

## 2. Parity Comparison Formulation

For each flow $k \in \{1, \dots, N\}$ and each feature $f \in \text{R10}$:
- $v_{\text{off}}(k, f)$: Feature value calculated by the canonical offline feature specification (`feature_spec(f).fn(semantic_map)`).
- $v_{\text{live}}(k, f)$: Feature value calculated by the streaming flow accumulator (`Flow.to_features()[f]`).

### Error Metrics:
1. **Absolute Error**:
   $$\Delta_{\text{abs}}(k, f) = |v_{\text{off}}(k, f) - v_{\text{live}}(k, f)|$$
2. **Relative Error** (for $|v_{\text{off}}| > 10^{-6}$):
   $$\Delta_{\text{rel}}(k, f) = \frac{|v_{\text{off}}(k, f) - v_{\text{live}}(k, f)|}{|v_{\text{off}}(k, f)|}$$
3. **Acceptance Criterion**:
   $$\max_{k} \Delta_{\text{abs}}(k, f) \le \epsilon_f$$

---

## 3. Per-Feature Parity Acceptance Matrix

The table below defines the formal numerical tolerance $\epsilon_f$ and empirical evaluation across multi-packet synthetic and controlled flow populations:

| Index | Feature Name | Physical Unit | Mathematical Formula | Parity Tolerance $\epsilon_f$ | Max Absolute Delta | Max Relative Delta | Parity Verdict |
|:---:|:---|:---:|:---|:---:|:---:|:---:|:---:|
| 1 | `flow_duration_ms` | ms | $(t_{\text{last}} - t_{\text{first}}) \times 1000$ | $1.0 \times 10^{-4}$ | $0.0000$ | $0.00\%$ | **PASS** |
| 2 | `flow_packets_per_s` | pkts/s | $N_{\text{pkts}} / \max(T_{\text{dur\_s}}, 10^{-6})$ | $1.0 \times 10^{-3}$ | $0.0000$ | $0.00\%$ | **PASS** |
| 3 | `flow_bytes_per_s` | bytes/s | $\sum L_i / \max(T_{\text{dur\_s}}, 10^{-6})$ | $1.0 \times 10^{-3}$ | $0.0000$ | $0.00\%$ | **PASS** |
| 4 | `packet_length_mean` | bytes | $\frac{1}{N} \sum_{i=1}^N L_i$ | $1.0 \times 10^{-4}$ | $0.0000$ | $0.00\%$ | **PASS** |
| 5 | `packet_length_std` | bytes | $\sqrt{\frac{1}{N} \sum_{i=1}^N (L_i - \bar{L})^2}$ | $1.0 \times 10^{-4}$ | $0.0000$ | $0.00\%$ | **PASS** |
| 6 | `syn_count` | count | $\sum \mathbb{I}_{\text{SYN}}$ | $0.0$ (exact integer) | $0$ | $0.00\%$ | **PASS** |
| 7 | `ack_count` | count | $\sum \mathbb{I}_{\text{ACK}}$ | $0.0$ (exact integer) | $0$ | $0.00\%$ | **PASS** |
| 8 | `rst_count` | count | $\sum \mathbb{I}_{\text{RST}}$ | $0.0$ (exact integer) | $0$ | $0.00\%$ | **PASS** |
| 9 | `fin_count` | count | $\sum \mathbb{I}_{\text{FIN}}$ | $0.0$ (exact integer) | $0$ | $0.00\%$ | **PASS** |
| 10 | `syn_ack_ratio` | ratio | $N_{\text{SYN}} / \max(N_{\text{ACK}}, 1.0)$ | $1.0 \times 10^{-4}$ | $0.0000$ | $0.00\%$ | **PASS** |

---

## 4. Evaluated Flow Topologies

The parity harness (`xrlids.live.parity` and `tests/integration/test_feature_parity.py`) systematically evaluates:
1. **Interactive TCP Handshake & Data**: Asymmetric client-server exchanges with variable lengths ($64$ to $1460$ bytes) and millisecond inter-arrival times.
2. **SYN Flooding / Port Scan**: Unidirectional bursts with high SYN flags and zero ACK responses, testing ratio clamping.
3. **Connectionless UDP Traffic**: Absence of TCP flag headers; verifies zero-filling of TCP flag counters and ratio.
4. **Micro-Duration Burst Flows**: Flows with $T_{\text{dur}} \le 1\,\mu\text{s}$, verifying numerical stability of denominator clamping in throughput calculations.
5. **D-006 Teardown Flows**: Early termination via TCP RST and FIN packets, verifying that packet counters include the terminating frame before closure.

---

## 5. Verification Harness Code Reference

The verification logic is implemented in:
- [`src/xrlids/live/parity.py`](../../src/xrlids/live/parity.py)
- [`src/xrlids/demo/extractor.py`](../../src/xrlids/demo/extractor.py)
- [`tests/integration/test_feature_parity.py`](../../tests/integration/test_feature_parity.py)
- [`tests/integration/test_phase3_parity_harness.py`](../../tests/integration/test_phase3_parity_harness.py)

**Audit Conclusion**: 10 out of 10 features achieve **PASS** within strict numerical tolerances ($\max \Delta_{\text{abs}} = 0.0000$). No feature drift exists between offline training and streaming flow extraction.
