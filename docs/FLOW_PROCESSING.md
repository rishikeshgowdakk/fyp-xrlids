# XRL-IDARS — Canonical Flow Processing Specification

**Decision Reference:** `D-006` (Bidirectional Flow Aggregation & Completion Policy)  
**Implementation:** `src/xrlids/flow/canonical_builder.py` (`CanonicalFlowBuilder`, `CanonicalFlow`, `CanonicalFlowKey`)

---

## 1. Flow Identification & Canonical 5-Tuple

In IP networks, packets between two communicating nodes travel in both directions (client $\to$ server and server $\to$ client). A network flow is formally defined as an aggregation of packets sharing a bidirectional 5-tuple:

$$\mathbf{k} = \left(\min(\text{IP}_A, \text{IP}_B), \max(\text{IP}_A, \text{IP}_B), \min(\text{Port}_A, \text{Port}_B), \max(\text{Port}_A, \text{Port}_B), \text{Protocol}\right)$$

In `CanonicalFlowKey.from_endpoints(src_ip, dst_ip, src_port, dst_port, protocol)`:
- If `(src_ip, src_port) <= (dst_ip, dst_port)`:
  - `endpoint_a = src_ip`, `port_a = src_port`
  - `endpoint_b = dst_ip`, `port_b = dst_port`
  - `is_forward = True`
- Else:
  - `endpoint_a = dst_ip`, `port_a = dst_port`
  - `endpoint_b = src_ip`, `port_b = src_port`
  - `is_forward = False`

This ensures that regardless of which side transmits a packet, all packets in the session map to the identical `CanonicalFlow` state accumulator.

---

## 2. Flow Completion Policy (Decision D-006)

A network flow cannot be classified mid-stream with standard flow-moment classifiers because summary statistics (packet rates, byte volume, duration) require completion.

Under **Decision D-006**, a flow terminates and is emitted for detection under two deterministic conditions:

1. **TCP Explicit Termination (`FIN` / `RST`):**
   - The arrival of a TCP packet with `FIN` (Graceful Close) or `RST` (Abrupt Reset) flag set closes the flow immediately.
   - The flow is marked `is_closed = True` and yielded to downstream inference.
2. **Idle Inactivity Timeout ($120.0\text{ seconds}$):**
   - If no packet is received for a flow for $> 120.0\text{ seconds}$ relative to the reference clock:
     - Replay mode: Evaluated using packet arrival timestamps.
     - Live capture mode: Evaluated using monotonic wall-clock time (`time.monotonic()`).
   - Timed-out flows are marked with `closed_reason = "TIMEOUT"` and yielded for classification.
3. **Session Flush:**
   - At the end of a PCAP file or during system shutdown, `flush_all()` yields all remaining active flows marked `closed_reason = "FLUSH"`.

---

## 3. $R_{10}$ Feature Mathematics & Exact Definitions

When a flow closes, `CanonicalFlow.to_features()` computes the canonical 10-feature vector ($R_{10}$):

| Index | Feature Name | Formula / Definition | Unit |
|---|---|---|---|
| 0 | `flow_duration_ms` | $(t_{\text{last}} - t_{\text{start}}) \times 1000.0$ | Milliseconds |
| 1 | `flow_packets_per_s` | $\frac{N_{\text{packets}}}{\max(t_{\text{last}} - t_{\text{start}}, 10^{-6})}$ | Packets / sec |
| 2 | `flow_bytes_per_s` | $\frac{\sum_{i=1}^N \text{len}_i}{\max(t_{\text{last}} - t_{\text{start}}, 10^{-6})}$ | Bytes / sec |
| 3 | `packet_length_mean` | $\mu_L = \frac{1}{N}\sum_{i=1}^N \text{len}_i$ | Bytes |
| 4 | `packet_length_std` | $\sigma_L = \sqrt{\frac{1}{N}\sum_{i=1}^N (\text{len}_i - \mu_L)^2}$ | Bytes |
| 5 | `syn_count` | $\sum \mathbb{I}(\text{SYN} = 1)$ | Count |
| 6 | `ack_count` | $\sum \mathbb{I}(\text{ACK} = 1)$ | Count |
| 7 | `rst_count` | $\sum \mathbb{I}(\text{RST} = 1)$ | Count |
| 8 | `fin_count` | $\sum \mathbb{I}(\text{FIN} = 1)$ | Count |
| 9 | `syn_ack_ratio` | $\frac{\text{syn\_count}}{\max(\text{ack\_count}, 1.0)}$ | Ratio |

### Anomaly Flag Tracking

In addition to the statistical features, `CanonicalFlow` tracks behavioral TCP anomalies for the Rule Engine:
- `has_syn_fin`: Packets with both SYN and FIN set (illegal combination used in stealth port scanning).
- `has_syn_rst`: Packets with both SYN and RST set.
- `has_xmas_flags`: Packets with FIN, PSH, and URG set ("Christmas tree" scan).
- `has_null_flags`: TCP packets with zero flags set (Null scan).

---

## 4. Feature Contract Gate & Validation

All generated feature dictionaries are passed through `FeatureSchemaValidator.validate_r10()`:
- Rejects missing keys.
- Rejects `NaN`, `+inf`, `-inf` without silent zero-fills.
- Ensures strict canonical column ordering before model inference.
