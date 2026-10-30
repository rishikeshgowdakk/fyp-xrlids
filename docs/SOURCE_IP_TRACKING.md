# XRL-IDARS — Source-IP Activity Tracker Specification

**Module:** `src/xrlids/tracking/source_tracker.py` (`SourceActivityTracker`)

---

## 1. Architectural Purpose

Per-flow intrusion detection models evaluate flows in temporal isolation. However, sophisticated attackers distribute attacks across multiple separate connections (e.g. slow port scans, multi-flow DoS bursts, credential brute-forcing).

The **Source-IP Activity Tracker** maintains rolling state across all incoming traffic per source IP, providing:
1. Multi-flow threat accumulation and context.
2. Escalation triggers when a host crosses defined threat thresholds.
3. Cooldown suppression to prevent alert flooding.
4. Per-host temporal feature sequence buffering for historical analysis.
5. Strict memory bounds via Least Recently Used (LRU) host eviction.

---

## 2. Sliding Window & Escalation Semantics

- **Time-Window Duration ($W$):** $60.0\text{ seconds}$ by default.
  - Flows older than $60\text{ s}$ relative to the current flow timestamp expire and are pruned from the window.
- **Escalation Threshold ($N_{\text{thresh}}$):** $5\text{ suspicious flows}$ within the active window $W$.
  - A flow is counted as suspicious if its threat score $S_t \ge 0.50$ or it triggers a deterministic rule match.
- **Escalation State:**
  - When $N_{\text{suspicious}} \ge N_{\text{thresh}}$, the tracker triggers an **Escalation** event:
    `escalate = True`, `escalation_reason = "THRESHOLD_EXCEEDED"`.
- **Cooldown Suppression Period ($C$):** $30.0\text{ seconds}$.
  - After an escalation event is emitted for a source IP, the host enters a 30s cooldown.
  - Subsquent suspicious flows during the cooldown period do not re-trigger redundant high-priority escalations (`cooldown_active = True`).
  - Once the cooldown expires, the host can re-escalate if suspicious behavior persists.

---

## 3. Sequence Buffering & LRU Memory Bounding

- **Per-Host Sequence Buffer:**
  - Maintains a sliding FIFO queue of the last $T=5$ feature vectors for each host.
  - Provides temporal context for offline or escalated multi-flow analysis.
- **LRU Memory Protection:**
  - Active hosts are bounded at `max_hosts = 10,000` (configurable).
  - When capacity is reached, the least recently seen host record is evicted.
