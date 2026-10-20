# The "1000 packets from one click" case

Status: **executed in `LiveMode.DRY_RUN`** as `EXP-P3-BURST-1000-001`
(`REPORT-P3E-BURST-1000-001`). Full evidence: `docs/phase3/PHASE3E_BURST_REPORT.md`.

## The professor's question

> If a user clicks once and 1000 packets go out, does the system call that an attack?

## Short answer

**Packet count ≠ maliciousness.** A legitimate browser interaction can produce a burst of many
packets. XRL-IDARS classifies **flow behaviour** using the frozen R10 features, not raw packet count.
A burst is only escalated if the flow-level detector score crosses the frozen threshold.

## What was measured

| Signal | Result |
|:---|:---|
| Total packets | 1,000 (800 benign + 200 controlled attack) |
| Completed flows evaluated | 270 |
| Capture-path packet drops | 0 |
| Malformed frames | 0 |
| Audit cards generated | 270 / 270 (100%) |
| Firewall / routing / socket mutations | 0 |
| Detector inference latency (RF) | median 47.6 ms/flow |
| End-to-end flow latency | median 50.0 ms/flow |
| Effective throughput | 73.3 packets/s · 19.8 flows/s |
| Proposed actions | ALLOW 42 · ALERT 228 · RATE_LIMIT 0 · ISOLATE 0 |
| Enforced actions | same as proposed (DRY_RUN; no actuation) |
| Safety overrides / failures | 0 |

The experiment demonstrates that the full stream → flow → R10 features → frozen RF → DQN policy →
safety gate path executes end-to-end without breaks, and that no network state is mutated.

## What this does **not** prove

- It is **not** a live-network accuracy result; the burst is synthetic and ground truth is known by
  construction.
- It does **not** prove kernel/interface packet-drop behavior or line-rate performance.
- It does **not** prove that every benign 1,000-packet burst is classified as benign. It shows the
  pipeline behaviour on the pre-registered synthetic mix; a separate benign-only burst case would
  be needed to quantify false-positive behaviour.
- The single-threaded CPU throughput (73.3 pkt/s) is sufficient for the lab demonstration, not for
  production multi-gigabit deployment.

## Why it matters for the viva

The experiment directly answers the "one click = 1000 packets" challenge: volume alone is not the
decision variable, and the system is observational in `DRY_RUN`. The measured latency bottleneck is
the unbatched Random Forest inference, not the safety gate or flow builder.

## Reproduction

```bash
.venv/bin/python scripts/phase3/run_burst_experiment.py
```

Artifacts: `results/phase3/EXP-P3-BURST-1000-001/` (including `run_summary.json`).
