# XRL-IDARS Web Console

A zero-dependency, lightweight web console with two views:

1. **Live Monitor** — observational live capture: packets → bidirectional flows (D-006) → frozen R10 features → frozen CIC-IDS2017 Random Forest detector. Streams per-flow records (endpoints, protocol, packet counts, threat scores, alerts).
2. **Replay & Evidence** — reproducible PCAP replay verification statistics, TreeSHAP feature attributions, and the generated research figures gallery.

---

## Quick Start (no root required)

```bash
python dashboard/server.py            # default port 8000
python dashboard/server.py 8080       # custom port
# Or: python scripts/demo/run_dashboard.py
```

Open `http://127.0.0.1:8000/` in your browser.

- **Live Monitor tab** → *Sample stream (no root)* → **Start Capture**: replays `data/demo/sample_traffic.pcap` at its original pacing (2× speed by default) through the exact live pipeline. This is sample traffic, clearly labeled as such — not your live network.
- **Attack Simulator panel** (inside the Live Monitor tab): injects calibrated synthetic attack scenarios on demand — see below.
- **Replay & Evidence tab**: static replay verification, TreeSHAP table, and research figures (including a *Run Replay Analysis* button that re-runs `scripts/demo/run_replay_demo.py`).

## Attack Simulator (simulation only)

The Live Monitor tab includes an **Attack Simulator** panel: choose a calibrated scenario, press
**Inject Attack**, and its packets are synthesised **in memory** and pushed through the exact
monitoring pipeline (FlowBuilder → frozen R10 features → frozen detector). Nothing is transmitted on
the network and no firewall/routing state is touched. Injected flows are tagged `SIM` in the flow
table and appear with the frozen model's real scores and alerts. Injection requires a running session;
at most one injection runs at a time.

### Calibrated scenario set

Every scenario ships with a **calibrated expectation** — the exact score the frozen detector produced
when the script was verified end-to-end (`scripts/demo/verify_attack_scenarios.py`, tolerance ±0.05):

| Scenario | Category | Packets | Duration | Flow(s) | Frozen score | Band |
|---|---|---|---|---|---|---|
| `slow_http_dos` | low-and-slow | 2 | 3.25 s | 1 | 0.9910 | HIGH |
| `slow_http_dos_lite` | low-and-slow | 2 | 3.27 s | 1 | 0.9163 | HIGH |
| `slowloris_session` | low-and-slow | 3 | 5.00 s | 1 | 0.7667 | ALERT |
| `low_rate_drip` | low-and-slow | 3 | 8.00 s | 1 | 0.5476 | ALERT |
| `syn_flood` | flood (evasion demo) | 201 | 1.00 s | 1 | 0.0002 | NOT DETECTED |
| `http_flood` | flood (evasion demo) | 301 | 1.50 s | 1 | 0.0290 | NOT DETECTED |
| `port_sweep` | scan (evasion demo) | 80 | 1.96 s | 40 | 0.0169 | NOT DETECTED |

### Why the evasion demos exist (documented limitation)

Probing the frozen detector across the physically realisable packet-script space (2–400 packets,
54–1500-byte lengths, 0.1 ms–8 s durations, flag mixes) shows that its high-confidence region for
clean synthetic traffic is the **low-and-slow family** (2–4 packets, 3–8 s, small equal-size
payloads). Classic fast patterns (SYN/HTTP floods, port sweeps) score near zero with this model: its
learned flood/scan regions rely on CIC FlowMeter artefacts — e.g. `packet_length_std` values above
the physical 1500-byte limit and flows of thousands of packets — that a clean synthetic capture
cannot reproduce. Those scenarios ship deliberately as *NOT DETECTED (evasion demo)* entries, so the
console shows the model's real behaviour rather than a staged detection. The same effect explains why
the bundled sample capture's attack flows score borderline (0.37–0.52) in Replay & Evidence.

### Verifying the calibration

```bash
.venv/bin/python scripts/demo/verify_attack_scenarios.py
```

Re-runs every scenario through `FlowBuilder → frozen R10 → frozen RF
(EXP-P1-CIC2017-R10-001)` and checks completed-flow counts, packet counts, recorded scores (±0.05),
and band consistency (`HIGH ≥ 0.85`, `ALERT ≥ 0.50`, `NONE < 0.50`).

### Pacing

Injections run at **1× speed**: the calibrated scores depend on each flow's time shape
(`flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`), so pacing is not rescaled in
production. Inter-packet deltas are preserved by wall-clock restamping at emission.

## Live Interface Capture (requires root)

Raw socket capture (AF_PACKET) requires `CAP_NET_RAW` / root:

```bash
sudo .venv/bin/python dashboard/server.py --live --iface wlo1
# Optional capture filter:
sudo .venv/bin/python dashboard/server.py --live --iface wlo1 --bpf "tcp port 443"
```

Or launch the server with `sudo` (no `--live`) and press **Start Capture** in the UI with mode *Live interface (requires root)* and an interface name (e.g. `wlo1`, listed via autocomplete).

**Safety invariants**

- **Strictly observational:** never injects, modifies, drops, or reroutes traffic; no firewall/iptables/routing mutations, ever.
- **No accuracy claims on live traffic:** real networks have no ground truth; the Live Monitor shows flows, alerts, and model scores only.
- **Scores use the frozen research threshold** $\tau = 0.50$ (D-003). The "Suggested Action" column is the DQN response-policy mapping for display only — the console never actuates.
- **Flow completion** follows the canonical D-006 policy: TCP FIN/RST or 120 s idle timeout (pending flows are flushed when the session stops).
- **Local only:** the server binds to `127.0.0.1`.

---

## File Structure

```text
dashboard/
├── app.js        # Vanilla JavaScript client logic (live polling + evidence view)
├── index.html    # Single-page console markup and embedded styles
├── README.md     # This documentation and operational guide
└── server.py     # Python HTTP/REST server: static assets, live session, APIs
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves `index.html` |
| `GET` | `/app.js` | Serves JavaScript application logic |
| `GET` | `/api/data` | Replay summary, SHAP importances, and figure listing (evidence view) |
| `POST` | `/api/run-replay` | Runs `scripts/demo/run_replay_demo.py` and returns the refreshed summary |
| `GET` | `/api/live` | Live session snapshot: status, counters, recent flows, recent alerts |
| `POST` | `/api/live/start` | Starts a session — JSON body: `{"mode": "sample"\|"live", "interface": "wlo1", "bpf_filter": "tcp port 443", "pcap": null, "pace_speed": 2.0, "loop": true, "max_packets": null}` |
| `POST` | `/api/live/stop` | Stops the session (flushes pending flows) and returns the final snapshot |
| `GET` | `/api/live/interfaces` | Available interface names + raw-socket permission status |
| `GET` | `/api/live/scenarios` | Calibrated attack-simulator scenario catalogue (metadata + expected scores/bands) |
| `POST` | `/api/live/inject-attack` | Injects a scenario into the live pipeline — JSON body: `{"scenario": "slow_http_dos"}` (simulation only; requires a running session) |
| `GET` | `/figures/{name}` | Serves generated research figures (`.png`) |

---

## Pipeline Components Reused (frozen, tested)

| Stage | Component | Source |
|---|---|---|
| Packet capture (live socket / PCAP / synthetic) | `PacketCaptureService` | `src/xrlids/live/capture.py` (Phase 3A) |
| Flow construction (canonical 5-tuple, D-006) | `FlowBuilder` | `src/xrlids/demo/flow.py` |
| R10 feature extraction | `flows_to_dataframe` | `src/xrlids/demo/extractor.py` |
| Detector + thresholds | `ReplayEngine` (frozen CIC RF, $\tau=0.50$) | `src/xrlids/demo/replay.py` |
| Observational flow/alert recording | `LiveLabMonitor` | `src/xrlids/demo/live_lab.py` |
| Attack scenario synthesis (simulation only) | `build_scenario_packets` | `src/xrlids/demo/attack_sim.py` (calibrated; verified by `scripts/demo/verify_attack_scenarios.py`) |

No new inference logic is introduced by the console; it is a display and orchestration layer over the frozen pipeline. Timestamps in Sample stream mode are restamped to wall-clock time, so timing-derived feature values (and therefore scores) may differ marginally from the frozen replay artifacts — expected for real-time operation.
