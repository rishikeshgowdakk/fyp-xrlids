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
- **Replay & Evidence tab**: static replay verification, TreeSHAP table, and research figures (including a *Run Replay Analysis* button that re-runs `scripts/demo/run_replay_demo.py`).

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

No new inference logic is introduced by the console; it is a display and orchestration layer over the frozen pipeline. Timestamps in Sample stream mode are restamped to wall-clock time, so timing-derived feature values (and therefore scores) may differ marginally from the frozen replay artifacts — expected for real-time operation.
