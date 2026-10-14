# XRL-IDARS Web Monitoring Dashboard

A zero-dependency, lightweight web dashboard for visualizing real-time packet-to-prediction replay metrics, TreeSHAP feature attributions, and research evaluation figures.

---

## Features

- **Live Flow & Threat Metrics:** Real-time display of total packets, flows, research F1/accuracy ($\tau = 0.50$), and operational F1/accuracy ($\tau = 0.85$).
- **Explainability (TreeSHAP):** Global feature importance ranking with human-readable domain explanations (e.g., TCP flag ratios, packet length variance, flow rates).
- **Research Artifacts:** Embedded visualization gallery for confusion matrices, baseline ladders, transfer heatmaps, and DQN learning curves.
- **Zero-Dependency Architecture:** Pure vanilla HTML5 / ES6 JavaScript frontend and Python standard library `http.server` backend (no npm, no node_modules, no external bundlers).

---

## Quick Start

### 1. Launch the Server

Run using the Python virtual environment:

```bash
python dashboard/server.py
```

Or via the demo scripts runner:

```bash
python scripts/demo/run_dashboard.py
```

Custom port (default `8000`):

```bash
python dashboard/server.py 8080
```

### 2. Access the Dashboard

Open your web browser at:
```text
http://127.0.0.1:8000/
```

---

## File Structure

```text
dashboard/
├── app.js        # Vanilla JavaScript client logic and state management
├── index.html    # Single-page dashboard markup and embedded styles
├── README.md     # Dashboard documentation and operational guide
└── server.py     # Python HTTP/REST server serving static assets and API data
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves `index.html` |
| `GET` | `/app.js` | Serves JavaScript application logic |
| `GET` | `/api/data` | Returns JSON summary of replay results, SHAP importances, and figure listings |
| `GET` | `/api/replay` | Triggers replay verification (`scripts/demo/run_replay_demo.py`) and returns updated summary |
| `GET` | `/reports/figures/{name}` | Serves static generated research figures (`.png`) |
