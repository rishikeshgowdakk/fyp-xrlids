#!/usr/bin/env python3
"""Automated Chrome DevTools Protocol (CDP) Screenshot Capture for XRL-IDARS.

Captures pixel-perfect screenshots of all 11 required operational dashboard pages
running against the genuine Streamlit application.
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
import sys
import time
import urllib.request
import websockets

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "results" / "acceptance" / "screenshots"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PAGES = [
    {
        "filename": "01_overview.png",
        "url": "http://localhost:8501/Overview",
        "name": "Overview & Architecture",
        "desc": "System architecture, 4-tier pipeline overview, latency budget matrix, and subsystem operational statuses.",
    },
    {
        "filename": "02_live_monitor_blocked.png",
        "url": "http://localhost:8501/Live_Monitor",
        "name": "Live Monitor (Permission Blocked Mode)",
        "desc": "Live monitoring telemetry, unprivileged capture status (CAP_NET_RAW / root required), and rolling security event stream.",
    },
    {
        "filename": "03_pcap_replay_active.png",
        "url": "http://localhost:8501/Packet_Flow_Ingestion?mode=pcap",
        "name": "PCAP Replay Ingestion",
        "desc": "Authentic packet trace streaming from sample_traffic.pcap through canonical 5-tuple flow engine and R10 feature extraction table.",
    },
    {
        "filename": "04_sample_evaluation.png",
        "url": "http://localhost:8501/Packet_Flow_Ingestion?mode=sample",
        "name": "Sample Attack Generation Evaluation",
        "desc": "Isolated lab attack simulator generation, TCP SYN burst synthesis, and feature extraction preview.",
    },
    {
        "filename": "05_detection_events.png",
        "url": "http://localhost:8501/Detection_Events",
        "name": "Detection & Security Events",
        "desc": "Unified security event log showing timestamps, flow IDs, Random Forest scores, rule violations, severity, and response actions.",
    },
    {
        "filename": "06_treeshap_explainability.png",
        "url": "http://localhost:8501/Explainability",
        "name": "TreeSHAP Local Explainability",
        "desc": "Exact local TreeSHAP waterfall attributions, base value equation, and feature importance table for Random Forest detections.",
    },
    {
        "filename": "07_dqn_response_policy.png",
        "url": "http://localhost:8501/DQN_Response_Policy",
        "name": "DQN Autonomous Response Policy",
        "desc": "Real event-linked response decisions, 6-dimensional causal state space, action Q-values across 4 discrete tiers, and advisory mode badge.",
    },
    {
        "filename": "08_safety_execution_audit.png",
        "url": "http://localhost:8501/Safety_Execution_Audit",
        "name": "Deterministic Safety & Execution Audit",
        "desc": "Safety gate invariants: critical host allowlists (gateway/DNS), 30s rate-limit cooldown, 5% blast-radius circuit breaker, and zero kernel mutations audit.",
    },
    {
        "filename": "09_model_evaluation.png",
        "url": "http://localhost:8501/Model_Evaluation",
        "name": "Empirical Model Evaluation",
        "desc": "Held-out test set performance for Random Forest detector on CSE-CIC-IDS2017 & 2018, multi-class confusion matrix, and attack family breakdown.",
    },
    {
        "filename": "10_research_benchmarks.png",
        "url": "http://localhost:8501/Research_Benchmarks",
        "name": "Offline Research Benchmarks",
        "desc": "Independent offline research track showing pretrained LSTM FlowSeq, RF-LSTM convex fusion, head-to-head comparison, and strict offline disclaimer.",
    },
    {
        "filename": "11_system_health.png",
        "url": "http://localhost:8501/System_Health",
        "name": "System Health & Integrity",
        "desc": "Model artifact SHA-256 integrity check table, OS environment diagnostics, CAP_NET_RAW capability check, and zero kernel mutation verification.",
    },
]


async def capture_page(target_info: dict, out_file: Path) -> int:
    ws_url = target_info["webSocketDebuggerUrl"]
    async with websockets.connect(ws_url, max_size=50_000_000) as ws:
        # Set viewport size
        await ws.send(json.dumps({
            "id": 1,
            "method": "Emulation.setDeviceMetricsOverride",
            "params": {
                "width": 1440,
                "height": 960,
                "deviceScaleFactor": 1,
                "mobile": False,
            }
        }))
        await ws.recv()

        # Wait for Streamlit React rendering and websocket data to complete
        await asyncio.sleep(4.0)

        # Capture screenshot
        await ws.send(json.dumps({
            "id": 2,
            "method": "Page.captureScreenshot",
            "params": {
                "format": "png",
                "captureBeyondViewport": True,
            }
        }))

        while True:
            raw = await ws.recv()
            resp = json.loads(raw)
            if resp.get("id") == 2:
                png_bytes = base64.b64decode(resp["result"]["data"])
                with open(out_file, "wb") as f:
                    f.write(png_bytes)
                return len(png_bytes)


def main() -> int:
    print("=" * 76)
    print("  XRL-IDARS — Automated Browser Screenshot Capture Suite (CDP)")
    print("=" * 76)

    success_count = 0
    results_summary = []

    for item in PAGES:
        filename = item["filename"]
        url = item["url"]
        name = item["name"]
        out_path = OUTPUT_DIR / filename

        print(f"\n[Capturing] {name}")
        print(f"  URL:  {url}")
        print(f"  File: {out_path.name}")

        try:
            req = urllib.request.Request(f"http://localhost:9222/json/new?{url}", method="PUT")
            with urllib.request.urlopen(req) as r:
                target = json.loads(r.read().decode())

            tid = target["id"]
            size_bytes = asyncio.run(capture_page(target, out_path))

            # Close tab
            close_req = urllib.request.Request(f"http://localhost:9222/json/close/{tid}", method="PUT")
            try:
                urllib.request.urlopen(close_req)
            except Exception:
                pass

            print(f"  ✓ Saved: {size_bytes:,} bytes")
            success_count += 1
            results_summary.append({
                "page": name,
                "filename": filename,
                "size_bytes": size_bytes,
                "status": "PASS",
                "desc": item["desc"],
            })

        except Exception as exc:
            print(f"  ✗ Capture Failed: {exc}")
            results_summary.append({
                "page": name,
                "filename": filename,
                "size_bytes": 0,
                "status": "FAIL",
                "desc": str(exc),
            })

    print("\n" + "=" * 76)
    print(f"  Screenshot Capture Completed: {success_count} / {len(PAGES)} successful.")
    print("=" * 76)

    return 0 if success_count == len(PAGES) else 1


if __name__ == "__main__":
    sys.exit(main())
