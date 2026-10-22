#!/usr/bin/env python3
"""Minimalist HTTP server for the XRL-IDARS dashboard.

Two views, zero external dependencies (Python standard library only):

1. Live Monitor — streams packets through the observational Phase 3 pipeline
   (PacketCaptureService -> FlowBuilder (D-006) -> frozen R10 detector) and
   serves rolling per-flow observations and alerts to the browser. Includes an
   attack simulator that injects calibrated synthetic packet scripts into the
   same pipeline (in memory only; nothing is ever transmitted).
2. Replay & Evidence — replay statistics, TreeSHAP attributions, and figures.

Safety invariants:
- Observational only: never injects, drops, or reroutes traffic (no firewall,
  iptables, or routing mutations of any kind).
- Binds to 127.0.0.1 only.
- Live interface capture requires root / CAP_NET_RAW. Without it, the Sample
  stream mode replays the bundled demo capture at its original pacing through
  the exact same pipeline (clearly labeled as sample traffic in the UI).
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, replace
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Generator
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.demo.attack_sim import build_scenario_packets, get_scenario, list_scenarios  # noqa: E402
from xrlids.demo.live_lab import AlertEvent, FlowObservation, LiveLabMonitor  # noqa: E402
from xrlids.demo.pcap import PacketInfo, PcapReader  # noqa: E402
from xrlids.demo.replay import ReplayEngine  # noqa: E402
from xrlids.live.capture import CaptureConfig, PacketCaptureService  # noqa: E402
from xrlids.live.devices import DeviceTracker  # noqa: E402

DASHBOARD_DIR = REPO_ROOT / "dashboard"
FIGURES_DIR = REPO_ROOT / "reports" / "figures"
REPLAY_SUMMARY = REPO_ROOT / "results" / "demo" / "replay_summary.json"
SHAP_SUMMARY = REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "shap_summary.json"
MULTI_SEED_METRICS = (
    REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "multi_seed_metrics.json"
)
BOOTSTRAP_CIS = (
    REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "bootstrap_cis.json"
)
SAMPLE_PCAP = REPO_ROOT / "data" / "demo" / "sample_traffic.pcap"
DEFAULT_MODEL_DIR = REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001"
RESEARCH_THRESHOLD = 0.50
OPERATIONAL_CANDIDATE_THRESHOLD = 0.40

# Sentinel pushed by the capture producer when the capture source is exhausted.
_CAPTURE_DONE = object()


def get_dashboard_data() -> dict:
    """Collect replay summary, SHAP data, and figure list."""
    data: dict = {
        "status": "ready",
        "replay": None,
        "shap": None,
        "model_comparison": None,
        "figures": [],
    }

    if REPLAY_SUMMARY.exists():
        try:
            with open(REPLAY_SUMMARY, "r", encoding="utf-8") as f:
                data["replay"] = json.load(f)
        except Exception as e:
            data["replay_error"] = str(e)

    if SHAP_SUMMARY.exists():
        try:
            with open(SHAP_SUMMARY, "r", encoding="utf-8") as f:
                shap_raw = json.load(f)
                data["shap"] = {
                    "methodology": shap_raw.get("methodology", "TreeSHAP"),
                    "global_importance": shap_raw.get("global_importance", [])[:10],
                }
        except Exception as e:
            data["shap_error"] = str(e)

    if MULTI_SEED_METRICS.exists():
        try:
            with open(MULTI_SEED_METRICS, "r", encoding="utf-8") as f:
                raw = json.load(f)
            summary = raw.get("summary", {})
            models: dict = {}
            for name in ("random_forest", "lstm", "fusion"):
                if name not in summary:
                    continue
                models[name] = {}
                for metric in ("accuracy", "f1", "roc_auc"):
                    entry = summary[name].get(metric)
                    if isinstance(entry, dict) and "mean" in entry:
                        models[name][metric] = {
                            "mean": entry["mean"],
                            "std": entry.get("std", 0.0),
                        }
            data["model_comparison"] = {
                "seeds": raw.get("seeds", []),
                "models": models,
                "source": str(MULTI_SEED_METRICS.relative_to(REPO_ROOT)),
            }

            # Attach bootstrap CIs from the frozen seed-42 predictions. The
            # mean ± std above is across seeds; the CI below is test-set
            # sampling uncertainty for the frozen reference run.
            if BOOTSTRAP_CIS.exists():
                try:
                    with open(BOOTSTRAP_CIS, "r", encoding="utf-8") as f:
                        ci_raw = json.load(f)
                    ci_seeds = ci_raw.get("seeds", {})
                    seed_payload = ci_seeds.get("42") or ci_seeds.get("frozen") or {}
                    seed_models = seed_payload.get("models", {})
                    for name in models:
                        model_ci = seed_models.get(name, {})
                        threshold_metrics = model_ci.get("threshold_metrics", {})
                        for metric in ("accuracy", "f1"):
                            entry = threshold_metrics.get(metric)
                            if entry and metric in models[name]:
                                models[name][metric]["ci"] = {
                                    "point": entry.get("point_estimate"),
                                    "lower": entry.get("ci_lower"),
                                    "upper": entry.get("ci_upper"),
                                }
                        auc_entry = model_ci.get("roc_auc")
                        if auc_entry and "roc_auc" in models[name]:
                            models[name]["roc_auc"]["ci"] = {
                                "point": auc_entry.get("point_estimate"),
                                "lower": auc_entry.get("ci_lower"),
                                "upper": auc_entry.get("ci_upper"),
                            }
                    data["model_comparison"]["ci_source"] = str(
                        BOOTSTRAP_CIS.relative_to(REPO_ROOT)
                    )
                    data["model_comparison"]["ci_note"] = (
                        "95% bootstrap CI for the frozen seed-42 test predictions"
                    )
                except Exception as e:  # pragma: no cover - defensive
                    data["model_comparison"]["ci_error"] = str(e)
        except Exception as e:
            data["model_comparison_error"] = str(e)

    if FIGURES_DIR.exists():
        data["figures"] = sorted([p.name for p in FIGURES_DIR.glob("*.png")])

    return data


def available_interfaces() -> list[str]:
    """List local network interface names (listing does not require root)."""
    try:
        return [name for _, name in socket.if_nameindex()]
    except (OSError, AttributeError):  # pragma: no cover - non-Linux fallback
        return []


def _ensure_sample_pcap(pcap_path: Path) -> Path:
    """Return the sample PCAP path, generating the bundled synthetic capture if missing."""
    if pcap_path.exists():
        return pcap_path
    try:
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        from scripts.demo.run_replay_demo import generate_synthetic_demo_pcap

        generate_synthetic_demo_pcap(pcap_path)
    except Exception as exc:  # pragma: no cover - defensive
        raise FileNotFoundError(
            f"Sample PCAP not found at {pcap_path} and could not be generated ({exc}). "
            "Run `python scripts/demo/run_replay_demo.py` once, or pass an explicit pcap path."
        ) from exc
    return pcap_path


class LiveSession:
    """Background observational evaluation session for the Live Monitor view.

    Reuses the canonical frozen components: PacketCaptureService (live socket,
    PCAP, or synthetic source), FlowBuilder (D-006 completion policy), the
    frozen R10 feature extraction, and the frozen CIC-IDS2017 Random Forest
    detector via ReplayEngine/LiveLabMonitor.

    This class never mutates the network; it only observes and records.
    """

    def __init__(self, engine: ReplayEngine | None = None, model_dir: str | Path | None = None) -> None:
        self.model_dir = Path(model_dir) if model_dir else DEFAULT_MODEL_DIR
        self._engine = engine
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._capture: PacketCaptureService | None = None
        self._packet_queue: "queue.Queue[Any] | None" = None
        self._injection_thread: threading.Thread | None = None
        self._device_tracker: DeviceTracker | None = None

        self.status = "stopped"  # stopped | running | error
        self.mode: str | None = None
        self.interface: str | None = None
        self.bpf_filter: str | None = None
        self.pcap: str | None = None
        self.started_at: str | None = None
        self.error: str | None = None
        self.engine_warning: str | None = None

        self.packets = 0
        self.total_bytes = 0
        self.flow_count = 0
        self.alert_count = 0
        self._t0: float | None = None
        self._t_end: float | None = None

        self.flows: deque[dict[str, Any]] = deque(maxlen=1000)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=200)
        self.injection: dict[str, Any] | None = None

    # ------------------------------------------------------------- engine
    def _get_engine(self) -> ReplayEngine:
        if self._engine is not None:
            return self._engine
        if self.model_dir.exists():
            try:
                self._engine = ReplayEngine(model_path=self.model_dir)
                return self._engine
            except Exception as exc:  # pragma: no cover - defensive
                self.engine_warning = f"Frozen model could not be loaded ({exc}); using heuristic fallback."
        else:
            self.engine_warning = (
                f"Frozen model directory not found ({self.model_dir}); using heuristic fallback."
            )
        self._engine = ReplayEngine(model=None)
        return self._engine

    # ------------------------------------------------------------- control
    def start(
        self,
        mode: str = "sample",
        interface: str | None = None,
        bpf_filter: str | None = None,
        pcap: str | None = None,
        pace_speed: float = 2.0,
        loop: bool = True,
        max_packets: int | None = None,
    ) -> dict[str, Any]:
        """Start an observational capture session; return the initial snapshot or an error dict."""
        with self._lock:
            if self.status == "running":
                return {"error": "A session is already running. Stop it first."}
            if mode == "live":
                if not interface:
                    return {"error": "Live mode requires an interface name (e.g. wlo1)."}
                if not PacketCaptureService.check_permissions():
                    return {
                        "error": (
                            "Live capture requires root / CAP_NET_RAW. Restart the dashboard with sudo, e.g. "
                            "`sudo .venv/bin/python dashboard/server.py` — or use the Sample stream mode (no root)."
                        )
                    }
            elif mode != "sample":
                return {"error": f"Unknown mode {mode!r} (expected 'sample' or 'live')."}

            self._reset_locked()
            if mode == "live" and interface:
                # Passive device discovery is created only for live capture.
                # It reads the local neighbour cache/iw link once and then
                # consumes raw frames through the capture callback.
                self._device_tracker = DeviceTracker.from_system(interface)
            self.status = "running"
            self.mode = mode
            self.interface = interface if mode == "live" else None
            self.bpf_filter = bpf_filter or None
            self.pcap = str(pcap) if pcap else (str(SAMPLE_PCAP) if mode == "sample" else None)
            self.started_at = datetime.now(timezone.utc).isoformat()
            self._t0 = time.time()
            self._stop_event.clear()

            # The merge queue exists for the whole session so injections can start immediately.
            packet_queue: "queue.Queue[Any]" = queue.Queue()
            self._packet_queue = packet_queue
            self._thread = threading.Thread(
                target=self._run,
                args=(mode, interface, bpf_filter, pcap, pace_speed, loop, max_packets, packet_queue),
                name="xrlids-live-session",
                daemon=True,
            )
            self._thread.start()
            return self.snapshot()

    def stop(self) -> dict[str, Any]:
        """Signal the running session to stop, wait briefly for flush, and return the final snapshot."""
        with self._lock:
            thread = self._thread
            if self.status == "running":
                self._stop_event.set()
                if self._capture is not None:
                    self._capture.stop()
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)
        return self.snapshot()

    # ------------------------------------------------------ attack simulator
    def inject_scenario(self, scenario_id: str, speed: float = 1.0) -> dict[str, Any]:
        """Inject a calibrated attack-simulation scenario into the live pipeline.

        Simulation only: packets are synthesised in memory by
        :mod:`xrlids.demo.attack_sim` and pushed through the same observational
        pipeline as captured traffic. Nothing is transmitted on the network.

        ``speed`` is a test aid (compresses inter-packet pacing); production
        injections run at 1x because the calibrated scores are time-shape dependent.
        """
        with self._lock:
            if self.status != "running" or self._packet_queue is None:
                return {"error": "No running session — start the monitor before injecting an attack scenario."}
            if self.injection is not None and self.injection.get("active"):
                active = self.injection.get("scenario")
                return {"error": f"Injection {active!r} is still running; wait for it to finish."}
            spec = get_scenario(scenario_id)
            if spec is None:
                return {"error": f"Unknown scenario {scenario_id!r}. See GET /api/live/scenarios."}

            packets = build_scenario_packets(spec)
            self.injection = {
                "active": True,
                "scenario": spec.id,
                "name": spec.name,
                "category": spec.category,
                "packets_total": len(packets),
                "packets_sent": 0,
                "duration_s": round(spec.duration_s, 3),
                "expected_score": spec.expected_score,
                "expected_band": spec.expected_band,
                "expected_flows": spec.expected_flows,
                "speed": speed,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": None,
            }
            thread = threading.Thread(
                target=self._injection_worker,
                args=(packets, max(speed, 1e-9), self._packet_queue),
                name="xrlids-attack-injection",
                daemon=True,
            )
            self._injection_thread = thread
            thread.start()
            return {"status": "injecting", "injection": dict(self.injection)}

    def device_snapshot(self) -> dict[str, Any]:
        """Return the passive device-discovery view (empty outside live mode)."""
        with self._lock:
            tracker = self._device_tracker
        if tracker is None:
            return {
                "scope": "passive-observed",
                "network": None,
                "devices": [],
                "counters": {"total": 0, "seen": 0, "cached": 0},
                "note": (
                    "Passive observation only. Device discovery is available in live capture "
                    "mode; sample/simulator traffic is synthetic. No probes or scans are sent."
                ),
            }
        return tracker.snapshot()

    def snapshot(self) -> dict[str, Any]:
        """Return a consistent view of the session for the API/UI."""
        with self._lock:
            elapsed = 0.0
            if self._t0 is not None:
                end = self._t_end if self._t_end is not None else time.time()
                elapsed = max(0.0, end - self._t0)
            pps = (self.packets / elapsed) if elapsed > 0 else 0.0
            device_data = self.device_snapshot()
            return {
                "status": self.status,
                "mode": self.mode,
                "interface": self.interface,
                "bpf_filter": self.bpf_filter,
                "pcap": self.pcap,
                "started_at": self.started_at,
                "error": self.error,
                "engine_warning": self.engine_warning,
                "permissions": {"raw_socket": PacketCaptureService.check_permissions()},
                "thresholds": {
                    "research": RESEARCH_THRESHOLD,
                    "operational_candidate": OPERATIONAL_CANDIDATE_THRESHOLD,
                },
                "counters": {
                    "packets": self.packets,
                    "bytes": self.total_bytes,
                    "flows": self.flow_count,
                    "alerts": self.alert_count,
                    "elapsed_s": round(elapsed, 2),
                    "packets_per_s": round(pps, 2),
                },
                "recent_flows": list(self.flows)[-500:],
                "recent_alerts": list(self.alerts)[-100:],
                "injection": dict(self.injection) if self.injection else None,
                "network": device_data.get("network"),
                "devices": device_data.get("devices", []),
                "device_counters": device_data.get("counters", {}),
                "device_discovery": {
                    "available": self.mode == "live",
                    "scope": device_data.get("scope", "passive-observed"),
                    "note": device_data.get("note", ""),
                },
            }

    # ------------------------------------------------------------- internals
    def _reset_locked(self) -> None:
        self.error = None
        self.packets = 0
        self.total_bytes = 0
        self.flow_count = 0
        self.alert_count = 0
        self._t0 = None
        self._t_end = None
        self.flows.clear()
        self.alerts.clear()
        self.injection = None
        self._device_tracker = None

    def _run(
        self,
        mode: str,
        interface: str | None,
        bpf_filter: str | None,
        pcap: str | None,
        pace_speed: float,
        loop: bool,
        max_packets: int | None,
        packet_queue: "queue.Queue[Any]",
    ) -> None:
        try:
            engine = self._get_engine()
            monitor = LiveLabMonitor(
                engine=engine,
                alert_threshold=RESEARCH_THRESHOLD,
                on_alert_callback=self._on_alert,
                on_flow_callback=self._on_flow,
            )
            if mode == "live":
                with self._lock:
                    tracker = self._device_tracker
                capture = PacketCaptureService(
                    CaptureConfig(interface=interface, bpf_filter=bpf_filter, max_packets=max_packets),
                    raw_packet_callback=tracker.observe_frame if tracker is not None else None,
                )
            else:
                pcap_path = _ensure_sample_pcap(Path(pcap) if pcap else SAMPLE_PCAP)
                capture = PacketCaptureService(
                    CaptureConfig(max_packets=max_packets),
                    synthetic_stream=self._paced_pcap_stream(pcap_path, pace_speed, loop, max_packets),
                )
            with self._lock:
                self._capture = capture

            def _produce() -> None:
                """Feed captured packets into the merge queue (single consumer: the monitor)."""
                try:
                    for pkt in capture.stream_packets():
                        if self._stop_event.is_set():
                            return
                        packet_queue.put(pkt)
                except (OSError, ValueError):
                    # Raw-socket teardown on stop() may raise from a closed descriptor; treat as a clean stop.
                    if not self._stop_event.is_set():
                        with self._lock:
                            self.error = "Capture stream failed (see server log)."
                        self._stop_event.set()
                except Exception as exc:  # pragma: no cover - defensive
                    with self._lock:
                        self.error = str(exc)
                    self._stop_event.set()
                finally:
                    packet_queue.put(_CAPTURE_DONE)

            producer = threading.Thread(target=_produce, name="xrlids-capture-producer", daemon=True)
            producer.start()
            monitor.process_packet_stream(self._count_packets(self._merge_packets(packet_queue)))
        except Exception as exc:
            with self._lock:
                if not self._stop_event.is_set():
                    self.error = str(exc)
                    self.status = "error"
        finally:
            with self._lock:
                self._t_end = time.time()
                self._packet_queue = None
                if self.status == "running":
                    self.status = "error" if self.error else "stopped"

    def _merge_packets(self, packet_queue: "queue.Queue[Any]") -> Generator[PacketInfo, None, None]:
        """Merge captured and injected packets into one ordered stream for the monitor.

        Both sources enqueue into ``packet_queue``; this single consumer guarantees
        the FlowBuilder state is only ever touched from the monitor thread.
        """
        while not self._stop_event.is_set():
            try:
                item = packet_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if item is _CAPTURE_DONE:
                # Capture source exhausted (single-pass sample stream): flush queued packets, then stop.
                while not self._stop_event.is_set():
                    try:
                        pending = packet_queue.get_nowait()
                    except queue.Empty:
                        break
                    if pending is not _CAPTURE_DONE:
                        yield pending
                return
            yield item

    def _count_packets(self, packet_iter: Generator[PacketInfo, None, None]) -> Generator[PacketInfo, None, None]:
        try:
            for pkt in packet_iter:
                if self._stop_event.is_set():
                    break
                with self._lock:
                    self.packets += 1
                    self.total_bytes += pkt.packet_length
                yield pkt
        except (OSError, ValueError):
            # Raw-socket teardown on stop() may raise from a closed descriptor; treat as a clean stop.
            if not self._stop_event.is_set():
                raise

    def _paced_pcap_stream(
        self,
        pcap_path: Path,
        pace_speed: float,
        loop: bool,
        max_packets: int | None,
    ) -> Generator[PacketInfo, None, None]:
        """Yield PCAP packets at their original inter-packet pacing (restamped to wall-clock time).

        This plays recorded traffic through the exact same live pipeline in
        real time; it is a sample stream, not a live network capture.
        """
        packets = list(PcapReader(pcap_path).read_packets())
        if not packets:
            return
        speed = pace_speed if pace_speed and pace_speed > 0 else 1.0
        emitted = 0
        while not self._stop_event.is_set():
            prev_ts: float | None = None
            for pkt in packets:
                if self._stop_event.is_set():
                    return
                if max_packets and emitted >= max_packets:
                    return
                if prev_ts is not None:
                    delay = min(max(pkt.timestamp - prev_ts, 0.0) / speed, 1.0)
                    if delay > 0 and self._stop_event.wait(delay):
                        return
                prev_ts = pkt.timestamp
                emitted += 1
                yield replace(pkt, timestamp=time.time())
            if not loop:
                return

    def _injection_worker(
        self, packets: list[PacketInfo], speed: float, packet_queue: "queue.Queue[Any] | None"
    ) -> None:
        """Pace scenario packets into the merge queue, restamped to wall-clock time.

        Restamping preserves inter-packet deltas, so the resulting flow features
        (and therefore the frozen model's scores) match the calibrated values.
        """
        prev_ts: float | None = None
        sent = 0
        try:
            for pkt in packets:
                if self._stop_event.is_set() or packet_queue is None:
                    break
                if prev_ts is not None:
                    delay = (pkt.timestamp - prev_ts) / speed
                    if delay > 0 and self._stop_event.wait(delay):
                        break
                prev_ts = pkt.timestamp
                packet_queue.put(replace(pkt, timestamp=time.time()))
                sent += 1
                with self._lock:
                    if self.injection is not None:
                        self.injection["packets_sent"] = sent
        finally:
            with self._lock:
                if self.injection is not None:
                    self.injection["active"] = False
                    self.injection["packets_sent"] = sent
                    self.injection["finished_at"] = datetime.now(timezone.utc).isoformat()

    def _on_flow(self, observation: FlowObservation) -> None:
        with self._lock:
            self.flow_count += 1
            self.flows.append(asdict(observation))

    def _on_alert(self, alert: AlertEvent) -> None:
        with self._lock:
            self.alert_count += 1
            self.alerts.append(asdict(alert))


LIVE_SESSION = LiveSession()


class DashboardHandler(BaseHTTPRequestHandler):
    """Handle dashboard requests (static assets + JSON APIs)."""

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.serve_file(DASHBOARD_DIR / "index.html", "text/html; charset=utf-8")
        elif path == "/app.js":
            self.serve_file(DASHBOARD_DIR / "app.js", "application/javascript; charset=utf-8")
        elif path == "/api/data":
            self.send_json(get_dashboard_data())
        elif path == "/api/live":
            self.send_json(LIVE_SESSION.snapshot())
        elif path == "/api/live/devices":
            self.send_json(LIVE_SESSION.device_snapshot())
        elif path == "/api/live/interfaces":
            self.send_json(
                {
                    "interfaces": available_interfaces(),
                    "permissions": {"raw_socket": PacketCaptureService.check_permissions()},
                }
            )
        elif path == "/api/live/scenarios":
            self.send_json(
                {
                    "scenarios": list_scenarios(),
                    "thresholds": {
                        "research": RESEARCH_THRESHOLD,
                        "operational_candidate": OPERATIONAL_CANDIDATE_THRESHOLD,
                    },
                    "notice": (
                        "Simulation only: scenarios synthesise TCP packets in memory and push them through the "
                        "observational pipeline; nothing is transmitted and no firewall/routing state is touched. "
                        "Scores are the frozen CIC-IDS2017 R10 Random Forest's real outputs."
                    ),
                }
            )
        elif path.startswith("/figures/"):
            filename = os.path.basename(path)
            fig_path = FIGURES_DIR / filename
            if fig_path.exists() and fig_path.suffix.lower() == ".png":
                self.serve_file(fig_path, "image/png")
            else:
                self.send_error(HTTPStatus.NOT_FOUND, "Figure not found")
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/run-replay":
            self._handle_run_replay()
        elif parsed.path == "/api/live/start":
            body = self.read_json_body()
            result = LIVE_SESSION.start(
                mode=str(body.get("mode", "sample")),
                interface=body.get("interface") or None,
                bpf_filter=body.get("bpf_filter") or None,
                pcap=body.get("pcap") or None,
                pace_speed=float(body.get("pace_speed", 2.0)),
                loop=bool(body.get("loop", True)),
                max_packets=int(body["max_packets"]) if body.get("max_packets") else None,
            )
            self.send_json(result, status=HTTPStatus.BAD_REQUEST if result.get("error") else HTTPStatus.OK)
        elif parsed.path == "/api/live/stop":
            self.send_json(LIVE_SESSION.stop())
        elif parsed.path == "/api/live/inject-attack":
            body = self.read_json_body()
            scenario_id = str(body.get("scenario", "")).strip()
            if not scenario_id:
                self.send_json({"error": "Missing 'scenario' in request body."}, status=HTTPStatus.BAD_REQUEST)
                return
            result = LIVE_SESSION.inject_scenario(scenario_id)
            self.send_json(result, status=HTTPStatus.BAD_REQUEST if result.get("error") else HTTPStatus.OK)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def _handle_run_replay(self) -> None:
        try:
            script_path = REPO_ROOT / "scripts" / "demo" / "run_replay_demo.py"
            proc = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                timeout=30,
            )
            data = get_dashboard_data()
            data["run_output"] = proc.stdout
            data["run_exit_code"] = proc.returncode
            self.send_json(data)
        except Exception as e:
            self.send_json({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def read_json_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            return {}

    def send_json(self, data: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def serve_file(self, file_path: Path, content_type: str) -> None:
        if not file_path.exists():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return
        content = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args) -> None:
        # Keep server log concise
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")


def create_server(port: int = 8000) -> ThreadingHTTPServer:
    """Create (but do not start) the dashboard HTTP server."""
    return ThreadingHTTPServer(("127.0.0.1", port), DashboardHandler)


def run(port: int = 8000, autostart: dict[str, Any] | None = None) -> None:
    httpd = create_server(port)
    print(f"XRL-IDARS Dashboard running at http://127.0.0.1:{port}/")
    if autostart is not None:
        result = LIVE_SESSION.start(**autostart)
        if "error" in result:
            print(f"Live session did not start: {result['error']}")
        else:
            print(f"Live session started: mode={result['mode']} interface={result['interface'] or '-'}")
    if not PacketCaptureService.check_permissions():
        print("Note: no raw-socket permission — use the Sample stream mode, or restart with sudo for live capture.")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        LIVE_SESSION.stop()
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="XRL-IDARS dashboard server (observational; no network mutations).")
    parser.add_argument("port", nargs="?", type=int, default=8000, help="HTTP port (default 8000)")
    parser.add_argument("--live", action="store_true", help="Auto-start live interface capture (requires root / CAP_NET_RAW)")
    parser.add_argument("--iface", default=None, help="Interface for --live (default: first non-loopback)")
    parser.add_argument("--bpf", default=None, help='Optional capture filter, e.g. "tcp port 443"')
    parser.add_argument("--sample", action="store_true", help="Auto-start the paced Sample stream (no root required)")
    args = parser.parse_args(argv)

    autostart: dict[str, Any] | None = None
    if args.live:
        interface = args.iface
        if not interface:
            candidates = [name for name in available_interfaces() if name != "lo"]
            interface = candidates[0] if candidates else None
        autostart = {"mode": "live", "interface": interface, "bpf_filter": args.bpf}
    elif args.sample:
        autostart = {"mode": "sample", "bpf_filter": args.bpf}

    run(port=args.port, autostart=autostart)
    return 0


if __name__ == "__main__":
    sys.exit(main())
