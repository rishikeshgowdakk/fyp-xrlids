#!/usr/bin/env python3
"""Minimalist HTTP server for XRL-IDARS dashboard.

Serves pure HTML/JS dashboard without external build tools (no Vite, no npm).
"""

from __future__ import annotations

import json
import mimetypes
import os
import subprocess
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = REPO_ROOT / "dashboard"
FIGURES_DIR = REPO_ROOT / "reports" / "figures"
REPLAY_SUMMARY = REPO_ROOT / "results" / "demo" / "replay_summary.json"
SHAP_SUMMARY = REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "shap_summary.json"


def get_dashboard_data() -> dict:
    """Collect replay summary, SHAP data, and figure list."""
    data: dict = {
        "status": "ready",
        "replay": None,
        "shap": None,
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

    if FIGURES_DIR.exists():
        data["figures"] = sorted([p.name for p in FIGURES_DIR.glob("*.png")])

    return data


class DashboardHandler(BaseHTTPRequestHandler):
    """Handle dashboard requests."""

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.serve_file(DASHBOARD_DIR / "index.html", "text/html; charset=utf-8")
        elif path == "/app.js":
            self.serve_file(DASHBOARD_DIR / "app.js", "application/javascript; charset=utf-8")
        elif path == "/api/data":
            payload = json.dumps(get_dashboard_data()).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
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
            try:
                # Run the replay demo script
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

                payload = json.dumps(data).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as e:
                err_payload = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(err_payload)))
                self.end_headers()
                self.wfile.write(err_payload)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def serve_file(self, file_path: Path, content_type: str) -> None:
        if not file_path.exists():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return
        content = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args) -> None:
        # Keep server log concise
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")


def run(port: int = 8000) -> None:
    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, DashboardHandler)
    print(f"XRL-IDARS Dashboard running at http://127.0.0.1:{port}/")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()


if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run(port=port)
