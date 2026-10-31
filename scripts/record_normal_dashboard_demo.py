"""Playwright Video Recorder for XRL-IDARS Live Operational Demonstration (Pure Dashboard).

Records a high-resolution, slow-paced, crystal-clear video demonstrating:
1. Pure Python Dashboard on port 8000 (demo.html & index.html Live Demo mode).
2. Live WiFi Network & Passive Device Discovery: Gateway Router (192.168.0.1 TP-Link),
   Host PC (192.168.0.109 Intel), active SSID (rgkkkk), Signal dBm.
3. Normal Scapy Ping: clean pipeline, RF benign classification, DQN ALLOW,
   safety gate permitted, ping succeeds (4/4 delivered), zero firewall blocks.
4. Controlled ICMP Flood: packet capture, R10 features, RF prediction vs Rule evidence,
   TreeSHAP attribution, DQN ISOLATE recommendation, Safety Gate authorization,
   temporary firewall rule installation against verified attacker 10.200.1.2,
   traffic block verification (4/4 packets dropped, 100% drop rate), drop counter telemetry.
5. Rule rollback / unblock and restored connectivity verification (4/4 delivered).
6. Controlled TCP SYN Flood burst scenario.
7. Main Dashboard (index.html) Live Demo mode: rolling observational flow stream,
   attack sources table with live Block/Unblock buttons, and passive WiFi devices.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import time

from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[1]
VIDEOS_DIR = REPO_ROOT / "docs" / "videos"
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
SCREENSHOTS_DIR = REPO_ROOT / "docs" / "screenshots"

VIDEOS_DIR.mkdir(parents=True, exist_ok=True)
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

BASE_URL = "http://localhost:8000"


def record_demo_video():
    print("=====================================================================")
    print("Starting Playwright Chrome for XRL-IDARS Live Operational Video")
    print("Run speed: Slow & deliberate | Visuals: Prominent & clear")
    print("=====================================================================")

    temp_video_dir = Path("/tmp/xrlids_normal_video_temp")
    if temp_video_dir.exists():
        shutil.rmtree(temp_video_dir)
    temp_video_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path="/usr/bin/google-chrome",
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--window-size=1600,1050",
            ],
        )

        context = browser.new_context(
            record_video_dir=str(temp_video_dir),
            record_video_size={"width": 1600, "height": 1050},
            viewport={"width": 1600, "height": 1050},
        )

        page = context.new_page()

        # -------------------------------------------------------------
        # STEP 1: Open Live Demonstration Interface (/demo.html)
        # -------------------------------------------------------------
        print("\n[Step 1] Navigating to http://localhost:8000/demo.html...")
        page.goto(f"{BASE_URL}/demo.html", wait_until="networkidle")
        page.wait_for_timeout(3000)
        page.screenshot(path=str(SCREENSHOTS_DIR / "norm_01_demo_initial.png"))

        # -------------------------------------------------------------
        # STEP 2: Inspect Live WiFi Discovery & Access Point Info
        # -------------------------------------------------------------
        print("[Step 2] Showcasing Live WiFi Devices & AP Discovery...")
        page.locator("#table-demo-devices").scroll_into_view_if_needed()
        page.wait_for_timeout(4000)
        page.screenshot(path=str(SCREENSHOTS_DIR / "norm_02_wifi_devices.png"))

        # -------------------------------------------------------------
        # STEP 3: Start Monitoring
        # -------------------------------------------------------------
        print("[Step 3] Starting Live Capture / Monitoring...")
        page.locator("#btn-start-monitoring").scroll_into_view_if_needed()
        page.wait_for_timeout(2000)
        page.click("#btn-start-monitoring")
        page.wait_for_timeout(3000)
        page.screenshot(path=str(SCREENSHOTS_DIR / "norm_03_monitoring_started.png"))

        # -------------------------------------------------------------
        # STEP 4: Scenario 1 — Normal Ping (Benign Traffic)
        # -------------------------------------------------------------
        print("[Step 4] Selecting and Launching Scenario Ping (Normal Ping)...")
        page.select_option("#select-scenario", "scenario_ping")
        page.wait_for_timeout(2000)
        page.click("#btn-launch-sim")
        page.wait_for_timeout(4000)

        # Inspect Normal Ping Result in Table and Response Policy
        print("[Step 4b] Verifying Benign Classification and ALLOW Response...")
        page.locator("#table-traffic").scroll_into_view_if_needed()
        page.wait_for_timeout(3000)
        page.locator("#resp-dqn-action").scroll_into_view_if_needed()
        page.wait_for_timeout(3000)

        # Run Test Ping Reachability before attack
        print("[Step 4c] Testing Connectivity for Benign Ping (should be 4/4 delivered)...")
        page.click("#btn-demo-ping")
        page.wait_for_timeout(4000)
        page.screenshot(path=str(SCREENSHOTS_DIR / "norm_04_benign_ping_success.png"))

        # -------------------------------------------------------------
        # STEP 5: Scenario 2 — Controlled ICMP Flood Burst
        # -------------------------------------------------------------
        print("[Step 5] Selecting and Launching Scenario D (Controlled ICMP Flood Burst)...")
        page.select_option("#select-scenario", "scenario_d_icmp_burst")
        page.wait_for_timeout(2000)
        page.click("#btn-launch-sim")
        page.wait_for_timeout(4500)

        # Inspect Packet Flow & Attack Detection
        print("[Step 5b] Inspecting Captured Wire Packets & Rule Detection...")
        page.locator("#table-traffic").scroll_into_view_if_needed()
        page.wait_for_timeout(3500)
        page.locator("#tbody-detection").scroll_into_view_if_needed()
        page.wait_for_timeout(3500)

        # Inspect TreeSHAP Explanation for Detected Attack
        print("[Step 5c] Inspecting TreeSHAP Feature Attributions...")
        page.locator("#shap-bars-container").scroll_into_view_if_needed()
        page.wait_for_timeout(4000)

        # Inspect DQN Recommendation and Firewall Enforcement
        print("[Step 5d] Inspecting Autonomous Response Policy (DQN ISOLATE) & Active Firewall...")
        page.locator("#resp-dqn-action").scroll_into_view_if_needed()
        page.wait_for_timeout(4000)
        page.screenshot(path=str(SCREENSHOTS_DIR / "norm_05_icmp_flood_blocked.png"))

        # -------------------------------------------------------------
        # STEP 6: Verify Attacker Traffic is Actively Blocked
        # -------------------------------------------------------------
        print("[Step 6] Testing Ping Reachability while Firewall Block is Active...")
        page.click("#btn-demo-ping")
        page.wait_for_timeout(5000)
        page.screenshot(path=str(SCREENSHOTS_DIR / "norm_06_attacker_traffic_blocked.png"))

        # -------------------------------------------------------------
        # STEP 7: Rollback / Unblock Rule and Verify Restored Connectivity
        # -------------------------------------------------------------
        print("[Step 7] Rolling back Firewall Rule / Unblocking Attacker...")
        page.click("#btn-demo-unblock")
        page.wait_for_timeout(3500)

        print("[Step 7b] Verifying Restored Connectivity via Ping Probe...")
        page.click("#btn-demo-ping")
        page.wait_for_timeout(4500)
        page.screenshot(path=str(SCREENSHOTS_DIR / "norm_07_restored_connectivity.png"))

        # -------------------------------------------------------------
        # STEP 8: Scenario 3 — TCP SYN Flood Burst
        # -------------------------------------------------------------
        print("[Step 8] Launching Scenario C (Volumetric TCP SYN Burst)...")
        page.select_option("#select-scenario", "scenario_c_syn_burst")
        page.wait_for_timeout(2000)
        page.click("#btn-launch-sim")
        page.wait_for_timeout(4500)

        page.locator("#tbody-detection").scroll_into_view_if_needed()
        page.wait_for_timeout(3500)
        page.locator("#resp-dqn-action").scroll_into_view_if_needed()
        page.wait_for_timeout(3500)
        page.screenshot(path=str(SCREENSHOTS_DIR / "norm_08_syn_flood_detected.png"))

        # -------------------------------------------------------------
        # STEP 9: Audit Event Timeline & Latency
        # -------------------------------------------------------------
        print("[Step 9] Inspecting Pipeline Latency and Audit Timeline...")
        page.locator(".latency-grid").scroll_into_view_if_needed()
        page.wait_for_timeout(3000)
        page.locator("#timeline-list").scroll_into_view_if_needed()
        page.wait_for_timeout(4000)
        page.screenshot(path=str(SCREENSHOTS_DIR / "norm_09_audit_timeline.png"))

        # -------------------------------------------------------------
        # STEP 10: Visit Main Research Workbench (/index.html Live Demo)
        # -------------------------------------------------------------
        print("\n[Step 10] Switching to Main Dashboard (/index.html) Live Demo mode...")
        page.goto(f"{BASE_URL}/index.html", wait_until="networkidle")
        page.wait_for_timeout(3000)

        # Switch to Live demo mode
        page.click("#btn-mode-live")
        page.wait_for_timeout(3500)

        # Start live stream
        print("[Step 10b] Starting stream in Live Demo workbench view...")
        page.click("#btn-live-start")
        page.wait_for_timeout(3500)

        # Scroll to Observational Flow Stream and Attack Sources
        print("[Step 10c] Inspecting Rolling Flows and Attack Sources with Block/Unblock buttons...")
        page.locator("#live-flows-tbody").scroll_into_view_if_needed()
        page.wait_for_timeout(3500)

        # Inspect WiFi Devices table in index.html
        print("[Step 10d] Inspecting WiFi Devices in main workbench...")
        page.locator("#devices-body").scroll_into_view_if_needed()
        page.wait_for_timeout(4000)
        page.screenshot(path=str(SCREENSHOTS_DIR / "norm_10_main_workbench_live.png"))

        # Quick simulation of ICMP flood from workbench view
        print("[Step 10e] Triggering quick ICMP Flood simulation from main workbench...")
        page.locator("#live-mode").scroll_into_view_if_needed()
        page.wait_for_timeout(2000)
        # Click the ICMP Flood button in Quick Simulation bar
        icmp_btn = page.locator("button:has-text('ICMP Flood')").first
        if icmp_btn.count() > 0:
            icmp_btn.click()
            page.wait_for_timeout(4000)

        page.locator("#attack-sources-body").scroll_into_view_if_needed()
        page.wait_for_timeout(4000)
        page.screenshot(path=str(SCREENSHOTS_DIR / "norm_11_attack_sources_firewall.png"))

        # Final pause to let viewer take in the system
        page.wait_for_timeout(3000)

        # Close context and save video
        context.close()
        browser.close()

    # Move recorded video to final locations
    video_files = list(temp_video_dir.glob("*.webm"))
    if video_files:
        src_video = video_files[0]
        final_video_1 = VIDEOS_DIR / "xrl_idars_live_operational_demo.webm"
        final_video_2 = ARTIFACTS_DIR / "xrl_idars_live_operational_demo.webm"
        shutil.copy2(src_video, final_video_1)
        shutil.copy2(src_video, final_video_2)
        print(f"\n=====================================================================")
        print(f"SUCCESS: Recorded Live Demo Video saved to:")
        print(f"  1. {final_video_1} ({final_video_1.stat().st_size / (1024*1024):.2f} MB)")
        print(f"  2. {final_video_2} ({final_video_2.stat().st_size / (1024*1024):.2f} MB)")
        print(f"=====================================================================")
    else:
        print("Warning: No video file found in temporary directory.")


if __name__ == "__main__":
    record_demo_video()
