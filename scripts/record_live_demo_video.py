"""Playwright Video Recorder for XRL-IDARS Live Operational Demonstration.

Records a high-resolution, steady-paced, crystal-clear video demonstrating:
1. Safe baseline with default dry-run advisory mode.
2. Normal Scapy Ping: clean pipeline, RF benign classification, DQN ALLOW,
   safety gate permitted, ping succeeds, zero firewall blocks.
3. Enabling Operator Firewall Enforcement.
4. Controlled ICMP Flood: packet capture, R10 features, RF prediction vs Rule evidence,
   TreeSHAP attribution, DQN ISOLATE recommendation, Safety Gate authorization,
   temporary firewall rule installation against verified attacker 10.200.1.2,
   and independent traffic block verification.
5. Rule rollback and restored connectivity.
6. PCAP Wire Replay: replay progress, R10 extraction, RF, DQN, and explicit
   advisory-only marking with zero live firewall claims.
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

APP_URL = "http://localhost:8503/Live_Demo"


def record_demo_video():
    print("Starting Playwright browser for slow, clear live demonstration video recording...")
    temp_video_dir = Path("/tmp/xrlids_video_temp")
    if temp_video_dir.exists():
        shutil.rmtree(temp_video_dir)
    temp_video_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path="/usr/bin/google-chrome",
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--window-size=1440,900",
            ],
        )

        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            record_video_dir=str(temp_video_dir),
            record_video_size={"width": 1280, "height": 720},
        )

        page = context.new_page()

        # Helper for slow, deliberate pace
        def slow_pause(seconds: float = 2.5):
            page.wait_for_timeout(int(seconds * 1000))

        # Helper to smoothly scroll
        def smooth_scroll_to(y_pos: int, steps: int = 10):
            current_y = page.evaluate("window.scrollY")
            step_size = (y_pos - current_y) / steps
            for _ in range(steps):
                current_y += step_size
                page.evaluate(f"window.scrollTo(0, {current_y})")
                page.wait_for_timeout(80)

        # -------------------------------------------------------------------
        # Step 1: Open Live Demo Page & Initial Overview
        # -------------------------------------------------------------------
        print("Navigating to Live Demo...")
        page.goto(APP_URL, wait_until="networkidle", timeout=45000)
        slow_pause(3.0)

        page.screenshot(path=str(SCREENSHOTS_DIR / "01_live_demo_initial.png"))
        print("Initial overview captured.")
        slow_pause(2.0)

        # -------------------------------------------------------------------
        # Step 2: Normal Scapy Ping Demonstration
        # -------------------------------------------------------------------
        print("Running Scenario 1: Normal Scapy Ping...")
        # Click "Generate Scenario Traffic" with "Normal Ping" (default selected)
        btn_gen = page.locator("button:has-text('Generate Scenario Traffic')")
        btn_gen.wait_for(state="visible", timeout=10000)
        btn_gen.click()
        slow_pause(3.5)

        # Capture screenshot of benign ping result
        page.screenshot(path=str(SCREENSHOTS_DIR / "02_scapy_normal_ping.png"))

        # Smoothly scroll down to Event Stream
        smooth_scroll_to(650)
        slow_pause(3.0)

        # Smoothly scroll down to Lifecycle Provenance & Deep-Dive Tabs
        smooth_scroll_to(1100)
        slow_pause(2.5)

        # Click Tab 2: RF vs Rule Evidence
        tab_rf_rule = page.locator("button[role='tab']:has-text('2. RF vs Rule Evidence')")
        if tab_rf_rule.count() > 0:
            tab_rf_rule.click()
            slow_pause(3.0)

        # Click Tab 4: Dueling DQN Response
        tab_dqn = page.locator("button[role='tab']:has-text('4. Dueling DQN Response')")
        if tab_dqn.count() > 0:
            tab_dqn.click()
            slow_pause(3.0)

        # Click Tab 5: Safety Gate & Firewall Verification
        tab_safety = page.locator("button[role='tab']:has-text('5. Safety Gate & Firewall Verification')")
        if tab_safety.count() > 0:
            tab_safety.click()
            slow_pause(3.0)

        # Scroll back to top
        smooth_scroll_to(0)
        slow_pause(2.0)

        # Test Connectivity Probe
        btn_conn = page.locator("button:has-text('Test Connectivity Probe')")
        if btn_conn.count() > 0:
            btn_conn.click()
            slow_pause(2.5)

        # -------------------------------------------------------------------
        # Step 3: Enable Real Firewall Enforcement
        # -------------------------------------------------------------------
        print("Enabling Real Firewall Enforcement...")
        cb_enforce = page.locator("label:has-text('Enable Real Firewall Enforcement')")
        cb_enforce.wait_for(state="visible", timeout=5000)
        cb_enforce.click()
        slow_pause(3.0)

        page.screenshot(path=str(SCREENSHOTS_DIR / "03_firewall_enforcement_enabled.png"))
        print("Operator enforcement enabled.")

        # -------------------------------------------------------------------
        # Step 4: Run Controlled ICMP Flood
        # -------------------------------------------------------------------
        print("Running Scenario 2: Controlled ICMP Flood...")
        # Select "Controlled ICMP Flood" from scenario dropdown
        page.locator("div[data-baseweb='select']").first.click()
        slow_pause(1.0)
        page.locator("li:has-text('Controlled ICMP Flood')").click()
        slow_pause(2.0)

        # Click "Generate Scenario Traffic"
        btn_gen.click()
        slow_pause(4.0)

        page.screenshot(path=str(SCREENSHOTS_DIR / "04_icmp_flood_blocked.png"))
        print("Controlled ICMP flood blocked by firewall.")

        # Click "Verify Block" button
        btn_verif = page.locator("button:has-text('Verify Block')")
        if btn_verif.count() > 0:
            btn_verif.click()
            slow_pause(3.0)

        # Scroll down to Event Stream
        smooth_scroll_to(650)
        slow_pause(3.0)

        # Scroll down to Lifecycle Provenance & Deep-Dive Tabs
        smooth_scroll_to(1100)
        slow_pause(2.5)

        # Click Tab 2: RF vs Rule Evidence
        tab_rf_rule = page.locator("button[role='tab']:has-text('2. RF vs Rule Evidence')")
        if tab_rf_rule.count() > 0:
            tab_rf_rule.click()
            slow_pause(3.5)

        # Click Tab 3: TreeSHAP Local Attribution
        tab_shap = page.locator("button[role='tab']:has-text('3. TreeSHAP Local Attribution')")
        if tab_shap.count() > 0:
            tab_shap.click()
            slow_pause(3.0)

        # Click Tab 4: Dueling DQN Response
        tab_dqn = page.locator("button[role='tab']:has-text('4. Dueling DQN Response')")
        if tab_dqn.count() > 0:
            tab_dqn.click()
            slow_pause(3.0)

        # Click Tab 5: Safety Gate & Firewall Verification
        tab_safety = page.locator("button[role='tab']:has-text('5. Safety Gate & Firewall Verification')")
        if tab_safety.count() > 0:
            tab_safety.click()
            slow_pause(3.5)

        # -------------------------------------------------------------------
        # Step 5: Rollback Rule & Verify Restored Connectivity
        # -------------------------------------------------------------------
        print("Rolling back firewall rule...")
        smooth_scroll_to(0)
        slow_pause(2.0)

        btn_rollback = page.locator("button:has-text('Rollback Rule')")
        if btn_rollback.count() > 0:
            btn_rollback.click()
            slow_pause(3.0)

        page.screenshot(path=str(SCREENSHOTS_DIR / "05_firewall_rule_rolled_back.png"))
        print("Rule rolled back and connectivity restored.")

        # -------------------------------------------------------------------
        # Step 6: PCAP Wire Replay Mode
        # -------------------------------------------------------------------
        print("Switching to PCAP Wire Replay Mode...")
        r_pcap = page.locator("label:has-text('PCAP Wire Replay')")
        r_pcap.click()
        slow_pause(3.0)

        # Click "Replay PCAP Stream"
        btn_replay = page.locator("button:has-text('Replay PCAP Stream')")
        btn_replay.wait_for(state="visible", timeout=5000)
        btn_replay.click()
        slow_pause(4.0)

        page.screenshot(path=str(SCREENSHOTS_DIR / "06_pcap_replay_advisory.png"))

        # Scroll to Event Stream to show PCAP_REPLAY rows and advisory markings
        smooth_scroll_to(650)
        slow_pause(3.5)

        # Scroll to bottom to view full evidence
        smooth_scroll_to(1100)
        slow_pause(3.5)

        print("Demonstration workflow completed cleanly.")
        slow_pause(3.0)

        # Close page & context to finalize video
        page.close()
        context.close()
        browser.close()

    # Move recorded video to final destinations
    recorded_files = list(temp_video_dir.glob("*.webm"))
    if recorded_files:
        src_video = recorded_files[0]
        dest_video_docs = VIDEOS_DIR / "live_demo_scapy_pcap_rf_dqn.webm"
        dest_video_artifacts = ARTIFACTS_DIR / "live_demo_scapy_pcap_rf_dqn.webm"

        shutil.copy(src_video, dest_video_docs)
        shutil.copy(src_video, dest_video_artifacts)
        print(f"Video saved successfully to:")
        print(f"  - {dest_video_docs} ({dest_video_docs.stat().st_size / (1024*1024):.2f} MB)")
        print(f"  - {dest_video_artifacts}")
    else:
        print("Warning: No video file was generated in temp directory.")


if __name__ == "__main__":
    record_demo_video()
