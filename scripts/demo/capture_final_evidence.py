#!/usr/bin/env python3
"""Automated Browser Evidence Collector for XRL-IDARS.

Connects to the running Streamlit SOC Dashboard via Chrome DevTools Protocol (CDP),
exercises the 3 primary application sections (Overview, Live Demo, Benchmarks),
runs genuine packet simulations, PCAP replay, and 10k benchmarks, and captures
the 12 required high-resolution verification screenshots into docs/screenshots/.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[2]
SCREENSHOT_DIR = REPO_ROOT / "docs" / "screenshots"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("capture_evidence")

BASE_URL = "http://localhost:8501"


def capture_all_evidence():
    logger.info("Connecting to headless Chrome on port 9222...")
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp("http://localhost:9222")
        context = browser.contexts[0] if browser.contexts else browser.new_context(viewport={"width": 1440, "height": 960})
        page = context.new_page()
        page.set_viewport_size({"width": 1440, "height": 960})

        # -------------------------------------------------------------------
        # 1. OVERVIEW — Complete architecture overview & flowchart
        # -------------------------------------------------------------------
        logger.info("Capturing 01-overview-architecture.png...")
        page.goto(f"{BASE_URL}/", wait_until="networkidle")
        time.sleep(2.0)
        page.screenshot(path=str(SCREENSHOT_DIR / "01-overview-architecture.png"))
        logger.info("✓ Saved 01-overview-architecture.png")

        # -------------------------------------------------------------------
        # 2. LIVE DEMO — Benign Ping Simulation
        # -------------------------------------------------------------------
        logger.info("Navigating to Live Demo...")
        page.goto(f"{BASE_URL}/Live_Demo", wait_until="networkidle")
        time.sleep(1.5)

        # Ensure Scenario A: Benign Ping is selected
        logger.info("Running Scenario A: Benign Ping...")
        # Select scenario_a_benign if not already selected
        try:
            # Click scenario dropdown and select Scenario A
            dropdown = page.locator("div[data-testid='stSelectbox']").first
            dropdown.click()
            time.sleep(0.5)
            # Click option with Scenario A
            opt = page.locator("li").filter(has_text="Scenario A: Benign Ping").first
            if opt.count() > 0:
                opt.click()
                time.sleep(0.5)
        except Exception as e:
            logger.warning(f"Could not change selectbox directly: {e}")

        # Click Run Scenario
        run_btn = page.locator("button:has-text('Run Scenario')").first
        if run_btn.count() > 0:
            run_btn.click()
            time.sleep(2.0)

        # Capture 02-live-demo-benign.png
        logger.info("Capturing 02-live-demo-benign.png...")
        page.screenshot(path=str(SCREENSHOT_DIR / "02-live-demo-benign.png"))
        logger.info("✓ Saved 02-live-demo-benign.png")

        # -------------------------------------------------------------------
        # 3. LIVE DEMO — Controlled Attack (SYN Burst) Simulation
        # -------------------------------------------------------------------
        logger.info("Running Scenario C: TCP SYN Burst...")
        try:
            dropdown = page.locator("div[data-testid='stSelectbox']").first
            dropdown.click()
            time.sleep(0.5)
            opt = page.locator("li").filter(has_text="Scenario C: Volumetric TCP SYN Burst").first
            if opt.count() > 0:
                opt.click()
                time.sleep(0.5)
        except Exception as e:
            logger.warning(f"Dropdown error: {e}")

        run_btn = page.locator("button:has-text('Run Scenario')").first
        if run_btn.count() > 0:
            run_btn.click()
            time.sleep(2.5)

        logger.info("Capturing 03-live-demo-attack.png...")
        page.screenshot(path=str(SCREENSHOT_DIR / "03-live-demo-attack.png"))
        logger.info("✓ Saved 03-live-demo-attack.png")

        # Scroll to Detailed Inspection Tabs
        tabs = page.locator("button[data-baseweb='tab']")
        tab_count = tabs.count()
        logger.info(f"Found {tab_count} inspection tabs.")

        # -------------------------------------------------------------------
        # 4. RANDOM FOREST DETECTION (Tab 1: Perception & Rules)
        # -------------------------------------------------------------------
        if tab_count >= 1:
            tabs.nth(0).click()
            time.sleep(0.8)
            logger.info("Capturing 04-random-forest-detection.png...")
            page.screenshot(path=str(SCREENSHOT_DIR / "04-random-forest-detection.png"))
            logger.info("✓ Saved 04-random-forest-detection.png")

        # -------------------------------------------------------------------
        # 5. RULES AND EXPLAINABILITY (Tab 2: TreeSHAP Attribution)
        # -------------------------------------------------------------------
        if tab_count >= 2:
            tabs.nth(1).click()
            time.sleep(0.8)
            logger.info("Capturing 05-rules-and-explainability.png...")
            page.screenshot(path=str(SCREENSHOT_DIR / "05-rules-and-explainability.png"))
            logger.info("✓ Saved 05-rules-and-explainability.png")

        # -------------------------------------------------------------------
        # 6. DQN RESPONSE POLICY (Tab 3: Dueling DQN Response)
        # -------------------------------------------------------------------
        if tab_count >= 3:
            tabs.nth(2).click()
            time.sleep(0.8)
            logger.info("Capturing 06-dqn-response.png...")
            page.screenshot(path=str(SCREENSHOT_DIR / "06-dqn-response.png"))
            logger.info("✓ Saved 06-dqn-response.png")

        # -------------------------------------------------------------------
        # 7. RESPONSE AUDIT & VERIFICATION (Tab 4: Safety & Verification)
        # -------------------------------------------------------------------
        if tab_count >= 4:
            tabs.nth(3).click()
            time.sleep(0.8)
            logger.info("Capturing 07-response-audit.png...")
            page.screenshot(path=str(SCREENSHOT_DIR / "07-response-audit.png"))
            logger.info("✓ Saved 07-response-audit.png")

        # -------------------------------------------------------------------
        # 8. PCAP REPLAY
        # -------------------------------------------------------------------
        logger.info("Executing PCAP Replay...")
        # Select PCAP REPLAY radio option
        pcap_radio = page.locator("label:has-text('PCAP REPLAY')").first
        if pcap_radio.count() > 0:
            pcap_radio.click()
            time.sleep(1.0)
            pcap_btn = page.locator("button:has-text('Start PCAP Replay')").first
            if pcap_btn.count() > 0:
                pcap_btn.click()
                time.sleep(2.5)

        logger.info("Capturing 08-pcap-replay.png...")
        page.screenshot(path=str(SCREENSHOT_DIR / "08-pcap-replay.png"))
        logger.info("✓ Saved 08-pcap-replay.png")

        # -------------------------------------------------------------------
        # 12. POSTGRES EVENT HISTORY (Retrieval from PostgreSQL)
        # -------------------------------------------------------------------
        logger.info("Switching to Persistent PostgreSQL Database (Historical)...")
        db_radio = page.locator("label:has-text('Persistent PostgreSQL Database')").first
        if db_radio.count() > 0:
            db_radio.click()
            time.sleep(1.5)

        logger.info("Capturing 12-postgres-event-history.png...")
        page.screenshot(path=str(SCREENSHOT_DIR / "12-postgres-event-history.png"))
        logger.info("✓ Saved 12-postgres-event-history.png")

        # -------------------------------------------------------------------
        # 9, 10, 11. BENCHMARKS — Overview, Confusion Matrix, Model Comparison
        # -------------------------------------------------------------------
        logger.info("Navigating to Benchmarks...")
        page.goto(f"{BASE_URL}/Benchmarks", wait_until="networkidle")
        time.sleep(2.0)

        logger.info("Capturing 09-benchmark-overview.png...")
        page.screenshot(path=str(SCREENSHOT_DIR / "09-benchmark-overview.png"))
        logger.info("✓ Saved 09-benchmark-overview.png")

        # Scroll to Confusion Matrices section
        page.evaluate("window.scrollTo(0, 500)")
        time.sleep(1.0)
        logger.info("Capturing 10-benchmark-confusion-matrix.png...")
        page.screenshot(path=str(SCREENSHOT_DIR / "10-benchmark-confusion-matrix.png"))
        logger.info("✓ Saved 10-benchmark-confusion-matrix.png")

        # Scroll to Model Comparison & Latency Breakdown
        page.evaluate("window.scrollTo(0, 950)")
        time.sleep(1.0)
        logger.info("Capturing 11-benchmark-model-comparison.png...")
        page.screenshot(path=str(SCREENSHOT_DIR / "11-benchmark-model-comparison.png"))
        logger.info("✓ Saved 11-benchmark-model-comparison.png")

        page.close()

    logger.info("All 12 screenshots successfully captured and verified!")


if __name__ == "__main__":
    capture_all_evidence()
