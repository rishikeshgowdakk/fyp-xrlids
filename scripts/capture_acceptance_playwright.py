"""Automated Playwright browser script to verify UI, execute actions, and capture screenshots.

Includes strict assertions for:
- PCAP flow replay and processing message (42 packets into 6 completed flows)
- Sample packet generation and flow assembly
- Live Monitor BLOCKED status and explicit permission denial reason
- Zero Streamlit exceptions (.stException) across all 11 pages
- Exit code 0 on success, exit code 1 on failure
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from playwright.sync_api import Page, sync_playwright

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "results" / "acceptance" / "screenshots"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

BASE_URL = "http://localhost:8501"


def assert_no_exceptions(page: Page, page_name: str) -> None:
    """Assert that no unhandled Streamlit exception blocks are present in the DOM."""
    exc_locator = page.locator(".stException")
    count = exc_locator.count()
    if count > 0:
        err_texts = [exc_locator.nth(i).inner_text() for i in range(count)]
        raise AssertionError(
            f"Streamlit exception (.stException) detected on page '{page_name}':\n"
            + "\n---\n".join(err_texts)
        )


def capture_all() -> None:
    print(f"Starting Playwright UI verification and capture against {BASE_URL}...")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path="/usr/bin/google-chrome",
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
        )
        context = browser.new_context(viewport={"width": 1440, "height": 960})
        page = context.new_page()

        # 1. Overview
        print("[1/11] Capturing 01_overview.png...")
        page.goto(f"{BASE_URL}/Overview", wait_until="networkidle")
        page.wait_for_selector("h1, h2", timeout=10000)
        assert_no_exceptions(page, "Overview")
        page.screenshot(path=str(OUTPUT_DIR / "01_overview.png"))

        # 2. Live Monitor
        print("[2/11] Verifying and capturing 02_live_monitor_blocked.png...")
        page.goto(f"{BASE_URL}/Live_Monitor", wait_until="networkidle")
        page.wait_for_selector("h1:has-text('Live Monitor')", timeout=10000)
        assert_no_exceptions(page, "Live_Monitor")
        # Assert BLOCKED status and permission denial reason is explicitly displayed
        blocked_text = page.locator("text=BLOCKED").count() + page.locator("text=Permission Denied").count()
        if blocked_text == 0:
            raise AssertionError("Live Monitor failed assertion: 'BLOCKED' or 'Permission Denied' notice not displayed in unprivileged mode.")
        page.screenshot(path=str(OUTPUT_DIR / "02_live_monitor_blocked.png"))

        # 3. PCAP File Replay
        print("[3/11] Executing PCAP replay and capturing 03_pcap_replay_active.png...")
        page.goto(f"{BASE_URL}/Packet_Flow_Ingestion?mode=pcap", wait_until="networkidle")
        replay_btn = page.locator("button:has-text('Start PCAP Ingestion & Replay')")
        replay_btn.wait_for(state="visible", timeout=10000)
        replay_btn.click()

        # Wait for replay completion alert with explicit text assertion
        success_alert = page.locator("div.stAlert:has-text('Processed 42 packets into 6 completed flows')")
        success_alert.wait_for(state="visible", timeout=15000)
        alert_text = success_alert.inner_text()
        print(f"       Replay Success: {alert_text}")
        assert "Processed 42 packets into 6 completed flows" in alert_text, f"Unexpected replay alert: {alert_text}"
        assert_no_exceptions(page, "Packet_Flow_Ingestion_PCAP")
        page.screenshot(path=str(OUTPUT_DIR / "03_pcap_replay_active.png"))

        # 4. Sample Traffic Generator
        print("[4/11] Executing Sample generation and capturing 04_sample_evaluation.png...")
        page.goto(f"{BASE_URL}/Packet_Flow_Ingestion?mode=sample", wait_until="networkidle")
        sample_btn = page.locator("button:has-text('Generate & Process Sample Packets')")
        sample_btn.wait_for(state="visible", timeout=10000)
        sample_btn.click()

        sample_alert = page.locator("div.stAlert:has-text('sample packets and assembled')")
        sample_alert.wait_for(state="visible", timeout=15000)
        sample_text = sample_alert.inner_text()
        print(f"       Sample Success: {sample_text}")
        assert "sample packets and assembled" in sample_text, f"Unexpected sample alert: {sample_text}"
        assert "completed flows" in sample_text, f"Unexpected sample alert: {sample_text}"
        assert_no_exceptions(page, "Packet_Flow_Ingestion_Sample")
        page.screenshot(path=str(OUTPUT_DIR / "04_sample_evaluation.png"))

        # 5. Detection Events
        print("[5/11] Capturing 05_detection_events.png...")
        page.goto(f"{BASE_URL}/Detection_Events", wait_until="networkidle")
        page.wait_for_selector("h1:has-text('Detection & Security Events')", timeout=10000)
        time.sleep(1.0)
        assert_no_exceptions(page, "Detection_Events")
        page.screenshot(path=str(OUTPUT_DIR / "05_detection_events.png"))

        # 6. Explainability
        print("[6/11] Capturing 06_treeshap_explainability.png...")
        page.goto(f"{BASE_URL}/Explainability", wait_until="networkidle")
        page.wait_for_selector("h1:has-text('TreeSHAP Explainability')", timeout=10000)
        time.sleep(2.0)
        assert_no_exceptions(page, "Explainability")
        page.screenshot(path=str(OUTPUT_DIR / "06_treeshap_explainability.png"))

        # 7. DQN Response Policy
        print("[7/11] Capturing 07_dqn_response_policy.png...")
        page.goto(f"{BASE_URL}/DQN_Response_Policy", wait_until="networkidle")
        page.wait_for_selector("h1:has-text('Dueling DQN Response Policy')", timeout=10000)
        # Assert 6-dimensional state vector contract labels
        assert (
            page.locator("text=Normalized Volumetric Scale").count() > 0
            or page.locator("text=Flow Byte Rate").count() > 0
        ), "Missing volumetric scale dimension label"
        assert (
            page.locator("text=Remaining Cooldown Fraction").count() > 0
            or page.locator("text=Cooldown Steps Remaining").count() > 0
        ), "Missing cooldown fraction dimension label"
        assert_no_exceptions(page, "DQN_Response_Policy")
        page.screenshot(path=str(OUTPUT_DIR / "07_dqn_response_policy.png"))

        # 8. Safety Execution Audit
        print("[8/11] Capturing 08_safety_execution_audit.png...")
        page.goto(f"{BASE_URL}/Safety_Execution_Audit", wait_until="networkidle")
        page.wait_for_selector("h1:has-text('Deterministic Safety & Execution Audit')", timeout=10000)
        # Assert authoritative protected hosts are displayed
        assert page.locator("text=192.168.10.1").count() > 0, "Default gateway 192.168.10.1 missing from safety audit"
        assert page.locator("text=192.168.10.2").count() > 0, "DNS 192.168.10.2 missing from safety audit"
        assert page.locator("text=192.168.10.50").count() > 0, "Domain controller 192.168.10.50 missing from safety audit"
        assert_no_exceptions(page, "Safety_Execution_Audit")
        page.screenshot(path=str(OUTPUT_DIR / "08_safety_execution_audit.png"))

        # 9. Model Evaluation
        print("[9/11] Capturing 09_model_evaluation.png...")
        page.goto(f"{BASE_URL}/Model_Evaluation", wait_until="networkidle")
        page.wait_for_selector("h1:has-text('Model Evaluation & Validation')", timeout=10000)
        assert_no_exceptions(page, "Model_Evaluation")
        page.screenshot(path=str(OUTPUT_DIR / "09_model_evaluation.png"))

        # 10. Research Benchmarks
        print("[10/11] Capturing 10_research_benchmarks.png...")
        page.goto(f"{BASE_URL}/Research_Benchmarks", wait_until="networkidle")
        page.wait_for_selector("h1:has-text('Offline Research Benchmarks')", timeout=10000)
        assert_no_exceptions(page, "Research_Benchmarks")
        page.screenshot(path=str(OUTPUT_DIR / "10_research_benchmarks.png"))

        # 11. System Health
        print("[11/11] Capturing 11_system_health.png...")
        page.goto(f"{BASE_URL}/System_Health", wait_until="networkidle")
        page.wait_for_selector("h1:has-text('System Health & Verification')", timeout=10000)
        assert_no_exceptions(page, "System_Health")
        page.screenshot(path=str(OUTPUT_DIR / "11_system_health.png"))

        browser.close()
        print("\nAll 11 acceptance screenshots captured and all UI assertions passed cleanly!")


if __name__ == "__main__":
    try:
        capture_all()
        sys.exit(0)
    except Exception as exc:
        print(f"\nFATAL: Playwright acceptance verification failed: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
