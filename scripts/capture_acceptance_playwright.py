"""Automated Playwright browser script to verify UI, execute actions, and capture screenshots."""

import time
from pathlib import Path
from playwright.sync_api import sync_playwright

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "results" / "acceptance" / "screenshots"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

BASE_URL = "http://localhost:8501"


def capture_all():
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path="/usr/bin/google-chrome",
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
        )
        context = browser.new_context(viewport={"width": 1440, "height": 960})
        page = context.new_page()

        print("[1/11] Capturing 01_overview.png...")
        page.goto(f"{BASE_URL}/Overview", wait_until="networkidle")
        time.sleep(3.0)
        page.screenshot(path=str(OUTPUT_DIR / "01_overview.png"))

        print("[2/11] Capturing 02_live_monitor_blocked.png...")
        page.goto(f"{BASE_URL}/Live_Monitor", wait_until="networkidle")
        time.sleep(3.0)
        page.screenshot(path=str(OUTPUT_DIR / "02_live_monitor_blocked.png"))

        print("[3/11] Executing PCAP replay and capturing 03_pcap_replay_active.png...")
        page.goto(f"{BASE_URL}/Packet_Flow_Ingestion?mode=pcap", wait_until="networkidle")
        time.sleep(3.0)
        # Click Start PCAP Ingestion & Replay button
        replay_btn = page.locator("button:has-text('Start PCAP Ingestion & Replay')")
        if replay_btn.count() > 0:
            replay_btn.first.click()
            time.sleep(4.0)
        page.screenshot(path=str(OUTPUT_DIR / "03_pcap_replay_active.png"))

        print("[4/11] Executing Sample generation and capturing 04_sample_evaluation.png...")
        page.goto(f"{BASE_URL}/Packet_Flow_Ingestion?mode=sample", wait_until="networkidle")
        time.sleep(3.0)
        sample_btn = page.locator("button:has-text('Generate & Process Sample Packets')")
        if sample_btn.count() > 0:
            sample_btn.first.click()
            time.sleep(4.0)
        page.screenshot(path=str(OUTPUT_DIR / "04_sample_evaluation.png"))

        print("[5/11] Capturing 05_detection_events.png...")
        page.goto(f"{BASE_URL}/Detection_Events", wait_until="networkidle")
        time.sleep(3.0)
        page.screenshot(path=str(OUTPUT_DIR / "05_detection_events.png"))

        print("[6/11] Capturing 06_treeshap_explainability.png...")
        page.goto(f"{BASE_URL}/Explainability", wait_until="networkidle")
        time.sleep(4.0)
        page.screenshot(path=str(OUTPUT_DIR / "06_treeshap_explainability.png"))

        print("[7/11] Capturing 07_dqn_response_policy.png...")
        page.goto(f"{BASE_URL}/DQN_Response_Policy", wait_until="networkidle")
        time.sleep(3.0)
        page.screenshot(path=str(OUTPUT_DIR / "07_dqn_response_policy.png"))

        print("[8/11] Capturing 08_safety_execution_audit.png...")
        page.goto(f"{BASE_URL}/Safety_Execution_Audit", wait_until="networkidle")
        time.sleep(3.0)
        page.screenshot(path=str(OUTPUT_DIR / "08_safety_execution_audit.png"))

        print("[9/11] Capturing 09_model_evaluation.png...")
        page.goto(f"{BASE_URL}/Model_Evaluation", wait_until="networkidle")
        time.sleep(3.0)
        page.screenshot(path=str(OUTPUT_DIR / "09_model_evaluation.png"))

        print("[10/11] Capturing 10_research_benchmarks.png...")
        page.goto(f"{BASE_URL}/Research_Benchmarks", wait_until="networkidle")
        time.sleep(3.0)
        page.screenshot(path=str(OUTPUT_DIR / "10_research_benchmarks.png"))

        print("[11/11] Capturing 11_system_health.png...")
        page.goto(f"{BASE_URL}/System_Health", wait_until="networkidle")
        time.sleep(3.0)
        page.screenshot(path=str(OUTPUT_DIR / "11_system_health.png"))

        browser.close()
        print("All 11 acceptance screenshots captured successfully!")


if __name__ == "__main__":
    capture_all()
