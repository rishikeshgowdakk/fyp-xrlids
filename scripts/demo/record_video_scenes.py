#!/usr/bin/env python3
"""Record high-fidelity 1080p video clips for each scene of the XRL-IDARS Open Day 2026 video."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import time
from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "artifacts" / "open_day_2026"
TEMP_DIR = REPO_ROOT / "artifacts" / "open_day_2026" / "raw_clips"
TEMP_DIR.mkdir(parents=True, exist_ok=True)

FFMPEG = str(REPO_ROOT / ".venv" / "bin" / "ffmpeg")


def record_clip(name: str, target_dur: float, action_fn):
    """Run an action inside Playwright and encode to exact duration MP4."""
    rec_dir = TEMP_DIR / f"rec_{name}"
    if rec_dir.exists():
        shutil.rmtree(rec_dir)
    rec_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path="/usr/bin/google-chrome", headless=True)
        ctx = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            record_video_dir=str(rec_dir),
            record_video_size={"width": 1920, "height": 1080},
        )
        page = ctx.new_page()
        
        # Inject custom styles for recording cleanliness (hide streamlit header/footer badges)
        page.add_init_script("""
            window.addEventListener('DOMContentLoaded', () => {
                const style = document.createElement('style');
                style.innerHTML = `
                    #MainMenu {visibility: hidden;}
                    footer {visibility: hidden;}
                    header {visibility: hidden;}
                    [data-testid="stStatusWidget"] {display: none !important;}
                    [data-testid="stToolbar"] {display: none !important;}
                    .stDeployButton {display: none !important;}
                `;
                document.head.appendChild(style);
            });
        """)

        action_fn(page)

        ctx.close()
        browser.close()

    # Find recorded webm
    recorded_files = list(rec_dir.glob("*.webm"))
    if not recorded_files:
        raise RuntimeError(f"No webm recorded for {name}")

    raw_webm = recorded_files[0]
    out_mp4 = OUTPUT_DIR / f"{name}.mp4"

    print(f"[*] Encoding {name}.mp4 (target {target_dur}s at 30 FPS 1080p)...")
    # Re-encode to standard H.264 1080p 30fps with exact duration
    subprocess.run([
        FFMPEG, "-y",
        "-i", str(raw_webm),
        "-t", f"{target_dur:.2f}",
        "-vf", "scale=1920:1080,fps=30,format=yuv420p",
        "-c:v", "libx264",
        "-preset", "fast",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        str(out_mp4)
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] Finished {out_mp4}")


def record_scene1(page):
    url = f"file://{OUTPUT_DIR}/scene1_intro.html"
    page.goto(url)
    page.wait_for_timeout(11500)


def record_scene2(page):
    page.goto("http://localhost:8501")
    page.wait_for_timeout(3500)
    # Smooth subtle scroll down to show executive cards
    page.evaluate("window.scrollBy({top: 180, behavior: 'smooth'})")
    page.wait_for_timeout(7000)


def record_scene3(page):
    page.goto("http://localhost:8501")
    page.wait_for_timeout(2500)
    # Scroll to animated SVG flowchart
    page.evaluate("window.scrollBy({top: 450, behavior: 'smooth'})")
    page.wait_for_timeout(8000)
    # Scroll down to latency budget table
    page.evaluate("window.scrollBy({top: 350, behavior: 'smooth'})")
    page.wait_for_timeout(6000)


def record_scene4(page):
    page.goto("http://localhost:8501")
    page.wait_for_timeout(2000)
    
    # Navigate to Live Demo
    nav_links = page.query_selector_all("a[data-testid='stSidebarNavLink']")
    for link in nav_links:
        if "Live Demo" in link.inner_text():
            link.click()
            break
    page.wait_for_timeout(3000)

    # 1. Click Benign Ping
    benign_btn = page.query_selector("button:has-text('Benign Ping')")
    if benign_btn:
        benign_btn.click()
        page.wait_for_timeout(2500)

    # 2. Click SYN Burst
    syn_btn = page.query_selector("button:has-text('SYN Burst')")
    if syn_btn:
        syn_btn.click()
        page.wait_for_timeout(2500)

    # Scroll to Deep-Dive Tabs
    page.evaluate("window.scrollBy({top: 350, behavior: 'smooth'})")
    page.wait_for_timeout(1500)

    # Cycle through 4 Deep-Dive tabs
    tabs = page.query_selector_all("*[role='tab']")
    if len(tabs) >= 4:
        # Tab 1: Perception
        tabs[0].click()
        page.wait_for_timeout(3000)
        # Tab 2: TreeSHAP
        tabs[1].click()
        page.wait_for_timeout(4000)
        # Tab 3: DQN Response
        tabs[2].click()
        page.wait_for_timeout(4000)
        # Tab 4: Safety & Verification
        tabs[3].click()
        page.wait_for_timeout(3500)


def record_scene5(page):
    page.goto("http://localhost:8501")
    page.wait_for_timeout(2000)

    # Navigate to Benchmarks
    nav_links = page.query_selector_all("a[data-testid='stSidebarNavLink']")
    for link in nav_links:
        if "Benchmarks" in link.inner_text():
            link.click()
            break
    page.wait_for_timeout(3500)

    # Show dataset overview & multi-model comparison table
    page.evaluate("window.scrollBy({top: 250, behavior: 'smooth'})")
    page.wait_for_timeout(5000)
    # Scroll to confusion matrix
    page.evaluate("window.scrollBy({top: 400, behavior: 'smooth'})")
    page.wait_for_timeout(5500)


def record_scene6(page):
    url = f"file://{OUTPUT_DIR}/scene6_impact.html"
    page.goto(url)
    page.wait_for_timeout(12000)


def record_scene7(page):
    url = f"file://{OUTPUT_DIR}/scene7_closing.html"
    page.goto(url)
    page.wait_for_timeout(7000)


def main():
    print("=================================================================")
    print(" Recording 7 High-Fidelity 1080p Clips for Open Day Video        ")
    print("=================================================================")

    # Scene 1: Introduction (10.5s)
    record_clip("clip_1_intro", 10.5, record_scene1)

    # Scene 2: Problem & Solution (9.5s)
    record_clip("clip_2_overview", 9.5, record_scene2)

    # Scene 3: Architecture & Workflow (15.5s)
    record_clip("clip_3_architecture", 15.5, record_scene3)

    # Scene 4: Live Demonstration (23.0s)
    record_clip("clip_4_livedemo", 23.0, record_scene4)

    # Scene 5: Benchmarks & Evaluation (13.0s)
    record_clip("clip_5_benchmarks", 13.0, record_scene5)

    # Scene 6: Real-World Applications (11.0s)
    record_clip("clip_6_impact", 11.0, record_scene6)

    # Scene 7: Closing (6.0s)
    record_clip("clip_7_closing", 6.0, record_scene7)

    print("\n[+] All 7 video clips recorded successfully!")


if __name__ == "__main__":
    main()
