#!/usr/bin/env python3
"""Assemble, subtitle, and mix the final 1080p 30 FPS Open Day Demonstration Video."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "artifacts" / "open_day_2026"
FFMPEG = str(REPO_ROOT / ".venv" / "bin" / "ffmpeg")


def main():
    print("=================================================================")
    print(" Assembling Final XRL-IDARS Open Day Demonstration Video        ")
    print("=================================================================")

    # 1. Create concat list
    concat_txt = OUTPUT_DIR / "concat_list.txt"
    clip_names = [
        "clip_1_intro.mp4",
        "clip_2_overview.mp4",
        "clip_3_architecture.mp4",
        "clip_4_livedemo.mp4",
        "clip_5_benchmarks.mp4",
        "clip_6_impact.mp4",
        "clip_7_closing.mp4",
    ]
    with open(concat_txt, "w") as f:
        for c in clip_names:
            f.write(f"file '{c}'\n")

    # Step 1: Concatenate video clips into a single video track
    concat_video = OUTPUT_DIR / "concatenated_video_track.mp4"
    print("[*] Concatenating 7 video clips...")
    subprocess.run([
        FFMPEG, "-y",
        "-f", "concat", "-safe", "0",
        "-i", str(concat_txt),
        "-c", "copy",
        str(concat_video)
    ], check=True)

    # Step 2: Final composite with audio and burned subtitles
    audio_mix = OUTPUT_DIR / "master_audio_mix.wav"
    srt_path = OUTPUT_DIR / "XRL_IDARS_Subtitles.srt"
    final_output = OUTPUT_DIR / "XRL_IDARS_Open_Day_Demo.mp4"

    # Subtitle style: professional cybersecurity broadcast look (clean white with dark translucent pill outline)
    sub_style = (
        "FontName=DejaVu Sans,"
        "FontSize=22,"
        "Bold=1,"
        "PrimaryColour=&H00FFFFFF,"
        "OutlineColour=&H00000000,"
        "BorderStyle=3,"
        "BackColour=&HB0050811,"
        "Outline=2,"
        "Shadow=0,"
        "MarginV=38,"
        "Alignment=2"
    )

    vf_filter = f"subtitles={srt_path}:force_style='{sub_style}'"

    print("[*] Rendering final video with subtitles and master audio mix...")
    cmd = [
        FFMPEG, "-y",
        "-i", str(concat_video),
        "-i", str(audio_mix),
        "-filter_complex", f"[0:v]{vf_filter}[v]",
        "-map", "[v]",
        "-map", "1:a",
        "-c:v", "libx264",
        "-preset", "medium",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        "-r", "30",
        "-c:a", "aac",
        "-b:a", "192k",
        "-movflags", "+faststart",
        "-shortest",
        str(final_output)
    ]
    subprocess.run(cmd, check=True)
    print(f"[+] Final Video created at: {final_output}")

    # Inspect final video
    res = subprocess.run([FFMPEG, "-i", str(final_output)], stderr=subprocess.PIPE, text=True)
    for line in res.stderr.splitlines():
        if "Duration:" in line or "Stream #0" in line:
            print("  ", line.strip())


if __name__ == "__main__":
    main()
